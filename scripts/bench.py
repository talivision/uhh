#!/usr/bin/env python3
"""Run Windows correctness gates, then randomized paired timing comparisons.
No timings are included in this source package. Any failed gate aborts the run.
"""
import argparse
import csv
import json
import random
import statistics
import subprocess
import time
from pathlib import Path

MODES = ['baseline', 'inline', 'veh-sw', 'debug-sw', 'debug-hw']
CAPACITY = 8192
MASK = (1 << 64) - 1


def expected_stats(target, callback, workload, n, warmup, instrumented):
    records = []
    matches = 0
    total_records = 0
    ordinal = 0

    def emit(row):
        nonlocal total_records
        total_records += 1
        if len(records) < CAPACITY:
            records.append(row)

    if instrumented:
        for count in (warmup, n):
            for i in range(count):
                if callback in ('filter', 'log') and i % 100 == 0:
                    matches += 1
                    if callback == 'log':
                        emit((0, target['flag_site'], 1, i))
                if workload == 'reads':
                    if callback != 'noop' and i % 4 in (0, 3):
                        matches += 1
                        if callback in ('mutate', 'log'):
                            emit((target['selected_handle'], target['range_start'] + (16 if i % 4 == 3 else 0), 16, ordinal))
                    ordinal += 1
    digest = 14695981039346656037
    for row in records:
        for word in row:
            digest = ((digest ^ word) * 1099511628211) & MASK
    return dict(flag_hits=n + warmup if instrumented else 0,
                read_hits=n + warmup if instrumented and workload == 'reads' else 0,
                matches=matches, errors=0, recorded=len(records),
                dropped=total_records - len(records), record_digest=digest)


def validate(objects, mode, workload, n, warmup, callback, prehook):
    targets = [o for o in objects if o.get('kind') == 'target']
    if len(targets) != 1:
        raise AssertionError('expected exactly one target result')
    target = targets[0]
    assert target['enabled'] == n, target
    assert target['successful_reads'] == (n if workload == 'reads' else 0), target
    checksum = sum(128 if i % 4 == 1 else 80 if i % 4 == 3 else 64 for i in range(n)) if workload == 'reads' else n
    assert target['checksum'] == checksum, target
    assert target['prehook'] == prehook, target
    assert target['prehook_calls'] == (n + warmup if prehook and workload == 'reads' else 0), target
    if mode.startswith('debug-'):
        controllers = [o for o in objects if o.get('kind') == 'controller']
        assert len(controllers) == 1, objects
        actual = controllers[0]
    else:
        actual = target
    expected = expected_stats(target, callback, workload, n, warmup, mode != 'baseline')
    for key, value in expected.items():
        assert actual[key] == value, (mode, workload, callback, key, actual[key], value)
    return target, actual


def run_case(binary_dir, mode, workload, n, warmup, callback, mutation, prehook, timeout):
    exe = 'probe_debugger.exe' if mode.startswith('debug-') else 'probe_target.exe'
    command = [str(binary_dir / exe), mode, workload, str(n), callback, mutation,
               str(warmup), 'prehook' if prehook else 'clean']
    begin = time.perf_counter_ns()
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    wall = time.perf_counter_ns() - begin
    if result.returncode:
        raise RuntimeError(f'{command!r}\nexit={result.returncode}\n{result.stdout}\n{result.stderr}')
    objects = [json.loads(line) for line in result.stdout.splitlines() if line.startswith('{')]
    target, actual = validate(objects, mode, workload, n, warmup, callback, prehook)
    # With an existing layer, both the classification and exactly-once counter
    # must agree. This is a controlled fixture, not a universal detector test.
    if mode != 'baseline' and workload == 'reads':
        lines = [line for line in result.stderr.splitlines() if line.startswith('probe: read @')]
        assert len(lines) == 1, result.stderr
        description = lines[0]
        assert ('fixture-clean' not in description and 'unknown' not in description) if prehook else 'fixture-clean' in description, description
    return dict(mode=mode, workload=workload, callback=callback, mutation=mutation,
                prehook=prehook, iterations=n, warmup=warmup,
                elapsed_ns=target['elapsed_ns'], subprocess_wall_ns=wall,
                recorded=actual['recorded'], dropped=actual['dropped'],
                target_cpu_ns=target['target_cpu_ns'],
                controller_cpu_ns_total=actual.get('controller_cpu_ns_total', 0))


def summarize(rows):
    groups = {}
    for r in rows:
        key = (r['workload'], r['callback'], r['mutation'], r['prehook'], r['mode'])
        groups.setdefault(key, []).append(r['elapsed_ns'] / r['iterations'])
    summaries = []
    for key, values in sorted(groups.items()):
        workload, callback, mutation, prehook, mode = key
        baseline = groups[(workload, callback, mutation, prehook, 'baseline')]
        median = statistics.median(values)
        # reads crosses flag + read probes. Report per iteration to avoid
        # attributing a two-probe workload to a single breakpoint.
        summaries.append(dict(workload=workload, callback=callback, mutation=mutation,
                              prehook=prehook, mode=mode, repeats=len(values),
                              median_ns_per_iteration=median, min_ns_per_iteration=min(values),
                              max_ns_per_iteration=max(values),
                              added_ns_per_iteration=median-statistics.median(baseline),
                              slowdown=median/statistics.median(baseline)))
    return summaries


def main():
    p = argparse.ArgumentParser()
    p.add_argument('--bin', type=Path, default=Path('build/Release'))
    p.add_argument('--iterations', type=int, default=2000)
    p.add_argument('--reads-iterations', type=int, default=200)
    p.add_argument('--warmup', type=int, default=32)
    p.add_argument('--repeats', type=int, default=3)
    p.add_argument('--timeout', type=float, default=90)
    p.add_argument('--out', type=Path, default=Path('results'))
    p.add_argument('--correctness-only', action='store_true')
    args = p.parse_args()
    if min(args.iterations, args.reads_iterations, args.repeats) <= 0 or args.warmup < 0:
        p.error('iterations/repeats must be positive; warmup must be nonnegative')
    args.bin = args.bin.resolve()
    args.out.mkdir(parents=True, exist_ok=True)
    correctness = []
    for prehook in (False, True):
        for mutation in ('register', 'memory'):
            for mode in MODES:
                correctness.append(run_case(args.bin, mode, 'reads', 64, 16,
                                            'mutate', mutation, prehook, args.timeout))
                print(f'PASS {mode} reads {mutation} prehook={prehook}', flush=True)
    (args.out / 'correctness.json').write_text(json.dumps(correctness, indent=2))
    if args.correctness_only:
        return
    rows = []
    rng = random.Random(20261103)
    scenarios = [('micro', c, False) for c in ('noop', 'filter', 'mutate', 'log')]
    scenarios += [('reads', 'mutate', prehook) for prehook in (False, True)]
    with (args.out / 'raw.jsonl').open('w') as out:
        for workload, callback, prehook in scenarios:
            n = args.iterations if workload == 'micro' else args.reads_iterations
            for repeat in range(args.repeats):
                order = MODES.copy()
                rng.shuffle(order)
                for mode in order:
                    row = run_case(args.bin, mode, workload, n, args.warmup, callback,
                                   'register', prehook, args.timeout)
                    row['repeat'] = repeat
                    rows.append(row)
                    out.write(json.dumps(row) + '\n')
                    out.flush()
                print(f'bench {workload} {callback} prehook={prehook} repeat={repeat+1}', flush=True)
    summary = summarize(rows)
    with (args.out / 'summary.csv').open('w', newline='') as out:
        writer = csv.DictWriter(out, fieldnames=list(summary[0]))
        writer.writeheader()
        writer.writerows(summary)
    (args.out / 'summary.json').write_text(json.dumps(summary, indent=2))
    print(f'All correctness gates passed. Results: {args.out.resolve()}')


if __name__ == '__main__':
    main()

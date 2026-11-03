"""Portable checks for the independent benchmark oracle, not Windows results."""
import importlib.util
import unittest
from pathlib import Path
spec = importlib.util.spec_from_file_location('bench', Path(__file__).parents[1] / 'scripts/bench.py')
bench = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bench)

class OracleTests(unittest.TestCase):
    def test_read_mixture_and_warmup_reset(self):
        t = dict(flag_site=0x111, selected_handle=7, range_start=0x2000)
        s = bench.expected_stats(t, 'mutate', 'reads', 5, 3, True)
        self.assertEqual(s['flag_hits'], 8)
        self.assertEqual(s['read_hits'], 8)
        self.assertEqual(s['matches'], 4)  # warm [0], measured [0,3,4]
        self.assertEqual(s['recorded'], 4)

    def test_failed_mutation_aborts(self):
        with self.assertRaises(AssertionError):
            bench.validate([dict(kind='target', enabled=0)], 'inline', 'reads', 5, 0, 'mutate', True)

    def test_dropped_records(self):
        t = dict(flag_site=0x111, selected_handle=7, range_start=0x2000)
        s = bench.expected_stats(t, 'mutate', 'reads', 20000, 0, True)
        self.assertEqual(s['matches'], 10000)
        self.assertEqual(s['recorded'], 8192)
        self.assertEqual(s['dropped'], 1808)

    def test_baseline_subtraction(self):
        rows = [dict(workload='micro', callback='noop', mutation='register', prehook=False,
                     mode=mode, elapsed_ns=cost, iterations=10)
                for mode, cost in [('baseline', 100), ('inline', 150)]]
        summary = bench.summarize(rows)
        inline = next(r for r in summary if r['mode'] == 'inline')
        self.assertEqual(inline['added_ns_per_iteration'], 5)
        self.assertEqual(inline['slowdown'], 1.5)

if __name__ == '__main__':
    unittest.main()

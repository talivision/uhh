# Validation during creation

Creation host: Linux x86_64. No Windows execution environment, Windows SDK,
MSVC/MASM or Wine was available. No Windows build or end-to-end benchmark has
been performed. There are no fabricated benchmark results in this package.

Executed:

- GCC C11 compilation of src/callback.c and tests/policy_tests.c with
  -Wall -Wextra -Werror and AddressSanitizer/UndefinedBehaviorSanitizer.
- Policy executable passed register mutation, memory mutation, invalid access,
  process-handle/range selection, overflow rejection, bounded-log drops and noop.
- LeakSanitizer cannot run under this host's tracing environment; the test was
  rerun with ASAN_OPTIONS=detect_leaks=0. Address and undefined-behaviour checking
  remained enabled. The portable test uses no dynamic allocation.
- Four Python unittest checks passed: independently calculated read selection
  including warmup-index reset, failure rejection, log-capacity accounting,
  baseline subtraction.
- Python syntax compilation of runner and tests passed.
- SafetyHook v0.7.0 public headers and CMake options were inspected to check the
  adapter's context field names, create_mid/create_inline, reset and target names.

These checks validate the shared policy and benchmark oracle, not Windows APIs,
trampoline relocation, exception re-arming, register preservation, DLL lifetime,
or actual timing. The supplied Windows runner and manual-dispatch workflow are
provided to establish those results next. The first expected acceptance run is:

    python scripts/bench.py --bin build/Release --correctness-only

Do not treat the source as production instrumentation or reuse the single-thread
software breakpoint handler in an arbitrary multithreaded target.

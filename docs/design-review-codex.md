# Design review

Overall: the architecture is promising, but `probe_add(..., cb, void *user, ...)` is not yet a sound cross-process API. The largest blockers are callback/config transport, capability declaration, the x86 ABI claim, and the impossible-at-entry `NtOpenProcess` mapping example.

## (a) Sound / keep

- **One callback source compiled for both execution domains is the right abstraction.** The handoff correctly distinguishes source portability from transporting a function pointer or reusing identical machine code ([handoff §Agreed design](/Users/tali/projects/usermodehooks/probe-first-pass/docs/windows-probe-agent-handoff.md:13)). Keep target memory behind helpers and normalize PC to the original site.

- **Per-probe backend selection is appropriate.** A cold mutation probe and hot inline read probe genuinely need different mechanisms ([plan-v2 §Backends](/Users/tali/projects/usermodehooks/probe-first-pass/docs/plan-v2.md:29)). Selection should remain per probe, subject to a session-wide compatibility/resource check.

- **Pending module-relative probes are the correct model.** Registration should succeed while unresolved, then transition visibly through pending/resolving/active states. The external debugger can arm at `LOAD_DLL` before continuing, as the precursor demonstrates ([session.cpp](/Users/tali/projects/usermodehooks/probe-first-pass/src/session.cpp:117)).

- **Fail-fast for an inline site modified before arrival is a good default.** It is conservative and, critically, requires rollback of the entire attempted installation. The diagnostic is appropriately described as advisory rather than an automatic detour solver ([plan-v2 §Pre-existing hook policy](/Users/tali/projects/usermodehooks/probe-first-pass/docs/plan-v2.md:41)).

- **Deferred logging and reader-side name lookup are sound goals.** Per-thread single-producer queues, fixed records, explicit drop accounting, and no callback-time name lookup are the right direction ([plan-v2 §Logging](/Users/tali/projects/usermodehooks/probe-first-pass/docs/plan-v2.md:80)).

- **PID plus creation identity is the correct process identity.** Creation-time eligibility, exact basename matching, optional path restriction, and no fallback to pre-existing instances should remain normative ([handoff §new process](/Users/tali/projects/usermodehooks/probe-first-pass/docs/windows-probe-agent-handoff.md:102)).

## (b) Risky or underspecified

### 1. The callback and `user` ABI cannot implement the advertised inline behavior

The API accepts a controller function pointer and an untyped `void *`, while saying the callback and user data are copied into the agent ([api sketch](/Users/tali/projects/usermodehooks/probe-first-pass/docs/api-sketch.md:10), [probe_add surface](/Users/tali/projects/usermodehooks/probe-first-pass/docs/api-sketch.md:77)). Neither is copyable as written:

- The inline agent needs an architecture-matched compiled callback artifact and a stable callback identity, not the controller address.
- A `void *` gives no size, alignment, ownership, pointer graph, or serialization rule.
- External probes observe controller-owned data live; inline probes apparently receive a snapshot. Mutating the same `user` object would therefore have backend-dependent semantics.
- Stack lifetime is unspecified if a probe outlives the creating scope.

**Suggestion:** register a callback descriptor containing an ABI version, stable callback ID, controller entry point, agent artifact/export identity, declared requirements, and an immutable fixed-width configuration blob with size. Copy the blob for *all* backends so semantics match. Add an explicit update operation if live configuration changes are required.

### 2. The handle-to-PID example cannot work at `NtOpenProcess` entry

On x64, `RCX` at `NtOpenProcess` entry is `PHANDLE`, not the resulting handle. The handle does not exist until successful return. Nevertheless, the flat-array example indexes it as the raw handle ([api sketch §Handle map](/Users/tali/projects/usermodehooks/probe-first-pass/docs/api-sketch.md:102)). `probe_client_pid()` also has no described mechanism; the PID resides behind the target `CLIENT_ID` pointer.

The main example is independently nonfunctional: `filter.selected_handle` and `range_start` remain zero ([api sketch](/Users/tali/projects/usermodehooks/probe-first-pass/docs/api-sketch.md:40)), while the target only announces the real values after starting ([app.cpp](/Users/tali/projects/usermodehooks/probe-first-pass/src/app.cpp:127)).

**Suggestion:** either:

1. Add a genuine return-probe/paired-call facility and record the returned handle only when `NTSTATUS` succeeds; or
2. Probe a known post-call site where the returned handle and PID are available.

For the controlled example, expose a readiness/event channel that lets the controller populate an immutable filter before arming/releasing the gate. Do not present an entry-only `NtOpenProcess` probe as a completed map.

### 3. “Capability error at `probe_add` time” is impossible with an opaque callback

The library cannot inspect an arbitrary C function and know that it may call `probe_set_reg`, change PC, write memory, or log. Some checks also depend on a module that has not loaded and on resources that can change later, such as DR-slot availability ([api sketch](/Users/tali/projects/usermodehooks/probe-first-pass/docs/api-sketch.md:87)).

**Suggestion:** put required effects in the callback/probe descriptor, such as:

- register read/write sets;
- memory read/write;
- logging;
- control-flow modification;
- concurrency/reentrancy requirements.

Validate static compatibility at `probe_add`, reserve scarce resources at `probe_run`, and report resolution/activation failures asynchronously against the probe handle. Runtime helpers must still return `UNSUPPORTED`, not silently succeed.

### 4. The register API is not architecture-neutral as shown

`PROBE_RAX`, `PROBE_RCX`, `PROBE_RDX`, and `PROBE_R9` encode the x64 machine and calling convention. A 32-bit `NtReadVirtualMemory` call places arguments on the stack; merely mapping `RAX` to `EAX` does not preserve the callback source. The present adapter confirms the x64 coupling ([probe.h](/Users/tali/projects/usermodehooks/probe-first-pass/include/probe.h:8), [win_common.hpp](/Users/tali/projects/usermodehooks/probe-first-pass/include/win_common.hpp:24)).

**Suggestion:**

- Put `probe_arch` and register width/availability in every context.
- Use logical overlapping IDs such as `PROBE_REG_AX`, with checked reads/writes and explicitly defined x86/x64 width semantics.
- For function-entry probes, optionally provide `probe_arg(ctx, calling_convention, index, ...)`; reject it at arbitrary mid-function sites.
- If callbacks must remain unchanged across the read wrapper on both architectures, define per-architecture capture expressions at registration and expose normalized named values to the callback.
- Use only fixed-width wire structures between x64 controllers, WoW64 targets, and x86 agents.

### 5. Backend combinations need an explicit compatibility matrix

Several combinations are not safely independent:

- An in-process INT3 under an external debugger sends each exception through the debugger first; the plan rejects this, but the API exposes both generic and external software breakpoint choices.
- In-process and external hardware breakpoints compete for the same four per-thread DR slots.
- In-process HW/VEH under a debugger still causes debugger-visible single-step exceptions.
- Two probes at the same address can overwrite or reinterpret each other’s patch.
- Fallback-to-HW cannot be guaranteed unless a slot is reserved across all current and future threads.
- Callback scheduling differs: debugger callbacks are serialized; inline callbacks are concurrent.

Current implementations already show global ownership assumptions and direct DR-slot use ([agent.cpp](/Users/tali/projects/usermodehooks/probe-first-pass/src/agent.cpp:38), [debugger.cpp](/Users/tali/projects/usermodehooks/probe-first-pass/src/debugger.cpp:59)). The multithreaded bugs are already catalogued in [review-findings.md](/Users/tali/projects/usermodehooks/probe-first-pass/docs/review-findings.md:46); the API must prevent those unsupported combinations from being selectable.

**Suggestion:** validate the complete session plan before arming. Define supported backend pairs, same-site composition/order, exception ownership, DR allocation, and whether a session may coexist with another debugger. Reject unsupported mixes deterministically.

### 6. Pending activation needs a formal state and module-identity model

A basename is insufficient for side-by-side modules, unload/reload, or same-name modules from different paths. The handoff requires reconciliation and unload handling ([handoff §Deferred activation](/Users/tali/projects/usermodehooks/probe-first-pass/docs/windows-probe-agent-handoff.md:185)), but the API exposes neither probe status nor module selection policy.

**Suggestion:** define a probe state machine such as:

`PENDING → RESOLVING → ACTIVE → PENDING_ON_UNLOAD / FAILED / REMOVED`

Use module identity comprising canonical path plus file identity/build identity and mapping base/generation. Deduplicate reconciliation and load events by that identity. On unload, invalidate the installation and remove HW state without trying to restore bytes into an unmapped generation.

For agent activation, explicitly require a post-loader-lock worker/rendezvous. “Automatically on load before first call” is only guaranteed for an external debugger stopped at the load event or a cooperative target gate.

### 7. Busy-wait attachment needs a session builder, not just a blocking constructor

`probe_wait_for_new(name, flags)` does not expose watcher readiness, timeout, cancellation, path restriction, tie-breaking, selected creation identity, or exit-before-attach—all required by the handoff ([api sketch](/Users/tali/projects/usermodehooks/probe-first-pass/docs/api-sketch.md:74), [handoff](/Users/tali/projects/usermodehooks/probe-first-pass/docs/windows-probe-agent-handoff.md:114)).

It also cannot promise interception of sites crossed between process creation and polling/attach.

**Suggestion:** separate session creation, probe registration, watcher start/readiness, successful attachment, and run. Hold a process handle, revalidate creation identity immediately before and after `DebugActiveProcess`, and document deterministic `(creation time, PID)` selection. Reserve first-call guarantees for debugger launch/suspended launch or the cooperative fixture gate.

### 8. Deferred printf formatting needs a restricted schema

“Format ID plus raw 8-byte arguments” is not sufficient for general C varargs:

- Format pointer values differ between controller and agent builds.
- Types, signedness, floating-point arguments, `*` width/precision, `%ls`, and Windows’ 32-bit `long` are not represented by raw values alone.
- `%s` may reference callback-local or target memory and may fault or change before copying.
- Hash-based IDs need collision and version handling.

**Suggestion:** require literal formats and a documented limited grammar, with compile-time type tags and a stable dictionary ID, or prefer generated structured event schemas. Record truncation and copy faults explicitly.

For queueing, define preallocated thread registration, pool-exhaustion behavior, TID reuse/generation, queue retirement, timestamp clock, per-thread sequence, and merge tie-breaks. Lossless blocking should not be the default for arbitrary inline sites because it can deadlock the target.

### 9. The prehook flags need tighter semantics

The default policy is right, but these details are open:

- `ALLOW_PREHOOKED` plus `FALLBACK_BREAKPOINT` precedence.
- Whether allowing means “attempt to relocate” or promises compatibility.
- Whether one pending probe’s later failure aborts and rolls back the whole session.
- Which HW domain fallback chooses.
- Whether the effective backend is visible in reports.

“Universal no-clobber fallback” overstates HW breakpoints: they have four slots, per-thread installation races, debugger conflicts, and no guarantee for newly created threads ([plan-v2](/Users/tali/projects/usermodehooks/probe-first-pass/docs/plan-v2.md:48)).

**Suggestion:** make fallback an explicit ordered backend list and make the two current flags mutually exclusive. Report requested backend, effective backend, reason, and reserved resources. Treat allow-prehooked as permission to *attempt* chaining; relocation failure must still fail safely.

The diagnostic’s reachability warning is honest. However, resolving an indirect `jmp [rip+disp]` requires reading the target pointer from the probed process; Zydis formatting alone only describes the operand ([disasm.hpp](/Users/tali/projects/usermodehooks/probe-first-pass/include/disasm.hpp:8)). Label direct, indirect-current-value, and unresolved targets distinctly.

## (c) Missing for real use

- **Probe handles and status:** `probe_add` should return a `probe_id`/handle supporting status inspection, hit/drop counts, resolved address/module generation, effective backend, disable/remove, and pending cancellation.

- **Structured error reporting:** every operation needs a status plus detailed error containing stage, probe ID, location, requested/effective backend, Win32/NT status, and cleanup outcome. Pending activation errors must be observable after `probe_run`.

- **Removal and quiescence:** define whether removal waits for active inline callbacks, when `user` may be freed, and whether `probe_close` is idempotent. Add `probe_stop`/`probe_detach`; waiting for process exit is not a teardown API for instrumentation of a long-lived attached process.

- **Lifecycle guarantees:** specify whether launch is suspended/debug-stopped until `probe_run`, whether `probe_run` is transactional, what happens to a launched child on setup failure, and who owns the debugger event-loop thread.

- **Callback safety contract:** document that inline callbacks may run concurrently at arbitrary target states and must not allocate, take uncontrolled locks, invoke loader-sensitive APIs, throw, or recursively hit instrumented code. Define callback-fault containment and agent-unload behavior.

- **Memory-helper results:** expose transferred length and error status. The current convenience helpers discard short-transfer information ([probe.h](/Users/tali/projects/usermodehooks/probe-first-pass/include/probe.h:38)), contrary to the handoff’s required contract.

- **Location forms:** add the required absolute-address form and a structured module selector supporting full path/build identity, architecture-specific RVA, symbol options, expected bytes, and instance policy.

- **ABI versioning:** version `probe_context`, helper tables, event records, serialized configuration, and callback artifacts so controller and injected agent mismatches fail before installation.

## (d) Inconsistencies

| Issue | Conflict |
|---|---|
| Handle mapping | The API sketch performs live inline flat-array lookup and logs PID ([api sketch](/Users/tali/projects/usermodehooks/probe-first-pass/docs/api-sketch.md:90)); the agreed plan says reads log only raw handles and the reader reconstructs timestamped open/close intervals ([plan-v2](/Users/tali/projects/usermodehooks/probe-first-pass/docs/plan-v2.md:65)). Choose one. The timestamped event replay is the only version that preserves historical reuse without a PID snapshot on every read. |
| `NtOpenProcess` site | Both documents imply entry-time mapping, but the returned handle is unavailable there. This also conflicts with the handoff, which calls return probes a future extension ([handoff](/Users/tali/projects/usermodehooks/probe-first-pass/docs/windows-probe-agent-handoff.md:88)). |
| Fixture handle source | The plan requires `OpenProcess(pid)` so `NtOpenProcess` is observed ([plan-v2](/Users/tali/projects/usermodehooks/probe-first-pass/docs/plan-v2.md:75)); the current app uses `PROCESS_INFORMATION.hProcess` directly ([app.cpp](/Users/tali/projects/usermodehooks/probe-first-pass/src/app.cpp:130)). |
| Backend names | The sketch lists both `PROBE_BREAKPOINT_SW/HW` and `PROBE_EXTERNAL_SW/HW` without defining the former’s execution domain ([api sketch](/Users/tali/projects/usermodehooks/probe-first-pass/docs/api-sketch.md:79)). The plan describes inline + in-process HW via VEH and explicitly rejects in-process INT3 under a debugger ([plan-v2](/Users/tali/projects/usermodehooks/probe-first-pass/docs/plan-v2.md:31)). |
| Location support | The handoff requires absolute addresses, module offsets, and symbols ([handoff](/Users/tali/projects/usermodehooks/probe-first-pass/docs/windows-probe-agent-handoff.md:30)); the API sketch lists only the latter two. |
| Configuration semantics | The handoff says inline configuration is serialized agent-local data ([handoff](/Users/tali/projects/usermodehooks/probe-first-pass/docs/windows-probe-agent-handoff.md:46)); the API supplies only an unbounded `void *`. |
| Memory contract | The handoff requires failure plus short-transfer reporting ([handoff](/Users/tali/projects/usermodehooks/probe-first-pass/docs/windows-probe-agent-handoff.md:54)); the implied API reduces helpers to whole-transfer Boolean success. |
| Win32 portability | The API claims `PROBE_RAX/RCX/R9` are arch-neutral ([api sketch](/Users/tali/projects/usermodehooks/probe-first-pass/docs/api-sketch.md:82)); the plan explicitly says x86 has no `r8–r15` and requires distinct adapters ([plan-v2](/Users/tali/projects/usermodehooks/probe-first-pass/docs/plan-v2.md:104)). |
| First-call guarantee | The sketch broadly says pending probes activate before the first call ([api sketch](/Users/tali/projects/usermodehooks/probe-first-pass/docs/api-sketch.md:49)); the handoff limits that guarantee for polling attachment and agent loader notification, requiring a debugger stop or cooperative rendezvous ([handoff](/Users/tali/projects/usermodehooks/probe-first-pass/docs/windows-probe-agent-handoff.md:124)). |
| Teardown order | The sketch waits for target exit and only then says `probe_close` restores bytes ([api sketch](/Users/tali/projects/usermodehooks/probe-first-pass/docs/api-sketch.md:64)). Restoration matters only while the process is alive; attached sessions require stop/remove/detach before waiting indefinitely. |

The key redesign is to make `probe_add` accept a versioned probe/callback descriptor and return a probe handle. Once callback identity, serialized configuration, declared capabilities, effective backend, and asynchronous state are explicit, the rest of the architecture can remain largely as planned.

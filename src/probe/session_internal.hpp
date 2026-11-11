// Internal to the probe_api library: the session / probe structures and the helpers shared
// by the session_*.cpp units (session.cpp: API; see each file's first lines for its part).
#pragma once
#include "win_common.hpp"
#include "probe_log_format.hpp"
#include "probe_agent_shared.hpp"
#include <cerrno>
#include <cstdlib>
#include <cwchar>
#include <cctype>
#include <cstdarg>
#include <climits>
#include <memory>
#include <type_traits>
#include <string>
#include <unordered_map>
#include <map>
#include <set>
#include <algorithm>
#include <charconv>
#include <vector>
#include <array>
#include <Zydis/Zydis.h>
#include "symbols.hpp"   // dbghelp+symsrv loaded dynamically; honours _NT_SYMBOL_PATH
#include <tlhelp32.h>
#include <timeapi.h>
#pragma comment(lib, "winmm.lib")
#include <unordered_set>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>
#include <psapi.h>

// Every thread-context write of this file goes through here: one that carries debug registers
// bumps g_dr_epoch, so a hw hit re-reads its thread's DR image after the callbacks only when
// something (a callback arming / releasing a hw probe, call_original's return catch) may have
// rewritten it -- the re-read was ~27 us of a ~120 us hw hit (x64 VM), every hit.
namespace uhh_session {

inline std::atomic<uint64_t> g_dr_epoch{0};
inline BOOL uhh_set_thread_context(HANDLE h, const CONTEXT *c) {
    if (c && (c->ContextFlags & CONTEXT_DEBUG_REGISTERS & ~CONTEXT_CONTROL & 0xFFu) != 0) g_dr_epoch.fetch_add(1, std::memory_order_relaxed);
    return ::SetThreadContext(h, c);
}
#define SetThreadContext uhh_set_thread_context
#pragma comment(lib, "psapi.lib")
} // namespace uhh_session

#include <aclapi.h>
#pragma comment(lib, "advapi32.lib")

namespace uhh_session {

// Probe views used by site vetting copy these values; live reports read them atomically.
template<class T> struct ReportValue : std::atomic<T> {
    using std::atomic<T>::atomic;
    using std::atomic<T>::operator=;
    ReportValue(const ReportValue &v) : std::atomic<T>(v.load()) {}
    ReportValue &operator=(const ReportValue &v) { this->store(v.load()); return *this; }
};

struct Probe {
    std::string location, module, callback_export;
    // A breakpoint/hw callback whose module has UHH_SHARED state, added before the session's
    // agent DLL is loaded: its export name in the agent; `callback` is bound to the agent's copy
    // once the agent is loaded (ensure_local_agent, before the target can run).
    std::string shared_export;
    std::string export_name;   // "module!Export+0xOFF": resolved from the export table at load
    uint64_t sym_offset = 0;
    // The location named its module without an extension ("kernel32!X"): module is then
    // "<name>.dll" (module_of_location); warned once if only "<name>.<other ext>" loads.
    bool bare_module = false, warned_bare = false;
    ReportValue<bool> retired{false}; // PROBE_ONCE probe that already fired (kept for the report)
    bool internal = false;     // library-owned (not reported)
    // Breakpoint probes: the original bytes that followed the INT3 (to recognise a copy of the
    // site another hooking tool relocated into its trampoline), and for such an adopted copy,
    // the probe it stands in for (its hits count there; the copy itself is not reported).
    std::vector<unsigned char> follow;
    struct Probe *alias_of = nullptr;
    bool runtime = false;      // added after launch: an install failure is reported, not fatal
    bool deferred_site_refused = false; // accepted runtime submission retired by deferred safety vetting
    bool vetted = false;       // pre-hook check done for this inline install
    uint64_t rva = 0, base = 0, address = 0;
    ReportValue<uint64_t> hits{0};
    ReportValue<uint32_t> agent_index{UINT32_MAX};
    uint32_t patch_len = 0;    // inline: bytes the hook overwrites at address (set when vetted)
    unsigned char original = 0;
    // Software-breakpoint displaced stepping: the full original instruction so it can
    // be executed out-of-line while the INT3 stays armed (no re-arm race, no thread
    // suspension). displaced_ok is false for control-flow instructions (handled by the
    // in-place fallback); riprel_disp_off marks a RIP-relative disp32 to retarget.
    std::vector<unsigned char> orig_insn;
    uint32_t insn_len = 0;
    bool displaced_ok = false;
    int riprel_disp_off = -1;
    // REP/REPE/REPNE string instruction: the trap flag fires after EVERY iteration, so it
    // is run out-of-line WITHOUT single-stepping, ended by an INT3 placed after the copy.
    bool rep_string = false;
    // x64 SYSCALL / INT 2E site: runs from a per-site trampoline (insn; mov rcx, site+len; jmp
    // site+len) without any trap flag or completion event (see syscall_trampoline). 0 = none yet.
    uint64_t tramp = 0;
    // Displaced instruction: its per-site out-of-line copy (insn, then a jump back to
    // address + insn_len), shared by every thread (see displaced_trampoline). 0 = none yet;
    // dtramp_site is the address it was built for (a module reloaded elsewhere gets a new one).
    uint64_t dtramp = 0, dtramp_site = 0;
    std::vector<unsigned char> dtramp_insn;   // the instruction bytes that copy holds
    probe_callback callback = nullptr;
    ReportValue<uint32_t> flags{0};
    std::vector<unsigned char> config;
    uint64_t hw_generation = 0; // changes on every arm, including module reloads
    int dr_slot = -1;   // hardware-breakpoint DR register (0-3); -1 if not a HW probe
    ReportValue<bool> active{false};
    bool warned_double_run = false;   // call_original without return_from (warn once)
    bool warned_pop = false;          // x86 return_from nargs contradicted call_original (warn once)
    bool warned_boundary = false;     // boundary override warning (once per probe)
    bool warned_log = false;          // a "uhh warning: ..." log record was emitted (once per probe, as inline)
    bool warned_call = false;         // a breakpoint/hw call_func was refused (warn once)
};

struct CallbackState {
    probe_session *session;
    Probe *probe;
    DWORD pid = 0, tid = 0;   // the stopped event's thread (call_func runs code on it)
    bool released = false;    // call_original: the original left without returning; the thread runs on
    // call_original returned: the thread's registers as the original left them (its return
    // registers: x86 EDX:EAX, XMM0, x86 ST0; the other volatile ones) and the callback's
    // registers at that moment. With return_from the caller gets them -- exactly what an
    // un-hooked call leaves -- except AX (the return_from value) and any register the
    // callback set_reg'd after the call (see apply_return_from).
    bool have_post = false;
    CONTEXT post{};
    probe_regs post_seen{};
    // The callback faulted after call_original ran the original: the hit returns to its caller
    // with everything the original left (run_callback), as inline does.
    bool faulted = false;
};
// The floating-point parts of a CONTEXT (x86: the x87 save area and the FXSAVE image with XMM).
#if defined(_WIN64)
#define UHH_CONTEXT_FP CONTEXT_FLOATING_POINT
#else
#define UHH_CONTEXT_FP (CONTEXT_FLOATING_POINT | CONTEXT_EXTENDED_REGISTERS)
#endif

// A thread mid-single-step over a software breakpoint. displaced == true means the
// INT3 was left armed and the instruction is running out-of-line (land at address +
// insn_len); false means the byte was lifted in place and must be re-armed.
struct StepState {
    Probe *probe = nullptr;
    bool displaced = false;
    // Captured at setup so single-step completion never dereferences the Probe*: a
    // mid-step UNLOAD_DLL zeroes probe->address, which would otherwise land RIP at
    // 0 + insn_len. site is the probe address (also the in-place re-arm target).
    uint64_t site = 0;
    uint32_t insn_len = 0;
    uint64_t scratch = 0;   // the out-of-line copy's slot (displaced steps)
    bool tail_int3 = false; // displaced copy ends at an INT3 (scratch + insn_len), no trap flag
    bool rep_string = false;// REP string op: an in-place step continues until it leaves the site
    bool syscall_insn = false; // SYSCALL stepped in place: the CPU copies OUR trap flag into R11
    bool pushf_insn = false;   // PUSHF stepped in place: the pushed image carries OUR trap flag
    bool prog_tf = false;      // ... unless the program had TF set itself
    bool popf_tf = false;      // flags popped by POPF, sampled before execution
    bool popf_insn = false;    // POPF supplies its own post-instruction TF
    bool windowed = false;     // in place under the in-place window (other threads held, see inplace_begin)
    bool refire = false;       // the in-place step faulted: re-running the instruction WITHOUT our trap flag
};

// One log line, optionally with a raw stack snapshot (return addresses only). Frames
// are symbolized by the file writer -- never inside the breakpoint.
struct LogRecord {
    std::string text;
    uint32_t tid = 0, probe = 0;
    bool has_stack = false;
    std::vector<uint64_t> frames;
    // Not a log line: "the module at sym_unload unloaded" -- the writer unregisters it from
    // dbghelp once every record queued before it is symbolized (see sym_unload).
    uint64_t sym_unload = 0, sym_size = 0;
    // > 0: a PACK of that many ring records, in order, in `text` (LogPackHdr + message bytes +
    // frames, each). The agent-ring drainer moves records in packs: one allocation and one queue
    // entry per up to LOG_PACK records instead of a string (and a queue node) per record.
    uint32_t packed = 0;
};

#if defined(_WIN64)
#define UHH_PC(ctx) (ctx).Rip
#else
#define UHH_PC(ctx) (ctx).Eip
#endif
// A debug event handled on a fiber of the debug thread (see "Callback fibers"): its
// callback can park inside call_func while the loop dispatches other events.
struct EventFiber {
    probe_session *s = nullptr;
    void *fiber = nullptr, *return_to = nullptr;
    DEBUG_EVENT ev{};                         // the event this handling started with
    DWORD disposition = DBG_CONTINUE;
    bool ok = true, done = false;
    // Parked in call_func: until when, and how the call ended (set by whoever resumes it).
    enum Outcome { WAITING, TRAPPED, FAULTED, TIMEOUT, GONE, EXITED };
    ULONGLONG call_start = 0, call_deadline = 0;
    Outcome call_outcome = WAITING;
    HANDLE call_held = nullptr;               // the callee returned while a call_original ran: thread suspended by us
    HANDLE resume_after = nullptr;            // the thread is suspended for the rest of the handling: resume, never continue
    bool stop_suspended = false;              // ...from the start (a replayed data-watch hit): call_func resumes it to call
};

} // namespace uhh_session

struct probe_session {
    std::vector<std::unique_ptr<uhh_session::Probe>> probes;
    std::mutex report_mu;                      // report vs run-end drainer/writer shutdown
    std::mutex probes_mu;                      // vector growth / report pointer snapshot and prehooks
    std::mutex agent_mu;
    std::mutex drain_mu;                       // shared ring has exactly one consumer at a time (lock_drain)
    std::atomic<int> drain_waiters{0};         // threads blocked taking drain_mu: the drainer lets them in
    uint32_t agent_map[PROBE_AGENT_MAX_PROBES] = {};   // agent request index -> probes[] index (under agent_mu)
    std::thread drainer;                       // empties the agent's log ring continuously
    std::atomic<uint64_t> controller_dropped{0}; // only broken file I/O/allocation can lose controller logs
    std::atomic<bool> drain_stop{false};
    uint64_t abandoned_slots = 0;              // ring slots skipped: their producer was killed mid-record
    // Both producer paths wait on this bounded queue. The writer never holds queue_mu
    // while symbolizing or writing, so a slow filesystem cannot invert locks with the
    // debugger or the agent-ring drainer.
    static constexpr size_t LOG_QUEUE_CAP = 2048;  // log RECORDS queued (a pack counts its records)
    std::deque<uhh_session::LogRecord> log_queue;
    size_t log_queue_records = 0;              // records_of() summed over log_queue (queue_mu)
    std::mutex queue_mu;
    std::condition_variable queue_readable, queue_writable, queue_flushed;
    std::vector<std::pair<uint64_t, uint64_t>> sym_pending;   // (base, size) unloads queued for the writer (queue_mu)
    std::thread log_writer;
    HANDLE log_file = INVALID_HANDLE_VALUE;
    HANDLE log_reader = INVALID_HANDLE_VALUE;
    std::wstring log_path;
    HANDLE stdout_handle = INVALID_HANDLE_VALUE;
    DWORD stdout_type = FILE_TYPE_UNKNOWN;
    bool stdout_is_console = false, tail_enabled = false;
    bool writer_stop = false, writer_busy = false, writer_failed = false;
    // Write coalescing (log_writer_main): the writer may hold a short batch briefly while records
    // stream in. writer_holding (queue_mu) says it is; a flush (flush_waiters), a stop or a
    // half-full queue ends the hold at once through writer_hold.
    bool writer_holding = false;
    int flush_waiters = 0;
    std::condition_variable writer_hold;
    std::string writer_error;
    std::thread log_tailer;
    std::mutex tail_mu;
    std::mutex stdout_mu;                      // whole-line stdout writes: log batches vs report lines
    std::condition_variable tail_changed, tail_caught_up;
    uint64_t log_bytes_written = 0, log_bytes_tailed = 0;
    uint64_t log_bytes_produced = 0;           // tail_mu: bytes handed to the session file (>= log_bytes_written)
    // The session file's appender (live tail only, see write_log_batch): the writer hands it each
    // batch after stdout, so a stalled file write never holds live records.
    std::thread log_filer;
    std::mutex file_mu;                        // never held while taking another lock
    std::condition_variable file_cv, file_idle;
    struct FileChunk { std::string bytes; uint64_t records = 0; };   // a batch and its probe_log records
    std::deque<FileChunk> file_queue;
    std::vector<std::string> file_spare;       // appended chunks, emptied, for the writer to reuse (no allocation churn)
    size_t file_queued = 0;                    // bytes in file_queue
    // file_failed: the session file stopped growing (an append failed, or a batch could not be
    // handed over); it holds exactly the records counted in logs_written (seq 0..logs_written-1).
    bool file_stop = false, file_busy = false, file_failed = false;
    std::string file_error;
    bool file_broken = false;                  // tail_mu: file_failed, for the tail's waits (bytes past
                                               // log_bytes_written never reach the file, nor stdout through it)
    bool tail_stop = false, tail_failed = false, console_warning = false;
    bool live_output_closed = false;           // stdout's reader went away: a warning, not an error
    std::string tail_error;
    // probe_launch: when the controller's stdout/stderr is a pipe or file, the target gets
    // its own pipe and a forwarder copies its bytes out line-wise (see forward_main), so
    // live log records never land inside one of the target's lines.
    struct StdForward {
        HANDLE pipe = INVALID_HANDLE_VALUE;     // server (read) end, overlapped
        HANDLE dst = INVALID_HANDLE_VALUE;      // the controller's real stdout / stderr
        bool to_stdout = false;                 // shares stdout_mu and the log tail's line state
        std::thread thread;
        HANDLE wake = nullptr, drained = nullptr;
        std::atomic<int> mode{0};               // FWD_RUN / FWD_DRAIN / FWD_STOP
        std::mutex mu;                          // whole-line writes to a non-stdout dst
    };
    StdForward fwd_out, fwd_err;
    bool fwd_out_active = false;               // the log tail goes through the line-state logic
    bool fwd_finished = false;
    std::atomic<bool> out_midline{false};      // stdout ends inside a target line (under stdout_mu)
    std::atomic<uint64_t> logs_written{0};
    // Self-verifying output: every probe_log record carries "seq" (0, 1, 2, ... in file order,
    // assigned by the writer thread), and the report states how many records reached stdout
    // ("stdout_logs"), so a capture with a gap or a missing tail shows it from its own lines.
    uint64_t log_seq = 0;                      // next seq (writer thread only)
    uint64_t logs_enqueued = 0;                // records accepted into log_queue (queue_mu)
    uint64_t stdout_logs = 0;                  // records written to stdout by the live tail (tail_mu)
    bool reported_to_stdout = false;           // a probe_report went to stdout ...
    uint64_t reported_stdout_logs = 0;         // ... stating this stdout_logs
    bool sym_ready = false;    // dbghelp initialised on the target (stack walk + symbolize)
    std::unordered_map<std::string, uint64_t> module_bases;
    std::unordered_map<std::string, std::string> module_paths;   // name -> on-disk image (prehook diff)
    std::unordered_map<uint64_t, uint32_t> module_sizes;          // mapped image base -> SizeOfImage
    std::vector<std::string> prehooks;                           // JSON lines for the report
    PROCESS_INFORMATION pi{};
    std::atomic<DWORD> exit_code{1};
    std::atomic<uint64_t> overrides{0};
    std::string error;
    HANDLE mapping = nullptr, remote_thread = nullptr;
    HANDLE agent_mapping = nullptr;             // TARGET handle: never CloseHandle in this process
    bool agent_mapping_duplicated = false;      // this session created it (not borrowed from the agent)
    probe_agent_shared *shared = nullptr;
    HMODULE local_agent = nullptr;
    // The controller's agent DLL is prepared (the per-session copy made, then loaded) on its own
    // thread from the first probe that needs it: a freshly written DLL is scanned by real-time
    // antivirus when it is first mapped (~100 ms on the test VM, every session), and that now
    // overlaps the rest of the session setup (dbghelp, process creation). ensure_local_agent
    // joins it. agent_prep_module / agent_prep_error: its result, read after the join.
    std::thread agent_prep;
    HMODULE agent_prep_module = nullptr;
    DWORD agent_prep_error = 0;
    std::unordered_set<std::string> agent_file_exports;   // the agent file's export names (read once)
    bool agent_file_exports_read = false;
    void *remote_path = nullptr;
    uint64_t remote_agent = 0;
    DWORD remote_tid = 0;
    std::string remote_fault;   // first fault raised on the agent's load/init thread (diagnostic)
    enum RemoteWork { REMOTE_NONE, REMOTE_LOAD_AGENT, REMOTE_INIT_AGENT, REMOTE_EARLY } remote_work = REMOTE_NONE;
    std::wstring agent_path;
    // One out-of-line step buffer per thread (lazily allocated in the target), so
    // concurrent threads can displaced-step independently without contending.
    // Out-of-line step slots, 64 bytes each, carved from 64 KiB blocks allocated within
    // +-2 GiB of the probed code (so x64 RIP-relative operands can be retargeted and every
    // site takes the exact displaced path). Keyed by (thread, 1 GiB region of the site).
    std::map<std::pair<DWORD, uint64_t>, uint64_t> scratch;
    std::map<uint64_t, std::vector<uint64_t>> scratch_free;   // region -> free slots
    std::vector<uint64_t> scratch_blocks;
    // Blocks holding inline configs larger than the request's buffer (fill_request): an inline
    // callback reads its config from there, so after a detach they are freed only if no
    // callback is still in flight (probe_close).
    std::vector<uint64_t> config_blocks;
    // Live target threads + hardware-breakpoint state. HW probes set a debug
    // register on EVERY thread (and each new one), so there is no code to modify
    // and no re-arm race: exact under threads for any instruction, up to 4 slots.
    std::unordered_set<DWORD> threads;
    // The debug events' own thread handles (THREAD_GET/SET_CONTEXT | THREAD_SUSPEND_RESUME), valid
    // until the thread's EXIT_THREAD event is continued; the debug subsystem closes them, never us.
    // Per-event checks use them instead of an OpenThread + CloseHandle each (ctx_watch_begin).
    std::unordered_map<DWORD, HANDLE> thread_handle;
    std::unordered_map<DWORD, HANDLE> own_thread_handle;   // event_thread: OUR handles (closed at EXIT_THREAD / end)
    uint8_t dr_used = 0;
    std::vector<std::pair<uint64_t, int>> gates; // (inline site, DR slot): hw gates until its hook is confirmed
    uint8_t dr_ever = 0;
    uint64_t hw_generation = 0;               // next hardware-probe arm identity
    uint8_t dr_next = 0;                       // next DR slot to try (rotation)
    uint64_t entry_reapply = 0;                // image entry: re-apply DRs on first arrival
    uint64_t entry_addr = 0;                   // image entry point (hold-for-install point)
    bool entry_seen = false;
    bool thread_start_fixup = false;           // library INT3 at ntdll!RtlUserThreadStart armed
    bool restore_fixup = false;                // library INT3s at ntdll!NtContinue[Ex] armed
    uint64_t debug_dispatch_addr = 0;
    uhh_session::Probe *debug_dispatch_probe = nullptr;
    // Windows snapshots the user exception CONTEXT before the debugger edits live DR6.
    // Agent sessions repair in the first VEH; the dispatcher catch/map below is
    // only for agent-less bp/hw sessions. Change only UHH's status contributions.
    struct DebugDelivery { uint64_t ip = 0; DWORD64 clear_bits = 0, set_bits = 0; };
    std::unordered_map<DWORD, DebugDelivery> debug_delivery;

    std::unordered_map<DWORD, uint64_t> restore_resume;   // x86: a WOW64 restore sent through call_trap -> its real EIP
    bool thread_start_due = false;             // a hw probe was released: arm it after this event
    HANDLE svc_event = nullptr;                // agent service: "install pending requests"
    HANDLE drain_event = nullptr;              // a producer wakes the idle drainer (probe_agent_drain_wait)
    std::vector<HANDLE> held;                  // threads held until inline installs confirm
    ULONGLONG held_since = 0;                       // slots we have ever owned (stale-#DB filter)
    std::unordered_set<uint64_t> retired_bps;  // removed INT3 sites (stale-hit filter)
    // Released hardware probes (stale-#DB filter), per thread. A release clears the DR on every
    // thread, but the write can be lost on a thread whose debug event is already QUEUED (see
    // enforce_owned_drs): until that thread reports an event, a DR image of a released address
    // on it may be our stale one. Each entry holds the thread's registers at the release; at its
    // next event, unchanged registers mean it has not run since (that event was queued before
    // the release) -> its image of those addresses is ours, cleared then and its #DB swallowed
    // (hw_stale); changed registers mean it ran, so our clear reached it -> whatever it has armed
    // since is the target's own. A released address is never the target's otherwise-forever.
    struct HwUnsettled { CONTEXT regs{}; bool have_regs = false; std::unordered_set<uint64_t> addrs; };
    std::unordered_map<DWORD, HwUnsettled> hw_unsettled;
    // Historical addresses for stale-event/cleanup recognition. Live ownership also
    // requires an active arm or an unsettled release on that thread (ROADMAP A7).
    std::unordered_set<uint64_t> hw_armed_ever;
    std::unordered_set<uint64_t> hw_execute_ever;
    bool warned_dr_full = false;
    DWORD hw_stale_tid = 0;                    // the thread of the event being handled, if it was unsettled
    std::unordered_set<uint64_t> hw_stale;     // ...and the released addresses still ours on it
    // Every released address not re-armed since. A thread still STARTING at the release
    // (LdrInitializeThunk) runs past the clear and then restores, by NtContinue, the DR image
    // captured at its first entry to user mode -- the released slot enabled again, on a thread
    // that "has run" (so not unsettled). At its arrival at RtlUserThreadStart (thread-start
    // fixup) nothing it runs later has set its DRs yet: an image of one of these there is ours.
    std::unordered_set<uint64_t> hw_released;
    // Writing a thread's debug registers zeroes its DR6, also the status of a #DB already raised
    // there and still QUEUED: that hit then arrives with no B-bit (an execute hit is recovered by
    // address; a watchpoint's cannot be). The status read just before the write is kept with the
    // thread's registers; at its next event, unchanged registers mean it has not run since -- that
    // event IS the queued #DB -- and the status is carried into its handling (dr6_carry).
    // Keep each bit's original address and probe identity too: slot reuse cannot turn an
    // old data access into a hit on a replacement probe (even at the same address).
    struct Dr6Lost { CONTEXT regs{}; DWORD64 bits = 0; uint64_t address[4]{}; uint64_t generation[4]{}; };
    std::unordered_map<DWORD, Dr6Lost> dr6_lost;
    DWORD dr6_carry_tid = 0;
    DWORD64 dr6_carry = 0;
    uint64_t dr6_carry_address[4]{};
    uint64_t dr6_carry_generation[4]{};
    std::vector<HANDLE> ipc_frozen;            // threads suspended for an agent hook write (FREEZE..THAW)
    DWORD ipc_freezer = 0;                     // the agent thread doing that write (0 = no freeze)
    int hw_active = 0;
    bool launched = false, inline_ready = false;
    std::atomic<bool> exited{false};
    bool cut_off_said = false;                        // probe_report named the interrupted callbacks
    bool interrupted = false, ctrl_counted = false;   // Ctrl+C ended this session / counted in g_ctrl_sessions
    std::atomic<bool> ran{false};              // probe_run has started (read by probe_close on any thread)
    int shadow_stack = -1;                     // target has hardware shadow stacks (CET): -1 unknown, 0/1
    uint64_t ret_gadgets = 0;                  // return_from: `ret` / `ret N` gadgets in the target
    bool warned_cb_fault = false;              // one stderr warning for a faulting controller-side callback
    DWORD inline_add_wait_tid = 0;              // hold this callback while a runtime inline add confirms
    DWORD cb_tid = 0;                          // thread whose callback / IPC is being serviced (0 = none)
    const uhh_session::Probe *cb_probe = nullptr;           // whose callback runs (an IPC add: its inline origin probe)
    std::wstring agent_copy;                   // per-session copy of the agent DLL (UHH_SHARED), deleted at close
    std::vector<DWORD> pending_hold;           // callers of a runtime inline add: hold until it lands
    bool attached = false;                     // probe_attach: detach (not kill) on close
    std::atomic<bool> stop_requested{false};   // probe_close from another thread while probe_run runs
    std::atomic<bool> running{false};          // probe_run is executing (on some thread)
    std::atomic<const char *> run_phase{""};   // what probe_run is doing (a slow close says it)
    std::atomic<bool> detached{false};
    bool detaching = false;                    // detach() running: no new holds, arming, gates or agent work
    bool detached_hooks = false;               // detach removed the inline hooks (stop_drainer may settle)
    bool guard_ready = false;                  // attach: breakpoint/hw probes may arm (no agent, or its guard is up / given up)
    ULONGLONG guard_since = 0;
    // attach: the modules mapped when the attach began (their LOAD_DLL events are the kernel's
    // replay); any other load is a fresh mapping whose code has not run yet (see arm_module)
    std::unordered_set<uint64_t> attach_modules;
    bool attach_modules_ok = false;
    bool agent_init_started = false;           // this session started the agent's init
    // The early init (on the main thread at the loader breakpoint) ran to completion: the agent
    // made its service thread then, and it reports itself (INSTALL_DONE) once process init lets it
    // run. Another init with nothing to install would only repeat that, on a thread of its own.
    bool early_inited = false;
    LONG init_returns_at = 0;                  // shared->init_returns when the remote init started
    std::vector<DWORD> detach_frozen;          // detach's own freeze of every thread (mirrored for the guard)
    // Threads whose debug event is being handled (nested: call_original). `running`: the handling
    // let its thread run again before it ended (call_func / call_original continued the event,
    // or call_original released it) -- the guard does not list it then (see guard_sync).
    struct Handled { DWORD tid; bool running; };
    std::vector<Handled> handling;
    DWORD debug_tid = 0;                       // the thread that launched/attached: owns the debug object
    DWORD in_call_tid = 0;                     // thread currently running a call_original (in place)
    std::vector<HANDLE> call_deferred;         // other threads' hits during a call_original: rewound + suspended
    bool skip_continue = false;                // the handling already continued (or released) the current event
    uint64_t call_trap = 0;                    // INT3 the callee returns into
    // The call running is the library's own (the agent's early load + init on the main thread,
    // see early_agent): probes it hits are not the program's (not counted), and the agent's
    // control-plane requests (PROBE_IPC: its hook-write freeze) are serviced, not a fault.
    DWORD quiet_tid = 0;
    // Callback fibers (breakpoint/hw call_func, see there): the debug thread's own fiber, idle
    // event fibers, the one running now (nullptr: the debug thread's own stack), and the
    // threads running a call_func callee -> the fiber parked on it.
    void *main_fiber = nullptr;
    bool fiber_converted = false, calls_closing = false, call_fiber_warned = false;
    std::vector<uhh_session::EventFiber *> fiber_pool;
    uhh_session::EventFiber *cur_fiber = nullptr;
    DWORD event_tid = 0;                       // the thread of the event being handled now (0: none)
    std::unordered_map<DWORD, uhh_session::EventFiber *> calls;
    // A call_func that timed out may already have its return trap (or a callee fault) QUEUED;
    // it arrives after the thread was restored: tid -> the IP the thread was left at when its
    // handling ended (it has not run since if it is still there).
    struct LateCall { uint64_t ip = 0; };
    std::unordered_map<DWORD, LateCall> call_late;
    // Data-watch hits held while a call is in flight (callbacks never overlap): the thread is
    // suspended right after the access, its callback replayed once no call is left.
    struct WatchHeld { bool reply_later = false; HANDLE thread = nullptr; DEBUG_EVENT ev{}; uhh_session::Probe *probes[4]{}; };
    std::vector<WatchHeld> watch_deferred;
    // call_original in flight (breakpoint/hw, see call_original): the probe address the call
    // starts at, the hit's SP, whether the breakpoint entry pass is still pending (the call's
    // own first INT3 execution: not a hit), and whether the thread was seen OUTSIDE the call
    // (a hit at or above the hit's SP: it left by exception/longjmp without returning -- or a
    // deeper one once the original's return address slot at co_sp no longer holds co_ret, see
    // co_slot_gone).
    uint64_t co_addr = 0, co_sp = 0, co_ret = 0;
    uint64_t co_exc_sp = 0;                    // the SP of the last exception raised on the call's thread (co_unwound)
    bool co_entry_pending = false, co_left = false;
    int co_borrowed_slot = -1;                 // a hw probe's own DR lent to the call_original thread's return catch
    bool co_warned_entry = false, co_warned_dr = false, co_warned_left = false, co_warned_nargs = false;
    bool initial_break = false;
    std::unordered_map<DWORD, uhh_session::StepState> stepping;   // threads mid single-step
    // Threads whose in-place step at a probe site faulted, the fault passed to the program
    // (without our trap flag: see StepState::refire). thread -> probe site and fault code.
    // If the handler continues execution there, the INT3 is hit again -- the same execution
    // restarting, not a new hit; after a skip or an unwind the next INT3 at the site is a new
    // hit. The thread's next event decides, by the exception's dispatcher frame
    // (fault_retried). (A trap flag the program set itself raises one stray step: absorbed.)
    struct Refault { uint64_t site = 0; DWORD code = 0; };
    std::unordered_map<DWORD, Refault> refault;
    // In-place window (see inplace_begin): while a thread steps an instruction at its real
    // address with our INT3 lifted, every other thread of the target is suspended by us, so
    // none can run through the site uncounted. owner = the stepping thread (0: no window).
    DWORD inplace_owner = 0;
    ULONGLONG inplace_since = 0;
    bool inplace_warned = false;
    std::vector<std::pair<DWORD, HANDLE>> inplace_suspended;
    std::unordered_map<DWORD, bool> agent_tid_cache;    // agent_thread() answers (remote reads)
    // x64 SYSCALL / INT 2E trampolines (Probe::tramp). Never freed: after a detach a thread
    // may still be blocked inside one (its syscall returns there).
    uint64_t tramp_next = 0, tramp_end = 0;
    // Displaced-instruction trampolines (Probe::dtramp): start -> (site, insn_len, probe), to map a
    // thread inside one back to the real code (a fault in the copy, a watch hit, a detach).
    // Never freed while attached (a thread may be inside one); 64-byte entries carved from
    // blocks near the site (x64 RIP-relative reach), region (site >> 30) -> [next, end).
    struct DTramp { uint64_t site = 0; uint32_t len = 0; uhh_session::Probe *probe = nullptr; };
    std::map<uint64_t, DTramp> dtramps;
    std::map<uint64_t, std::pair<uint64_t, uint64_t>> dtramp_pool;
    // Fairness (ROADMAP A5): every debug event freezes the whole target, so threads that hit
    // probes back to back can keep it frozen nearly all the time and starve the others. When
    // the target ran unfrozen for less than a tenth of the last 20 ms, the threads whose hits
    // are continued are parked (suspended) until the event queue has been empty for 2 ms --
    // the other threads run then -- and released together. See fair_tick.
    std::vector<std::pair<DWORD, HANDLE>> parked;
    bool parking = false;
    bool fine_timer = false;
    uint32_t fair_events = 0;                   // debug events in the current fairness window
    LONGLONG round_wake = 0;                    // the current yield round ends (interrupt time, 100 ns: KUSER_SHARED_DATA)
    LONGLONG round_wake_ft = 0;                 // ... the same moment as system time (a stub that sleeps)
    std::unordered_set<DWORD> yielded_round;    // threads that yielded in the current round (once each)
    // Demand-driven rounds (fair_tick): a round is also a probe. While its hot threads sleep the
    // target runs with no debug event at all, and the loop's idle ticks then ask the kernel
    // whether any other thread of the target wants the CPU (others_runnable). Rounds come every
    // 20 ms while one does; after each round in which none did, the period doubles, to 80 ms --
    // a lone hot thread, or one whose siblings are all blocked, then yields ~4 ms in 84 instead
    // of 4 in 24. Not further: a thread blocked with a TIMEOUT (a heartbeat's timed wait) reads
    // "waiting", yet its timeout elapses only while the process runs -- it is starved too, and
    // cannot be told from a thread blocked for good; 80 ms bounds what it loses.
    uint32_t fair_period_ms = 20;
    std::vector<unsigned char> sysproc_buf;     // others_runnable's NtQuerySystemInformation buffer
    bool quiet_sampled = false;                 // the round's first idle tick passed
    std::unordered_set<DWORD> runnable_prev;    // others_runnable: runnable at the previous idle tick
    std::unordered_map<DWORD, ULONG> cs_prev;   // ... and context-switch counts then
    std::unordered_set<DWORD> hot_now, hot_prev;   // threads with exception events this / the last window
    int round_demand = -1;                      // this round: -1 no idle tick compared yet, 0 none ran, 1 one ran
    uint32_t quiet_rounds = 0, fair_events_last = 0;
    uint64_t rounds_by_demand[3] = {};          // PROBE_TRACE statistics: rounds ending with demand -1 / 0 / 1
    std::chrono::steady_clock::time_point round_quiet_until{};  // the round's yielders sleep until then (round_quiet_tick)
    std::chrono::steady_clock::time_point next_quiet_sample{};  // round_quiet_tick's next query (~1 ms apart)
    uint64_t park_rounds = 0, parked_total = 0;   // fairness statistics (PROBE_TRACE: printed at the end)
    // Yield stubs (see yield_thread): per thread, `resume address; code`, carved from blocks that
    // are never freed (a thread may sleep inside one across a detach).
    std::unordered_map<DWORD, uint64_t> yield_stubs;
    uint64_t yield_next = 0, yield_end = 0, yield_fn = 0, yield_spin_fn = 0;
    bool yield_unusable = false;
    ULONGLONG rekick_at = 0;
    std::unordered_set<uint64_t> early_unloaded;   // instances torn down at a newer LOAD (their late UNLOAD skipped)
    // Every mapped instance of every module, in LOAD order (module_bases keeps only the latest):
    // a DLL loaded concurrently can be mapped twice, one mapping discarded. See retarget_pending.
    std::vector<std::pair<std::string, uint64_t>> module_instances;
    // Other instances' copies of inline sites (gated too, see LOAD_DLL): a thread hitting one
    // proves that instance is the live one -- its probe moves there (handle_gate).
    struct ExtraGate { uint64_t site = 0, base = 0; uhh_session::Probe *probe = nullptr; };
    std::vector<ExtraGate> extra_gates;                   // ask the agent's service for another install round then (0: no)                   // timeBeginPeriod(1) held (only while something polls at 1 ms)
    std::chrono::steady_clock::time_point fair_window{}, last_event{};
    std::chrono::steady_clock::duration fair_gaps{};
    // Context round-trips (ROADMAP A4): a thread whose debug event we handled while the target
    // itself had it suspended may get the context the target captured DURING that event
    // written back (Suspend + GetThreadContext + SetThreadContext + Resume, as GCs and
    // profilers do) -- undoing our resume state (an INT3 hit resumed one byte into the
    // instruction, a hw hit without RF reported twice). Such a thread is held by us as well
    // until the target resumes it; then whatever it wrote back gets our changes re-applied.
    struct CtxWatch { DWORD tid = 0; HANDLE t = nullptr; CONTEXT before{}, after{}; ULONGLONG deadline = 0; };
    std::vector<std::unique_ptr<CtxWatch>> ctx_watch;
};

namespace uhh_session {
// A 32-bit (WOW64) controller's Get/SetThreadContext on a thread other than the one whose
// event it is handling is an implicit suspend + resume INSIDE the call (ROADMAP L13): killed in
// the middle of one, the controller leaves that thread suspended once with nothing of ours
// recording it (the guard resumes the event threads, call threads and explicit holds only).
// While such a call runs, the thread is listed among the guard's held threads as a CONDITIONAL
// entry carrying its suspend count from before the call (probe_agent_guard::held_floor): after
// a controller death the guard resumes it once only if its count is above that -- i.e. the
// implicit suspension is in place. Killed before the call or after it returned, the entry is a
// no-op even when the PROGRAM holds the thread suspended (an unconditional resume would have
// released the program's own suspension). Taken off again right after the call. x64
// controllers have no implicit suspend: nothing to do.
#if defined(UHH_TEST_HOOKS)
// Test-only: UHH_TEST_DIE_IN_TOUCH fires only in a touch made while arming a user hw probe on
// every thread (arm_hw) -- the window its checks are about, whatever other touches (an inline
// install's freeze, with --guard's inline probe in the session) come first.
inline bool g_test_in_arm_hw = false;
bool test_fault_retried(probe_session *, const CONTEXT &, uint64_t, DWORD);
#endif
struct GuardTouch {
#if !defined(_WIN64)
    probe_agent_guard *g = nullptr;
    LONG n = 0;
    GuardTouch(const probe_session *s, DWORD tid);
    ~GuardTouch() { if (g) { g->held_tids[n] = 0; MemoryBarrier(); if (g->held_count == n + 1) g->held_count = n; } }
#else
    GuardTouch(const probe_session *, DWORD) {}
#endif
    GuardTouch(const GuardTouch &) = delete;
    GuardTouch &operator=(const GuardTouch &) = delete;
};
// Bench knob, not API: UHH_BENCH_PHASES=1 stamps the session's lifecycle phases on stderr
// ("  phase <QPC ms> <name> [arg]"; bench/perfab/phases.py turns them into a timeline) and, at
// probe_close, the writer/drainer counters below. Off: one cached getenv per stamp.
inline std::atomic<uint64_t> g_diag_file_writes{0}, g_diag_file_bytes{0}, g_diag_enqueues{0}, g_diag_passes{0}, g_diag_moved{0};
#if defined(_WIN64)
#define EMU_IP(c) (c).Rip
#define EMU_SP(c) (c).Rsp
#define EMU_CX(c) (c).Rcx
#else
#define EMU_IP(c) (c).Eip
#define EMU_SP(c) (c).Esp
#define EMU_CX(c) (c).Ecx
#endif

static constexpr const char *kAddForeignCallback =
    "a probe added from a callback needs a callback exported by the calling callback's module";
struct FiberHost {               // the debug thread as a fiber host while the session dispatches
    probe_session *s; bool outer = false;
    explicit FiberHost(probe_session *ss) : s(ss) {
        if (s->main_fiber) return;
        outer = true;
        if (IsThreadAFiber()) s->main_fiber = GetCurrentFiber();
        else if ((s->main_fiber = ConvertThreadToFiberEx(nullptr, FIBER_FLAG_FLOAT_SWITCH)) != nullptr) s->fiber_converted = true;
    }
    ~FiberHost() { end(); }
    void end() {                 // explicit where the session must not be touched afterwards
        if (!outer) return;
        outer = false;
        for (EventFiber *f : s->fiber_pool) { DeleteFiber(f->fiber); delete f; }   // idle (parked ones were finished)
        s->fiber_pool.clear();
        if (s->fiber_converted) ConvertFiberToThread();
        s->fiber_converted = false; s->main_fiber = nullptr;
    }
};

// ---- Shared between the session units (each defined in the file named above its group) ----
// session.cpp
bool trace_enabled();
void bench_phase(const char *what, const char *arg = nullptr);
void set_error(probe_session *s, const std::string &message);
std::string win_error(const char *what);
bool has_inline(const probe_session *s);
bool arm_module(probe_session *s, const std::string &module, uint64_t base, bool fresh);
Probe *probe_at(probe_session *s, uint64_t address);
uint32_t probe_index(probe_session *s, const Probe *probe);
bool remote_range_ok(HANDLE h, uint64_t a, size_t n, bool write);
const probe_controller_api *controller_api_table();
extern const probe_ops callback_ops;
// session_loop.cpp
bool continue_foreign_event(const probe_session *s, const DEBUG_EVENT &ev);
bool service_event(probe_session *s, DEBUG_EVENT &ev);
void pump(probe_session *s, DWORD ms);
void park_release(probe_session *s);
DWORD fair_tick(probe_session *s, std::chrono::steady_clock::duration blocked, bool got);
void ctx_watch_poll(probe_session *s, bool all = false);
HANDLE event_thread(probe_session *s, DWORD tid);
void forget_event_thread(probe_session *s, DWORD tid);
void trace_thread_stacks(probe_session *s, const char *why);
bool dispatch_event(probe_session *s, DEBUG_EVENT &event, DWORD &disposition);
bool arm_quietly(probe_session *s, const std::string &name, uint64_t base);
// session_log.cpp
void append_json_string(std::string &out, std::string_view value);
void writer_failed(probe_session *s, const std::string &message, uint64_t unwritten);
void tail_failed(probe_session *s, const std::string &message);
bool make_forward_pipe(HANDLE &server, HANDLE &client);
bool forwardable(HANDLE h);
bool same_object(HANDLE a, HANDLE b);
bool forward_start(probe_session *s, probe_session::StdForward *f);
void forward_stop(probe_session *s);
bool start_log_output(probe_session *s);
void flush_log_writer(probe_session *s, bool up_to_now = false);
void sym_unload(probe_session *s, uint64_t base);
void wait_sym_unloads(probe_session *s, uint64_t base, uint64_t size);
void stop_log_output(probe_session *s);
void enqueue_agent_record(probe_session *s, const probe_agent_log &rec);
size_t drain_agent_logs(probe_session *s, bool unloading = false);
void deliver_past_stall(probe_session *s, bool all_published = false);
void start_drainer(probe_session *s);
void stop_drainer(probe_session *s);
std::string symbolize(probe_session *s, uint64_t addr);
void vlog_entry(probe_context *c, int stack, const char *format, va_list ap);
// session_agent.cpp
bool module_of(const void *address, HMODULE &m);
void start_agent_prep(probe_session *s);
bool bind_shared_callback(probe_session *s, probe_callback &cb, uint32_t flags, std::string &pending_export);
bool resolve_inline(probe_session *s, Probe &p, uint64_t base);
void release_unclaimed_agent_mapping(probe_session *s);
bool create_agent_channel(probe_session *s);
bool register_runtime_inline(probe_session *s, Probe &p);
bool inline_hold_needed(const probe_session *s);
bool agent_thread(const probe_session *s, DWORD tid);
void hold_thread(probe_session *s, DWORD tid);
bool arm_gates_for_pending(probe_session *s);
bool handle_gate(probe_session *s, const DEBUG_EVENT &event, bool &handled, bool *failed = nullptr);
void release_held(probe_session *s, const char *why);
bool kick_agent(probe_session *s);
bool confirm_runtime_inline(probe_session *s, Probe &p);
bool reuse_target_agent(probe_session *s);
bool bind_pending_shared(probe_session *s);
void retarget_pending(probe_session *s);
void ipc_thaw(probe_session *s);
bool ipc_freeze_thread(probe_session *s, DWORD tid);
bool handle_ipc(probe_session *s, const DEBUG_EVENT &event);
HANDLE create_remote_thread_boosted(HANDLE process, LPTHREAD_START_ROUTINE entry, void *argument, DWORD *tid);
bool start_agent_load(probe_session *s);
bool start_agent_init(probe_session *s);
bool early_agent(probe_session *s, const DEBUG_EVENT &event, bool &ok);
bool accept_agent_install(probe_session *s, bool completed_round = true);
bool agent_has_pending(const probe_session *s);
bool complete_remote_thread(probe_session *s, DWORD result);
// session_bp.cpp
bool patch(HANDLE process, uint64_t address, unsigned char byte);
void restore_original(HANDLE process, uint64_t address, unsigned char original);
bool thread_terminating(HANDLE thread);
bool target_has_shadow_stack(probe_session *s);
bool emulate_site(probe_session *s, const Probe &p, CONTEXT &c);
size_t int3_armed(const probe_session *s);
bool arm_breakpoint(probe_session *s, Probe &p, uint64_t base);
bool refresh_breakpoint(probe_session *s, Probe &p);
void count_hit(Probe *p);
Probe *adopt_relocated_breakpoint(probe_session *s, uint64_t at);
bool still_armed(probe_session *s, uint64_t site);
void end_inplace_step(probe_session *s, DWORD tid, uint64_t site);
bool inplace_exempt(probe_session *s, DWORD tid);
void inplace_begin(probe_session *s, DWORD tid);
void inplace_release_all(probe_session *s);
void inplace_watchdog(probe_session *s);
void inplace_sync(probe_session *s, const DEBUG_EVENT &ev);
void site_traits(const Probe &p, bool &pushf, bool &may_block);
uint64_t thread_scratch(probe_session *s, DWORD tid, uint64_t site);
uint64_t displaced_trampoline(probe_session *s, Probe &p);
uint64_t hw_trampoline(probe_session *s, Probe &p);
const probe_session::DTramp *dtramp_at(const probe_session *s, uint64_t a, uint64_t *start = nullptr);
void sync_int3_table(probe_session *s);
#if defined(_WIN64)
uint64_t syscall_trampoline(probe_session *s, Probe &p);
#endif
// session_hw.cpp
void hw_rw_len(uint32_t flags, uint32_t &rw, uint32_t &len);
uint64_t dr_address(const CONTEXT &c, int slot);
bool hw_released_on(const probe_session *s, DWORD tid, uint64_t address);
bool hw_slot_is_ours(const probe_session *s, DWORD tid, const CONTEXT &c, int slot);
bool target_owns_slot(const probe_session *s, DWORD tid, const CONTEXT &c, int slot);
uint8_t target_slots_any(const probe_session *s);
void keep_queued_dr6(probe_session *s, DWORD tid, HANDLE t);
DWORD64 dr6_carried(const probe_session *s, DWORD tid);
DWORD64 queued_dr6(const probe_session *s, DWORD tid, const CONTEXT &now);
void retire_hw_address(probe_session *s, uint64_t address);
void settle_hw_thread(probe_session *s, DWORD tid);
bool arm_hw(probe_session *s, Probe &p, uint64_t base);
void hw_yield_to_target(probe_session *s, DWORD tid, HANDLE t);
void reapply_all_hw(probe_session *s);
void arm_entry_fixup(probe_session *s, uint64_t entry);
void reapply_hw_thread(probe_session *s, DWORD tid);
void thread_start_fixup(probe_context *c);
void arm_thread_start_fixup(probe_session *s);
void release_hw(probe_session *s, Probe &p);
void enforce_owned_drs(const probe_session *s, DWORD tid, CONTEXT &c, bool clear_stale);
bool handle_hw(probe_session *s, const DEBUG_EVENT &event, bool &handled);
bool queue_debug_delivery(probe_session *s, DWORD tid, uint64_t ip, DWORD64 clear_bits, DWORD64 set_bits);
bool repair_debug_delivery(probe_session *s, DWORD tid, const CONTEXT &native);

#if defined(UHH_TEST_HOOKS)
extern bool g_test_die_on_continue;
void test_note_repcopy();
void test_die_after_arm();
#endif
// session_site.cpp
std::string hex_bytes(const unsigned char *b, size_t n);
void zydis_init(ZydisDecoder &dec);
bool refuse_mid_instruction(probe_session *s, Probe &p, uint64_t site);
bool vet_site(probe_session *s, Probe &p, bool &moved_to_hw);
// session_call.cpp
void warn_record(probe_context *c, Probe *probe, const char *text, bool *warned = nullptr);
EventFiber *fiber_get(probe_session *s);
bool fiber_step(probe_session *s, EventFiber *f, const DEBUG_EVENT *ev);
bool call_resume(probe_session *s, DWORD tid, EventFiber::Outcome how, const DEBUG_EVENT *ev);
bool thread_in_call(const probe_session *s, DWORD tid);
bool defer_hits_now(const probe_session *s, DWORD tid);
bool poll_calls(probe_session *s);
void finish_calls(probe_session *s);
void restore_fixup(probe_context *c);
void arm_restore_fixup(probe_session *s);
bool co_slot_gone(probe_session *s, uint64_t sp);
bool co_unwound(probe_session *s, DWORD tid, const CONTEXT &at, uint64_t pc);
bool defer_hit_during_call(probe_session *s, DWORD tid, uint64_t address, bool rewind_ip);
bool hold_watch_hit(probe_session *s, const DEBUG_EVENT &event, const CONTEXT &native, uint8_t theirs);
void run_callback(probe_session *s, Probe *probe, probe_context *c);
bool apply_return_from(probe_session *s, Probe *probe, const probe_context &c, CONTEXT &native);
void call_refused(Probe *probe, const std::string &why);
int run_call(probe_session *s, CallbackState *st, uint64_t fn, uint64_t *ret, int nargs, const uint64_t *args,
             DWORD timeout_ms, uint64_t probe_to, uint64_t *grow_to);
int call_func_args(probe_context *c, const char *symbol, uint64_t *ret, int nargs, const uint64_t *in);
// session_lifecycle.cpp
bool guard_pending(const probe_session *s);
void guard_note_hold(probe_session *s, DWORD tid);
bool guard_set_ready(probe_session *s, const char *why);
bool guard_claim_event(probe_session *s, const DEBUG_EVENT &event);
bool guard_continue(probe_session *s, DWORD pid, DWORD tid, DWORD disposition);
void guard_sync(probe_session *s);
void guard_resync(probe_session *s);
void handling_running(probe_session *s, DWORD tid, bool running);
void detach(probe_session *s);
// session_symbols.cpp
std::string event_module_name(HANDLE process, HANDLE file, uint64_t base);
uint32_t remote_image_size(HANDLE process, uint64_t base);
void sym_register(probe_session *s, HANDLE file, uint64_t base);
std::string module_name_from_module(HMODULE module);
bool iequals(const std::string &a, const std::string &b);
bool parse_location(probe_session *s, const char *text, Probe &p);
bool resolve_export(probe_session *s, uint64_t base, const std::string &name, uint64_t &rva, std::string *forward = nullptr);
bool remote_export_owner(probe_session *s, std::string &module, std::string &name, uint64_t &base, uint64_t &rva);
uint64_t resolve_symbol(probe_session *s, const char *symbol);

// Never install a trap the bounded death-guard ownership table cannot represent.
inline bool guard_dr_available(const probe_session *s, uint64_t address) {
    return !s->attached || !s->shared || s->hw_armed_ever.count(address) ||
           s->hw_armed_ever.size() < PROBE_AGENT_GUARD_DR_SITES;
}

// Program debug register `slot` for execute (rw=0,len=0) or a data watchpoint. rw:
// 0=execute, 1=write, 3=read/write. len: 0=1,1=2,3=4,2=8 bytes (Intel DR7 LEN encoding).
// With `s` and `tid`: never over a slot the target itself has armed there; a past
// address alone does not prove ownership (see hw_yield_to_target).
inline bool set_dr_on_thread(HANDLE thread, int slot, uint64_t addr, bool enable,
                             uint32_t rw = 0, uint32_t len = 0, const probe_session *s = nullptr, DWORD tid = 0) {
    CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &c)) return false;
    if (s && slot >= 0 && slot < 4 && ((c.Dr7 >> (slot * 2)) & 3)) {
        const uint64_t cur = slot == 0 ? c.Dr0 : slot == 1 ? c.Dr1 : slot == 2 ? c.Dr2 : c.Dr3;
        if (cur != addr && !hw_slot_is_ours(s, tid, c, slot)) return true;
    }
    switch (slot) { case 0: c.Dr0 = addr; break; case 1: c.Dr1 = addr; break;
                    case 2: c.Dr2 = addr; break; case 3: c.Dr3 = addr; break; default: return false; }
    DWORD64 ln = (DWORD64)1 << (slot * 2);                       // local-enable Ln
    DWORD64 fieldmask = (DWORD64)0xF << (16 + slot * 4);         // this slot's RWn|LENn nibble
    DWORD64 field = (DWORD64)(((len & 3u) << 2) | (rw & 3u)) << (16 + slot * 4);
    DWORD64 dr7 = c.Dr7;
    if (enable) { dr7 &= ~fieldmask; dr7 |= ln | field; } else { dr7 &= ~(ln | fieldmask); }   // full release
    c.Dr7 = dr7;
    return !!SetThreadContext(thread, &c);
}
// Release only the image installed at this site; the target may have replaced it.
inline bool clear_dr_on_thread(HANDLE thread, int slot, uint64_t address) {
    CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &c)) return false;
    if (dr_address(c, slot) != address) return true;
    c.Dr7 &= ~((decltype(c.Dr7))3 << (slot * 2)) & ~((decltype(c.Dr7))0xF << (16 + slot * 4));
    switch (slot) { case 0: c.Dr0 = 0; break; case 1: c.Dr1 = 0; break;
                    case 2: c.Dr2 = 0; break; default: c.Dr3 = 0; break; }
    c.Dr6 &= ~((decltype(c.Dr6))1 << slot);
    return !!SetThreadContext(thread, &c);
}
inline int call_in_target(probe_session *s, CallbackState *st, uint64_t fn, uint64_t *ret, int nargs, const uint64_t *args,
                          DWORD timeout_ms = 5000) {
    uint64_t low = 0;
    const int r = run_call(s, st, fn, ret, nargs, args, timeout_ms, 0, &low);
    if (r != -1) return r;
    if (trace_enabled()) std::fprintf(stderr, "  call_func: thread %lu grows its stack to 0x%llx\n", (unsigned long)st->tid,
                                      (unsigned long long)low);
    if (run_call(s, st, 0, nullptr, 0, nullptr, timeout_ms, low, nullptr) != 1) {
        if (!st->released && !s->exited) call_refused(st->probe, "the thread could not grow its stack down to the call frame");
        return 0;
    }
    return run_call(s, st, fn, ret, nargs, args, timeout_ms, 0, nullptr);     // committed now (else refused, loudly)
}

} // namespace uhh_session

// Public x64 breakpoint + inline backends. The debug API binds event consumption
// to the launching thread, so probe_run owns the event loop through exit.
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
#include <vector>
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
#pragma comment(lib, "psapi.lib")

struct Probe {
    std::string location, module, callback_export;
    std::string export_name;   // "module!Export+0xOFF": resolved from the export table at load
    uint64_t sym_offset = 0;
    // The location named its module without an extension ("kernel32!X"): module is then
    // "<name>.dll" (module_of_location); warned once if only "<name>.<other ext>" loads.
    bool bare_module = false, warned_bare = false;
    bool retired = false;      // PROBE_ONCE probe that already fired (kept for the report)
    bool internal = false;     // library-owned (not reported)
    // Breakpoint probes: the original bytes that followed the INT3 (to recognise a copy of the
    // site another hooking tool relocated into its trampoline), and for such an adopted copy,
    // the probe it stands in for (its hits count there; the copy itself is not reported).
    std::vector<unsigned char> follow;
    struct Probe *alias_of = nullptr;
    bool runtime = false;      // added after launch: an install failure is reported, not fatal
    bool vetted = false;       // pre-hook check done for this inline install
    uint64_t rva = 0, base = 0, address = 0, hits = 0;
    uint32_t agent_index = UINT32_MAX;
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
    probe_callback callback = nullptr;
    uint32_t flags = 0;
    std::vector<unsigned char> config;
    int dr_slot = -1;   // hardware-breakpoint DR register (0-3); -1 if not a HW probe
    bool active = false;
    bool warned_double_run = false;   // call_original without return_from (warn once)
    bool warned_pop = false;          // x86 return_from nargs contradicted call_original (warn once)
    bool warned_log = false;          // a "uhh warning: ..." log record was emitted (once per probe, as inline)
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
#if defined(_WIN64)
#define UHH_POST_AX Rax
#else
#define UHH_POST_AX Eax
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
};

struct probe_session {
    std::vector<std::unique_ptr<Probe>> probes;
    std::mutex agent_mu;
    std::mutex drain_mu;                       // shared ring has exactly one consumer at a time
    uint32_t agent_map[PROBE_AGENT_MAX_PROBES] = {};   // agent request index -> probes[] index (under agent_mu)
    std::thread drainer;                       // empties the agent's log ring continuously
    std::atomic<uint64_t> controller_dropped{0}; // only broken file I/O/allocation can lose controller logs
    std::atomic<bool> drain_stop{false};
    uint64_t abandoned_slots = 0;              // ring slots skipped: their producer was killed mid-record
    // Both producer paths wait on this bounded queue. The writer never holds queue_mu
    // while symbolizing or writing, so a slow filesystem cannot invert locks with the
    // debugger or the agent-ring drainer.
    static constexpr size_t LOG_QUEUE_CAP = 2048;
    std::deque<LogRecord> log_queue;
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
    std::string writer_error;
    std::thread log_tailer;
    std::mutex tail_mu;
    std::mutex stdout_mu;                      // whole-line stdout writes: log batches vs report lines
    std::condition_variable tail_changed, tail_caught_up;
    uint64_t log_bytes_written = 0, log_bytes_tailed = 0;
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
    bool sym_ready = false;    // dbghelp initialised on the target (stack walk + symbolize)
    std::unordered_map<std::string, uint64_t> module_bases;
    std::unordered_map<std::string, std::string> module_paths;   // name -> on-disk image (prehook diff)
    std::unordered_map<uint64_t, uint32_t> module_sizes;          // mapped image base -> SizeOfImage
    std::vector<std::string> prehooks;                           // JSON lines for the report
    PROCESS_INFORMATION pi{};
    DWORD exit_code = 1;
    uint64_t overrides = 0;
    std::string error;
    HANDLE mapping = nullptr, remote_thread = nullptr;
    probe_agent_shared *shared = nullptr;
    HMODULE local_agent = nullptr;
    void *remote_path = nullptr;
    uint64_t remote_agent = 0;
    DWORD remote_tid = 0;
    std::string remote_fault;   // first fault raised on the agent's load/init thread (diagnostic)
    enum RemoteWork { REMOTE_NONE, REMOTE_LOAD_AGENT, REMOTE_INIT_AGENT } remote_work = REMOTE_NONE;
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
    uint8_t dr_used = 0;
    std::vector<std::pair<uint64_t, int>> gates; // (inline site, DR slot): hw gates until its hook is confirmed
    uint8_t dr_ever = 0;
    uint8_t dr_next = 0;                       // next DR slot to try (rotation)
    uint64_t entry_reapply = 0;                // image entry: re-apply DRs on first arrival
    uint64_t entry_addr = 0;                   // image entry point (hold-for-install point)
    bool entry_seen = false;
    bool thread_start_fixup = false;           // library INT3 at ntdll!RtlUserThreadStart armed
    HANDLE svc_event = nullptr;                // agent service: "install pending requests"
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
    DWORD hw_stale_tid = 0;                    // the thread of the event being handled, if it was unsettled
    std::unordered_set<uint64_t> hw_stale;     // ...and the released addresses still ours on it
    std::vector<HANDLE> ipc_frozen;            // threads suspended for an agent hook write (FREEZE..THAW)
    DWORD ipc_freezer = 0;                     // the agent thread doing that write (0 = no freeze)
    int hw_active = 0;
    bool launched = false, exited = false, inline_ready = false;
    bool interrupted = false, ctrl_counted = false;   // Ctrl+C ended this session / counted in g_ctrl_sessions
    std::atomic<bool> ran{false};              // probe_run has started (read by probe_close on any thread)
    bool call_cet_warned = false;              // call_func refused under CET (warn once)
    int shadow_stack = -1;                     // target has hardware shadow stacks (CET): -1 unknown, 0/1
    uint64_t ret_gadgets = 0;                  // return_from: `ret` / `ret N` gadgets in the target
    bool warned_cb_fault = false;              // one stderr warning for a faulting controller-side callback
    DWORD cb_tid = 0;                          // thread whose callback / IPC is being serviced (0 = none)
    std::wstring agent_copy;                   // per-session copy of the agent DLL (UHH_SHARED), deleted at close
    std::vector<DWORD> pending_hold;           // callers of a runtime inline add: hold until it lands
    bool attached = false;                     // probe_attach: detach (not kill) on close
    std::atomic<bool> stop_requested{false};   // probe_close from another thread while probe_run runs
    std::atomic<bool> running{false};          // probe_run is executing (on some thread)
    bool detached = false;
    bool detaching = false;                    // detach() running: no new holds, arming, gates or agent work
    bool detached_hooks = false;               // detach removed the inline hooks (stop_drainer may settle)
    bool guard_ready = false;                  // attach: controller-death guard up (or given up): arm breakpoint/hw
    ULONGLONG guard_since = 0;
    bool agent_init_started = false;           // this session started the agent's init
    std::vector<DWORD> detach_frozen;          // detach's own freeze of every thread (mirrored for the guard)
    std::vector<DWORD> handling;               // threads whose debug event is being handled (nested: call_original)
    DWORD debug_tid = 0;                       // the thread that launched/attached: owns the debug object
    DWORD in_call_tid = 0;                     // thread currently running a call_func callee
    std::vector<HANDLE> call_deferred;         // other threads' hits during a call_func: rewound + suspended
    bool skip_continue = false;                // call_func already continued the current event
    uint64_t call_trap = 0;                    // INT3 the callee returns into
    // call_original in flight (breakpoint/hw, see call_original): the probe address the call
    // starts at, the hit's SP, whether the breakpoint entry pass is still pending (the call's
    // own first INT3 execution: not a hit), and whether the thread was seen OUTSIDE the call
    // (a hit at or above the hit's SP: it left by exception/longjmp without returning).
    uint64_t co_addr = 0, co_sp = 0;
    bool co_entry_pending = false, co_left = false;
    bool co_warned_entry = false, co_warned_dr = false, co_warned_left = false, co_warned_nargs = false;
    bool initial_break = false;
    std::unordered_map<DWORD, StepState> stepping;   // threads mid single-step
    // Threads whose in-place step at a probe site faulted: the fault went to the target with
    // OUR trap flag in its context. If the target's handler continues execution there, the
    // INT3 is hit again (with TF set) -- the same execution restarting, not a new hit; if it
    // continues elsewhere, the trap flag raises one stray step. thread -> probe site.
    // A WOW64 (x86) handler's context comes back WITHOUT our trap flag: there the restart is
    // the thread's next event being the INT3 at the site (whatever registers it repaired).
    struct Refault { uint64_t site = 0; };
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
};

static bool register_runtime_inline(probe_session *s, Probe &p);
// A 32-bit (WOW64) controller's Get/SetThreadContext on a thread other than the one whose
// event it is handling is an implicit suspend + resume INSIDE the call (ROADMAP L13): killed in
// the middle of one, the controller leaves that thread suspended once with nothing of ours
// recording it (the guard resumes the event threads, call threads and explicit holds only).
// While such a call runs, the thread is listed among the guard's held threads -- after a
// controller death it gets one resume, a no-op unless the call was in progress -- and it is
// taken off again right after. x64 controllers have no implicit suspend: nothing to do.
struct GuardTouch {
#if !defined(_WIN64)
    probe_agent_guard *g = nullptr;
    LONG n = 0;
    GuardTouch(const probe_session *s, DWORD tid);
    ~GuardTouch() { if (g && g->held_count == n + 1) { MemoryBarrier(); g->held_count = n; } }
#else
    GuardTouch(const probe_session *, DWORD) {}
#endif
    GuardTouch(const GuardTouch &) = delete;
    GuardTouch &operator=(const GuardTouch &) = delete;
};
#if !defined(_WIN64)
GuardTouch::GuardTouch(const probe_session *s, DWORD tid) {
    if (!s->attached || !s->shared || s->detached || !tid) return;
    auto &gg = s->shared->guard;
    const LONG count = gg.held_count;
#if defined(UHH_TEST_HOOKS)
    // Test-only (probe_api_testhooks): UHH_TEST_NO_TOUCH_GUARD=1 leaves the touch unrecorded
    // (the control run of regress cxlib-touchkill-hw).
    static const bool off = std::getenv("UHH_TEST_NO_TOUCH_GUARD") != nullptr;
    if (off) {} else
#endif
    if (count >= 0 && count < (LONG)PROBE_AGENT_GUARD_TIDS) {
        gg.held_tids[count] = tid;
        MemoryBarrier();
        gg.held_count = count + 1;
        g = &gg; n = count;
    }
#if defined(UHH_TEST_HOOKS)
    // UHH_TEST_DIE_IN_TOUCH=<tid>: at the first such call on that thread, do what the kernel
    // does inside it (suspend the thread) and die there -- the WOW64 implicit-suspend window.
    static const DWORD die_tid = [] { const char *v = std::getenv("UHH_TEST_DIE_IN_TOUCH"); return v ? (DWORD)std::strtoul(v, nullptr, 10) : 0u; }();
    if (die_tid && tid == die_tid) {
        if (HANDLE t = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid)) SuspendThread(t);
        std::fflush(nullptr);
        TerminateProcess(GetCurrentProcess(), 98);
    }
#endif
}
#endif
static bool kick_agent(probe_session *s);
static bool resolve_inline(probe_session *s, Probe &p, uint64_t base);
static Probe *probe_at(probe_session *s, uint64_t address);
static bool trace_enabled() { static const bool on = std::getenv("PROBE_TRACE") != nullptr; return on; }
static void start_drainer(probe_session *s);
static void stop_drainer(probe_session *s);
static std::string symbolize(probe_session *s, uint64_t addr);
static bool start_log_output(probe_session *s);
static bool enqueue_log(probe_session *s, LogRecord &&record);
static size_t drain_agent_logs(probe_session *s);
static void deliver_past_stall(probe_session *s);
static void enqueue_agent_record(probe_session *s, const probe_agent_log &rec);
static void flush_log_writer(probe_session *s);
static void stop_log_output(probe_session *s);
static void forward_finish(probe_session *s);
static void forward_stop(probe_session *s);
static void release_hw(probe_session *s, Probe &p);
static bool dispatch_event(probe_session *s, DEBUG_EVENT &event, DWORD &disposition);
static void release_held(probe_session *s, const char *why);

static void set_error(probe_session *s, const std::string &message) {
    if (s && s->error.empty()) s->error = message;
    std::fprintf(stderr, "probe: error: %s\n", message.c_str());
}

static std::string win_error(const char *what) {
    return std::string(what) + " (Win32=" + std::to_string(GetLastError()) + ")";
}

// Length of the well-formed UTF-8 sequence at p (n bytes left), or 0 if it is not one.
static size_t utf8_sequence(const unsigned char *p, size_t n) {
    unsigned char c = p[0];
    size_t len = c >= 0xC2 && c <= 0xDF ? 2 : c >= 0xE0 && c <= 0xEF ? 3 : c >= 0xF0 && c <= 0xF4 ? 4 : 0;
    if (!len || len > n) return 0;
    for (size_t i = 1; i < len; ++i) if ((p[i] & 0xC0) != 0x80) return 0;
    if (c == 0xE0 && p[1] < 0xA0) return 0;              // overlong
    if (c == 0xED && p[1] >= 0xA0) return 0;             // UTF-16 surrogate
    if (c == 0xF0 && p[1] < 0x90) return 0;              // overlong
    if (c == 0xF4 && p[1] >= 0x90) return 0;             // > U+10FFFF
    return len;
}

// A JSON string that is always valid JSON and valid UTF-8, and loses nothing: every control
// character (NUL included) is escaped, and a byte that is not part of well-formed UTF-8 is
// written as \u00XX (that byte's value) instead of being passed through raw.
static void append_json_string(std::string &out, const std::string &value) {
    static const char hex[] = "0123456789abcdef";
    out.push_back('"');
    const auto *p = reinterpret_cast<const unsigned char *>(value.data());
    for (size_t i = 0, n = value.size(); i < n; ) {
        unsigned char ch = p[i];
        if (ch == '"' || ch == '\\') { out.push_back('\\'); out.push_back((char)ch); ++i; continue; }
        if (ch >= 0x20 && ch < 0x80) { out.push_back((char)ch); ++i; continue; }
        if (ch == '\n') { out += "\\n"; ++i; continue; }
        if (ch == '\r') { out += "\\r"; ++i; continue; }
        if (ch == '\t') { out += "\\t"; ++i; continue; }
        if (ch >= 0x80) {
            if (size_t len = utf8_sequence(p + i, n - i)) { out.append(value, i, len); i += len; continue; }
        }
        out += "\\u00"; out.push_back(hex[ch >> 4]); out.push_back(hex[ch & 15]); ++i;
    }
    out.push_back('"');
}

static std::string format_log_line(probe_session *s, const LogRecord &r) {
    char prefix[96];
    int n = std::snprintf(prefix, sizeof(prefix),
                          "{\"kind\":\"probe_log\",\"probe\":%u,\"tid\":%u,\"message\":",
                          r.probe, r.tid);
    std::string line(prefix, n > 0 ? (size_t)n : 0);
    append_json_string(line, r.text);
    if (r.has_stack) {
        line += ",\"stack\":[";
        for (size_t i = 0; i < r.frames.size(); ++i) {
            if (i) line.push_back(',');
            append_json_string(line, symbolize(s, r.frames[i]));
        }
        line.push_back(']');
    }
    line += "}\n";
    return line;
}

static void writer_failed(probe_session *s, const std::string &message, uint64_t unwritten) {
    std::lock_guard<std::mutex> lock(s->queue_mu);
    if (!s->writer_failed) {
        s->writer_failed = true;
        s->writer_error = message;
        for (const LogRecord &r : s->log_queue) {
            if (r.sym_unload) uhh_sym::unregister_module(s->pi.hProcess, r.sym_unload);
            else ++unwritten;
        }
        s->log_queue.clear();
        s->sym_pending.clear();
        s->controller_dropped.fetch_add(unwritten, std::memory_order_relaxed);
        std::fprintf(stderr, "probe: error: %s\n", message.c_str());
    }
    s->writer_busy = false;
    s->queue_writable.notify_all();
    s->queue_flushed.notify_all();
}

static bool write_stdout_chunk(probe_session *s, const char *bytes, size_t size);
static void tail_catch_up_locked(probe_session *s, const char *fresh, size_t fresh_size, uint64_t fresh_end);
static bool write_log_batch(probe_session *s, const std::string &bytes, uint64_t records) {
    if (bytes.empty()) return true;
    DWORD wrote = 0;
    if (s->log_file == nullptr || s->log_file == INVALID_HANDLE_VALUE ||
        bytes.size() > MAXDWORD ||
        !WriteFile(s->log_file, bytes.data(), (DWORD)bytes.size(), &wrote, nullptr) ||
        (size_t)wrote != bytes.size()) {
        writer_failed(s, win_error("write probe log file"), records);
        return false;
    }
    s->logs_written.fetch_add(records, std::memory_order_relaxed);
    uint64_t end = 0;
    {
        std::lock_guard<std::mutex> lock(s->tail_mu);
        end = s->log_bytes_written += bytes.size();
    }
    // Live output: the SAME batch goes to stdout right away, from this thread (the
    // separate tailer let stdout fall seconds behind under load). A slow stdout (a
    // console) back-pressures the producers instead -- nothing is dropped; the file
    // above is the complete record either way.
    // A stdout that stops taking data (the reader closed the pipe: `| head`) ends the live
    // tail only -- reported as an error once -- never the file: the file stays the complete
    // record and no log is counted lost for a reader that went away.
    bool tail;
    {
        std::lock_guard<std::mutex> lock(s->tail_mu);
        tail = s->tail_enabled && !s->tail_failed;
    }
    if (tail && s->fwd_out_active) {
        // The target's stdout is forwarded: the batch goes out only at a line boundary of it.
        std::lock_guard<std::mutex> out_lock(s->stdout_mu);
        tail_catch_up_locked(s, bytes.data(), bytes.size(), end);
        tail = false;                                   // tail_catch_up_locked tracked the bytes
    }
    if (tail && !write_stdout_chunk(s, bytes.data(), bytes.size())) tail = false;   // tail_failed() said why
    if (tail) {
        std::lock_guard<std::mutex> lock(s->tail_mu);
        s->log_bytes_tailed = s->log_bytes_written;
    }
    s->tail_changed.notify_one();
    s->tail_caught_up.notify_all();
    return true;
}

static void log_writer_main(probe_session *s) {
    constexpr size_t BATCH_BYTES = 64 * 1024;
    uint64_t unwritten = 0;
    try {
        for (;;) {
            {
                std::unique_lock<std::mutex> lock(s->queue_mu);
                s->queue_readable.wait(lock, [s] { return s->writer_stop || !s->log_queue.empty(); });
                if (s->log_queue.empty() && s->writer_stop) break;
                s->writer_busy = true;
            }

            std::string batch;
            uint64_t batch_records = 0;
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(10);
            for (;;) {
                LogRecord record;
                {
                    std::lock_guard<std::mutex> lock(s->queue_mu);
                    if (s->log_queue.empty()) break;
                    record = std::move(s->log_queue.front());
                    s->log_queue.pop_front();
                    s->queue_writable.notify_one();
                }
                if (record.sym_unload) {
                    // Every record queued before this unload is formatted (symbolized) by now.
                    uhh_sym::unregister_module(s->pi.hProcess, record.sym_unload);
                    std::lock_guard<std::mutex> lock(s->queue_mu);
                    for (auto it = s->sym_pending.begin(); it != s->sym_pending.end(); ++it)
                        if (it->first == record.sym_unload) { s->sym_pending.erase(it); break; }
                    s->queue_flushed.notify_all();
                    continue;
                }
                ++unwritten;
                std::string line = format_log_line(s, record);
                if (!batch.empty() && batch.size() + line.size() > BATCH_BYTES) {
                    if (!write_log_batch(s, batch, batch_records)) return;
                    unwritten -= batch_records;
                    batch.clear(); batch_records = 0;
                    deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(10);
                }
                batch += line; ++batch_records;
                if (batch.size() >= BATCH_BYTES || std::chrono::steady_clock::now() >= deadline) {
                    if (!write_log_batch(s, batch, batch_records)) return;
                    unwritten -= batch_records;
                    batch.clear(); batch_records = 0;
                    deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(10);
                }
            }
            // An empty queue is an idle boundary: do not hold a short batch for the timer.
            if (!write_log_batch(s, batch, batch_records)) return;
            unwritten -= batch_records;
            {
                std::lock_guard<std::mutex> lock(s->queue_mu);
                s->writer_busy = false;
                s->queue_flushed.notify_all();
            }
        }
    } catch (const std::exception &e) {
        writer_failed(s, std::string("probe log writer failed: ") + e.what(), unwritten);
        return;
    } catch (...) {
        writer_failed(s, "probe log writer failed", unwritten);
        return;
    }
    std::lock_guard<std::mutex> lock(s->queue_mu);
    s->writer_busy = false;
    s->queue_flushed.notify_all();
}

static void warn_console_once(probe_session *s) {
    bool print = false;
    {
        std::lock_guard<std::mutex> lock(s->tail_mu);
        if (s->stdout_is_console && !s->console_warning) {
            s->console_warning = true; print = true;
        }
    }
    if (print)
        std::fprintf(stderr, "probe: logs are being written to a console, which is slowing the target; "
                             "redirect stdout to a file or pipe for full speed\n");
    if (print) std::fflush(stderr);
}

static void tail_failed(probe_session *s, const std::string &message) {
    {
        std::lock_guard<std::mutex> lock(s->tail_mu);
        if (s->tail_failed) return;
        s->tail_failed = true;
        s->tail_error = message;
    }
    std::fprintf(stderr, "probe: error: %s\n", message.c_str());
    s->tail_caught_up.notify_all();
}

// The reader of the controller's stdout went away (the pipe was closed: `| head`). Normal use,
// not a session failure: the live tail stops, every log still goes to the session JSONL file
// (the complete record), and probe_report says "live_output_closed":true. Any other stdout
// failure stays an error.
static bool reader_gone(DWORD e) {
    return e == ERROR_BROKEN_PIPE || e == ERROR_NO_DATA || e == ERROR_PIPE_NOT_CONNECTED;
}
static void tail_closed(probe_session *s, DWORD e) {
    {
        std::lock_guard<std::mutex> lock(s->tail_mu);
        if (s->tail_failed) return;
        s->tail_failed = true;                     // ends the live tail only
        s->live_output_closed = true;
    }
    std::fprintf(stderr, "probe: warning: live output closed (Win32=%lu); every log still goes to the session log file\n",
                 (unsigned long)e);
    s->tail_caught_up.notify_all();
}
// A raw write to stdout failed (GetLastError still set by WriteFile).
static void tail_write_failed(probe_session *s, const char *what) {
    DWORD e = GetLastError();
    if (reader_gone(e)) { tail_closed(s, e); return; }
    SetLastError(e);
    tail_failed(s, win_error(what));
}
// fflush(stdout) failed: the CRT keeps the Win32 error in _doserrno.
static void tail_flush_failed(probe_session *s) {
    unsigned long e = 0;
    if (_get_doserrno(&e) == 0 && reader_gone((DWORD)e)) { tail_closed(s, (DWORD)e); return; }
    tail_failed(s, "flush controller stdout before probe logs");
}

static bool write_stdout_chunk(probe_session *s, const char *bytes, size_t size) {
    if (!size) return true;
    std::lock_guard<std::mutex> out_lock(s->stdout_mu);
    // The driver still owns the CRT FILE*. Empty it before the raw-handle write so its
    // own complete lines cannot remain buffered behind newer tailed log lines.
    if (std::fflush(stdout) != 0) {
        tail_flush_failed(s); return false;
    }
    DWORD wrote = 0;
    auto started = std::chrono::steady_clock::now();
    if (s->stdout_handle == nullptr || s->stdout_handle == INVALID_HANDLE_VALUE || size > MAXDWORD ||
        !WriteFile(s->stdout_handle, bytes, (DWORD)size, &wrote, nullptr) || (size_t)wrote != size) {
        tail_write_failed(s, "tail probe logs to stdout"); return false;
    }
    if (s->stdout_is_console && std::chrono::steady_clock::now() - started >= std::chrono::seconds(1))
        warn_console_once(s);
    return true;
}

static bool write_all(HANDLE h, const char *bytes, size_t size) {
    while (size) {
        DWORD chunk = (DWORD)std::min<size_t>(size, 1u << 20), wrote = 0;
        if (h == nullptr || h == INVALID_HANDLE_VALUE || !WriteFile(h, bytes, chunk, &wrote, nullptr) || !wrote) return false;
        bytes += wrote; size -= wrote;
    }
    return true;
}

// ---- Forwarded target stdout/stderr (probe_launch) ------------------------------------------
// The target writes into its own pipe; forward_main copies the bytes to the controller's real
// stdout/stderr a complete line at a time, and the live log tail writes its records only while
// stdout is at a line boundary. Records written while the target sits inside an unfinished line
// (a prompt, a progress line, binary output) stay in the log FILE and are replayed from there
// the moment the target ends that line -- so nothing is held in memory and nothing blocks the
// writer (blocking it could deadlock: the target thread that would finish the line may be the
// one waiting to log). Both run under stdout_mu.

// stdout_mu held. Write log bytes up to fresh_end (the log file length) unless stdout is inside
// a target line. [tailed, fresh_end - fresh_size) is replayed from the file; the rest -- the
// writer's batch just appended -- comes from memory.
static void tail_catch_up_locked(probe_session *s, const char *fresh, size_t fresh_size, uint64_t fresh_end) {
    if (s->out_midline.load()) return;                  // deferred: replayed at the next newline
    uint64_t tailed = 0;
    {
        std::lock_guard<std::mutex> lock(s->tail_mu);
        if (s->tail_failed || !s->tail_enabled) return;
        tailed = s->log_bytes_tailed;
        if (!fresh_size) fresh_end = s->log_bytes_written;
    }
    if (tailed >= fresh_end) return;
    if (std::fflush(stdout) != 0) { tail_flush_failed(s); return; }
    const uint64_t file_end = fresh_end - fresh_size;
    while (tailed < file_end) {
        char buffer[64 * 1024];
        OVERLAPPED at{}; at.Offset = (DWORD)tailed; at.OffsetHigh = (DWORD)(tailed >> 32);
        DWORD want = (DWORD)std::min<uint64_t>(sizeof(buffer), file_end - tailed), got = 0;
        if (!ReadFile(s->log_reader, buffer, want, &got, &at) || !got) {
            tail_failed(s, win_error("replay probe log file to stdout")); return;
        }
        if (!write_all(s->stdout_handle, buffer, got)) { tail_write_failed(s, "tail probe logs to stdout"); return; }
        tailed += got;
    }
    if (tailed < fresh_end) {
        size_t skip = (size_t)(fresh_size - (fresh_end - tailed));
        if (!write_all(s->stdout_handle, fresh + skip, fresh_size - skip)) {
            tail_write_failed(s, "tail probe logs to stdout"); return;
        }
        tailed = fresh_end;
    }
    {
        std::lock_guard<std::mutex> lock(s->tail_mu);
        s->log_bytes_tailed = tailed;
    }
    s->tail_caught_up.notify_all();
}

enum { FWD_RUN = 0, FWD_DRAIN = 1, FWD_STOP = 2 };

// Write target bytes to the real stream. false: the stream is gone (the reader closed it).
static bool forward_emit(probe_session *s, probe_session::StdForward *f, const char *bytes, size_t size) {
    if (!size) return true;
    if (!f->to_stdout) {
        std::lock_guard<std::mutex> lock(f->mu);
        return write_all(f->dst, bytes, size);
    }
    bool ok;
    {
        std::lock_guard<std::mutex> out_lock(s->stdout_mu);
        std::fflush(stdout);                            // the driver's own complete lines first
        ok = write_all(f->dst, bytes, size);
        if (!ok) { DWORD e = GetLastError(); if (reader_gone(e)) tail_closed(s, e); }   // stdout's reader left
        s->out_midline = ok && bytes[size - 1] != '\n';
        if (ok) tail_catch_up_locked(s, nullptr, 0, 0);  // records that waited for this newline
    }
    { std::lock_guard<std::mutex> lock(s->tail_mu); }   // no lost wakeup for flush_log_writer
    s->tail_caught_up.notify_all();
    return ok;
}

static void forward_main(probe_session *s, probe_session::StdForward *f) {
    constexpr ULONGLONG PARTIAL_MS = 50;      // an unfinished line idle this long goes out as is
    constexpr ULONGLONG DRAIN_IDLE_MS = 100;  // after the target exited: quiet this long = drained
    constexpr ULONGLONG DRAIN_MAX_MS = 2000;  // ... or this long at most (a grandchild keeps writing)
    constexpr size_t PARTIAL_MAX = 64 * 1024; // a line this long (binary output) goes out unfinished
    OVERLAPPED ov{}; ov.hEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    std::vector<char> buffer(64 * 1024);
    std::string pending;
    bool reading = false, eof = false, dead = !ov.hEvent;
    ULONGLONG last = GetTickCount64(), drain_start = 0;
    bool drained = false;
    auto emit = [&](bool all) {
        if (pending.empty() || dead) return;
        size_t n = pending.size();
        if (!all) {
            size_t nl = pending.rfind('\n');
            if (nl == std::string::npos) { if (n < PARTIAL_MAX) return; }
            else n = nl + 1;
        }
        if (!forward_emit(s, f, pending.data(), n)) dead = true;
        pending.erase(0, n);
    };
    auto take = [&](DWORD got) { if (got) { pending.append(buffer.data(), got); last = GetTickCount64(); emit(false); } };
    while (!eof && !dead) {
        const int mode = f->mode.load();
        if (mode == FWD_STOP) break;
        if (mode == FWD_DRAIN && !drain_start) drain_start = GetTickCount64();
        if (!reading) {
            ResetEvent(ov.hEvent);
            if (ReadFile(f->pipe, buffer.data(), (DWORD)buffer.size(), nullptr, &ov) || GetLastError() == ERROR_IO_PENDING)
                reading = true;
            else { eof = true; break; }                 // every writer is gone (ERROR_BROKEN_PIPE)
        }
        ULONGLONG now = GetTickCount64(), idle = now - last;
        DWORD timeout = INFINITE;
        if (!pending.empty()) timeout = (DWORD)(idle >= PARTIAL_MS ? 0 : PARTIAL_MS - idle);
        if (drain_start && !drained) {
            ULONGLONG a = idle >= DRAIN_IDLE_MS ? 0 : DRAIN_IDLE_MS - idle;
            ULONGLONG b = now - drain_start >= DRAIN_MAX_MS ? 0 : DRAIN_MAX_MS - (now - drain_start);
            timeout = (DWORD)std::min<ULONGLONG>(timeout, std::min(a, b));
        }
        HANDLE waits[2] = {ov.hEvent, f->wake};
        DWORD w = WaitForMultipleObjects(2, waits, FALSE, timeout);
        if (w == WAIT_OBJECT_0) {
            DWORD got = 0;
            reading = false;
            if (GetOverlappedResult(f->pipe, &ov, &got, FALSE)) take(got);
            else if (GetLastError() == ERROR_MORE_DATA) take(got);
            else eof = true;
        }
        now = GetTickCount64();
        if (!pending.empty() && now - last >= PARTIAL_MS) emit(true);    // a prompt shows promptly
        if (drain_start && !drained &&
            ((pending.empty() && now - last >= DRAIN_IDLE_MS) || now - drain_start >= DRAIN_MAX_MS)) {
            emit(true); drained = true; SetEvent(f->drained);
        }
    }
    if (reading) {
        CancelIoEx(f->pipe, &ov);
        DWORD got = 0;
        if (GetOverlappedResult(f->pipe, &ov, &got, TRUE)) take(got);
    }
    emit(true);
    // The real stream is gone: close our end so the target's own writes fail as they would
    // have on the stream it was started with (and it never blocks on a full pipe).
    if (dead) { CloseHandle(f->pipe); f->pipe = INVALID_HANDLE_VALUE; }
    if (ov.hEvent) CloseHandle(ov.hEvent);
    SetEvent(f->drained);
}

// A pipe for the target's stdout/stderr: an overlapped server end we read, and an inheritable
// synchronous client end the target writes (GetFileType: FILE_TYPE_PIPE).
static bool make_forward_pipe(HANDLE &server, HANDLE &client) {
    static std::atomic<unsigned> counter{0};
    wchar_t name[96];
    std::swprintf(name, 96, L"\\\\.\\pipe\\uhh-stdio-%lu-%u-%llu", (unsigned long)GetCurrentProcessId(),
                  counter.fetch_add(1), (unsigned long long)GetTickCount64());
    server = CreateNamedPipeW(name, PIPE_ACCESS_INBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE,
                              PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                              1, 0, 64 * 1024, 0, nullptr);
    if (server == INVALID_HANDLE_VALUE) return false;
    SECURITY_ATTRIBUTES sa{sizeof(sa), nullptr, TRUE};
    client = CreateFileW(name, GENERIC_WRITE | FILE_READ_ATTRIBUTES, 0, &sa, OPEN_EXISTING, 0, nullptr);
    if (client == INVALID_HANDLE_VALUE) { CloseHandle(server); server = INVALID_HANDLE_VALUE; return false; }
    return true;
}

// Forward a stream only when it is a pipe or a file: there a line-based reader sees the
// target's bytes and the records interleaved. A console (or NUL) stays inherited: an
// interactive target keeps its console (GetConsoleMode, colours, line editing).
static bool forwardable(HANDLE h) {
    if (h == nullptr || h == INVALID_HANDLE_VALUE) return false;
    DWORD type = GetFileType(h);
    return type == FILE_TYPE_PIPE || type == FILE_TYPE_DISK;
}

static bool same_object(HANDLE a, HANDLE b) {
    if (a == b) return true;
    using compare_fn = BOOL(WINAPI *)(HANDLE, HANDLE);
    static compare_fn compare = (compare_fn)(void *)GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "CompareObjectHandles");
    return compare && compare(a, b);
}

// Start a forwarder thread for an already-created pipe.
static bool forward_start(probe_session *s, probe_session::StdForward *f) {
    if (f->pipe == INVALID_HANDLE_VALUE) return true;
    f->wake = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    f->drained = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!f->wake || !f->drained) return false;
    try { f->thread = std::thread(forward_main, s, f); } catch (...) { return false; }
    return true;
}

// The target is gone: let the forwarders pass on what it wrote (until end of file, or a short
// quiet spell when a grandchild still holds the pipe), then let the records that waited
// behind an unfinished last line out -- on a line of their own.
static void forward_finish(probe_session *s) {
    if (s->fwd_finished) return;
    s->fwd_finished = true;
    for (auto *f : {&s->fwd_out, &s->fwd_err})
        if (f->thread.joinable()) { f->mode = FWD_DRAIN; SetEvent(f->wake); }
    for (auto *f : {&s->fwd_out, &s->fwd_err})
        if (f->thread.joinable()) WaitForSingleObject(f->drained, 5000);
    if (!s->fwd_out_active) return;
    std::lock_guard<std::mutex> out_lock(s->stdout_mu);
    bool behind;
    {
        std::lock_guard<std::mutex> lock(s->tail_mu);
        behind = s->log_bytes_tailed < s->log_bytes_written && !s->tail_failed;
    }
    if (s->out_midline && behind) {
        std::fflush(stdout);
        if (write_all(s->stdout_handle, "\n", 1)) s->out_midline = false;
        else tail_write_failed(s, "tail probe logs to stdout");
    }
    tail_catch_up_locked(s, nullptr, 0, 0);
}

static void forward_stop(probe_session *s) {
    for (auto *f : {&s->fwd_out, &s->fwd_err}) {
        if (f->thread.joinable()) { f->mode = FWD_STOP; SetEvent(f->wake); f->thread.join(); }
        if (f->pipe != INVALID_HANDLE_VALUE) CloseHandle(f->pipe);
        if (f->wake) CloseHandle(f->wake);
        if (f->drained) CloseHandle(f->drained);
        f->pipe = INVALID_HANDLE_VALUE; f->wake = f->drained = nullptr;
    }
}

static void log_tailer_main(probe_session *s) {
    constexpr size_t CHUNK_BYTES = 64 * 1024;
    std::string pending;
    uint64_t file_bytes_read = 0;
    auto behind_since = std::chrono::steady_clock::time_point{};
    try {
        for (;;) {
            uint64_t published = 0;
            {
                std::unique_lock<std::mutex> lock(s->tail_mu);
                s->tail_changed.wait(lock, [s, file_bytes_read] {
                    return s->tail_stop || s->tail_failed || s->log_bytes_written > file_bytes_read;
                });
                if (s->tail_failed) return;
                published = s->log_bytes_written;
                if (s->tail_stop && published == file_bytes_read && pending.empty()) break;
            }
            if (published > file_bytes_read && behind_since == std::chrono::steady_clock::time_point{})
                behind_since = std::chrono::steady_clock::now();

            while (file_bytes_read < published) {
                char buffer[CHUNK_BYTES];
                DWORD want = (DWORD)std::min<uint64_t>(sizeof(buffer), published - file_bytes_read);
                DWORD got = 0;
                if (!ReadFile(s->log_reader, buffer, want, &got, nullptr)) {
                    tail_failed(s, win_error("read probe log file")); return;
                }
                if (!got) { Sleep(1); continue; }       // published only after WriteFile; defensive for cache lag
                pending.append(buffer, got);
                file_bytes_read += got;

                for (;;) {
                    size_t limit = std::min(pending.size(), CHUNK_BYTES);
                    size_t newline = limit ? pending.rfind('\n', limit - 1) : std::string::npos;
                    if (newline == std::string::npos) {
                        newline = pending.find('\n');
                        if (newline == std::string::npos) break;
                    }
                    size_t chunk = newline + 1;          // every raw stdout write ends on a line boundary
                    if (!write_stdout_chunk(s, pending.data(), chunk)) return;
                    pending.erase(0, chunk);
                    {
                        std::lock_guard<std::mutex> lock(s->tail_mu);
                        s->log_bytes_tailed += chunk;
                    }
                    s->tail_caught_up.notify_all();
                }
            }

            uint64_t written = 0, tailed = 0;
            {
                std::lock_guard<std::mutex> lock(s->tail_mu);
                written = s->log_bytes_written; tailed = s->log_bytes_tailed;
            }
            if (written == tailed) behind_since = {};
            else if (s->stdout_is_console && behind_since != std::chrono::steady_clock::time_point{} &&
                     std::chrono::steady_clock::now() - behind_since >= std::chrono::seconds(1))
                warn_console_once(s);
        }
    } catch (const std::exception &e) {
        tail_failed(s, std::string("probe log tailer failed: ") + e.what());
    } catch (...) {
        tail_failed(s, "probe log tailer failed");
    }
}

static std::string utf8_path(const std::wstring &path) {
    if (path.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, path.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::vector<char> bytes((size_t)n);
    return WideCharToMultiByte(CP_UTF8, 0, path.c_str(), -1, bytes.data(), n, nullptr, nullptr)
               ? std::string(bytes.data()) : std::string{};
}

static bool make_directory(const std::wstring &path) {
    return CreateDirectoryW(path.c_str(), nullptr) || GetLastError() == ERROR_ALREADY_EXISTS;
}

static bool start_log_output(probe_session *s) {
    wchar_t temp[MAX_PATH];
    DWORD n = GetTempPathW(MAX_PATH, temp);
    if (!n || n >= MAX_PATH - 64) { set_error(s, win_error("find temporary log directory")); return false; }
    std::wstring root = std::wstring(temp, n) + L"uhh";
    std::wstring directory = root + L"\\logs";
    if (!make_directory(root) || !make_directory(directory)) {
        set_error(s, win_error("create temporary log directory")); return false;
    }

    static std::atomic<unsigned> counter{0};
    for (unsigned attempts = 0; attempts < 1000; ++attempts) {
        unsigned id = counter.fetch_add(1, std::memory_order_relaxed);
        s->log_path = directory + L"\\uhh-" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                      std::to_wstring(id) + L".jsonl";
        s->log_file = CreateFileW(s->log_path.c_str(), GENERIC_WRITE,
                                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                  nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (s->log_file != INVALID_HANDLE_VALUE) break;
        if (GetLastError() != ERROR_FILE_EXISTS && GetLastError() != ERROR_ALREADY_EXISTS) break;
    }
    if (s->log_file == INVALID_HANDLE_VALUE) { set_error(s, win_error("create probe log file")); return false; }

    s->stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    bool stdout_valid = s->stdout_handle != nullptr && s->stdout_handle != INVALID_HANDLE_VALUE;
    s->stdout_type = stdout_valid ? GetFileType(s->stdout_handle) : FILE_TYPE_UNKNOWN;
    DWORD console_mode = 0;
    s->stdout_is_console = s->stdout_type == FILE_TYPE_CHAR &&
                           GetConsoleMode(s->stdout_handle, &console_mode) != FALSE;
    // NUL is a character device but not a console. It is the no-new-API opt-out: keep
    // the complete file and avoid spending a thread copying bytes into the null device.
    s->tail_enabled = stdout_valid &&
                      !(s->stdout_type == FILE_TYPE_CHAR && !s->stdout_is_console);
    if (s->fwd_out_active && !s->tail_enabled) s->fwd_out_active = false;
    if (s->fwd_out_active) {   // records deferred behind an unfinished target line are replayed from the file
        s->log_reader = CreateFileW(s->log_path.c_str(), GENERIC_READ,
                                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                    nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (s->log_reader == INVALID_HANDLE_VALUE) {
            set_error(s, win_error("open probe log tail")); CloseHandle(s->log_file);
            s->log_file = INVALID_HANDLE_VALUE; return false;
        }
    }

    try {
        s->log_writer = std::thread(log_writer_main, s);
        (void)log_tailer_main;               // kept for reference; the writer writes stdout directly
    } catch (...) {
        {
            std::lock_guard<std::mutex> lock(s->queue_mu); s->writer_stop = true;
        }
        s->queue_readable.notify_one();
        if (s->log_writer.joinable()) s->log_writer.join();
        if (s->log_reader != INVALID_HANDLE_VALUE) { CloseHandle(s->log_reader); s->log_reader = INVALID_HANDLE_VALUE; }
        CloseHandle(s->log_file); s->log_file = INVALID_HANDLE_VALUE;
        set_error(s, "probe log thread creation failed"); return false;
    }
    std::string shown = utf8_path(s->log_path);
    std::fprintf(stderr, "probe: logs -> %s\n", shown.empty() ? "(unprintable path)" : shown.c_str());
    std::fflush(stderr);
    return true;
}

static bool enqueue_log(probe_session *s, LogRecord &&record) {
    std::unique_lock<std::mutex> lock(s->queue_mu);
    bool blocked = s->log_queue.size() >= probe_session::LOG_QUEUE_CAP && !s->writer_failed;
    auto blocked_at = std::chrono::steady_clock::now();
    s->queue_writable.wait(lock, [s] {
        return s->log_queue.size() < probe_session::LOG_QUEUE_CAP || s->writer_failed;
    });
    if (s->writer_failed) {
        s->controller_dropped.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    bool warned = blocked && std::chrono::steady_clock::now() - blocked_at >= std::chrono::seconds(1);
    try { s->log_queue.push_back(std::move(record)); }
    catch (...) {
        s->controller_dropped.fetch_add(1, std::memory_order_relaxed);
        return false;
    }
    lock.unlock();
    if (warned) warn_console_once(s);
    s->queue_readable.notify_one();
    return true;
}

static void flush_log_writer(probe_session *s) {
    if (s->log_file == INVALID_HANDLE_VALUE) return;
    std::string error;
    {
        std::unique_lock<std::mutex> lock(s->queue_mu);
        s->queue_flushed.wait(lock, [s] {
            return (s->log_queue.empty() && !s->writer_busy) || s->writer_failed;
        });
        error = s->writer_error;
    }
    if (!error.empty()) set_error(s, error);
    if (s->exited) forward_finish(s);          // the target's last bytes, then the waiting records

    std::string tail_error;
    if (s->tail_enabled) {
        std::unique_lock<std::mutex> lock(s->tail_mu);
        uint64_t target = s->log_bytes_written;
        // While the (running) target is inside a line, records wait for its newline.
        s->tail_caught_up.wait(lock, [s, target] {
            return s->log_bytes_tailed >= target || s->tail_failed || s->out_midline.load();
        });
        tail_error = s->tail_error;
    }
    if (!tail_error.empty()) set_error(s, tail_error);
}

// A module unloaded. Stack frames are captured as raw addresses at the hit and symbolized
// later on the writer thread, so records captured BEFORE the unload may still be queued (or,
// inline, in the agent's ring): dbghelp keeps the module until the writer has passed them.
// The unregister travels through the log queue, behind those records.
static size_t drain_agent_logs(probe_session *s);
static void sym_unload(probe_session *s, uint64_t base) {
    if (!s->sym_ready) return;
    auto sz = s->module_sizes.find(base);
    const uint64_t size = sz != s->module_sizes.end() ? sz->second : 1;
    if (s->log_writer.joinable()) {
        drain_agent_logs(s);                               // inline records captured before the unload
        std::unique_lock<std::mutex> lock(s->queue_mu);
        s->queue_writable.wait(lock, [s] {
            return s->log_queue.size() < probe_session::LOG_QUEUE_CAP || s->writer_failed;
        });
        if (!s->writer_failed) {
            try {
                LogRecord r; r.sym_unload = base; r.sym_size = size;
                s->sym_pending.push_back({base, size});
                s->log_queue.push_back(std::move(r));
                lock.unlock();
                s->queue_readable.notify_one();
                return;
            } catch (...) {
                if (!s->sym_pending.empty() && s->sym_pending.back().first == base) s->sym_pending.pop_back();
            }
        }
    }
    uhh_sym::unregister_module(s->pi.hProcess, base);
}
// Before registering a module over [base, base+size): wait until the writer has unregistered
// any unloaded module still held for older records in that range.
static void wait_sym_unloads(probe_session *s, uint64_t base, uint64_t size) {
    std::unique_lock<std::mutex> lock(s->queue_mu);
    s->queue_flushed.wait(lock, [&] {
        if (s->writer_failed) return true;
        for (auto &p : s->sym_pending)
            if (p.first < base + size && base < p.first + p.second) return false;
        return true;
    });
}

static void stop_log_output(probe_session *s) {
    if (s->log_writer.joinable()) {
        {
            std::lock_guard<std::mutex> lock(s->queue_mu); s->writer_stop = true;
        }
        s->queue_readable.notify_one();
        s->log_writer.join();
        flush_log_writer(s);
    }
    if (s->log_tailer.joinable()) {
        {
            std::lock_guard<std::mutex> lock(s->tail_mu); s->tail_stop = true;
        }
        s->tail_changed.notify_one();
        s->log_tailer.join();
    }
    forward_finish(s);                          // the session ends: whatever the target left
    forward_stop(s);
    if (!s->writer_error.empty()) set_error(s, s->writer_error);
    if (!s->tail_error.empty()) set_error(s, s->tail_error);
    if (s->log_reader != INVALID_HANDLE_VALUE) CloseHandle(s->log_reader);
    if (s->log_file != INVALID_HANDLE_VALUE) CloseHandle(s->log_file);
    s->log_reader = s->log_file = INVALID_HANDLE_VALUE;
}

static std::string basename_of(std::string path) {
    size_t p = path.find_last_of("\\/");
    return p == std::string::npos ? path : path.substr(p + 1);
}

static std::string module_name_from_handle(HANDLE file) {
    if (!file) return {};
    char path[MAX_PATH];
    DWORD n = GetFinalPathNameByHandleA(file, path, MAX_PATH, FILE_NAME_NORMALIZED);
    return n && n < MAX_PATH ? basename_of(path) : std::string{};
}

static std::string module_path_from_handle(HANDLE file) {
    if (!file) return {};
    char path[MAX_PATH];
    DWORD n = GetFinalPathNameByHandleA(file, path, MAX_PATH, FILE_NAME_NORMALIZED);
    if (!n || n >= MAX_PATH) return {};
    std::string r(path);
    if (r.rfind("\\\\?\\", 0) == 0) r = r.substr(4);
    return r;
}

// SizeOfImage of the image mapped at base in the target (0 if unreadable).
static uint32_t remote_image_size(HANDLE process, uint64_t base) {
    size_t got = 0;
    IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS nt{};
    if (remote_read(process, base, &dos, sizeof(dos), &got) && got == sizeof(dos) && dos.e_magic == IMAGE_DOS_SIGNATURE &&
        remote_read(process, base + (uint32_t)dos.e_lfanew, &nt, sizeof(nt), &got) && got == sizeof(nt) &&
        nt.Signature == IMAGE_NT_SIGNATURE)
        return nt.OptionalHeader.SizeOfImage;
    return 0;
}

static void wait_sym_unloads(probe_session *s, uint64_t base, uint64_t size);
// Register a mapped image with dbghelp (deferred: no symbol I/O until the writer sees
// a stack frame). Keeps working after the target exits: it reads files.
static void sym_register(probe_session *s, HANDLE file, uint64_t base) {
    const uint32_t size = remote_image_size(s->pi.hProcess, base);
    if (size) s->module_sizes[base] = size;
    std::string path = module_path_from_handle(file);
    if (path.empty()) return;
    s->module_paths[basename_of(path)] = path;
    if (!s->sym_ready) return;
    // Pass the real SizeOfImage: with deferred loads dbghelp does not read the image yet,
    // so a size of 0 registers only the base address and no frame inside it resolves.
    // A module that unloaded from this range may still be registered for log records
    // captured before its unload (see sym_unload): those are written first.
    wait_sym_unloads(s, base, size ? size : 1);
    // dbghelp gets the exact (wide) path, so non-ASCII directories work.
    std::wstring wpath;
    {
        wchar_t w[1024];
        DWORD n = GetFinalPathNameByHandleW(file, w, 1024, FILE_NAME_NORMALIZED);
        if (n && n < 1024) {
            wpath.assign(w, n);
            if (wpath.size() > 4 && wpath.compare(0, 4, L"\\\\?\\") == 0) wpath = wpath.substr(4);
        }
    }
    if (!wpath.empty()) uhh_sym::register_module(s->pi.hProcess, wpath, base, size);
}

static std::string module_name_from_module(HMODULE module) {
    char path[MAX_PATH]; DWORD n = GetModuleFileNameA(module, path, MAX_PATH);
    return n && n < MAX_PATH ? basename_of(path) : std::string{};
}

static bool iequals(const std::string &a, const std::string &b) {
    return a.size() == b.size() && !_stricmp(a.c_str(), b.c_str());
}

static bool has_inline(const probe_session *s) {
    for (const auto &p : s->probes) if (p->flags & PROBE_INLINE) return true;
    return false;
}
// The agent goes into every ATTACHED target: besides inline hooks it is the controller-death
// guard (probe_agent_shared.hpp). Breakpoint/hw probes of an attach arm once it is up, so a
// controller that dies at any point never leaves an unguarded trap behind.
static bool guard_pending(const probe_session *s) { return s->attached && s->shared && !s->guard_ready; }
static bool needs_agent(const probe_session *s) { return has_inline(s) || (s->attached && s->shared); }

// ---- UHH_SHARED: one callbacks DLL file, loaded by controller and target ---------------
static bool image_has_section(const unsigned char *base, const char *name) {
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        if (!strncmp(reinterpret_cast<const char *>(sec[i].Name), name, 8)) return true;
    return false;
}

static bool module_of(const void *address, HMODULE &m) {
    return GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                              reinterpret_cast<LPCSTR>(address), &m) != 0;
}

// A forwarded export (kernel32!HeapAlloc -> ntdll!RtlAllocateHeap, or into an API set):
// follow it the way the loader does, through THIS process's copy of the same system DLL
// (controller and target are the same bitness, so they load the same files), then map the
// final function onto the target's module of the same name. 0 = not resolvable.
// Where a forwarded export finally lands: module name + RVA, via this process's copy of
// the same system DLL (same bitness as the target, so the same files).
static bool forwarded_export_owner(const std::string &module, const std::string &name,
                                   std::string &owner_name, uint64_t &owner_rva) {
    HMODULE m = GetModuleHandleA(module.c_str());
    if (!m) m = LoadLibraryExA(module.c_str(), nullptr, LOAD_LIBRARY_SEARCH_SYSTEM32);
    FARPROC f = m ? GetProcAddress(m, name.c_str()) : nullptr;
    HMODULE owner{};
    if (!f || !module_of(reinterpret_cast<const void *>(f), owner)) return false;
    owner_name = module_name_from_module(owner);
    owner_rva = (uint64_t)((uintptr_t)f - (uintptr_t)owner);
    return !owner_name.empty();
}

static uint64_t forwarded_export_target(probe_session *s, const std::string &module, const std::string &name) {
    std::string owner_name; uint64_t rva = 0;
    if (!forwarded_export_owner(module, name, owner_name, rva)) return 0;
    for (auto &kv : s->module_bases)
        if (iequals(kv.first, owner_name)) return kv.second + rva;
    return 0;
}

static std::wstring sibling_agent_path() {
    wchar_t path[MAX_PATH]; DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (!n || n >= MAX_PATH) return L"probe_api_agent.dll";
    std::wstring result(path, n); size_t slash = result.find_last_of(L"\\/");
    result.resize(slash == std::wstring::npos ? 0 : slash + 1);
    return result + L"probe_api_agent.dll";
}

const probe_controller_api *controller_api_table();

static bool file_has_section(const std::wstring &path, const char *name) {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    std::vector<unsigned char> head(8192); DWORD got = 0;
    BOOL ok = ReadFile(f, head.data(), (DWORD)head.size(), &got, nullptr);
    CloseHandle(f);
    if (!ok || got < 1024) return false;
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(head.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || (DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > got) return false;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(head.data() + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    if ((const unsigned char *)(sec + nt->FileHeader.NumberOfSections) > head.data() + got) return false;
    return image_has_section(head.data(), name);
}

// The agent DLL this session loads into BOTH processes. If it carries UHH_SHARED state,
// every session gets its own copy of the file (a shared section is shared by everyone who
// maps the same file): %TEMP%\uhh\<pid>-<n>\probe_api_agent.dll, deleted at close; stale
// copies of dead sessions are swept here.
static bool ensure_local_agent(probe_session *s) {
    if (s->local_agent) return true;
    if (s->agent_path.empty()) {
        s->agent_path = sibling_agent_path();
        if (file_has_section(s->agent_path, "uhhshr")) {
            wchar_t tmp[MAX_PATH]; DWORD n = GetTempPathW(MAX_PATH, tmp);
            if (n && n < MAX_PATH - 64) {
                std::wstring root = std::wstring(tmp) + L"uhh";
                CreateDirectoryW(root.c_str(), nullptr);
                WIN32_FIND_DATAW fd{}; HANDLE h = FindFirstFileW((root + L"\\*").c_str(), &fd);   // sweep
                if (h != INVALID_HANDLE_VALUE) {
                    do {
                        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] == L'.') continue;
                        // Only copies of DEAD controllers: a live session may have just made its
                        // copy and not loaded it yet (it would look unused). Name: <pid>-<tick>-<n>.
                        const DWORD owner = (DWORD)wcstoul(fd.cFileName, nullptr, 10);
                        if (owner) {
                            HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, owner);
                            DWORD code = 0;
                            const bool alive = ph && GetExitCodeProcess(ph, &code) && code == STILL_ACTIVE;
                            if (ph) CloseHandle(ph);
                            if (alive) continue;
                        }
                        std::wstring d = root + L"\\" + fd.cFileName;
                        if (DeleteFileW((d + L"\\probe_api_agent.dll").c_str()) || GetLastError() == ERROR_FILE_NOT_FOUND)
                            RemoveDirectoryW(d.c_str());          // in use by a live session: left alone
                    } while (FindNextFileW(h, &fd));
                    FindClose(h);
                }
                static std::atomic<unsigned> counter{0};
                std::wstring dir = root + L"\\" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                                   std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(counter++);
                std::wstring copy = dir + L"\\probe_api_agent.dll";
                if (CreateDirectoryW(dir.c_str(), nullptr) && CopyFileW(s->agent_path.c_str(), copy.c_str(), TRUE)) {
                    s->agent_path = copy; s->agent_copy = copy;
                } else {
                    std::fprintf(stderr, "probe: warning: could not make a per-session copy of the agent DLL; "
                                         "UHH_SHARED state is shared with other sessions using the same file\n");
                }
            }
        }
    }
    s->local_agent = LoadLibraryW(s->agent_path.c_str());
    if (!s->local_agent || !GetProcAddress(s->local_agent, "probe_agent_init")) {
        set_error(s, win_error("map probe_api_agent.dll exports")); return false;
    }
    // Callbacks this process runs from its copy of the agent DLL must reach THIS library.
    using bind_fn = void (*)(const probe_controller_api *);
    if (auto bind = reinterpret_cast<bind_fn>(GetProcAddress(s->local_agent, "probe_agent_bind_controller")))
        bind(controller_api_table());
    return true;
}

// A breakpoint/hw callback whose module uses UHH_SHARED runs from the controller's copy of
// the agent DLL (found by export name), so it shares those globals with inline callbacks.
static bool bind_shared_callback(probe_session *s, probe_callback &cb, uint32_t flags) {
    if (flags & PROBE_INLINE) return true;                   // runs in the target's copy anyway
    HMODULE m{};
    if (!module_of(reinterpret_cast<const void *>(cb), m) || m == s->local_agent ||
        !image_has_section(reinterpret_cast<const unsigned char *>(m), "uhhshr")) return true;
    std::string name;
    if (!callback_export_name(cb, name)) {
        set_error(s, "callback uses UHH_SHARED state but is not a named export (the controller runs it from the agent DLL)");
        return false;
    }
    if (!ensure_local_agent(s)) return false;
    auto shared_cb = reinterpret_cast<probe_callback>(GetProcAddress(s->local_agent, name.c_str()));
    if (!shared_cb) { set_error(s, "UHH_SHARED callback '" + name + "' is not exported by the agent DLL"); return false; }
    cb = shared_cb;
    return true;
}

static bool patch(HANDLE process, uint64_t address, unsigned char byte) {
    DWORD old{}, ignored{}; SIZE_T done{};
    if (!VirtualProtectEx(process, (void *)(uintptr_t)address, 1, PAGE_EXECUTE_READWRITE, &old)) return false;
    BOOL wrote = WriteProcessMemory(process, (void *)(uintptr_t)address, &byte, 1, &done);
    BOOL flushed = FlushInstructionCache(process, (void *)(uintptr_t)address, 1);
    BOOL restored = VirtualProtectEx(process, (void *)(uintptr_t)address, 1, old, &ignored);
    return wrote && done == 1 && flushed && restored;
}

// Put a breakpoint probe's original byte back -- only if our INT3 is still there. Another
// hooking tool may have rewritten the site since (e.g. Frida/Detours writing their jump over
// it): restoring our byte then would corrupt THEIR hook.
static void restore_original(HANDLE process, uint64_t address, unsigned char original) {
    unsigned char now = 0; SIZE_T got = 0;
    if (ReadProcessMemory(process, (void *)(uintptr_t)address, &now, 1, &got) && got == 1 && now == 0xcc)
        patch(process, address, original);
}

// Re-arm our INT3 after an in-place step -- only if the site still holds the byte we lifted.
// Anything else means another hooking tool wrote there meanwhile: leave its bytes alone.
static bool rearm_breakpoint(HANDLE process, uint64_t address, unsigned char original) {
    unsigned char now = 0; SIZE_T got = 0;
    if (!ReadProcessMemory(process, (void *)(uintptr_t)address, &now, 1, &got) || got != 1) return false;
    if (now == 0xcc) return true;                         // already armed
    return now == original && patch(process, address, 0xcc);
}

static bool parse_hex(const char *number, uint64_t &out) {
    if (!number || !*number) return false;
    for (const char *d = number; *d; ++d) if (!std::isxdigit((unsigned char)*d)) return false;
    errno = 0; char *end = nullptr;
    unsigned long long v = std::strtoull(number, &end, 16);
    if (errno == ERANGE || !end || *end) return false;
    out = (uint64_t)v; return true;
}

// THE module grammar, shared by probe locations (every backend, launch/attach/runtime adds,
// uhh_trace -p) and call_func (breakpoint/hw here; inline in agent.cpp agent_module, whose
// GetModuleHandleA reads names the same way): the module is matched by its FILE NAME, case-
// insensitively (a directory part is ignored), and a name without an extension means
// "<name>.dll", as LoadLibrary/GetModuleHandle read it: "kernel32" == "kernel32.dll", and
// "probe_app" names probe_app.dll -- never probe_app.exe (an EXE is named with its ".exe").
// A trailing dot means "no extension" ("foo." == the file "foo"). Empty = no module named.
static std::string module_of_location(const std::string &text, bool *bare = nullptr) {
    std::string m = basename_of(text);
    if (bare) *bare = false;
    if (m.empty() || m == ".") return {};
    if (m.back() == '.') { m.pop_back(); return m; }
    if (m.find('.') != std::string::npos) return m;
    if (bare) *bare = true;
    return m + ".dll";
}

// "module+0xRVA" or "module!Export[+0xOFF]" (module: see module_of_location).
static bool parse_location(probe_session *s, const char *text, Probe &p) {
    if (!text || !*text) { set_error(s, "empty probe location"); return false; }
    p.location = text;
    size_t bang = p.location.find('!');
    if (bang != std::string::npos) {
        p.module = module_of_location(p.location.substr(0, bang), &p.bare_module);
        if (p.module.empty()) { set_error(s, "symbol location has an empty module"); return false; }
        std::string rest = p.location.substr(bang + 1);
        size_t plus = rest.find('+');
        p.export_name = rest.substr(0, plus);
        if (p.export_name.empty()) { set_error(s, "symbol location has an empty export name"); return false; }
        if (plus != std::string::npos) {
            std::string off = rest.substr(plus + 1);
            if (off.size() < 3 || off[0] != '0' || (off[1] != 'x' && off[1] != 'X') ||
                !parse_hex(off.c_str() + 2, p.sym_offset)) {
                set_error(s, "symbol offset must be +0xHEX"); return false;
            }
        }
        return true;
    }
    size_t plus = p.location.rfind('+');
    if (!plus || plus == std::string::npos || plus + 3 > p.location.size() ||
        p.location[plus + 1] != '0' || (p.location[plus + 2] != 'x' && p.location[plus + 2] != 'X')) {
        set_error(s, "location must be module+0xRVA or module!Export[+0xOFF]"); return false;
    }
    p.module = module_of_location(p.location.substr(0, plus), &p.bare_module);
    if (p.module.empty()) { set_error(s, "location has an empty module"); return false; }
    if (!parse_hex(p.location.c_str() + plus + 3, p.rva)) { set_error(s, "location has an invalid RVA"); return false; }
    return true;
}

// Resolve an export by name from the TARGET's image (read remotely; works before the
// module has run any code). Forwarded exports are rejected: hook the forward target.
static bool resolve_export(probe_session *s, uint64_t base, const std::string &name, uint64_t &rva) {
    HANDLE h = s->pi.hProcess; size_t got = 0;
    IMAGE_DOS_HEADER dos{};
    if (!remote_read(h, base, &dos, sizeof(dos), &got) || got != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) {
        set_error(s, "export lookup: bad DOS header"); return false;
    }
    IMAGE_NT_HEADERS nt{};
    if (!remote_read(h, base + (uint32_t)dos.e_lfanew, &nt, sizeof(nt), &got) || got != sizeof(nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
        set_error(s, "export lookup: bad NT headers"); return false;
    }
    auto dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir.VirtualAddress || !dir.Size) { set_error(s, "export lookup: module has no exports"); return false; }
    // Every size below comes from the (possibly hostile) target image: bound them all.
    if (dir.Size < sizeof(IMAGE_EXPORT_DIRECTORY) || dir.Size > (64u << 20)) {
        set_error(s, "export lookup: implausible export directory size"); return false;
    }
    std::vector<unsigned char> blob(dir.Size);
    if (!remote_read(h, base + dir.VirtualAddress, blob.data(), blob.size(), &got) || got != blob.size()) {
        set_error(s, "export lookup: cannot read export directory"); return false;
    }
    auto in_dir = [&](uint32_t r, size_t n) { return r >= dir.VirtualAddress && r - dir.VirtualAddress + n <= dir.Size; };
    auto ex = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(blob.data());
    if (ex->NumberOfNames > (1u << 20) || ex->NumberOfFunctions > (1u << 20)) {
        set_error(s, "export lookup: implausible export counts"); return false;
    }
    // The name/function tables may live outside the directory range: read them separately.
    std::vector<DWORD> names(ex->NumberOfNames), funcs(ex->NumberOfFunctions);
    std::vector<WORD> ords(ex->NumberOfNames);
    if ((!names.empty() && (!remote_read(h, base + ex->AddressOfNames, names.data(), names.size() * 4, &got) || got != names.size() * 4)) ||
        (!ords.empty() && (!remote_read(h, base + ex->AddressOfNameOrdinals, ords.data(), ords.size() * 2, &got) || got != ords.size() * 2)) ||
        (!funcs.empty() && (!remote_read(h, base + ex->AddressOfFunctions, funcs.data(), funcs.size() * 4, &got) || got != funcs.size() * 4))) {
        set_error(s, "export lookup: cannot read export tables"); return false;
    }
    char buf[256];
    for (size_t i = 0; i < names.size(); ++i) {
        size_t n = 0;
        if (in_dir(names[i], 1)) {
            const char *str = reinterpret_cast<const char *>(blob.data() + (names[i] - dir.VirtualAddress));
            size_t lim = dir.Size - (names[i] - dir.VirtualAddress);
            n = strnlen(str, lim); if (n >= sizeof(buf)) continue; std::memcpy(buf, str, n);
        } else {
            if (!remote_read(h, base + names[i], buf, sizeof(buf) - 1, &got) || !got) continue;
            n = strnlen(buf, got);
        }
        buf[n] = 0;
        if (name != buf) continue;
        if (ords[i] >= funcs.size()) break;
        uint32_t f = funcs[ords[i]];
        if (in_dir(f, 0)) { set_error(s, "export '" + name + "' is forwarded; probe the forward target"); return false; }
        rva = f; return true;
    }
    set_error(s, "export '" + name + "' not found"); return false;
}

static std::string quote_arg(const char *arg) {
    std::string in = arg ? arg : "";
    if (!in.empty() && in.find_first_of(" \t\n\v\"") == std::string::npos) return in;
    std::string out = "\""; size_t slashes = 0;
    for (char ch : in) {
        if (ch == '\\') { ++slashes; continue; }
        if (ch == '\"') out.append(slashes * 2 + 1, '\\');
        else out.append(slashes, '\\');
        slashes = 0; out += ch;
    }
    out.append(slashes * 2, '\\'); out += '\"'; return out;
}

// ---- Emulated sites ---------------------------------------------------------------------
// Instructions that cannot run out-of-line (relative/indirect branches, call, ret, loop,
// pushf/popf) used to be stepped IN PLACE: the INT3 was lifted for the step, so another
// thread could cross the site unseen (inexact), and TF leaked into a pushf'd flags image
// (RtlCaptureContext starts with pushfq). They are now executed by the controller on the
// stopped thread's context: the INT3 never leaves, no single-step, no trap flag. Anything
// not understood here (or a memory access that fails, which must fault for real) still
// takes the in-place path.
#if defined(_WIN64)
#define EMU_IP(c) (c).Rip
#define EMU_SP(c) (c).Rsp
#define EMU_CX(c) (c).Rcx
#else
#define EMU_IP(c) (c).Eip
#define EMU_SP(c) (c).Esp
#define EMU_CX(c) (c).Ecx
#endif
static bool emu_reg(const CONTEXT &c, ZydisRegister r, uint64_t next_ip, uint64_t &v) {
    if (r == ZYDIS_REGISTER_NONE) { v = 0; return true; }
    if (r == ZYDIS_REGISTER_RIP || r == ZYDIS_REGISTER_EIP) { v = next_ip; return true; }
    ZydisRegister full = ZydisRegisterGetLargestEnclosing(
#if defined(_WIN64)
        ZYDIS_MACHINE_MODE_LONG_64,
#else
        ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
#endif
        r);
    uint64_t x;
    switch (full) {
#if defined(_WIN64)
        case ZYDIS_REGISTER_RAX: x = c.Rax; break; case ZYDIS_REGISTER_RCX: x = c.Rcx; break;
        case ZYDIS_REGISTER_RDX: x = c.Rdx; break; case ZYDIS_REGISTER_RBX: x = c.Rbx; break;
        case ZYDIS_REGISTER_RSP: x = c.Rsp; break; case ZYDIS_REGISTER_RBP: x = c.Rbp; break;
        case ZYDIS_REGISTER_RSI: x = c.Rsi; break; case ZYDIS_REGISTER_RDI: x = c.Rdi; break;
        case ZYDIS_REGISTER_R8:  x = c.R8;  break; case ZYDIS_REGISTER_R9:  x = c.R9;  break;
        case ZYDIS_REGISTER_R10: x = c.R10; break; case ZYDIS_REGISTER_R11: x = c.R11; break;
        case ZYDIS_REGISTER_R12: x = c.R12; break; case ZYDIS_REGISTER_R13: x = c.R13; break;
        case ZYDIS_REGISTER_R14: x = c.R14; break; case ZYDIS_REGISTER_R15: x = c.R15; break;
#else
        case ZYDIS_REGISTER_EAX: x = c.Eax; break; case ZYDIS_REGISTER_ECX: x = c.Ecx; break;
        case ZYDIS_REGISTER_EDX: x = c.Edx; break; case ZYDIS_REGISTER_EBX: x = c.Ebx; break;
        case ZYDIS_REGISTER_ESP: x = c.Esp; break; case ZYDIS_REGISTER_EBP: x = c.Ebp; break;
        case ZYDIS_REGISTER_ESI: x = c.Esi; break; case ZYDIS_REGISTER_EDI: x = c.Edi; break;
#endif
        default: return false;
    }
    const ZyanU16 width = ZydisRegisterGetWidth(
#if defined(_WIN64)
        ZYDIS_MACHINE_MODE_LONG_64,
#else
        ZYDIS_MACHINE_MODE_LONG_COMPAT_32,
#endif
        r);
    if (width == 64) v = x;
    else if (width == 32) v = (uint32_t)x;
    else return false;                                   // 16/8-bit addressing: not emulated
    return true;
}

static bool emu_cond(ZydisMnemonic m, DWORD f) {
    const bool cf = f & 0x1, pf = f & 0x4, zf = f & 0x40, sf = f & 0x80, of = f & 0x800;
    switch (m) {
        case ZYDIS_MNEMONIC_JO: return of;           case ZYDIS_MNEMONIC_JNO: return !of;
        case ZYDIS_MNEMONIC_JB: return cf;           case ZYDIS_MNEMONIC_JNB: return !cf;
        case ZYDIS_MNEMONIC_JZ: return zf;           case ZYDIS_MNEMONIC_JNZ: return !zf;
        case ZYDIS_MNEMONIC_JBE: return cf || zf;    case ZYDIS_MNEMONIC_JNBE: return !cf && !zf;
        case ZYDIS_MNEMONIC_JS: return sf;           case ZYDIS_MNEMONIC_JNS: return !sf;
        case ZYDIS_MNEMONIC_JP: return pf;           case ZYDIS_MNEMONIC_JNP: return !pf;
        case ZYDIS_MNEMONIC_JL: return sf != of;     case ZYDIS_MNEMONIC_JNL: return sf == of;
        case ZYDIS_MNEMONIC_JLE: return zf || sf != of; case ZYDIS_MNEMONIC_JNLE: return !zf && sf == of;
        default: return false;
    }
}

// Executes the instruction at `site` on `c`. Returns true when emulated (c updated,
// memory written); false = not handled, take the stepping path instead.
// Hardware-enforced shadow stacks (Intel CET, /CETCOMPAT): an emulated CALL/RET would move
// the normal stack but not the shadow stack, so the target would fault at its next real ret.
// Such targets get CALL/RET stepped by the CPU (in-place path) instead.
static bool target_has_shadow_stack(probe_session *s) {
    if (s->shadow_stack < 0) {
        s->shadow_stack = 0;
        PROCESS_MITIGATION_USER_SHADOW_STACK_POLICY pol{};
        using GetPolicyFn = BOOL(WINAPI *)(HANDLE, PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
        auto get = reinterpret_cast<GetPolicyFn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetProcessMitigationPolicy"));
        if (get && s->pi.hProcess && get(s->pi.hProcess, ProcessUserShadowStackPolicy, &pol, sizeof(pol)))
            s->shadow_stack = pol.EnableUserShadowStack ? 1 : 0;
    }
    return s->shadow_stack == 1;
}

static bool remote_range_ok(HANDLE h, uint64_t a, size_t n, bool write);
static bool emulate_site(probe_session *s, const Probe &p, CONTEXT &c) {
    if (p.orig_insn.empty()) return false;
    ZydisDecoder dec;
#if defined(_WIN64)
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    const uint32_t ptr = 8;
#else
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
    const uint32_t ptr = 4;
#endif
    ZydisDecodedInstruction in;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, p.orig_insn.data(), p.orig_insn.size(), &in, ops))) return false;
    const uint64_t site = p.address, next = site + in.length;
    HANDLE h = s->pi.hProcess;
    // Every memory access is checked against the CPU's view first (committed, not PAGE_GUARD,
    // readable / writable): Read/WriteProcessMemory would consume a guard page (the stack's own
    // guard -> no stack growth, the next overflow an access violation) or write through a
    // read-only page. Anything that would fault is left to the CPU (in-place step).
    auto push = [&](uint64_t v, uint32_t size) {
        uint64_t sp = (uint64_t)EMU_SP(c) - size; size_t n = 0;
        if (!remote_range_ok(h, sp, size, true)) return false;
        if (!remote_write(h, sp, &v, size, &n) || n != size) return false;
        EMU_SP(c) = (decltype(EMU_SP(c)))sp; return true;
    };
    auto pop = [&](uint64_t &v, uint32_t size) {
        v = 0; size_t n = 0;
        if (!remote_range_ok(h, (uint64_t)EMU_SP(c), size, false)) return false;
        if (!remote_read(h, (uint64_t)EMU_SP(c), &v, size, &n) || n != size) return false;
        EMU_SP(c) = (decltype(EMU_SP(c)))((uint64_t)EMU_SP(c) + size); return true;
    };
    // The branch target of operand 0 (relative immediate, register, or memory pointer).
    auto target = [&](uint64_t &t) {
        const ZydisDecodedOperand &o = ops[0];
        if (o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && o.imm.is_relative) {
            t = next + (uint64_t)o.imm.value.s;
#if !defined(_WIN64)
            t = (uint32_t)t;
#endif
            return true;
        }
        if (o.type == ZYDIS_OPERAND_TYPE_REGISTER) return emu_reg(c, o.reg.value, next, t) && o.size == ptr * 8;
        if (o.type == ZYDIS_OPERAND_TYPE_MEMORY) {
            if (o.mem.segment == ZYDIS_REGISTER_FS || o.mem.segment == ZYDIS_REGISTER_GS) return false;
            if (o.size != ptr * 8) return false;                       // far pointers etc.
            uint64_t base = 0, index = 0;
            if (!emu_reg(c, o.mem.base, next, base) || !emu_reg(c, o.mem.index, next, index)) return false;
            uint64_t a = base + index * o.mem.scale + (uint64_t)o.mem.disp.value;
#if !defined(_WIN64)
            a = (uint32_t)a;
#endif
            t = 0; size_t n = 0;
            return remote_range_ok(h, a, ptr, false) && remote_read(h, a, &t, ptr, &n) && n == ptr;
        }
        return false;
    };
    if (in.operand_width != 0 && in.operand_width != 64 && in.operand_width != 32) return false;
    uint64_t t = 0, v = 0;
    const CONTEXT before = c;
    bool ok = false;
    switch (in.mnemonic) {
        case ZYDIS_MNEMONIC_JMP:
            ok = target(t); if (ok) EMU_IP(c) = (decltype(EMU_IP(c)))t; break;
        case ZYDIS_MNEMONIC_CALL:
            if (target_has_shadow_stack(s)) break;          // the CPU must push the shadow stack itself
            ok = target(t) && push(next, ptr); if (ok) EMU_IP(c) = (decltype(EMU_IP(c)))t; break;
        case ZYDIS_MNEMONIC_RET:
            if (target_has_shadow_stack(s)) break;          // ... and pop it
            if (in.operand_count_visible > 1) break;
            ok = pop(v, ptr);
            if (ok && in.operand_count_visible == 1 && ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE)
                EMU_SP(c) = (decltype(EMU_SP(c)))((uint64_t)EMU_SP(c) + ops[0].imm.value.u);
            if (ok) EMU_IP(c) = (decltype(EMU_IP(c)))v;
            break;
        case ZYDIS_MNEMONIC_JO: case ZYDIS_MNEMONIC_JNO: case ZYDIS_MNEMONIC_JB: case ZYDIS_MNEMONIC_JNB:
        case ZYDIS_MNEMONIC_JZ: case ZYDIS_MNEMONIC_JNZ: case ZYDIS_MNEMONIC_JBE: case ZYDIS_MNEMONIC_JNBE:
        case ZYDIS_MNEMONIC_JS: case ZYDIS_MNEMONIC_JNS: case ZYDIS_MNEMONIC_JP: case ZYDIS_MNEMONIC_JNP:
        case ZYDIS_MNEMONIC_JL: case ZYDIS_MNEMONIC_JNL: case ZYDIS_MNEMONIC_JLE: case ZYDIS_MNEMONIC_JNLE:
            ok = target(t); if (ok) EMU_IP(c) = (decltype(EMU_IP(c)))(emu_cond(in.mnemonic, c.EFlags) ? t : next); break;
        case ZYDIS_MNEMONIC_JRCXZ: case ZYDIS_MNEMONIC_JECXZ: case ZYDIS_MNEMONIC_JCXZ: {
            // The counter width is the ADDRESS size: jrcxz (x64), jecxz (x86, or 67h on x64),
            // jcxz (67h on x86).
            uint64_t cx = 0;
            ok = target(t);
            if (ok && in.mnemonic == ZYDIS_MNEMONIC_JCXZ) cx = (uint64_t)(EMU_CX(c) & 0xFFFFu);
            else if (ok) ok = emu_reg(c, in.mnemonic == ZYDIS_MNEMONIC_JRCXZ ? ZYDIS_REGISTER_RCX : ZYDIS_REGISTER_ECX, next, cx);
            if (ok) EMU_IP(c) = (decltype(EMU_IP(c)))(cx == 0 ? t : next);
            break;
        }
        case ZYDIS_MNEMONIC_LOOP: case ZYDIS_MNEMONIC_LOOPE: case ZYDIS_MNEMONIC_LOOPNE: {
            // The counter is rcx / ecx / cx by ADDRESS size (67h selects ecx on x64, cx on x86).
            if (!target(t)) break;
            bool nz;
#if defined(_WIN64)
            if (in.address_width == 64) { --c.Rcx; nz = c.Rcx != 0; }
            else if (in.address_width == 32) {          // a 32-bit counter write zero-extends, as
                const uint32_t e = (uint32_t)c.Rcx - 1;  // the CPU does (inplace-loop_a32 compares)
                c.Rcx = e; nz = e != 0;
            } else break;
#else
            if (in.address_width == 32) { --c.Ecx; nz = c.Ecx != 0; }
            else if (in.address_width == 16) {         // cx only; the upper half of ecx is kept
                const WORD cx = (WORD)(c.Ecx - 1);
                c.Ecx = (c.Ecx & 0xFFFF0000u) | cx; nz = cx != 0;
            } else break;
#endif
            const bool zf = c.EFlags & 0x40;
            const bool take = nz && (in.mnemonic == ZYDIS_MNEMONIC_LOOP ||
                                          (in.mnemonic == ZYDIS_MNEMONIC_LOOPE && zf) ||
                                          (in.mnemonic == ZYDIS_MNEMONIC_LOOPNE && !zf));
            EMU_IP(c) = (decltype(EMU_IP(c)))(take ? t : next); ok = true;
            break;
        }
        case ZYDIS_MNEMONIC_PUSHFQ: case ZYDIS_MNEMONIC_PUSHFD:
            // The image the CPU pushes: RF and VM read as 0. TF as the TARGET has it (ours
            // is never set here: there is no single-step).
            ok = push((uint64_t)(c.EFlags & ~0x30000u), ptr); if (ok) EMU_IP(c) = (decltype(EMU_IP(c)))next; break;
        case ZYDIS_MNEMONIC_POPFQ: case ZYDIS_MNEMONIC_POPFD: {
            // CPL 3: CF PF AF ZF SF TF DF OF NT AC ID change; IF/IOPL/VM/RF do not.
            const DWORD mask = 0x1 | 0x4 | 0x10 | 0x40 | 0x80 | 0x100 | 0x400 | 0x800 | 0x4000 | 0x40000 | 0x200000;
            ok = pop(v, ptr);
            if (ok) { c.EFlags = (c.EFlags & ~mask) | ((DWORD)v & mask); EMU_IP(c) = (decltype(EMU_IP(c)))next; }
            break;
        }
        default: break;
    }
    if (!ok) { c = before; return false; }
    // Undo a partial write is not needed: push writes only below SP, which the CPU would
    // have written as well; on any failure c is restored and the real instruction runs.
    return true;
}

// Decode the site instruction to plan the single-step. Fills its length, whether it
// may be stepped out-of-line (not a relative branch / call / ret), and the offset of a
// RIP-relative disp32 to retarget in the out-of-line copy. Control-flow instructions
// return displaced_ok=false so the caller uses the in-place fallback.
static bool decode_site(const unsigned char *bytes, size_t n, uint32_t &len,
                        bool &displaced_ok, int &riprel_off, bool *rep_string = nullptr) {
    ZydisDecoder dec;
#if defined(_WIN64)
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#endif
    ZydisDecodedInstruction insn;
    ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, bytes, n, &insn, ops))) return false;
    len = insn.length; riprel_off = -1; displaced_ok = true;
    if (rep_string) *rep_string = false;
    if (insn.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE ||
        insn.meta.category == ZYDIS_CATEGORY_CALL || insn.meta.category == ZYDIS_CATEGORY_RET ||
        insn.meta.category == ZYDIS_CATEGORY_COND_BR || insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
        displaced_ok = false; return true;            // control flow -> in-place fallback
    }
    // Flags-image / trap / privileged instructions can clear or expose the trap flag,
    // or raise their own exception instead of the single-step, so out-of-line stepping
    // misbehaves; route them to the in-place fallback.
    switch (insn.mnemonic) {
        case ZYDIS_MNEMONIC_POPF:  case ZYDIS_MNEMONIC_POPFD:  case ZYDIS_MNEMONIC_POPFQ:
        case ZYDIS_MNEMONIC_PUSHF: case ZYDIS_MNEMONIC_PUSHFD: case ZYDIS_MNEMONIC_PUSHFQ:
        case ZYDIS_MNEMONIC_STI:   case ZYDIS_MNEMONIC_CLI:
        case ZYDIS_MNEMONIC_INT:   case ZYDIS_MNEMONIC_INT3:   case ZYDIS_MNEMONIC_INT1:
        case ZYDIS_MNEMONIC_SYSCALL: case ZYDIS_MNEMONIC_SYSENTER:
            displaced_ok = false; return true;
        default: break;
    }
    // REP/REPE/REPNE string ops: the trap flag fires after EACH iteration, so neither a
    // trap-flag step out-of-line (truncates the operation) nor in place (the re-armed INT3
    // fires the callback again for every remaining iteration, with RCX counting down) is
    // right. The caller runs them out-of-line to completion, ended by a trailing INT3.
    if (insn.attributes & (ZYDIS_ATTRIB_HAS_REP | ZYDIS_ATTRIB_HAS_REPE | ZYDIS_ATTRIB_HAS_REPNE)) {
        if (rep_string) *rep_string = true; else displaced_ok = false;
        return true;
    }
    // RIP-relative memory operand (x64): record the disp32 so the copy can be retargeted.
    for (int i = 0; i < insn.operand_count; ++i) {
        if (ops[i].type == ZYDIS_OPERAND_TYPE_MEMORY && ops[i].mem.base == ZYDIS_REGISTER_RIP) {
            if (insn.raw.disp.size == 32 && insn.raw.disp.offset) riprel_off = insn.raw.disp.offset;
            else displaced_ok = false;                // RIP-relative but not a disp32 we can retarget
            break;
        }
    }
    return true;
}

// Program debug register `slot` for execute (rw=0,len=0) or a data watchpoint. rw:
// 0=execute, 1=write, 3=read/write. len: 0=1,1=2,3=4,2=8 bytes (Intel DR7 LEN encoding).
static bool set_dr_on_thread(HANDLE thread, int slot, uint64_t addr, bool enable,
                             uint32_t rw = 0, uint32_t len = 0) {
    CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &c)) return false;
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

// Hardware execute breakpoint: no code is modified, so there is no re-arm window and
// nothing to single-step. Set the DR on every current thread; new threads get it in
// the CREATE_THREAD handler. Exact under multithreading for ANY instruction (incl.
// control-flow/REP the displaced software path cannot handle), limited to 4 slots.
// Translate the probe flags into the DR7 RW/LEN encoding: execute breakpoint by
// default, or a data watchpoint (write / read+write) of one machine word.
static void hw_rw_len(uint32_t flags, uint32_t &rw, uint32_t &len) {
    if (flags & PROBE_WATCH_RW)          rw = 3;
    else if (flags & PROBE_WATCH_WRITE)  rw = 1;
    else { rw = 0; len = 0; return; }                 // execute breakpoint, 1 byte
    len = 3;   // LEN=11 -> 4-byte (dword) watchpoint; the address must be dword-aligned
}

// The TARGET's own debug registers. A program may set hardware breakpoints/watchpoints on
// its own threads (SetThreadContext) and catch the #DB itself; those must keep working. A
// slot is the target's on a thread when it is enabled there, is not one we use, and does not
// hold an address we armed and released (a stale image of ours).
static uint64_t dr_address(const CONTEXT &c, int slot) {
    switch (slot) { case 0: return c.Dr0; case 1: return c.Dr1; case 2: return c.Dr2; default: return c.Dr3; }
}
// A released address is still ours on `tid` only while that thread is unsettled (see
// probe_session::hw_unsettled); once it has run since the release, it is the target's.
static bool hw_released_on(const probe_session *s, DWORD tid, uint64_t address) {
    if (tid == s->hw_stale_tid && s->hw_stale.count(address)) return true;
    const auto it = s->hw_unsettled.find(tid);
    return it != s->hw_unsettled.end() && it->second.addrs.count(address);
}
static bool target_owns_slot(const probe_session *s, DWORD tid, const CONTEXT &c, int slot) {
    if (s->dr_used & (1u << slot)) return false;
    if (!((c.Dr7 >> (slot * 2)) & 3)) return false;
    return !hw_released_on(s, tid, dr_address(c, slot));
}
static uint8_t target_slots(const probe_session *s, DWORD tid, const CONTEXT &c) {
    uint8_t m = 0;
    for (int k = 0; k < 4; ++k) if (target_owns_slot(s, tid, c, k)) m |= (uint8_t)(1u << k);
    return m;
}
// Slots the target owns on ANY of its threads (debug registers are per thread).
static uint8_t target_slots_any(const probe_session *s) {
    uint8_t m = 0;
    for (DWORD tid : s->threads) {
        HANDLE t = OpenThread(THREAD_GET_CONTEXT, FALSE, tid);
        CONTEXT c{}; c.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GuardTouch touch(s, tid);
        if (t && GetThreadContext(t, &c)) m |= target_slots(s, tid, c);
        if (t) CloseHandle(t);
    }
    return m;
}
// The integer registers, IP, SP and flags: equal -> the thread has not run in between.
static bool same_thread_regs(const CONTEXT &a, const CONTEXT &b) {
#if defined(_WIN64)
    return a.Rip == b.Rip && a.Rsp == b.Rsp && a.EFlags == b.EFlags && a.Rax == b.Rax && a.Rbx == b.Rbx &&
           a.Rcx == b.Rcx && a.Rdx == b.Rdx && a.Rsi == b.Rsi && a.Rdi == b.Rdi && a.Rbp == b.Rbp && a.R8 == b.R8 &&
           a.R9 == b.R9 && a.R10 == b.R10 && a.R11 == b.R11 && a.R12 == b.R12 && a.R13 == b.R13 && a.R14 == b.R14 &&
           a.R15 == b.R15;
#else
    return a.Eip == b.Eip && a.Esp == b.Esp && a.EFlags == b.EFlags && a.Eax == b.Eax && a.Ebx == b.Ebx &&
           a.Ecx == b.Ecx && a.Edx == b.Edx && a.Esi == b.Esi && a.Edi == b.Edi && a.Ebp == b.Ebp;
#endif
}
// A hardware probe at `address` was just released (its DR cleared on every thread): until
// each thread reports an event, an image of it there may be our stale one. A thread that has
// run since an earlier release settled that one (our clear reached it): only the new counts.
static void retire_hw_address(probe_session *s, uint64_t address) {
    for (DWORD tid : s->threads) {
        auto &u = s->hw_unsettled[tid];
        CONTEXT now{}; now.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        HANDLE t = OpenThread(THREAD_GET_CONTEXT, FALSE, tid);
        bool got;
        { GuardTouch touch(s, tid); got = t && GetThreadContext(t, &now); }
        if (t) CloseHandle(t);
        if (got && u.have_regs && !same_thread_regs(u.regs, now)) u.addrs.clear();
        if (got && (!u.have_regs || u.addrs.empty())) { u.regs = now; u.have_regs = true; }
        u.addrs.insert(address);
    }
}
// Re-armed by us: no image of it is stale any more.
static void unretire_hw_address(probe_session *s, uint64_t address) {
    s->hw_stale.erase(address);
    for (auto it = s->hw_unsettled.begin(); it != s->hw_unsettled.end(); ) {
        it->second.addrs.erase(address);
        it = it->second.addrs.empty() ? s->hw_unsettled.erase(it) : std::next(it);
    }
}
// At each debug event of `tid`, before it is handled: settle it (see hw_unsettled).
static void settle_hw_thread(probe_session *s, DWORD tid) {
    s->hw_stale_tid = 0; s->hw_stale.clear();
    const auto it = s->hw_unsettled.find(tid);
    if (it == s->hw_unsettled.end()) return;
    probe_session::HwUnsettled u = std::move(it->second);
    s->hw_unsettled.erase(it);
    HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
    if (!t) return;
    CONTEXT now{}; now.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
    // Without a register snapshot nothing tells "has run" apart: keep the address ours.
    if (GetThreadContext(t, &now) && (!u.have_regs || same_thread_regs(u.regs, now))) {
        // Not run since the release: this event was queued before it, and our clear may not
        // have landed. Its image of a released address is ours -- clear it now (a write at the
        // thread's own event sticks) and treat this event's #DB from it as stale.
        bool changed = false;
        for (int slot = 0; slot < 4; ++slot) {
            if ((s->dr_used & (1u << slot)) || !((now.Dr7 >> (slot * 2)) & 3) || !u.addrs.count(dr_address(now, slot))) continue;
            now.Dr7 &= ~((decltype(now.Dr7))3 << (slot * 2)) & ~((decltype(now.Dr7))0xF << (16 + slot * 4));
            changed = true;
        }
        if (changed) { now.ContextFlags = CONTEXT_DEBUG_REGISTERS; SetThreadContext(t, &now); }
        s->hw_stale_tid = tid; s->hw_stale = std::move(u.addrs);
    }
    CloseHandle(t);
}

static void arm_thread_start_fixup(probe_session *s);
static void guard_sync(probe_session *s);
#if defined(UHH_TEST_HOOKS)
// Test-only build (probe_api_testhooks, never shipped): UHH_TEST_DIE_AFTER_ARM=n kills the
// controller right after it writes its n-th user INT3 or arms its n-th hardware probe on the
// target's threads -- a controller death at the worst instant for the agent's guard
// (regress cxlib-killarm-*).
// UHH_TEST_DIE_IN_REPCOPY=1: die right after continuing a thread into a displaced REP string
// copy (it ends at an INT3 in our scratch; regress cxlib-reptail).
static bool g_test_die_on_continue = false;
static void test_note_repcopy() {
    static const bool on = std::getenv("UHH_TEST_DIE_IN_REPCOPY") != nullptr;
    if (on) g_test_die_on_continue = true;
}
static void test_die_after_arm() {
    static const long n = [] { const char *v = std::getenv("UHH_TEST_DIE_AFTER_ARM"); return v ? std::atol(v) : 0L; }();
    static long seen = 0;
    if (n > 0 && ++seen == n) { std::fflush(nullptr); TerminateProcess(GetCurrentProcess(), 99); }
}
#endif
static bool arm_hw(probe_session *s, Probe &p, uint64_t base) {
    if (p.rva > UINT64_MAX - base) { set_error(s, "probe address overflow"); return false; }
    uint64_t address = base + p.rva;
    int slot = -1;
    // Rotate through free slots so a just-released slot is reused last: a #DB already in
    // flight for the old probe is then far less likely to be blamed on a new one.
    // Slots the TARGET itself has enabled on any of its threads are not ours to take.
    const uint8_t foreign = target_slots_any(s);
    for (int k = 0; k < 4; ++k) {
        int i = (s->dr_next + k) & 3;
        if (!(s->dr_used & (1u << i)) && !(foreign & (1u << i))) { slot = i; break; }
    }
    if (slot >= 0) s->dr_next = (uint8_t)((slot + 1) & 3);
    if (slot < 0) { set_error(s, "no free hardware breakpoint slot (max 4)"); return false; }
    uint32_t rw = 0, len = 0; hw_rw_len(p.flags, rw, len);
    // The guard's DR mask gets the slot BEFORE any thread has it armed (as for an INT3, see
    // arm_breakpoint): a controller killed in between left an enabled DR the guard took for
    // the target's own -- never cleared, its #DB unhandled (0x80000004) at the next hit.
    const uint8_t ever_before = s->dr_ever;
    s->dr_ever |= (uint8_t)(1u << slot);
    guard_sync(s);
    size_t tried = 0, set_ok = 0;
    for (DWORD tid : s->threads) {
        HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
        if (!t) continue;
        ++tried;
        GuardTouch touch(s, tid);
        if (set_dr_on_thread(t, slot, address, true, rw, len)) ++set_ok;
        CloseHandle(t);
    }
#if defined(UHH_TEST_HOOKS)
    if (set_ok && !p.internal) test_die_after_arm();
#endif
    if (tried && !set_ok) {   // could not arm the DR on any thread -> the probe would never fire
        s->dr_ever = ever_before; guard_sync(s);
        set_error(s, win_error("set hardware breakpoint on target threads")); return false;
    }
    s->dr_used |= (uint8_t)(1u << slot); s->dr_ever |= (uint8_t)(1u << slot); ++s->hw_active;
    unretire_hw_address(s, address);
    p.dr_slot = slot; p.base = base; p.address = address; p.active = true;
    std::fprintf(stderr, "probe: active %s -> base=0x%llx addr=0x%llx (hw DR%d, %s)\n",
                 p.location.c_str(), (unsigned long long)base, (unsigned long long)address, slot,
                 rw == 3 ? "watch rw" : rw == 1 ? "watch write" : "execute");
    arm_thread_start_fixup(s);
    return true;
}

static void sync_int3_table(probe_session *s);
// Armed software breakpoints: the entries of the agent's INT3 table (probe_agent_shared::int3).
static bool int3_entry(const Probe &p) {
    return p.active && (p.flags & PROBE_BREAKPOINT) && !p.orig_insn.empty() && p.address;
}
static size_t int3_armed(const probe_session *s) {
    size_t n = 0;
    for (const auto &p : s->probes) n += int3_entry(*p);
    return n;
}
static bool arm_breakpoint(probe_session *s, Probe &p, uint64_t base) {
    if (p.rva > UINT64_MAX - base) { set_error(s, "probe address overflow"); return false; }
    uint64_t address = base + p.rva; size_t got{};
    unsigned char buf[16];
    if (!remote_read(s->pi.hProcess, address, buf, sizeof(buf), &got) || got != sizeof(buf)) {
        set_error(s, win_error("read original probe bytes")); return false;
    }
    if (buf[0] == 0xcc) {
        Probe *owner = probe_at(s, address);
        if (owner && owner->internal && !owner->orig_insn.empty()) {
            // Take over the library's own entry INT3: reuse its saved original bytes; the
            // re-apply still happens (entry_reapply) when this probe first fires.
            std::memcpy(buf, owner->orig_insn.data(), owner->orig_insn.size());
            owner->active = false; owner->retired = true;
            uint32_t len = 0; bool disp_ok = false, rep_str = false; int riprel = -1;
            if (!decode_site(buf, sizeof(buf), len, disp_ok, riprel, &rep_str) || len == 0 || len > sizeof(buf)) {
                set_error(s, "could not decode probe site instruction"); return false;
            }
            p.original = buf[0]; p.orig_insn.assign(buf, buf + len);
            p.insn_len = len; p.displaced_ok = disp_ok; p.riprel_disp_off = riprel; p.rep_string = rep_str;
            p.base = base; p.address = address; p.active = true;
            s->retired_bps.erase(address);
            sync_int3_table(s);
            return true;
        }
        set_error(s, "pre-hooked INT3 sites are unsupported by this breakpoint backend"); return false;
    }
    uint32_t len = 0; bool disp_ok = false, rep_str = false; int riprel = -1;
    if (!decode_site(buf, sizeof(buf), len, disp_ok, riprel, &rep_str) || len == 0 || len > sizeof(buf)) {
        set_error(s, "could not decode probe site instruction"); return false;
    }
    // The agent's copy must hold every one (an inline get_mem masks them). Without inline
    // probes (an attach's channel carries only the guard) no limit applies: past the cap the
    // guard covers the first PROBE_AGENT_INT3_CAP only.
    if (s->shared && has_inline(s) && int3_armed(s) >= PROBE_AGENT_INT3_CAP) {
        set_error(s, "too many software breakpoints armed alongside inline probes (max " +
                     std::to_string(PROBE_AGENT_INT3_CAP) + ")");
        return false;
    }
    p.original = buf[0];
    p.orig_insn.assign(buf, buf + len);
    p.follow.assign(buf + 1, buf + sizeof(buf));
    p.insn_len = len; p.displaced_ok = disp_ok; p.riprel_disp_off = riprel; p.rep_string = rep_str;
    // Published to the agent's INT3 table (the controller-death guard) BEFORE the byte is
    // written: a controller killed right after the write left an INT3 neither the guard's VEH
    // nor its cleanup knew -- the target died at its next execution (unhandled breakpoint).
    // An entry whose byte is not (yet) 0xCC is harmless: the cleanup writes back the byte that
    // is already there, an inline get_mem overlays only a 0xCC.
    const uint64_t old_base = p.base, old_address = p.address;
    const bool old_active = p.active;
    p.base = base; p.address = address; p.active = true;
    sync_int3_table(s);
    guard_sync(s);
    if (!patch(s->pi.hProcess, address, 0xcc)) {
        p.base = old_base; p.address = old_address; p.active = old_active;
        sync_int3_table(s);
        set_error(s, win_error("arm software breakpoint")); return false;
    }
#if defined(UHH_TEST_HOOKS)
    if (!p.internal) test_die_after_arm();
#endif
    s->retired_bps.erase(address);
    if (!p.internal || trace_enabled())       // library-owned probes are not the user's to see
        std::fprintf(stderr, "%s %s -> base=0x%llx addr=0x%llx (was 0x%02x, len=%u, %s)\n",
                     p.internal ? "  internal" : "probe: active", p.location.c_str(), (unsigned long long)base,
                     (unsigned long long)address, p.original, len, disp_ok ? "displaced" : "in-place");
    return true;
}

static bool resolve_inline(probe_session *s, Probe &p, uint64_t base) {
    if (p.rva > UINT64_MAX - base) { set_error(s, "probe address overflow"); return false; }
    if (!s->shared || p.agent_index >= s->shared->request_count) {
        set_error(s, "inline shared request is unavailable"); return false;
    }
    p.base = base; p.address = base + p.rva;
    auto &request = s->shared->requests[p.agent_index];
    request.site = p.address; MemoryBarrier();
    // A probe re-armed after its module was unloaded and loaded again: a new install.
    if (request.status != PROBE_AGENT_PENDING) InterlockedExchange(&request.status, PROBE_AGENT_PENDING);
    std::fprintf(stderr, "probe: resolved %s -> base=0x%llx addr=0x%llx (awaiting agent)\n",
                 p.location.c_str(), (unsigned long long)base, (unsigned long long)p.address);
    return true;
}

// ---- Foreign-hook ("pre-hooked site") detection -------------------------------------
// Compare the live bytes at a probe site with the same RVA in the module's file on disk
// (bytes covered by base relocations are ignored: they legitimately differ). If they
// differ, someone patched the site: report both byte strings disassembled, the hook
// pattern and where it leads, and weakly suggest alternative probe points.
static std::string hex_bytes(const unsigned char *b, size_t n) {
    std::string r; char t[4];
    for (size_t i = 0; i < n; ++i) { std::snprintf(t, sizeof(t), i ? " %02x" : "%02x", b[i]); r += t; }
    return r;
}

static void zydis_init(ZydisDecoder &dec) {
#if defined(_WIN64)
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#endif
}

static std::vector<std::string> disasm(const unsigned char *b, size_t n, uint64_t at, size_t max_insns) {
    std::vector<std::string> out;
    ZydisDecoder dec; zydis_init(dec);
    ZydisFormatter fmt; ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
    size_t off = 0;
    while (off < n && out.size() < max_insns) {
        ZydisDecodedInstruction insn; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, b + off, n - off, &insn, ops))) { out.push_back("(undecodable)"); break; }
        char text[96];
        if (!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&fmt, &insn, ops, insn.operand_count_visible, text,
                                                          sizeof(text), at + off, nullptr))) std::snprintf(text, sizeof(text), "?");
        char line[160];
        std::snprintf(line, sizeof(line), "+%zu: %-24s %s", off, hex_bytes(b + off, insn.length).c_str(), text);
        out.emplace_back(line);
        off += insn.length;
    }
    return out;
}

struct DiskImage {          // just enough of the PE file to map RVAs and find relocations
    std::vector<IMAGE_SECTION_HEADER> sections;
    IMAGE_DATA_DIRECTORY reloc{};
    HANDLE file = INVALID_HANDLE_VALUE;
    ~DiskImage() { if (file != INVALID_HANDLE_VALUE) CloseHandle(file); }
    bool read_at(uint64_t off, void *buf, size_t n) const {
        LARGE_INTEGER li; li.QuadPart = (LONGLONG)off; DWORD got = 0;
        return SetFilePointerEx(file, li, nullptr, FILE_BEGIN) && ReadFile(file, buf, (DWORD)n, &got, nullptr) && got == n;
    }
    bool rva_to_off(uint32_t rva, size_t n, uint64_t &off) const {
        for (auto &sec : sections) {
            uint32_t size = sec.SizeOfRawData;
            if (rva >= sec.VirtualAddress && (uint64_t)rva + n <= (uint64_t)sec.VirtualAddress + size) {
                off = (uint64_t)sec.PointerToRawData + (rva - sec.VirtualAddress); return true;
            }
        }
        return false;
    }
    bool open(const std::string &path) {
        file = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;
        IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS nt{};
        if (!read_at(0, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
        if (!read_at((uint32_t)dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) return false;
        uint32_t count = nt.FileHeader.NumberOfSections;
        if (count > 96) return false;
        sections.resize(count);
        uint64_t sec_off = (uint32_t)dos.e_lfanew + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;
        if (count && !read_at(sec_off, sections.data(), count * sizeof(IMAGE_SECTION_HEADER))) return false;
        reloc = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        return true;
    }
    // Mark bytes of [rva, rva+n) that a base relocation rewrites at load time.
    void reloc_mask(uint32_t rva, size_t n, std::vector<bool> &mask) const {
        mask.assign(n, false);
        if (!reloc.VirtualAddress || !reloc.Size || reloc.Size > (16u << 20)) return;
        uint64_t off = 0;
        if (!rva_to_off(reloc.VirtualAddress, reloc.Size, off)) return;
        std::vector<unsigned char> blob(reloc.Size);
        if (!read_at(off, blob.data(), blob.size())) return;
        size_t at = 0;
        while (at + sizeof(IMAGE_BASE_RELOCATION) <= blob.size()) {
            auto *blk = reinterpret_cast<const IMAGE_BASE_RELOCATION *>(blob.data() + at);
            if (blk->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || at + blk->SizeOfBlock > blob.size()) break;
            size_t entries = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            auto *e = reinterpret_cast<const WORD *>(blk + 1);
            for (size_t i = 0; i < entries; ++i) {
                int type = e[i] >> 12; uint32_t where = blk->VirtualAddress + (e[i] & 0xfff);
                size_t width = type == IMAGE_REL_BASED_DIR64 ? 8 : type == IMAGE_REL_BASED_HIGHLOW ? 4 : 0;
                for (size_t k = 0; k < width; ++k) {
                    uint64_t b = (uint64_t)where + k;
                    if (b >= rva && b < (uint64_t)rva + n) mask[(size_t)(b - rva)] = true;
                }
            }
            at += blk->SizeOfBlock;
        }
    }
};

// Returns true when the site is modified relative to disk; fills a JSON report and
// prints a readable one. Sites in modules we have no file for are not judged.
static bool detect_prehook(probe_session *s, const Probe &p, std::string &json) {
    if (p.module.empty() || !p.address || p.address < p.base) return false;
    std::string path;
    for (auto &kv : s->module_paths) if (iequals(kv.first, p.module)) { path = kv.second; break; }
    if (trace_enabled()) std::fprintf(stderr, "  prehook-check %s path=%s\n", p.location.c_str(), path.c_str());
    if (path.empty()) return false;
    constexpr size_t N = 24;
    unsigned char live[N]{}, disk[N]{}; size_t got = 0;
    if (!remote_read(s->pi.hProcess, p.address, live, N, &got) || got != N) return false;
    DiskImage img; uint64_t off = 0;
    uint32_t rva = (uint32_t)(p.address - p.base);
    if (!img.open(path) || !img.rva_to_off(rva, N, off) || !img.read_at(off, disk, N)) return false;
    std::vector<bool> mask; img.reloc_mask(rva, N, mask);
    // Our own INT3 (a breakpoint probe on the same site) is not a foreign hook.
    size_t first = N, last = 0;
    for (size_t i = 0; i < 16; ++i) {
        if (mask[i] || live[i] == disk[i]) continue;
        if (i == 0 && live[0] == 0xcc) { Probe *own = probe_at(s, p.address); if (own && own != &p && !(own->flags & PROBE_INLINE)) continue; }
        if (first == N) first = i;
        last = i;
    }
    if (first == N) return false;
    size_t patched = last + 1;
    // Pattern + destination from the live bytes.
    ZydisDecoder dec; zydis_init(dec);
    ZydisDecodedInstruction insn; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    std::string pattern = "unknown modification"; uint64_t dest = 0;
    if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, live, N, &insn, ops))) {
        if (insn.mnemonic == ZYDIS_MNEMONIC_JMP && insn.operand_count_visible >= 1) {
            ZyanU64 target = 0;
            if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[0], p.address, &target))) {
                pattern = insn.length == 2 ? "jmp rel8" : "jmp rel32 (5-byte detour)"; dest = target;
            } else if (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[0], p.address, &target))) {
                uint64_t ptr = 0; size_t w = sizeof(void *);
                if (remote_read(s->pi.hProcess, target, &ptr, w, &got) && got == w) dest = ptr;
                pattern = "jmp [mem] (indirect detour)";
            }
        } else if (insn.mnemonic == ZYDIS_MNEMONIC_INT3) {
            pattern = "int3 (another debugger/instrumenter's breakpoint)";
        } else if (insn.mnemonic == ZYDIS_MNEMONIC_PUSH && ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                   live[insn.length] == 0xc3) {
            pattern = "push imm; ret (detour)"; dest = (uint32_t)ops[0].imm.value.u;
        } else if (insn.mnemonic == ZYDIS_MNEMONIC_MOV && ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                   ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            ZydisDecodedInstruction j; ZydisDecodedOperand jo[ZYDIS_MAX_OPERAND_COUNT];
            if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, live + insn.length, N - insn.length, &j, jo)) &&
                j.mnemonic == ZYDIS_MNEMONIC_JMP && jo[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                pattern = "mov reg, imm; jmp reg (absolute detour)"; dest = ops[1].imm.value.u;
                patched = (std::max)(patched, (size_t)insn.length + j.length);
            }
        }
    }
    // Follow the jump chain (hooking libraries usually jump to a small relay stub that
    // jumps on to the replacement): up to 4 hops through jmp rel/[mem]/reg-imm, stopping
    // at the first address inside a loaded module, which is what the user can act on.
    std::vector<uint64_t> hops;
    for (int hop = 0; dest && hop < 4; ++hop) {
        bool in_module = false;
        for (auto &kv : s->module_bases) {
            IMAGE_DOS_HEADER d{}; IMAGE_NT_HEADERS n{}; size_t g = 0;
            if (dest < kv.second) continue;
            if (remote_read(s->pi.hProcess, kv.second, &d, sizeof(d), &g) && g == sizeof(d) &&
                remote_read(s->pi.hProcess, kv.second + (uint32_t)d.e_lfanew, &n, sizeof(n), &g) && g == sizeof(n) &&
                dest < kv.second + n.OptionalHeader.SizeOfImage) { in_module = true; break; }
        }
        if (in_module) break;
        unsigned char code[24]{};
        if (!remote_read(s->pi.hProcess, dest, code, sizeof(code), &got) || got != sizeof(code)) break;
        ZydisDecodedInstruction ji; ZydisDecodedOperand jo[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code, sizeof(code), &ji, jo))) break;
        uint64_t next = 0; ZyanU64 t = 0;
        if (ji.mnemonic == ZYDIS_MNEMONIC_JMP && jo[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
            ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ji, &jo[0], dest, &t))) next = t;
        else if (ji.mnemonic == ZYDIS_MNEMONIC_JMP && jo[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                 ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ji, &jo[0], dest, &t))) {
            uint64_t ptr = 0;
            if (remote_read(s->pi.hProcess, t, &ptr, sizeof(void *), &got) && got == sizeof(void *)) next = ptr;
        } else if (ji.mnemonic == ZYDIS_MNEMONIC_MOV && jo[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                   jo[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            ZydisDecodedInstruction j2; ZydisDecodedOperand o2[ZYDIS_MAX_OPERAND_COUNT];
            if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code + ji.length, sizeof(code) - ji.length, &j2, o2)) &&
                j2.mnemonic == ZYDIS_MNEMONIC_JMP && o2[0].type == ZYDIS_OPERAND_TYPE_REGISTER) next = jo[1].imm.value.u;
        }
        if (!next || next == dest) break;
        hops.push_back(dest);
        dest = next;
    }
    // First unmodified instruction boundary in the ORIGINAL code at/after the patch.
    size_t resume = 0;
    while (resume < patched && resume < N) {
        ZydisDecodedInstruction d; ZydisDecodedOperand dops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, disk + resume, N - resume, &d, dops))) { resume = 0; break; }
        resume += d.length;
    }
    auto live_d = disasm(live, (std::max)(patched, (size_t)8), p.address, 4);
    auto disk_d = disasm(disk, resume ? resume : 8, p.address, 4);
    std::string dest_s = dest ? symbolize(s, dest) : std::string();
    std::string via;
    for (uint64_t h : hops) { char b[32]; std::snprintf(b, sizeof(b), "%s0x%llx", via.empty() ? "" : " -> ", (unsigned long long)h); via += b; }
    std::vector<std::string> suggest;
    char line[256];
    std::snprintf(line, sizeof(line), "PROBE_HW at %s (debug register; modifies no code, coexists with the existing hook)", p.location.c_str());
    suggest.emplace_back(line);
    if (dest) {
        std::snprintf(line, sizeof(line), "probe the detour target %s (runs before the other hook's logic)", dest_s.c_str());
        suggest.emplace_back(line);
    }
    if (resume && resume < N) {
        std::snprintf(line, sizeof(line), "%s+0x%x: first unmodified original instruction; usually reached when the existing hook resumes the original code",
                      p.module.c_str(), rva + (uint32_t)resume);
        suggest.emplace_back(line);
    }
    // Human-readable report.
    std::fprintf(stderr, "probe: PRE-HOOKED SITE %s (0x%llx): %zu byte(s) differ from %s\n",
                 p.location.c_str(), (unsigned long long)p.address, patched, path.c_str());
    std::fprintf(stderr, "probe:   pattern: %s%s%s%s%s\n", pattern.c_str(), dest ? " -> " : "", dest_s.c_str(),
                 via.empty() ? "" : "  (via ", via.empty() ? "" : (via + ")").c_str());
    std::fprintf(stderr, "probe:   live (in memory):\n");
    for (auto &l : live_d) std::fprintf(stderr, "probe:     %s\n", l.c_str());
    std::fprintf(stderr, "probe:   original (on disk):\n");
    for (auto &l : disk_d) std::fprintf(stderr, "probe:     %s\n", l.c_str());
    std::fprintf(stderr, "probe:   you could instead (suggestions, not verified):\n");
    for (auto &l : suggest) std::fprintf(stderr, "probe:     - %s\n", l.c_str());
    // JSON for the report.
    auto q = [](const std::string &v) {
        std::string r = "\"";
        for (char ch : v) { if (ch == '"' || ch == '\\') r += '\\'; if ((unsigned char)ch >= 0x20) r += ch; }
        return r + "\"";
    };
    auto arr = [&](const std::vector<std::string> &v) {
        std::string r = "["; for (size_t i = 0; i < v.size(); ++i) { if (i) r += ","; r += q(v[i]); } return r + "]";
    };
    char addr[32]; std::snprintf(addr, sizeof(addr), "0x%llx", (unsigned long long)p.address);
    json = std::string("{\"kind\":\"prehook\",\"location\":") + q(p.location) + ",\"address\":" + q(addr) +
           ",\"patched_bytes\":" + std::to_string(patched) + ",\"pattern\":" + q(pattern) +
           ",\"destination\":" + (dest ? q(dest_s) : std::string("null")) +
           ",\"via\":" + q(via) +
           ",\"live\":" + q(hex_bytes(live, (std::max)(patched, (size_t)8))) + ",\"original\":" + q(hex_bytes(disk, (std::max)(patched, (size_t)8))) +
           ",\"live_disasm\":" + arr(live_d) + ",\"original_disasm\":" + arr(disk_d) + ",\"suggest\":" + arr(suggest) + "}";
    return true;
}

// Decide what to do with a pre-hooked site for a code-modifying probe. Inline probes are
// refused by default (installing over an unknown detour chains through code we did not
// inspect); PROBE_ALLOW_PREHOOKED chains anyway, PROBE_FALLBACK_HW moves the probe to a
// debug register. Breakpoint probes still work (the jmp is stepped in place): report only.
// Returns false when the probe must not be armed; sets moved_to_hw when converted.
// An inline hook replaces the first instructions at the site (>= 5 bytes) with a jump.
// That is only safe if nothing else can arrive INSIDE those bytes later:
//  1. a CALL among them that is not the last one: a thread inside the callee when the
//     hook is written returns into the middle of the jump (no freeze can fix a return
//     address on a stack);
//  2. another exported function starting inside them (a probe on a function's final
//     `ret` overwrites its neighbour: e.g. the next ntdll syscall stub on x86);
//  3. a branch elsewhere in the same function landing inside them (x64: the function's
//     bounds come from .pdata; e.g. a syscall stub's `jne` into its `int 2e; ret` tail);
//  4. an exit (ret/jmp) followed, still inside them, by anything but padding: that code
//     is reachable only by a jump (the same stub tail, even without .pdata).
// Such sites go to the hardware backend with PROBE_FALLBACK_HW, else are refused.
static uint32_t inline_patch_len(const unsigned char *b, size_t n, int64_t *call_end, bool *code_after_exit,
                                 size_t *exit_at = nullptr) {
    ZydisDecoder dec;
#if defined(_WIN64)
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#endif
    size_t off = 0; *call_end = -1; *code_after_exit = false;
    bool exited = false;
    while (off < 5) {
        ZydisDecodedInstruction insn{};
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&dec, nullptr, b + off, n - off, &insn))) return 0;
        off += insn.length;
        if (exited && insn.mnemonic != ZYDIS_MNEMONIC_NOP && insn.mnemonic != ZYDIS_MNEMONIC_INT3)
            *code_after_exit = true;                   // reachable only by a jump into the patch
        if (insn.meta.category == ZYDIS_CATEGORY_CALL) *call_end = (int64_t)off;
        if (!exited && (insn.meta.category == ZYDIS_CATEGORY_RET || insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                        insn.mnemonic == ZYDIS_MNEMONIC_INT3 || insn.mnemonic == ZYDIS_MNEMONIC_UD2)) {
            exited = true;
            if (exit_at) *exit_at = off - insn.length;
        }
    }
    return (uint32_t)off;
}

static bool read_image_dir(probe_session *s, uint64_t base, int which, IMAGE_DATA_DIRECTORY &dir,
                           uint32_t *size_of_image = nullptr) {
    IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS nt{}; size_t got = 0;
    if (!remote_read(s->pi.hProcess, base, &dos, sizeof(dos), &got) || got != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (!remote_read(s->pi.hProcess, base + (uint32_t)dos.e_lfanew, &nt, sizeof(nt), &got) || got != sizeof(nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) return false;
    if (size_of_image) *size_of_image = nt.OptionalHeader.SizeOfImage;
    dir = nt.OptionalHeader.DataDirectory[which];
    return dir.VirtualAddress && dir.Size;
}

// ---- Entry points near an inline site --------------------------------------------------
// Every address control can ARRIVE at (other than by falling through): function starts
// from every source we have, plus -- inside the function that holds the site -- branch
// targets, return points after calls, and switch-table targets. Over-collecting is the
// safe direction: an extra entry point can only make a hook refuse, never clobber code.
struct SiteAnalysis {
    uint64_t func_start = 0, func_end = 0;      // 0/0: function bounds unknown
    const char *bounds_from = "none";
    std::vector<uint64_t> insns;                // instruction starts in the function (linear)
    std::set<uint64_t> entries;                 // entry points (absolute)
    int tables = 0;                             // switch tables recovered
    std::vector<uint64_t> indirect_jumps;       // jmp reg / jmp [reg...]: targets unknown unless a table explains them
};

static void add_export_starts(probe_session *s, uint64_t base, std::set<uint64_t> &out) {
    IMAGE_DATA_DIRECTORY dir{};
    if (!read_image_dir(s, base, IMAGE_DIRECTORY_ENTRY_EXPORT, dir) || dir.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) return;
    IMAGE_EXPORT_DIRECTORY ex{}; size_t got = 0;
    if (!remote_read(s->pi.hProcess, base + dir.VirtualAddress, &ex, sizeof(ex), &got) || got != sizeof(ex)) return;
    if (!ex.NumberOfFunctions || ex.NumberOfFunctions > (1u << 20)) return;
    std::vector<DWORD> funcs(ex.NumberOfFunctions);
    if (!remote_read(s->pi.hProcess, base + ex.AddressOfFunctions, funcs.data(), funcs.size() * 4, &got) || got != funcs.size() * 4) return;
    for (DWORD r : funcs)
        if (r && !(r >= dir.VirtualAddress && r < dir.VirtualAddress + dir.Size)) out.insert(base + r);   // skip forwarders
}

// Control Flow Guard: every address-taken function (static ones included).
static void add_cfg_starts(probe_session *s, uint64_t base, std::set<uint64_t> &out) {
    IMAGE_DATA_DIRECTORY dir{};
    if (!read_image_dir(s, base, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, dir)) return;
#if defined(_WIN64)
    IMAGE_LOAD_CONFIG_DIRECTORY64 lc{};
#else
    IMAGE_LOAD_CONFIG_DIRECTORY32 lc{};
#endif
    size_t got = 0, want = (std::min)((size_t)dir.Size, sizeof(lc));
    if (!remote_read(s->pi.hProcess, base + dir.VirtualAddress, &lc, want, &got) || got != want) return;
    if (lc.Size < offsetof(decltype(lc), GuardFlags) + sizeof(lc.GuardFlags)) return;
    if (!lc.GuardCFFunctionTable || !lc.GuardCFFunctionCount || lc.GuardCFFunctionCount > (1u << 22)) return;
    const size_t stride = 4 + ((lc.GuardFlags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT);
    std::vector<unsigned char> t((size_t)lc.GuardCFFunctionCount * stride);
    if (!remote_read(s->pi.hProcess, (uint64_t)lc.GuardCFFunctionTable, t.data(), t.size(), &got) || got != t.size()) return;
    for (size_t i = 0; i < (size_t)lc.GuardCFFunctionCount; ++i) {
        DWORD rva; std::memcpy(&rva, t.data() + i * stride, 4); out.insert(base + rva);
    }
}

#if defined(_WIN64)
// x64 .pdata: the start of every non-leaf function; also the bounds of the site's own.
static void add_pdata(probe_session *s, uint64_t base, uint64_t site, std::set<uint64_t> &out,
                      uint64_t &fs, uint64_t &fe) {
    IMAGE_DATA_DIRECTORY dir{};
    if (!read_image_dir(s, base, IMAGE_DIRECTORY_ENTRY_EXCEPTION, dir)) return;
    const size_t count = dir.Size / sizeof(RUNTIME_FUNCTION);
    if (!count || count > (1u << 22)) return;
    std::vector<RUNTIME_FUNCTION> rf(count); size_t got = 0;
    if (!remote_read(s->pi.hProcess, base + dir.VirtualAddress, rf.data(), count * sizeof(RUNTIME_FUNCTION), &got) ||
        got != count * sizeof(RUNTIME_FUNCTION)) return;
    for (const auto &f : rf) {
        out.insert(base + f.BeginAddress);
        if (site >= base + f.BeginAddress && site < base + f.EndAddress) { fs = base + f.BeginAddress; fe = base + f.EndAddress; }
    }
}
#endif

static void analyse_site(probe_session *s, uint64_t base, uint64_t site, SiteAnalysis &a) {
    uint32_t image_size = 0; IMAGE_DATA_DIRECTORY unused{};
    read_image_dir(s, base, IMAGE_DIRECTORY_ENTRY_EXPORT, unused, &image_size);
    add_export_starts(s, base, a.entries);
    add_cfg_starts(s, base, a.entries);
#if defined(_WIN64)
    add_pdata(s, base, site, a.entries, a.func_start, a.func_end);
    if (a.func_start) a.bounds_from = ".pdata";
#endif
    if (s->sym_ready) {                                            // PDB: every function, statics included
        uint64_t fs = 0; uint32_t fz = 0;
        if (uhh_sym::containing_function(s->pi.hProcess, site, fs, fz) && fz <= (1u << 20)) {
            a.entries.insert(fs);
            if (!a.func_start || fs + fz > a.func_end) { a.func_start = fs; a.func_end = fs + fz; a.bounds_from = "pdb"; }
        }
        for (uint64_t x = site + 1; x < site + 32; ++x)            // a PDB function starting just after the site
            if (uhh_sym::containing_function(s->pi.hProcess, x, fs, fz) && fs == x) a.entries.insert(fs);
    }
    if (!a.func_start || a.func_end - a.func_start > (1u << 16)) { a.func_start = a.func_end = 0; return; }
    std::vector<unsigned char> code(a.func_end - a.func_start); size_t got = 0;
    if (!remote_read(s->pi.hProcess, a.func_start, code.data(), code.size(), &got) || got != code.size()) { a.func_start = a.func_end = 0; return; }
    ZydisDecoder dec;
#if defined(_WIN64)
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#endif
    ZydisDecodedInstruction in; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    const uint64_t fs = a.func_start, fe = a.func_end;
    auto inside = [&](uint64_t t) { return t >= fs && t < fe; };
    for (size_t off = 0; off < code.size();) {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code.data() + off, code.size() - off, &in, ops))) { ++off; continue; }
        const uint64_t at = fs + off, next = at + in.length;
        a.insns.push_back(at);
        if (in.mnemonic == ZYDIS_MNEMONIC_JMP && in.operand_count_visible >= 1) {
            const auto &o = ops[0];
            const bool via_import = o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.mem.index == ZYDIS_REGISTER_NONE &&
                (o.mem.base == ZYDIS_REGISTER_NONE || o.mem.base == ZYDIS_REGISTER_RIP);   // jmp [IAT]: leaves the function
            if (o.type == ZYDIS_OPERAND_TYPE_REGISTER || (o.type == ZYDIS_OPERAND_TYPE_MEMORY && !via_import))
                a.indirect_jumps.push_back(at);
        }
        if (in.meta.category == ZYDIS_CATEGORY_CALL) a.entries.insert(next);               // return point
        for (int k = 0; k < in.operand_count_visible; ++k) {
            const auto &o = ops[k];
            if (o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && o.imm.is_relative && in.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE) {
                uint64_t t = next + (uint64_t)o.imm.value.s;
#if !defined(_WIN64)
                t = (uint32_t)t;
#endif
                a.entries.insert(t);                                                      // direct branch/call target
            }
            // Switch tables: [reg*4 + disp32] (x86: absolute entries; x64 MSVC: image-base
            // relative, base register = image base). Read entries while they land in this
            // function; every one is an entry point.
            if (o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.mem.index != ZYDIS_REGISTER_NONE &&
                o.mem.scale == 4 && o.mem.disp.has_displacement && o.mem.disp.value > 0) {
#if defined(_WIN64)
                const uint64_t table = base + (uint64_t)o.mem.disp.value;
                if ((uint64_t)o.mem.disp.value >= image_size) continue;
#else
                const uint64_t table = (uint32_t)o.mem.disp.value;
                if (table < base || table - base >= image_size) continue;
#endif
                int found = 0;
                for (int e = 0; e < 4096; ++e) {
                    uint32_t v = 0; size_t n = 0;
                    if (!remote_read(s->pi.hProcess, table + 4ull * e, &v, 4, &n) || n != 4) break;
#if defined(_WIN64)
                    const uint64_t t = base + v;
#else
                    const uint64_t t = v;
#endif
                    if (!inside(t)) break;
                    a.entries.insert(t); ++found;
                }
                if (found) ++a.tables;
            }
        }
        off += in.length;
    }
}

// The section holding [lo, hi): false when the patch would leave executable code.
static bool patch_in_code_section(probe_session *s, uint64_t base, uint64_t lo, uint64_t hi, std::string &name) {
    IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS nt{}; size_t got = 0;
    if (!remote_read(s->pi.hProcess, base, &dos, sizeof(dos), &got) || got != sizeof(dos)) return true;
    const uint64_t nth = base + (uint32_t)dos.e_lfanew;
    if (!remote_read(s->pi.hProcess, nth, &nt, sizeof(nt), &got) || got != sizeof(nt)) return true;
    const uint16_t nsec = nt.FileHeader.NumberOfSections;
    if (!nsec || nsec > 96) return true;
    std::vector<IMAGE_SECTION_HEADER> sec(nsec);
    const uint64_t first = nth + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;
    if (!remote_read(s->pi.hProcess, first, sec.data(), nsec * sizeof(IMAGE_SECTION_HEADER), &got) ||
        got != nsec * sizeof(IMAGE_SECTION_HEADER)) return true;
    for (const auto &h : sec) {
        const uint64_t st = base + h.VirtualAddress, en = st + (std::max)(h.Misc.VirtualSize, h.SizeOfRawData);
        if (lo < st || lo >= en) continue;
        name.assign((const char *)h.Name, strnlen((const char *)h.Name, 8));
        return (h.Characteristics & IMAGE_SCN_MEM_EXECUTE) && hi <= en;
    }
    return true;                                     // not in a mapped image section: nothing to say
}

// Inline hooks overwrite >= 5 bytes; they are refused where code could ARRIVE inside those
// bytes, with one clear reason per case:
//   [exit]     the patch runs past a ret/jmp into code only a jump can reach
//   [call]     a call inside the patch returns into it
//   [entry]    a function start, branch target, return point or switch-table target is inside it
//   [indirect] the function has an indirect jump whose targets cannot be resolved
//   [section]  the patch runs past the end of the executable section
//   [reloc]    a rel8-only branch (jrcxz/jecxz/loop*) inside it cannot be relocated
// (Threads executing inside the patch when it is written are handled by the freeze.)
// Not visible to any static check: jumps into this function from OTHER code.
static bool inline_site_unsafe(probe_session *s, const Probe &p, std::string &why) {
    unsigned char b[32] = {}; size_t n = 0;
    if (!remote_read(s->pi.hProcess, p.address, b, sizeof(b), &n) || n < 5) return false;
    // Decode the PROGRAM's bytes: our own INT3s read as the instruction they replace.
    uint64_t own_bp = UINT64_MAX;
    for (auto &q : s->probes)
        if (q->active && (q->flags & PROBE_BREAKPOINT) && !q->orig_insn.empty() && q->address >= p.address &&
            q->address < p.address + n && b[q->address - p.address] == 0xCC) {
            b[q->address - p.address] = q->original;
            own_bp = std::min(own_bp, q->address);
        }
    int64_t call_end = -1; bool code_after_exit = false; size_t exit_at = 0;
    const uint32_t len = inline_patch_len(b, n, &call_end, &code_after_exit, &exit_at);
    if (!len) return false;
    char buf[320];
    std::string reason;          // "<N>-byte hook would be written across <what> at +0xK"
    std::string secname;
    if (own_bp < p.address + len) {
        // The hook would relocate a live UHH INT3 into its trampoline, where it would no
        // longer be recognised (an unknown breakpoint in the target).
        std::snprintf(buf, sizeof(buf), "%u-byte hook would be written over a software-breakpoint probe at +0x%llx "
                      "(probe that instruction with one of breakpoint / inline, or use hw with either)",
                      len, (unsigned long long)(own_bp - p.address));
        reason = buf;
    } else if (p.base && !patch_in_code_section(s, p.base, p.address, p.address + len, secname)) {
        std::snprintf(buf, sizeof(buf), "%u-byte hook would be written across the end of section %s", len, secname.c_str());
        reason = buf;
    } else if (code_after_exit) {
        std::snprintf(buf, sizeof(buf), "%u-byte hook would be written across the end of the function (ret/jmp at +0x%zx)",
                      len, exit_at);
        reason = buf;
    } else if (call_end >= 0 && call_end != (int64_t)len) {
        std::snprintf(buf, sizeof(buf), "%u-byte hook would be written across a call's return point at +0x%llx",
                      len, (unsigned long long)call_end);
        reason = buf;
    }
    if (reason.empty()) {
        // [reloc] jrcxz/jecxz/loop* exist only with a rel8 displacement: copied into a
        // trampoline they cannot reach their target (the hook engine does not rewrite them).
        ZydisDecoder dec;
#if defined(_WIN64)
        ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
        ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#endif
        ZydisDecodedInstruction in{};
        for (size_t off = 0; off < len && ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&dec, nullptr, b + off, n - off, &in));
             off += in.length) {
            const ZydisMnemonic m = in.mnemonic;
            if (m == ZYDIS_MNEMONIC_JCXZ || m == ZYDIS_MNEMONIC_JECXZ || m == ZYDIS_MNEMONIC_JRCXZ ||
                m == ZYDIS_MNEMONIC_LOOP || m == ZYDIS_MNEMONIC_LOOPE || m == ZYDIS_MNEMONIC_LOOPNE) {
                std::snprintf(buf, sizeof(buf), "%u-byte hook would relocate %s at +0x%zx (rel8-only branch: cannot be "
                              "relocated)", len, ZydisMnemonicGetString(m), off);
                reason = buf;
                break;
            }
        }
    }
    SiteAnalysis a;
    if (p.base) analyse_site(s, p.base, p.address, a);
    if (reason.empty()) {
        auto it = a.entries.upper_bound(p.address);
        if (it != a.entries.end() && *it < p.address + len) {
            std::snprintf(buf, sizeof(buf), "%u-byte hook would be written across a jump/call target at +0x%llx",
                          len, (unsigned long long)(*it - p.address));
            reason = buf;
        }
    }
    // Unresolved indirect jumps make MID-function sites unverifiable. At the function's own
    // start they do not: a switch/jump table targets case labels in the body, never the
    // entry's first bytes (direct back-edges to the entry were checked above).
    if (reason.empty() && a.func_start && a.func_start != p.address && !a.indirect_jumps.empty() && !a.tables) {
        std::snprintf(buf, sizeof(buf), "%u-byte hook cannot be verified: the function has an indirect jump at 0x%llx "
                      "with unknown targets", len, (unsigned long long)a.indirect_jumps.front());
        reason = buf;
    }
    if (reason.empty() && p.base && !a.func_start) {
        // No function bounds (no .pdata/PDB entry): walk forward from the site to the end of
        // its block and check every direct branch met there (catches loops back into it).
        ZydisDecoder dec;
#if defined(_WIN64)
        ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
        ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#endif
        unsigned char w[512] = {}; size_t wn = 0;
        remote_read(s->pi.hProcess, p.address, w, sizeof(w), &wn);
        ZydisDecodedInstruction in; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        for (size_t off = 0; off < wn && reason.empty();) {
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, w + off, wn - off, &in, ops))) break;
            const uint64_t at = p.address + off, next = at + in.length;
            if (in.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE && in.operand_count_visible >= 1 &&
                ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[0].imm.is_relative) {
                uint64_t t = next + (uint64_t)ops[0].imm.value.s;
#if !defined(_WIN64)
                t = (uint32_t)t;
#endif
                if (t > p.address && t < p.address + len) {
                    std::snprintf(buf, sizeof(buf), "%u-byte hook would be written across a jump target at +0x%llx",
                                  len, (unsigned long long)(t - p.address));
                    reason = buf;
                }
            }
            if (in.meta.category == ZYDIS_CATEGORY_RET || in.meta.category == ZYDIS_CATEGORY_UNCOND_BR) break;
            off += in.length;
        }
    }
    if (reason.empty()) return false;
    // Suggest instruction boundaries in this function where the whole patch passes the same
    // checks, nearest first. The callback would run at a different instruction there.
    std::string modname;
    for (auto &kv : s->module_bases) if (kv.second == p.base) { modname = kv.first; break; }
    std::vector<std::pair<uint64_t, uint64_t>> cands;    // (distance, address)
    const bool fn_ok = !(!a.indirect_jumps.empty() && !a.tables);
    for (uint64_t x : a.insns) {
        if (x == p.address || !fn_ok) continue;
        unsigned char c[32] = {}; size_t cn = 0;
        if (!remote_read(s->pi.hProcess, x, c, sizeof(c), &cn) || cn < 5) continue;
        int64_t ce = -1; bool cx = false;
        const uint32_t cl = inline_patch_len(c, cn, &ce, &cx);
        if (!cl || cx || (ce >= 0 && ce != (int64_t)cl) || x + cl > a.func_end) continue;
        auto it = a.entries.upper_bound(x);
        if (it != a.entries.end() && *it < x + cl) continue;
        cands.push_back({x > p.address ? x - p.address : p.address - x, x});
    }
    std::sort(cands.begin(), cands.end());
    std::string sugg;
    for (size_t i = 0; i < cands.size() && i < 3; ++i) {
        const uint64_t x = cands[i].second;
        std::snprintf(buf, sizeof(buf), "%s%s+0x%llx (%s%llu bytes)", sugg.empty() ? "" : ", ",
                      modname.empty() ? "module" : modname.c_str(), (unsigned long long)(x - p.base),
                      x < p.address ? "-" : "+", (unsigned long long)cands[i].first);
        sugg += buf;
    }
    why = reason;
    if (!sugg.empty()) std::fprintf(stderr, "probe: %s: inline-safe nearby: %s\n", p.location.c_str(), sugg.c_str());
    return true;
}

// Two inline hooks whose patches overlap corrupt each other: the second decodes (and
// relocates) the first one's jump bytes, and removing either restores bytes under the
// other. Same address included. Never overridable: refused, or hw with PROBE_FALLBACK_HW.
static bool inline_overlaps_probe(probe_session *s, Probe &p, std::string &why) {
    unsigned char b[32] = {}; size_t n = 0; int64_t call_end = -1; bool after_exit = false;
    if (remote_read(s->pi.hProcess, p.address, b, sizeof(b), &n) && n >= 5)
        p.patch_len = inline_patch_len(b, n, &call_end, &after_exit);
    const uint64_t lo = p.address, hi = p.address + (p.patch_len ? p.patch_len : 5);
    for (const auto &o : s->probes) {
        if (!(o->flags & PROBE_INLINE) || o->retired || !o->address || o->agent_index == p.agent_index) continue;
        const uint64_t olo = o->address, ohi = o->address + (o->patch_len ? o->patch_len : 5);
        if (olo < hi && lo < ohi) {
            char buf[256];
            std::snprintf(buf, sizeof(buf), "its %llu-byte hook would overlap the hook of inline probe %s at 0x%llx",
                          (unsigned long long)(hi - lo), o->location.c_str(), (unsigned long long)olo);
            why = buf;
            return true;
        }
    }
    return false;
}

static bool vet_site(probe_session *s, Probe &p, bool &moved_to_hw) {
    moved_to_hw = false;
    if (p.flags & PROBE_HW) return true;
    std::string inner;
    if ((p.flags & PROBE_INLINE) && inline_overlaps_probe(s, p, inner)) {
        if (p.flags & PROBE_FALLBACK_HW) {
            p.flags = (p.flags & ~(uint32_t)PROBE_INLINE) | PROBE_HW; moved_to_hw = true;
            std::fprintf(stderr, "probe: %s -> hardware fallback (%s)\n", p.location.c_str(), inner.c_str());
            return true;
        }
        std::string msg = "inline probe " + p.location + " refused: " + inner + ".";
        std::fprintf(stderr, "probe: %s\n", msg.c_str());
        set_error(s, msg);
        return false;
    }
    if ((p.flags & PROBE_INLINE) && inline_site_unsafe(s, p, inner)) {
        if (p.flags & PROBE_ALLOW_UNSAFE_SITE) {
            std::fprintf(stderr, "probe: warning: inline probe %s: %s (installed: PROBE_ALLOW_UNSAFE_SITE)\n",
                         p.location.c_str(), inner.c_str());
        } else if (p.flags & PROBE_FALLBACK_HW) {
            p.flags = (p.flags & ~(uint32_t)PROBE_INLINE) | PROBE_HW; moved_to_hw = true;
            std::fprintf(stderr, "probe: %s -> hardware fallback (%s)\n", p.location.c_str(), inner.c_str());
            return true;
        } else {
            std::string msg = "inline probe " + p.location + " refused: " + inner + ". Override with PROBE_ALLOW_UNSAFE_SITE.";
            std::fprintf(stderr, "probe: %s\n", msg.c_str());
            set_error(s, msg);
            return false;
        }
    }
    std::string json;
    if (!detect_prehook(s, p, json)) return true;
    s->prehooks.push_back(json);
    if (!(p.flags & PROBE_INLINE) || (p.flags & PROBE_ALLOW_PREHOOKED)) return true;
    if (p.flags & PROBE_FALLBACK_HW) {
        p.flags = (p.flags & ~(uint32_t)PROBE_INLINE) | PROBE_HW; moved_to_hw = true;
        std::fprintf(stderr, "probe: %s -> hardware fallback (pre-hooked site)\n", p.location.c_str());
        return true;
    }
    set_error(s, "inline probe " + p.location + " is on a pre-hooked site (see the prehook report; "
                 "use PROBE_ALLOW_PREHOOKED to chain, PROBE_FALLBACK_HW or PROBE_HW to avoid)");
    return false;
}

static bool arm_probe(probe_session *s, Probe &item, uint64_t base) {
    // A late-resolving inline probe (the gate is already released, so the target may
    // call the site before the async agent install lands) with PROBE_FALLBACK_HW set
    // becomes a hardware probe: that arms synchronously here (just debug registers —
    // no in-target code, no loader lock, no race) and is exact. The callback is
    // backend-agnostic, so it runs controller-side unchanged.
    // With the agent's service thread running, a late inline site is installed while the
    // loading thread is held (synchronous), so the fallback is only needed without it.
    // Judge an inline site BEFORE any backend decision, so a foreign hook is always
    // reported (and handled per PROBE_ALLOW_PREHOOKED / PROBE_FALLBACK_HW) -- including
    // when the late-install rule below would move the probe anyway.
    if (item.flags & PROBE_INLINE) {
        Probe view = item; view.base = base;
        bool known = true;
        if (!item.export_name.empty()) {
            uint64_t exp = 0; std::string saved = s->error;
            known = resolve_export(s, base, item.export_name, exp);
            if (known) view.rva = exp + item.sym_offset;
            s->error = saved;
        }
        // (A forwarded / symbol-only name has no RVA here yet: its real site is judged by
        //  vet_pending_inline before the hook is written -- never the module header.)
        view.address = base + view.rva;
        bool moved = false;
        if (known && !vet_site(s, view, moved)) { item.retired = true; return false; }
        if (moved) item.flags = view.flags;                // pre-hooked -> hw (PROBE_FALLBACK_HW)
        item.patch_len = view.patch_len;                   // later inline probes must not overlap it
    }
    // (No "late inline -> hardware" rule: launch holds the main thread at the entry point
    // until the agent is ready, and a module loaded later is gated until its hooks are in.
    // Inline stays inline.)
    if (!item.export_name.empty()) {
        uint64_t exp = 0;
        const bool exported = resolve_export(s, base, item.export_name, exp);
        if (!exported && s->error.find("forwarded") != std::string::npos) {
            // A forwarded export: probe the function it forwards to (in its own module).
            uint64_t target = forwarded_export_target(s, item.module, item.export_name);
            std::string owner; uint64_t owner_rva = 0;
            if (!target && forwarded_export_owner(item.module, item.export_name, owner, owner_rva) &&
                !iequals(owner, item.module)) {
                // The forward target's module is not mapped yet (ole32!CoCreateInstance ->
                // combase, mapped AFTER ole32): the probe now lives in that module and stays
                // pending until it loads, like any probe on a not-yet-loaded module.
                s->error.clear();
                std::fprintf(stderr, "probe: %s is forwarded -> %s+0x%llx (pending until it loads)\n",
                             item.location.c_str(), owner.c_str(), (unsigned long long)owner_rva);
                item.module = owner; item.export_name.clear(); item.rva = owner_rva + item.sym_offset;
                return true;
            }
            if (!target) { s->error += " (and its target module is not loaded in the target yet)"; return false; }
            s->error.clear();
            exp = target - base;                       // may point into another module: base + rva is absolute
            std::fprintf(stderr, "probe: %s is forwarded -> 0x%llx\n", item.location.c_str(), (unsigned long long)target);
        } else if (!exported) {
            // Not exported: try the module's symbols (PDB beside the image, or a symbol
            // server via _NT_SYMBOL_PATH) -- internal functions by name.
            uint64_t addr = 0; std::string saved = s->error;
            uint32_t image = 0;
            {
                IMAGE_DOS_HEADER d{}; IMAGE_NT_HEADERS n{}; size_t g = 0;
                if (remote_read(s->pi.hProcess, base, &d, sizeof(d), &g) && g == sizeof(d) &&
                    remote_read(s->pi.hProcess, base + (uint32_t)d.e_lfanew, &n, sizeof(n), &g) && g == sizeof(n))
                    image = n.OptionalHeader.SizeOfImage;
            }
            // The symbol must lie inside THIS module's image (not a stale or same-named one).
            if (!s->sym_ready || !uhh_sym::resolve(s->pi.hProcess, item.module, item.export_name, addr) ||
                addr < base || addr >= base + image)
                return false;
            s->error.clear();
            exp = addr - base;
            std::fprintf(stderr, "probe: %s resolved from symbols -> %s+0x%llx\n", item.location.c_str(),
                         item.module.c_str(), (unsigned long long)exp);
            (void)saved;
        }
        item.rva = exp + item.sym_offset;
    }
    if (item.flags & PROBE_BREAKPOINT) {
        // Judge the site BEFORE planting our INT3 (address is known: base + rva).
        Probe probe_view = item; probe_view.base = base; probe_view.address = base + item.rva;
        bool moved = false; (void)vet_site(s, probe_view, moved);
        return arm_breakpoint(s, item, base);
    }
    return item.flags & PROBE_HW ? arm_hw(s, item, base) : resolve_inline(s, item, base);
}

// "probe_app!X" names probe_app.dll (module_of_location), so it does not match the loaded
// probe_app.exe and would stay pending in silence: say so, once per probe, when a module of
// that name with another extension loads.
static void warn_bare_module(probe_session *s, const std::string &module) {
    const size_t dot = module.rfind('.');
    if (dot == std::string::npos || iequals(module.substr(dot), ".dll")) return;
    const std::string as_dll = module.substr(0, dot) + ".dll";
    for (size_t i = 0; i < s->probes.size(); ++i) {
        Probe &item = *s->probes[i];
        if (!item.bare_module || item.warned_bare || item.active || item.retired || item.address ||
            !iequals(item.module, as_dll)) continue;
        item.warned_bare = true;
        const size_t bang = item.location.find('!');
        const std::string rest = item.location.substr(bang != std::string::npos ? bang : item.location.rfind('+'));
        std::fprintf(stderr, "probe: warning: %s names %s (a module name without extension means .dll); "
                             "the loaded %s is not matched -- write %s%s to probe it\n",
                     item.location.c_str(), item.module.c_str(), module.c_str(), module.c_str(),
                     rest.c_str());
    }
}

// Launch-time probes that fail to arm fail the session (the user asked for them up
// front). A probe added at runtime -- possibly pending on a module that loads much
// later -- only reports its failure and retires; the run and other probes continue.
static bool arm_module(probe_session *s, const std::string &module, uint64_t base) {
    // Detaching: a module loading while the detach drains its last events must not get a
    // fresh INT3 / debug register / hook after everything was removed (seen: a DLL that
    // reloaded during the drain kept its new INT3 and the detached target died on it).
    if (s->detaching) return true;
    warn_bare_module(s, module);
    bool all_ok = true;
    for (size_t i = 0; i < s->probes.size(); ++i) {
        Probe &item = *s->probes[i];
        if (item.active || item.retired || item.address || !iequals(item.module, module)) continue;
        if (!(item.flags & PROBE_INLINE) && guard_pending(s)) continue;   // armed by guard_set_ready
        std::string saved = s->error;
        bool ok = false;
        try { ok = arm_probe(s, item, base); }
        catch (const std::exception &e) { set_error(s, std::string("arm ") + item.location + ": " + e.what()); }
        if (ok) continue;
        if (item.runtime) {
            std::fprintf(stderr, "probe: runtime probe %s failed to arm: %s\n", item.location.c_str(), s->error.c_str());
            s->error = saved; item.retired = true; continue;
        }
        all_ok = false;   // keep arming the module's other probes; the session still fails
    }
    return all_ok;
}

// The guard is up (or will not come): arm the breakpoint/hw probes held back until now.
static void guard_sync(probe_session *s);
// Called BEFORE the controller suspends a thread it does not resume within the same few
// instructions: the guard's held list gets the thread first, so a controller killed between
// the suspension and the next guard_sync still has it resumed (an entry for a thread that was
// never suspended, or already resumed, costs a no-op ResumeThread). guard_sync rewrites the
// list from the session's own bookkeeping after every event.
static void guard_note_hold(probe_session *s, DWORD tid) {
    if (!s->attached || !s->shared || s->detached || !tid) return;
    auto &g = s->shared->guard;
    const LONG n = g.held_count;
    if (n < 0 || n >= (LONG)PROBE_AGENT_GUARD_TIDS) return;
    g.held_tids[n] = tid;
    MemoryBarrier();
    g.held_count = n + 1;
}
static bool guard_set_ready(probe_session *s, const char *why) {
    if (s->guard_ready) return true;
    s->guard_ready = true;
    if (why) std::fprintf(stderr, "probe: warning: controller-death guard unavailable (%s): "
                                  "breakpoint/hw probes armed without it\n", why);
    bool ok = true;
    std::vector<std::pair<std::string, uint64_t>> mods(s->module_bases.begin(), s->module_bases.end());
    for (auto &m : mods) ok = arm_module(s, m.first, m.second) && ok;
    guard_sync(s);
    return ok;
}

static void guard_sync(probe_session *s) {
    if (!s->attached || !s->shared || s->detached) return;
    // (Armed INT3s: the INT3 table, kept current by sync_int3_table.)
    auto &g = s->shared->guard;
    uint32_t n = 0;
    for (auto &kv : s->stepping) if (n < PROBE_AGENT_GUARD_TIDS) g.step_tids[n++] = kv.first;
    g.step_count = (LONG)n;
    n = 0;
    for (const auto *list : {&s->held, &s->ipc_frozen, &s->call_deferred})
        for (HANDLE t : *list)
            if (const DWORD tid = GetThreadId(t); tid && n < PROBE_AGENT_GUARD_TIDS) g.held_tids[n++] = tid;
    for (const auto &e : s->inplace_suspended)          // an in-place step window's suspensions
        if (n < PROBE_AGENT_GUARD_TIDS) g.held_tids[n++] = e.first;
    for (DWORD tid : s->detach_frozen) if (n < PROBE_AGENT_GUARD_TIDS) g.held_tids[n++] = tid;
    // The threads whose events are being handled, and a call_original/call_func thread: a
    // 32-bit (WOW64) controller's Get/SetThreadContext on another thread is an implicit
    // suspend + resume inside the call, so a controller killed in the middle of one leaves
    // that thread suspended once with nothing of ours recording it (seen on x86: a thread
    // parked for good at its NtOpenProcess hit). One resume for each covers it -- a no-op
    // for a thread that is not suspended.
    for (DWORD tid : s->handling) if (n < PROBE_AGENT_GUARD_TIDS) g.held_tids[n++] = tid;
    if (s->in_call_tid && n < PROBE_AGENT_GUARD_TIDS) g.held_tids[n++] = s->in_call_tid;
    g.held_count = (LONG)n;
    n = 0;
    for (uint64_t b : s->scratch_blocks) if (n < PROBE_AGENT_GUARD_BLOCKS) g.blocks[n++] = b;
    g.block_count = (LONG)n;
    g.dr_mask = s->dr_ever | s->dr_used;          // incl. a call_original's return-catch slot
    MemoryBarrier();
    g.enabled = 1;
}

// A lifted (in-place) breakpoint byte may only be re-armed while a breakpoint probe is
// still active at exactly that site: after detach, PROBE_ONCE retirement or an unload
// (where another module may now live at the address) the original byte must stay.
static Probe *probe_at(probe_session *s, uint64_t address);
// Is `copy` (read at `at`, starting with an INT3) the other tool's relocation of probe p's
// site? Its bytes after the INT3 must be the site's own following bytes, verbatim, up to a
// jump back into the original function at exactly the offset reached (the shape every
// trampoline has: relocated prologue + jmp site+n); or, without such a jump in view, at
// least 8 matching bytes.
static bool is_relocated_copy(const unsigned char *copy, size_t got, uint64_t at, const Probe &p) {
    ZydisDecoder dec; zydis_init(dec);
    size_t k = 1;
    while (k < got) {
        ZydisDecodedInstruction insn; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, copy + k, got - k, &insn, ops))) break;
        if (insn.mnemonic == ZYDIS_MNEMONIC_JMP && insn.operand_count_visible >= 1 && k >= 2) {
            ZyanU64 target = 0;
            if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[0], at + k, &target)))
                return target == p.address + k;                 // back to the same offset: our site's copy
            if (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY && insn.length == 6 && k + 6 + sizeof(void *) <= got &&
                ops[0].mem.base == ZYDIS_REGISTER_RIP && ops[0].mem.disp.value == 0) {   // jmp [rip+0]; dq target
                uint64_t dest = 0; std::memcpy(&dest, copy + k + 6, sizeof(void *));
                return dest == p.address + k;
            }
            return false;
        }
        if (k - 1 + insn.length > p.follow.size() || std::memcmp(copy + k, p.follow.data() + (k - 1), insn.length) != 0)
            return false;                                       // not the site's bytes, verbatim
        k += insn.length;
        if (k > 8) return true;                                 // long verbatim run: same code
    }
    return false;
}

// A hit on an adopted copy (see adopt_relocated_breakpoint) counts for the probe it stands in for.
static void count_hit(Probe *p) {
    ++p->hits;
    if (p->alias_of) ++p->alias_of->hits;
}

// Another hooking tool installed its inline hook on top of one of our breakpoint probes
// AFTER us (seen: Frida's Interceptor on a site UHH already holds): it read our 0xCC as part
// of the function, wrote its jump over the site, and copied the INT3 -- followed by the
// site's real bytes -- into its trampoline. That copy now traps at an address we do not own.
// Recognise it -- an INT3 in private executable memory, followed by exactly the bytes that
// followed our site, where our own site no longer holds our INT3 -- and adopt it: put the
// real byte back (the other tool's trampoline is then exactly what it meant to build) and
// arm our breakpoint THERE, same callback and config. Both tools keep seeing every call.
static Probe *adopt_relocated_breakpoint(probe_session *s, uint64_t at) {
    MEMORY_BASIC_INFORMATION m{};
    if (!VirtualQueryEx(s->pi.hProcess, (void *)(uintptr_t)at, &m, sizeof(m)) || m.State != MEM_COMMIT ||
        m.Type == MEM_IMAGE ||
        !(m.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)))
        return nullptr;
    unsigned char copy[16]; size_t got = 0;
    if (!remote_read(s->pi.hProcess, at, copy, sizeof(copy), &got) || got < 5 || copy[0] != 0xcc) return nullptr;
    for (auto &up : s->probes) {
        Probe &p = *up;
        if (!p.active || !(p.flags & PROBE_BREAKPOINT) || p.alias_of || p.internal || p.follow.size() < 4) continue;
        unsigned char now = 0; size_t one = 0;
        if (!remote_read(s->pi.hProcess, p.address, &now, 1, &one) || one != 1 || now == 0xcc) continue;   // still ours
        if (trace_enabled())
            std::fprintf(stderr, "  relocated? %s site_now=0x%02x copy=%s follow=%s\n", p.location.c_str(), now,
                         hex_bytes(copy, got).c_str(), hex_bytes(p.follow.data(), p.follow.size()).c_str());
        if (!is_relocated_copy(copy, got, at, p)) continue;
        auto a = std::make_unique<Probe>();
        a->location = p.location + " (relocated copy)";
        a->flags = p.flags & ~PROBE_ONCE; a->callback = p.callback; a->callback_export = p.callback_export;
        a->config = p.config;
        a->rva = at; a->internal = true; a->alias_of = &p;
        if (!patch(s->pi.hProcess, at, p.original)) return nullptr;    // the copy now runs the real code
        Probe *raw = a.get();
        s->probes.push_back(std::move(a));                              // returns before the loop goes on
        std::string saved = s->error;
        if (!arm_breakpoint(s, *raw, 0)) {                   // the copy now holds the real byte:
            raw->retired = true; s->error = saved;               // rewind onto it (stale-INT3 path)
            s->retired_bps.insert(at);
            return nullptr;
        }
        std::fprintf(stderr, "probe: %s was re-hooked by another tool that relocated our breakpoint to 0x%llx; "
                             "following it there\n", p.location.c_str(), (unsigned long long)at);
        return raw;
    }
    return nullptr;
}

static bool still_armed(probe_session *s, uint64_t site) {
    Probe *p = probe_at(s, site);
    return p && (p->flags & PROBE_BREAKPOINT);
}

// An in-place step at site is over: re-arm the INT3 (see the re-lift in handle_exception
// for a second thread that is still mid in-place step there).
static void end_inplace_step(probe_session *s, DWORD tid, uint64_t site) {
    (void)tid;
    if (still_armed(s, site)) rearm_breakpoint(s->pi.hProcess, site, probe_at(s, site)->original);
}

// ---- In-place window -------------------------------------------------------------------
// The few sites that are neither displaced nor emulated (see emulate_site: segment-relative or
// 16-bit branches, an access the CPU must fault on, CALL/RET under CET shadow stacks, a REP
// string op without scratch, ...) are stepped IN PLACE: our INT3 is lifted for one trap-flag
// step. While it is lifted, every OTHER thread of the target is suspended by us, so none can
// run through the site uncounted; a hit another thread raised just before (its event was
// already queued) is rewound onto the INT3 and replays after the window (handle_exception).
// No deadlock: the window covers exactly one instruction of the stepping thread (one REP
// iteration at a time for a string op), which reports its trap or its fault to us before any
// other code of the target runs -- it cannot wait for a suspended thread. The instructions
// that can block in the kernel (SYSCALL / INT 2E run from a trampoline instead; SYSENTER,
// INT 2B, far transfers that may switch to 64-bit code) never get a window, and a window not
// closed within 2 s (the target suspended the stepping thread itself) is released with a
// warning. Our agent's threads are never suspended (an entry hold waits for them).
static bool agent_thread(probe_session *s, DWORD tid);
static bool inplace_exempt(probe_session *s, DWORD tid) {
    if (s->remote_tid && tid == s->remote_tid) return true;
    if (!s->remote_agent) return false;
    if (auto it = s->agent_tid_cache.find(tid); it != s->agent_tid_cache.end()) return it->second;
    const bool a = agent_thread(s, tid);
    s->agent_tid_cache[tid] = a;
    return a;
}
static void inplace_suspend(probe_session *s, DWORD tid) {
    if (tid == s->inplace_owner || inplace_exempt(s, tid)) return;
    for (auto &e : s->inplace_suspended) if (e.first == tid) return;
    HANDLE t = OpenThread(THREAD_SUSPEND_RESUME, FALSE, tid);
    if (!t) return;
    guard_note_hold(s, tid);
    if (SuspendThread(t) == (DWORD)-1) { CloseHandle(t); return; }
    try { s->inplace_suspended.emplace_back(tid, t); } catch (...) { ResumeThread(t); CloseHandle(t); }
}
static void inplace_begin(probe_session *s, DWORD tid) {
    if (s->inplace_owner) return;            // ours already, or tid is held in another thread's
                                             // window and gets it handed over (inplace_sync)
    s->inplace_owner = tid; s->inplace_since = GetTickCount64();
    for (DWORD o : s->threads) if (o != tid) inplace_suspend(s, o);
}
static void inplace_release_all(probe_session *s) {
    for (auto &e : s->inplace_suspended) { ResumeThread(e.second); CloseHandle(e.second); }
    s->inplace_suspended.clear();
    s->inplace_owner = 0;
}
static void inplace_watchdog(probe_session *s) {
    if (!s->inplace_owner || GetTickCount64() - s->inplace_since < 2000) return;
    if (!s->inplace_warned) {
        s->inplace_warned = true;
        std::fprintf(stderr, "probe: warning: in-place step on thread %lu not done within 2 s: other threads released "
                             "(a call through that site meanwhile may be missed). Further cases are not reported.\n",
                     (unsigned long)s->inplace_owner);
    }
    if (auto it = s->stepping.find(s->inplace_owner); it != s->stepping.end()) {
        if (it->second.refire) {
            // A faulted instruction re-run without our trap flag did not fault again (the memory
            // changed meanwhile): it ran on with the byte lifted. Arm the site again.
            end_inplace_step(s, it->first, it->second.site);
            s->stepping.erase(it);
        } else {
            it->second.windowed = false;
        }
    }
    inplace_release_all(s);
}
// After every debug event: the window lasts exactly as long as its owner's in-place step.
static void inplace_sync(probe_session *s, const DEBUG_EVENT &ev) {
    if (ev.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT) s->agent_tid_cache.erase(ev.dwThreadId);
    if (!s->inplace_owner) return;
    if (ev.dwDebugEventCode == CREATE_THREAD_DEBUG_EVENT) inplace_suspend(s, ev.dwThreadId);   // born in the window
    auto pending = [&](DWORD tid) {
        auto it = s->stepping.find(tid);
        return it != s->stepping.end() && !it->second.displaced && it->second.windowed;
    };
    if (pending(s->inplace_owner)) { inplace_watchdog(s); return; }
    // Hand the window to another thread whose own in-place step is pending (it is held in
    // this window) without letting any other thread run in between.
    DWORD next = 0;
    for (auto &kv : s->stepping) if (kv.first != s->inplace_owner && pending(kv.first)) { next = kv.first; break; }
    if (!next) { inplace_release_all(s); return; }
    const DWORD prev = s->inplace_owner;
    s->inplace_owner = next; s->inplace_since = GetTickCount64();
    for (auto it = s->inplace_suspended.begin(); it != s->inplace_suspended.end(); ++it)
        if (it->first == next) { ResumeThread(it->second); CloseHandle(it->second); s->inplace_suspended.erase(it); break; }
    if (s->threads.count(prev)) inplace_suspend(s, prev);
}

// What an in-place step of the site needs: a pushed flags image to correct (PUSHF), and
// whether the instruction may block in the kernel or leave 32-bit code (then no window).
static void site_traits(const Probe &p, bool &pushf, bool &may_block) {
    pushf = false; may_block = false;
    ZydisDecoder dec;
#if defined(_WIN64)
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#endif
    ZydisDecodedInstruction in; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    if (p.orig_insn.empty() || !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, p.orig_insn.data(), p.orig_insn.size(), &in, ops))) {
        may_block = true; return;                           // unknown: stay as before (no window)
    }
    switch (in.mnemonic) {
        case ZYDIS_MNEMONIC_PUSHF: case ZYDIS_MNEMONIC_PUSHFD: case ZYDIS_MNEMONIC_PUSHFQ: pushf = true; break;
        case ZYDIS_MNEMONIC_SYSCALL: case ZYDIS_MNEMONIC_SYSENTER: case ZYDIS_MNEMONIC_IRET:
        case ZYDIS_MNEMONIC_IRETD: case ZYDIS_MNEMONIC_IRETQ: may_block = true; break;
        case ZYDIS_MNEMONIC_INT:
            may_block = ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && (ops[0].imm.value.u == 0x2E || ops[0].imm.value.u == 0x2B);
            break;
        default: break;
    }
    if (in.meta.branch_type == ZYDIS_BRANCH_TYPE_FAR) may_block = true;
}

// The active SOFTWARE-BREAKPOINT probe at an address (the owner of an INT3 there). Other
// backends may probe the same address too (hw + breakpoint on one instruction): an INT3
// must never be attributed to them -- that ran the hw callback a second time and then
// "re-armed" the site with the hw probe's (zero) original byte, corrupting the code.
static Probe *probe_at(probe_session *s, uint64_t address) {
    for (auto &p : s->probes)
        if (p->active && p->address == address && (p->flags & PROBE_BREAKPOINT)) return p.get();
    return nullptr;
}
static Probe *probe_any_at(probe_session *s, uint64_t address) {
    for (auto &p : s->probes) if (p->active && p->address == address) return p.get();
    return nullptr;
}

static uint32_t probe_index(probe_session *s, const Probe *probe) {
    for (size_t i = 0; i < s->probes.size(); ++i)
        if (s->probes[i].get() == probe) return (uint32_t)i;
    return 0;
}

// The loader finishes process initialisation with NtContinue on the initial thread's
// start context, which carries the debug registers captured at thread creation. Any
// hardware probe armed later in loader init (a static import such as ucrtbase loading)
// is silently wiped there. A library-owned one-shot breakpoint at the image entry point
// re-applies every active hardware probe to every thread right after that point.
static void reapply_all_hw(probe_session *s) {
    s->entry_reapply = 0;
    for (auto &p : s->probes) {
        if (!p->active || !(p->flags & PROBE_HW)) continue;
        uint32_t rw = 0, len = 0; hw_rw_len(p->flags, rw, len);
        for (DWORD tid : s->threads) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
            GuardTouch touch(s, tid);
            if (t) { set_dr_on_thread(t, p->dr_slot, p->address, true, rw, len); CloseHandle(t); }
        }
    }
}

static void reapply_hw(probe_context *c) {
    if (probe_session *s = get_session(c)) reapply_all_hw(s);
}

static void arm_entry_fixup(probe_session *s, uint64_t entry) {
    if (!entry) return;
    s->entry_reapply = entry; s->entry_addr = entry;
    if (probe_at(s, entry)) return;   // a user breakpoint is already there: it triggers the re-apply
    try {
        auto p = std::make_unique<Probe>();
        p->location = "<entry>"; p->flags = PROBE_BREAKPOINT | PROBE_ONCE; p->callback = reapply_hw;
        p->rva = entry; p->internal = true;
        Probe *raw = p.get(); s->probes.push_back(std::move(p));
        std::string saved = s->error;
        if (!arm_breakpoint(s, *raw, 0)) { raw->retired = true; s->error = saved; }
    } catch (...) {}
}

// The same NtContinue wipe hits EVERY thread, not just the initial one: a thread still in
// its loader initialisation (LdrInitializeThunk: DLL_THREAD_ATTACH, TLS) when a hardware
// probe is armed at runtime -- from a callback, or at a later DLL load -- resumes at
// ntdll!RtlUserThreadStart with the DR image captured when it was created, and never sees
// that probe (found by examples/famous retval_override: whole worker threads missed a
// return-site probe added while they were starting). A library-owned breakpoint at
// RtlUserThreadStart re-applies the active hardware probes to each thread arriving there,
// i.e. right after its context was restored. Armed the first time a hardware probe is
// armed while the process is already running.
static uint64_t resolve_symbol(probe_session *s, const char *symbol);
static void reapply_hw_thread(probe_session *s, DWORD tid) {
    if (!s->hw_active) return;
    HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
    if (!t) return;
    for (auto &p : s->probes) {
        if (!p->active || !(p->flags & PROBE_HW)) continue;
        uint32_t rw = 0, len = 0; hw_rw_len(p->flags, rw, len);
        set_dr_on_thread(t, p->dr_slot, p->address, true, rw, len);
    }
    CloseHandle(t);
}

static void thread_start_fixup(probe_context *c) {
    if (probe_session *s = get_session(c)) reapply_hw_thread(s, c->tid);
}

static void arm_thread_start_fixup(probe_session *s) {
    if (s->thread_start_fixup || !(s->entry_seen || s->attached)) return;
    uint64_t at = resolve_symbol(s, "ntdll.dll!RtlUserThreadStart");
    if (!at) return;
    s->thread_start_fixup = true;
    if (Probe *owner = probe_at(s, at)) { (void)owner; return; }   // a user probe owns the site: rare, left as is
    try {
        auto p = std::make_unique<Probe>();
        p->location = "<thread-start>"; p->flags = PROBE_BREAKPOINT; p->callback = thread_start_fixup;
        p->rva = at; p->internal = true;
        Probe *raw = p.get(); s->probes.push_back(std::move(p));
        std::string saved = s->error;
        if (!arm_breakpoint(s, *raw, 0)) { raw->retired = true; s->error = saved; }
    } catch (...) {}
}

extern "C" probe_session *probe_session_create(void) {
    try { return new probe_session; }
    catch (...) { std::fprintf(stderr, "probe: error: session allocation failed\n"); return nullptr; }
}

// Dynamic (post-launch) control-plane calls come from a callback while the target is
// stopped. A failure there returns 0 to the callback but must not poison the session's
// end-of-run status, so the error is logged and the previous error state restored.
struct DynamicScope {
    probe_session *s; std::string saved; bool dynamic;
    explicit DynamicScope(probe_session *ss) : s(ss), saved(ss->error), dynamic(ss->launched) {}
    int done(int ok) {
        if (dynamic && !ok) {
            std::fprintf(stderr, "probe: dynamic add failed: %s\n", s->error.c_str());
            s->error = saved;
        }
        return ok;
    }
};

// A probe added from INSIDE a callback (any backend) must have a named-export callback: an
// inline callback's control calls reach the controller by export name, so only exports can
// work there. Requiring it on every backend keeps one callback source portable (a static
// function used to work from a breakpoint/hw callback and return 0 from an inline one).
static bool callback_ok_from_callback(probe_session *s, probe_callback cb) {
    std::string name;
    if (!s->cb_tid || GetCurrentThreadId() != s->debug_tid || !cb || callback_export_name(cb, name)) return true;
    set_error(s, "a probe added from a callback needs a callback exported by name (dllexport)");
    return false;
}

// The export name(s) the agent resolves an inline probe's callback by (all names of a folded
// function that fit the request, see callback_export_names).
static bool inline_callback_names(probe_session *s, probe_callback cb, std::string &out) {
    std::string names;
    if (!callback_export_names(cb, names)) { set_error(s, "inline callback is not a named export"); return false; }
    out = export_names_fit(names, PROBE_AGENT_EXPORT_CAP);
    if (out.empty()) { set_error(s, "inline callback export name is too long"); return false; }
    return true;
}

static uint32_t hw_in_use(const probe_session *s) {
    uint32_t n = 0;
    for (auto &pp : s->probes) if ((pp->flags & PROBE_HW) && !pp->retired) ++n;
    return n;
}

static_assert(PROBE_AGENT_FLAG_UNSAFE_FAST_PATCH == PROBE_UNSAFE_FAST_PATCH, "agent flag mirror");
static bool check_flags(probe_session *s, uint32_t flags, bool allow_inline) {
    constexpr uint32_t types = PROBE_BREAKPOINT | PROBE_INLINE | PROBE_HW;
    constexpr uint32_t known = types | PROBE_AT_RETURN | PROBE_ALLOW_PREHOOKED | PROBE_FALLBACK_HW
                             | PROBE_WATCH_WRITE | PROBE_WATCH_RW | PROBE_ONCE | PROBE_UNSAFE_FAST_PATCH
                             | PROBE_ALLOW_UNSAFE_SITE;
    if (flags & ~known) { set_error(s, "unknown probe flags"); return false; }
    uint32_t type = flags & types;
    uint32_t watch = flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW);
    if ((type != PROBE_BREAKPOINT && type != PROBE_INLINE && type != PROBE_HW) || (flags & PROBE_AT_RETURN) ||
        ((flags & PROBE_ALLOW_PREHOOKED) && type != PROBE_INLINE) || // only meaningful for inline
        ((flags & PROBE_FALLBACK_HW) && type != PROBE_INLINE) ||     // fallback only modifies an inline probe
        ((flags & PROBE_UNSAFE_FAST_PATCH) && type != PROBE_INLINE) || // only inline hooks write code
        ((flags & PROBE_ALLOW_UNSAFE_SITE) && type != PROBE_INLINE) || // only inline hooks overwrite >1 byte
        (watch && type != PROBE_HW) ||                               // a watchpoint uses the DR/HW backend
        watch == (PROBE_WATCH_WRITE | PROBE_WATCH_RW) ||             // pick one access mode, not both
        ((flags & PROBE_ONCE) && type == PROBE_INLINE)) {            // one-shot needs a controller backend
        set_error(s, "requested probe type/options are unsupported in this build");
        return false;
    }
    (void)allow_inline;
    if (type == PROBE_HW && hw_in_use(s) >= 4) {
        set_error(s, "too many hardware probes (max 4 DR slots)"); return false;
    }
    if (type == PROBE_INLINE) {                            // the agent has a fixed number of hook slots
        size_t inl = 0; for (auto &pp : s->probes) if ((pp->flags & PROBE_INLINE) && !pp->retired) ++inl;
        if (inl >= PROBE_AGENT_MAX_PROBES) {
            set_error(s, "too many inline probes (max " + std::to_string(PROBE_AGENT_MAX_PROBES) + ")"); return false;
        }
    }
    return true;
}

extern "C" int probe_add_symbol_cfg(probe_session *s, const char *location, probe_callback callback,
                                    uint32_t flags, const void *config, size_t config_len) {
    if (!s) return 0;
    DynamicScope scope(s);
    if (s->exited) { set_error(s, "session already exited"); return 0; }
    if (!callback) { set_error(s, "probe callback is null"); return scope.done(0); }
    if (!callback_ok_from_callback(s, callback)) return scope.done(0);
    if (!check_flags(s, flags, !s->launched)) return scope.done(0);
    uint32_t type = flags & (PROBE_BREAKPOINT | PROBE_INLINE | PROBE_HW);
    if (config_len && !config) { set_error(s, "non-empty probe config is null"); return scope.done(0); }
    if ((uint64_t)config_len > UINT32_MAX) { set_error(s, "probe config is larger than 4 GB"); return scope.done(0); }
    try {
        auto p = std::make_unique<Probe>();
        if (!parse_location(s, location, *p)) return scope.done(0);
        p->callback = callback; p->flags = flags; p->runtime = s->launched;
        if (!bind_shared_callback(s, p->callback, flags)) return scope.done(0);
        if (type == PROBE_INLINE && !inline_callback_names(s, callback, p->callback_export)) return scope.done(0);
        if (config_len) {
            auto first = static_cast<const unsigned char *>(config);
            p->config.assign(first, first + config_len);
        }
        std::fprintf(stderr, "probe: pending %s\n", p->location.c_str());
        Probe *raw = p.get();
        s->probes.push_back(std::move(p));          // heap-stable: callbacks may add mid-iteration
        if (s->launched && type == PROBE_INLINE && !register_runtime_inline(s, *raw)) {
            raw->retired = true; return scope.done(0);
        }
        if (s->launched) {                          // runtime add: arm now if the module is mapped
            if (raw->bare_module) for (auto &kv : s->module_bases) warn_bare_module(s, kv.first);
            for (auto &kv : s->module_bases)
                if (iequals(kv.first, raw->module)) {
                    if (!arm_probe(s, *raw, kv.second)) { raw->retired = true; return scope.done(0); }
                    break;
                }
            if (type == PROBE_INLINE && raw->address && !kick_agent(s)) { raw->retired = true; return scope.done(0); }
        }
        return 1;
    } catch (const std::exception &e) { set_error(s, e.what()); return scope.done(0); }
}

extern "C" int probe_add_symbol(probe_session *s, const char *location, probe_callback callback, uint32_t flags) {
    return probe_add_symbol_cfg(s, location, callback, flags, nullptr, 0);
}

// Absolute-address probes only make sense once the process exists (ASLR), so they are a
// runtime operation: typically called from a callback with an address it just read.
static int add_absolute(probe_session *s, uint64_t address, probe_callback cb, uint32_t flags) {
    if (!s) return 0;
    DynamicScope scope(s);
    if (!s->launched || s->exited) { set_error(s, "absolute-address probes need a running target"); return scope.done(0); }
    if (!cb) { set_error(s, "probe callback is null"); return scope.done(0); }
    if (!callback_ok_from_callback(s, cb)) return scope.done(0);
    if (!check_flags(s, flags, false)) return scope.done(0);
    try {
        auto p = std::make_unique<Probe>();
        char loc[40]; std::snprintf(loc, sizeof(loc), "0x%llx", (unsigned long long)address);
        p->location = loc; p->flags = flags; p->callback = cb; p->rva = address; p->runtime = true;
        if (!bind_shared_callback(s, p->callback, flags)) return scope.done(0);
        if ((flags & PROBE_INLINE) && !inline_callback_names(s, cb, p->callback_export)) return scope.done(0);
        Probe *raw = p.get();
        s->probes.push_back(std::move(p));
        bool ok = (flags & PROBE_INLINE) ? register_runtime_inline(s, *raw) && resolve_inline(s, *raw, 0) && kick_agent(s)
                : (flags & PROBE_HW)     ? arm_hw(s, *raw, 0) : arm_breakpoint(s, *raw, 0);
        if (!ok) raw->retired = true;
        return scope.done(ok ? 1 : 0);
    } catch (const std::exception &e) { set_error(s, e.what()); return scope.done(0); }
}

extern "C" int probe_add_address(probe_session *s, uint64_t address, probe_callback cb, uint32_t flags) {
    if (s && (flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW))) {
        DynamicScope scope(s); set_error(s, "use probe_watch for data watchpoints"); return scope.done(0);
    }
    return add_absolute(s, address, cb, flags);
}

extern "C" int probe_watch(probe_session *s, uint64_t address, probe_callback cb, uint32_t flags) {
    uint32_t mode = flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW);
    if (s && (flags & ~(uint32_t)(PROBE_WATCH_WRITE | PROBE_WATCH_RW | PROBE_ONCE | PROBE_HW))) {
        DynamicScope scope(s); set_error(s, "probe_watch takes PROBE_WATCH_WRITE/RW and PROBE_ONCE only"); return scope.done(0);
    }
    if (s && (address & 3)) {
        DynamicScope scope(s); set_error(s, "probe_watch address must be 4-byte aligned (watches one dword)"); return scope.done(0);
    }
    return add_absolute(s, address, cb, PROBE_HW | (mode ? mode : (uint32_t)PROBE_WATCH_WRITE) | (flags & PROBE_ONCE));
}

static bool open_agent_section(probe_session *s, uint32_t count) {
    if (count && int3_armed(s) > PROBE_AGENT_INT3_CAP) { // the agent's INT3 copy could not hold them all
        set_error(s, "too many software breakpoints armed alongside inline probes (max " +
                     std::to_string(PROBE_AGENT_INT3_CAP) + ")");
        return false;
    }
    wchar_t name[64]; probe_agent_mapping_name(s->pi.dwProcessId, name);
    s->mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
                                    (DWORD)sizeof(probe_agent_shared), name);
    // ALREADY_EXISTS on attach: an agent from an earlier, detached session is still loaded
    // in the target and holds the section. It is quiescent (its hooks were removed and it
    // stopped logging at that detach), so the channel is reset below and reused; the
    // agent's init re-arms it. Anywhere else an existing section is not ours: refuse.
    if (!s->mapping || (GetLastError() == ERROR_ALREADY_EXISTS && !s->attached)) {
        set_error(s, win_error("create inline shared section")); return false;
    }
    s->shared = static_cast<probe_agent_shared *>(MapViewOfFile(
        s->mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(probe_agent_shared)));
    if (!s->shared) { set_error(s, win_error("map inline shared section")); return false; }
    std::memset(s->shared, 0, sizeof(*s->shared));
    s->shared->magic = PROBE_AGENT_MAGIC; s->shared->version = PROBE_AGENT_VERSION;
    s->shared->request_count = count;
    for (uint32_t i = 0; i < PROBE_AGENT_LOG_CAP; ++i) s->shared->logs[i].seq = i;   // ring: all free
    sync_int3_table(s);                                 // breakpoints armed before the channel existed
    s->shared->controller_pid = GetCurrentProcessId();
    s->shared->log_ipc = 1;                     // this debugger services PROBE_IPC_LOG (cleared before it leaves)
    // Benchmark-only knob (not API): compare inline extended-state handling strategies.
    if (const char *m = std::getenv("UHH_BENCH_XSTATE"))
        s->shared->xstate_mode = !std::strcmp(m, "none") ? 1 : !std::strcmp(m, "full") ? 2 :
                                 !std::strcmp(m, "noxsave") ? 3 : 0;   // 3: regress, a CPU without OSXSAVE
    if (s->attached) {          // the agent's guard waits on this handle (closes it itself)
        HANDLE dup = nullptr;
        if (DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), s->pi.hProcess, &dup, SYNCHRONIZE, FALSE, 0))
            s->shared->guard.controller_process = (LONG64)(uintptr_t)dup;
        s->guard_since = GetTickCount64();
    }
    start_drainer(s);
    wchar_t svc[64]; probe_agent_service_name(s->pi.dwProcessId, svc);
    s->svc_event = CreateEventW(nullptr, FALSE, FALSE, svc);
    return ensure_local_agent(s);
}

// A config larger than the request's inline buffer goes to a block allocated in the target
// (freed at close unless a callback may still read it), so an inline probe takes the same configs as a breakpoint/hw probe. If
// that block cannot be made, config_remote stays 0 and the agent refuses the request.
static void fill_request(probe_session *s, const Probe &p) {
    auto &request = s->shared->requests[p.agent_index]; request.flags = p.flags;
    request.config_len = (uint32_t)p.config.size();
    std::memcpy(request.callback, p.callback_export.c_str(), p.callback_export.size() + 1);   // '\n'-separated aliases
    if (p.config.size() <= PROBE_AGENT_CONFIG_CAP) {
        if (!p.config.empty()) std::memcpy(request.config, p.config.data(), p.config.size());
        return;
    }
    void *mem = VirtualAllocEx(s->pi.hProcess, nullptr, p.config.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    size_t wrote = 0;
    if (!mem) return;
    if (!remote_write(s->pi.hProcess, (uint64_t)(uintptr_t)mem, p.config.data(), p.config.size(), &wrote) ||
        wrote != p.config.size()) { VirtualFreeEx(s->pi.hProcess, mem, 0, MEM_RELEASE); return; }
    s->config_blocks.push_back((uint64_t)(uintptr_t)mem);
    request.config_remote = (uint64_t)(uintptr_t)mem;
}

static bool create_agent_channel(probe_session *s) {
    uint32_t count = 0;
    {
        std::lock_guard<std::mutex> lock(s->agent_mu);
        for (auto &m : s->agent_map) m = UINT32_MAX;
        for (size_t i = 0; i < s->probes.size(); ++i)
            if (s->probes[i]->flags & PROBE_INLINE) {
                if (count < PROBE_AGENT_MAX_PROBES) s->agent_map[count] = (uint32_t)i;
                s->probes[i]->agent_index = count++;
            }
    }
    if (!count && !s->attached) return true;
    if (count > PROBE_AGENT_MAX_PROBES) { set_error(s, "too many inline probes"); return false; }
    if (!open_agent_section(s, count)) return false;
    for (const auto &p : s->probes) if (p->flags & PROBE_INLINE) fill_request(s, *p);
    return true;
}

static bool start_agent_load(probe_session *s);
static bool start_agent_init(probe_session *s);
static bool agent_has_pending(const probe_session *s);
static bool accept_agent_install(probe_session *s);

// An inline probe added while the target runs (from a callback). It gets the next free
// request slot -- creating the channel on first use -- and is installed by the agent on
// a FRESH remote thread, never inside the calling callback: the installer freezes other
// threads, and the caller may hold locks (heap, loader) a frozen thread is waiting on.
// The calling thread is held until the agent confirms the hook (see pending_hold), so
// from the caller's point of view the add is synchronous.
static bool register_runtime_inline(probe_session *s, Probe &p) {
    if (!s->shared && !open_agent_section(s, 0)) return false;
    uint32_t idx = s->shared->request_count;
    if (idx >= PROBE_AGENT_MAX_PROBES) { set_error(s, "too many inline probes"); return false; }
    p.agent_index = idx; p.runtime = true;
    {
        std::lock_guard<std::mutex> lock(s->agent_mu);
        if (idx == 0) for (auto &m : s->agent_map) m = UINT32_MAX;
        s->agent_map[idx] = probe_index(s, &p);
    }
    fill_request(s, p);
    MemoryBarrier();
    s->shared->request_count = idx + 1;
    // Synchronous for the caller: the thread whose callback added the probe is held
    // (after its event is handled) until the agent confirms the hook, so its next call
    // through the new site is seen. Other threads run on; they were never promised it.
    if (s->cb_tid) s->pending_hold.push_back(s->cb_tid);
    return true;
}

// ---- Synchronous inline install -----------------------------------------------------
// An inline hook installed asynchronously races the target's first calls unless the
// target happens to wait. So threads that could reach an uninstalled site are HELD
// (suspended) until the agent confirms the install round: the main thread at the image
// entry point (the loader lock is free there, so the agent can still be loaded), and a
// thread that is loading a DLL with inline sites (it holds the loader lock, so the
// install is done by the agent's already-running service thread, never a new thread).
static bool inline_unconfirmed(const probe_session *s) {
    for (const auto &p : s->probes)
        if ((p->flags & PROBE_INLINE) && p->address && !p->active && !p->retired) return true;
    return false;
}

// Hold the main thread at the entry point while an inline install is outstanding OR
// while inline probes exist but the agent's service thread is not up yet: a module
// with an inline site may load at any moment after entry, and the thread loading it
// holds the loader lock -- only an already-running service thread can install then.
static bool inline_hold_needed(const probe_session *s) {
    if (inline_unconfirmed(s)) return true;
    return has_inline(s) && !(s->shared && s->shared->service_ready && s->svc_event);
}

// A thread of OUR agent (its service thread, started from the agent image): never hold it
// -- it may own the agent's install lock or be the one that must do the install.
static bool agent_thread(probe_session *s, DWORD tid) {
    if (!s->remote_agent) return false;
    using QueryFn = LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static auto query = reinterpret_cast<QueryFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
    HANDLE t = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!t || !query) { if (t) CloseHandle(t); return false; }
    PVOID start = nullptr;
    LONG st = query(t, 9 /*ThreadQuerySetWin32StartAddress*/, &start, sizeof(start), nullptr);
    CloseHandle(t);
    if (st < 0) return false;
    IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS nt{}; size_t got = 0;
    if (!remote_read(s->pi.hProcess, s->remote_agent, &dos, sizeof(dos), &got) || got != sizeof(dos) ||
        !remote_read(s->pi.hProcess, s->remote_agent + (uint32_t)dos.e_lfanew, &nt, sizeof(nt), &got) || got != sizeof(nt))
        return false;
    const uint64_t a = (uint64_t)(uintptr_t)start;
    return a >= s->remote_agent && a < s->remote_agent + nt.OptionalHeader.SizeOfImage;
}

static void hold_thread(probe_session *s, DWORD tid) {
    // While detaching, the drain dispatches queued events (CREATE_THREADs, gate hits) that
    // would otherwise place an install hold -- and its release (the agent confirming) may
    // never come before we let go: the target would be left with suspended threads after
    // the detach. No hooks are being installed any more anyway.
    if (s->detaching) return;
    // (QUERY_LIMITED: the controller-death guard mirrors held threads by id, GetThreadId.)
    HANDLE t = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!t) return;
    guard_note_hold(s, tid);
    DWORD prev = SuspendThread(t);
    if (prev == (DWORD)-1) { CloseHandle(t); return; }
    if (trace_enabled()) std::fprintf(stderr, "  hold tid=%lu prev_suspend=%lu\n", (unsigned long)tid, (unsigned long)prev);
    if (s->held.empty()) s->held_since = GetTickCount64();
    s->held.push_back(t);
    std::fprintf(stderr, "probe: holding thread %lu until inline installs confirm\n", (unsigned long)tid);
    if (trace_enabled()) std::fprintf(stderr, "  hold t=%llu\n", (unsigned long long)GetTickCount64());
}

// ---- Inline-install gates ------------------------------------------------------------
// A module with inline sites that loads while the target runs: rather than park the
// LOADING thread at its LOAD_DLL event (it is the loader's load owner; parking it is safe
// only because the agent's service thread never needs the loader once it runs -- it reports
// ready from its own code, after its loader thread-init), put a hardware execute breakpoint
// on each pending site.
// Whoever reaches a site before its hook is confirmed is held THERE (no loader locks),
// and resumes straight into the hook once it is in. No call is missed, nothing waits on
// the loader. Falls back to the old hold when the debug registers are all taken.
static bool arm_gates_for_pending(probe_session *s) {
    if (s->detaching) return true;                 // no new gates (nor holds) while letting go
    std::vector<uint64_t> sites;
    for (auto &p : s->probes)
        if ((p->flags & PROBE_INLINE) && p->address && !p->active && !p->retired) {
            bool gated = false;
            for (auto &g : s->gates) if (g.first == p->address) gated = true;
            if (!gated) sites.push_back(p->address);
        }
    std::vector<int> slots;
    const uint8_t foreign = sites.empty() ? 0 : target_slots_any(s);
    for (int slot = 0; slot < 4 && slots.size() < sites.size(); ++slot)
        if (!(s->dr_used & (1u << slot)) && !(foreign & (1u << slot))) slots.push_back(slot);
    if (slots.size() < sites.size()) return false;           // not enough DRs: caller holds instead
    for (size_t i = 0; i < sites.size(); ++i) {
        const int slot = slots[i];
        for (DWORD tid : s->threads) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
            GuardTouch touch(s, tid);
            if (t) { set_dr_on_thread(t, slot, sites[i], true); CloseHandle(t); }
        }
        s->dr_used |= (uint8_t)(1u << slot); s->dr_ever |= (uint8_t)(1u << slot);
        s->gates.push_back({sites[i], slot});
        if (trace_enabled()) std::fprintf(stderr, "  gate 0x%llx DR%d\n", (unsigned long long)sites[i], slot);
    }
    return true;
}

static void clear_gates(probe_session *s) {
    for (auto &g : s->gates) {
        for (DWORD tid : s->threads) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
            GuardTouch touch(s, tid);
            if (t) { set_dr_on_thread(t, g.second, 0, false); CloseHandle(t); }
        }
        s->dr_used &= (uint8_t)~(1u << g.second);
        retire_hw_address(s, g.first);                       // a #DB already in flight is stale
    }
    s->gates.clear();
}

// A gate fired: hold this thread at the site until the hook is confirmed.
static bool handle_gate(probe_session *s, const DEBUG_EVENT &event) {
    if (s->gates.empty()) return false;
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
    if (!thread) return false;
    CONTEXT c{}; c.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    bool hit = false;
    if (GetThreadContext(thread, &c)) {
        for (auto &g : s->gates)
            if (c.Dr6 & (1u << g.second)) { hit = true; c.Dr6 &= ~(DWORD64)(1u << g.second); }
        if (hit) { c.EFlags |= 0x10000u; SetThreadContext(thread, &c); }   // RF: run the site once resumed
    }
    CloseHandle(thread);
    if (hit) hold_thread(s, event.dwThreadId);
    return hit;
}

static void release_held(probe_session *s, const char *why) {
    clear_gates(s);                                          // hooks confirmed (or giving up): gates go first
    if (s->held.empty()) return;
    for (HANDLE t : s->held) {
        DWORD prev = ResumeThread(t);
        if (trace_enabled()) std::fprintf(stderr, "  release tid=%lu prev_suspend=%lu\n", (unsigned long)GetThreadId(t), (unsigned long)prev);
        CloseHandle(t);
    }
    std::fprintf(stderr, "probe: released %zu held thread(s) (%s)\n", s->held.size(), why);
    s->held.clear();
}

static bool vet_pending_inline(probe_session *s);

// Start (or queue) agent work for pending inline requests.
static bool kick_agent(probe_session *s) {
    if (s->detaching) return true;                 // the session is letting go: install nothing more
    if (s->shared && s->shared->service_ready && s->svc_event) {     // persistent service thread
        if (trace_enabled()) std::fprintf(stderr, "  vet start t=%llu\n", (unsigned long long)GetTickCount64());
        if (!vet_pending_inline(s)) return false;
        if (trace_enabled()) std::fprintf(stderr, "  vet end t=%llu\n", (unsigned long long)GetTickCount64());
        if (trace_enabled()) std::fprintf(stderr, "  kick service t=%llu\n", (unsigned long long)GetTickCount64());
        SetEvent(s->svc_event); return true;
    }
    if (s->remote_work != probe_session::REMOTE_NONE) return true;   // picked up when it finishes
    if (!s->remote_agent) return start_agent_load(s);
    return start_agent_init(s);
}

static bool same_bitness(probe_session *s, HANDLE process);
extern "C" int probe_launch(probe_session *s, char *const argv[]) {
    if (!s || !argv || !argv[0]) { if (s) set_error(s, "launch argv is empty"); return 0; }
    if (s->launched) { set_error(s, "session already launched"); return 0; }
    s->error.clear();          // a refused probe_add already reported itself (returned 0)
    try {
        std::string command;
        for (size_t i = 0; argv[i]; ++i) { if (i) command += ' '; command += quote_arg(argv[i]); }
        // The target gets the controller's own stdin, exactly as if it had been started
        // without UHH (a filter reading stdin to EOF must see the caller's stream). Its
        // stdout/stderr are the controller's too when those are a console (or NUL); when they
        // are a pipe or a file, the target writes into its own pipe and UHH forwards its bytes
        // line-wise, so the live log records never land inside one of its lines. A stdout and
        // stderr that are one stream (2>&1) share one pipe: their relative order is kept.
        STARTUPINFOA si{}; si.cb = sizeof(si); si.dwFlags = STARTF_USESTDHANDLES;
        si.hStdInput = GetStdHandle(STD_INPUT_HANDLE); si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        HANDLE client_out = INVALID_HANDLE_VALUE, client_err = INVALID_HANDLE_VALUE;
        const bool fwd_out = forwardable(si.hStdOutput), fwd_err = forwardable(si.hStdError);
        const bool one_stream = fwd_out && fwd_err && same_object(si.hStdOutput, si.hStdError);
        if (fwd_out) {
            if (!make_forward_pipe(s->fwd_out.pipe, client_out)) { set_error(s, win_error("create target stdout pipe")); return 0; }
            s->fwd_out.dst = si.hStdOutput; s->fwd_out.to_stdout = true; s->fwd_out_active = true;
            si.hStdOutput = client_out;
            if (one_stream) si.hStdError = client_out;
        }
        if (fwd_err && !one_stream) {
            if (!make_forward_pipe(s->fwd_err.pipe, client_err)) {
                if (client_out != INVALID_HANDLE_VALUE) CloseHandle(client_out);
                forward_stop(s); s->fwd_out_active = false;
                set_error(s, win_error("create target stderr pipe")); return 0;
            }
            s->fwd_err.dst = si.hStdError;
            si.hStdError = client_err;
        }
        // A process created under a debugger gets the NT debug heap (fill patterns,
        // different layout): the target must run exactly as it would without UHH.
        char prev_ndh[16] = {0};
        DWORD had_ndh = GetEnvironmentVariableA("_NO_DEBUG_HEAP", prev_ndh, sizeof(prev_ndh));
        SetEnvironmentVariableA("_NO_DEBUG_HEAP", "1");
        BOOL ok = CreateProcessA(argv[0], command.data(), nullptr, nullptr, TRUE,
                                 DEBUG_ONLY_THIS_PROCESS, nullptr, nullptr, &si, &s->pi);
        SetEnvironmentVariableA("_NO_DEBUG_HEAP", had_ndh && had_ndh < sizeof(prev_ndh) ? prev_ndh : nullptr);
        DWORD launch_error = GetLastError();
        // Only the target (and what it hands them to) holds the write ends: end of file
        // arrives when its tree closes them.
        if (client_out != INVALID_HANDLE_VALUE) CloseHandle(client_out);
        if (client_err != INVALID_HANDLE_VALUE) CloseHandle(client_err);
        if (!ok) {
            forward_stop(s); s->fwd_out_active = false;
            SetLastError(launch_error); set_error(s, win_error("debug launch")); return 0;
        }
        if (!same_bitness(s, s->pi.hProcess)) {
            TerminateProcess(s->pi.hProcess, 3);
            CloseHandle(s->pi.hThread); CloseHandle(s->pi.hProcess); s->pi = {};
            return 0;
        }
        s->launched = true;
        s->debug_tid = GetCurrentThreadId();
        if (!start_log_output(s)) { TerminateProcess(s->pi.hProcess, 3); return 0; }
        if (!forward_start(s, &s->fwd_out) || !forward_start(s, &s->fwd_err)) {
            set_error(s, "target output forwarder creation failed"); TerminateProcess(s->pi.hProcess, 3); return 0;
        }
        { std::string which; s->sym_ready = uhh_sym::init(s->pi.hProcess, which);
          std::fprintf(stderr, "probe: symbols via %s%s\n", which.c_str(), uhh_sym::has_symbol_server() ? " (symbol server capable)" : ""); }
        if (!create_agent_channel(s)) { TerminateProcess(s->pi.hProcess, 3); return 0; }
        if (!has_inline(s)) s->inline_ready = true;
        return 1;
    } catch (const std::exception &e) { set_error(s, e.what()); return 0; }
}

// The controller and target must be the same bitness: callbacks run with the controller's
// view of registers, argument slots and pointer width. A mismatch would silently produce
// garbage, so refuse it up front.
static bool same_bitness(probe_session *s, HANDLE process) {
    BOOL me = FALSE, it = FALSE;
    if (!IsWow64Process(GetCurrentProcess(), &me) || !IsWow64Process(process, &it)) return true;   // cannot tell
    if (me == it) return true;
    set_error(s, it ? "target is a 32-bit (WOW64) process: use the x86 build of UHH"
                    : "target is a 64-bit process: use the x64 build of UHH");
    return false;
}

extern "C" int probe_attach(probe_session *s, uint32_t pid) {
    if (!s) return 0;
    if (s->launched) { set_error(s, "session already launched"); return 0; }
    s->error.clear();          // a refused probe_add already reported itself (returned 0)
    s->pi.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!s->pi.hProcess) { set_error(s, win_error("open target process")); return 0; }
    if (!same_bitness(s, s->pi.hProcess)) { CloseHandle(s->pi.hProcess); s->pi.hProcess = nullptr; return 0; }
    // Kill-on-exit OFF before the attach exists: DebugActiveProcess creates the thread's debug
    // object with kill-on-close set, so a controller ended in between (Ctrl+C during the
    // attach) took the target down with it (exit 0xC0000354). Create the object first.
    {
        using ConnectFn = LONG(NTAPI *)();
        auto connect = reinterpret_cast<ConnectFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "DbgUiConnectToDbg"));
        if (connect && connect() >= 0) DebugSetProcessKillOnExit(FALSE);
    }
    if (!DebugActiveProcess(pid)) {
        set_error(s, win_error("attach debugger")); CloseHandle(s->pi.hProcess); s->pi.hProcess = nullptr; return 0;
    }
    DebugSetProcessKillOnExit(FALSE);              // our exit must never take the target down
    s->debug_tid = GetCurrentThreadId();
    s->pi.dwProcessId = pid;
    s->attached = true; s->launched = true; s->inline_ready = true;
    // A failure below lets go of the target at once and leaves the session NOT attached: a
    // probe_close (from any thread) then has nothing to detach and no probe_run to wait for.
    auto fail = [&] {
        DebugActiveProcessStop(pid);
        s->attached = s->launched = false; s->debug_tid = 0;
        return 0;
    };
    if (!start_log_output(s)) return fail();
    { std::string which; s->sym_ready = uhh_sym::init(s->pi.hProcess, which); }
    if (!create_agent_channel(s)) return fail();
    return 1;
}

static void snapshot_pids(const char *name, std::unordered_set<DWORD> &out, DWORD *newest_new,
                          const std::unordered_set<DWORD> *exclude) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    wchar_t wname[MAX_PATH]{};
    MultiByteToWideChar(CP_UTF8, 0, name, -1, wname, MAX_PATH);
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    for (BOOL more = Process32FirstW(snap, &pe); more; more = Process32NextW(snap, &pe)) {
        if (_wcsicmp(pe.szExeFile, wname)) continue;
        out.insert(pe.th32ProcessID);
        if (newest_new && exclude && !exclude->count(pe.th32ProcessID)) {
            // Several new instances can appear in one snapshot (e.g. the target and the
            // helpers it spawns with the same image name): take the EARLIEST created.
            auto created = [](DWORD pid) -> ULONGLONG {
                HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
                FILETIME c{}, e{}, k{}, u{};
                ULONGLONG t = ~0ull;
                if (h && GetProcessTimes(h, &c, &e, &k, &u)) t = ((ULONGLONG)c.dwHighDateTime << 32) | c.dwLowDateTime;
                if (h) CloseHandle(h);
                return t;
            };
            if (!*newest_new || created(pe.th32ProcessID) < created(*newest_new)) *newest_new = pe.th32ProcessID;
        }
    }
    CloseHandle(snap);
}

extern "C" int probe_attach_new(probe_session *s, const char *image_name, uint32_t timeout_ms) {
    if (!s) return 0;
    if (!image_name || !*image_name) { set_error(s, "attach_new needs an image name"); return 0; }
    std::unordered_set<DWORD> existing; snapshot_pids(image_name, existing, nullptr, nullptr);
    std::fprintf(stderr, "probe: waiting for a new %s (%zu already running, ignored)\n", image_name, existing.size());
    timeBeginPeriod(1);                               // ~1 ms polling granularity
    ULONGLONG start = GetTickCount64();
    DWORD pid = 0;
    while (!pid) {
        std::unordered_set<DWORD> now; snapshot_pids(image_name, now, &pid, &existing);
        if (pid) break;
        if (timeout_ms && GetTickCount64() - start > timeout_ms) break;
        Sleep(1);
    }
    timeEndPeriod(1);
    if (!pid) { set_error(s, std::string("no new ") + image_name + " appeared"); return 0; }
    std::fprintf(stderr, "probe: new %s pid %lu -> attaching\n", image_name, (unsigned long)pid);
    return probe_attach(s, pid);
}

// Detach from an attached, still-running target leaving it exactly as it ran before:
// inline hooks removed by the agent, every INT3 restored, every debug register cleared,
// and no thread left mid single-step. Events keep being dispatched while that happens
// (a thread may hit a breakpoint or finish a step in the meantime).
// Debug events are per DEBUGGER THREAD, not per session: a thread that ran an earlier
// session can still have that (terminated) target's last events queued. They belong to
// another process -- continue them untouched and never let them reach this session's state.
static bool continue_foreign_event(const probe_session *s, const DEBUG_EVENT &ev) {
    if (ev.dwProcessId == s->pi.dwProcessId) return false;
    if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
    if (ev.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
    ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId,
                       ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT ? DBG_EXCEPTION_NOT_HANDLED : DBG_CONTINUE);
    return true;
}

static void pump(probe_session *s, DWORD ms) {
    DEBUG_EVENT event{};
    ULONGLONG until = GetTickCount64() + ms;
    while (!s->exited && GetTickCount64() < until) {
        if (!WaitForDebugEvent(&event, 20)) continue;
        if (continue_foreign_event(s, event)) continue;
        DWORD disposition = DBG_CONTINUE;
        dispatch_event(s, event, disposition);
        if (s->skip_continue) { s->skip_continue = false; continue; }
        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, disposition);
        if (s->remote_work == probe_session::REMOTE_NONE && s->stepping.empty() && ms == 0) break;
    }
}

static void ipc_thaw(probe_session *s);
static void pump(probe_session *s, DWORD ms);
static void detach(probe_session *s) {
    s->error.clear();
    // From here on nothing may start new agent work, arm anything, gate or hold a thread: the
    // event pumping below dispatches events (an agent load completing, a DLL with pending
    // sites loading, the initial breakpoint) that would otherwise start an init AFTER the stop
    // -- hooks installed into the target we are detaching from (seen: Ctrl+C 50 ms into an
    // inline attach left every hook live) -- or re-hold threads the agent's work then waits on.
    s->detaching = true;
    release_held(s, "detach");
    // Agent work in flight (load/init on a remote thread): let it finish first, or its hooks
    // would land AFTER the agent was told to stop -- live hooks in a detached process.
    for (ULONGLONG until = GetTickCount64() + 5000;
         s->remote_work != probe_session::REMOTE_NONE && !s->exited && GetTickCount64() < until; )
        pump(s, 20);
    if (s->remote_work != probe_session::REMOTE_NONE && s->shared) {
        // Still not done (e.g. the target holds its loader lock, so the remote thread cannot
        // even start). It may run after we are gone: tell the agent the session is over, so a
        // late init installs nothing into the detached target.
        std::fprintf(stderr, "probe: detach: agent work still pending after 5 s; it will install nothing\n");
        InterlockedExchange(&s->shared->controller_gone, 1);
    }
    // The stop runs even then: an init that already wrote hooks but cannot finish (its thread
    // exit waits on the loader) would otherwise leave them live. If the stop cannot run within
    // the wait either, it runs whenever the target lets it -- then without us (the agent
    // freezes in-process for a session that is over).
    if (s->remote_agent && s->local_agent) {
        auto local_stop = reinterpret_cast<uintptr_t>(GetProcAddress(s->local_agent, "probe_agent_stop"));
        if (local_stop) {
            uint64_t remote_stop = s->remote_agent + local_stop - reinterpret_cast<uintptr_t>(s->local_agent);
            HANDLE t = CreateRemoteThread(s->pi.hProcess, nullptr, 0,
                                          reinterpret_cast<LPTHREAD_START_ROUTINE>((uintptr_t)remote_stop), nullptr, 0, nullptr);
            if (t) {                                   // keep dispatching until it has run
                ULONGLONG until = GetTickCount64() + 5000;
                while (!s->exited && WaitForSingleObject(t, 0) == WAIT_TIMEOUT && GetTickCount64() < until) pump(s, 20);
                s->detached_hooks = WaitForSingleObject(t, 0) == WAIT_OBJECT_0;
                CloseHandle(t);
            }
        }
    }
    ipc_thaw(s);                                      // never leave an agent hook-write freeze behind
    // From here no target thread may run until the debugger is gone: a thread could hit an
    // INT3 or debug register just before it is removed, and an event still queued at
    // DebugActiveProcessStop would reach the target as an unhandled exception.
    std::vector<HANDLE> frozen;
    for (DWORD tid : s->threads) {
        HANDLE t = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT |
                              THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
        if (!t) continue;
        guard_note_hold(s, tid);
        if (SuspendThread(t) == (DWORD)-1) { CloseHandle(t); continue; }
        frozen.push_back(t);
        s->detach_frozen.push_back(tid);
    }
    for (auto &p : s->probes) {
        if (!p->active) continue;
        if (p->flags & PROBE_BREAKPOINT) {
            restore_original(s->pi.hProcess, p->address, p->original);
            s->retired_bps.insert(p->address); p->active = false; sync_int3_table(s);
        } else if (p->flags & PROBE_HW) {
            release_hw(s, *p);
        }
    }
    // Drain everything already queued: stale INT3 hits are rewound onto the restored
    // instruction, stale #DBs are swallowed, finished steps land. (Continuing an event of
    // a suspended thread leaves it suspended.)
    // Let the threads RUN while draining: a thread can be caught (frozen) between raising
    // an exception and its delivery to the debugger -- on WOW64 the 32-bit exception is
    // first processed by the 64-bit layer in user mode -- and such an event would only
    // surface after we let go. With every probe already removed nothing new can trap, so
    // run until the queue has been quiet for 200 ms: everything in flight lands here.
    for (HANDLE t : frozen) ResumeThread(t);
    s->detach_frozen.clear(); guard_sync(s);
    // Only EXCEPTIONS are what this waits for: a target that keeps creating threads or
    // loading DLLs never goes quiet in thread/module events (that kept a detach busy for
    // minutes), so those are handled but do not extend the wait -- and the whole drain is
    // bounded in time as well (an exception-heavy target of its own).
    int drained_logged = 0;
    const ULONGLONG drain_until = GetTickCount64() + 5000;
    ULONGLONG last_exception = GetTickCount64();
    for (int guard = 0; guard < 100000 && !s->exited && GetTickCount64() < drain_until &&
                        GetTickCount64() - last_exception < 200; ++guard) {
        DEBUG_EVENT ev{};
        if (!WaitForDebugEvent(&ev, 50)) continue;
        if (continue_foreign_event(s, ev)) continue;
        if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) last_exception = GetTickCount64();
        if (ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT && drained_logged < 24) {
            ++drained_logged;
            std::fprintf(stderr, "probe: detach-drain tid=%lu code=0x%lx addr=0x%llx first=%lu\n",
                         (unsigned long)ev.dwThreadId, (unsigned long)ev.u.Exception.ExceptionRecord.ExceptionCode,
                         (unsigned long long)(uintptr_t)ev.u.Exception.ExceptionRecord.ExceptionAddress,
                         (unsigned long)ev.u.Exception.dwFirstChance);
        }
        DWORD disposition = DBG_CONTINUE;
        dispatch_event(s, ev, disposition);
        if (s->skip_continue) { s->skip_continue = false; continue; }
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, disposition);
    }
    for (HANDLE t : frozen) {                                // freeze again for the fix-ups below
        const DWORD tid = GetThreadId(t);
        guard_note_hold(s, tid);
        SuspendThread(t);
        s->detach_frozen.push_back(tid);
    }
    // A thread still mid single-step: put it on the real instruction stream (the INT3 is
    // gone) with the trap flag clear.
    for (auto &kv : s->stepping) {
        HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, kv.first);
        CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL;
        GuardTouch touch(s, kv.first);
        if (t && GetThreadContext(t, &w)) {
#if defined(_WIN64)
            uint64_t ip = w.Rip;
#else
            uint64_t ip = w.Eip;
#endif
            if (kv.second.displaced && kv.second.scratch && ip >= kv.second.scratch &&
                ip <= kv.second.scratch + kv.second.insn_len)
                ip = kv.second.site + (ip - kv.second.scratch);     // not yet run -> site; run -> site+len
#if defined(_WIN64)
            w.Rip = ip;
#else
            w.Eip = (DWORD)ip;
#endif
            w.EFlags &= ~0x100u;
            SetThreadContext(t, &w);
        }
        if (t) CloseHandle(t);
    }
    s->stepping.clear();
    inplace_release_all(s);                                 // every INT3 is gone: nothing to hold for
    // Final pass, after every queued event has been continued: continuing an event can
    // restore the debug registers captured when the exception was raised. Clear our DR
    // slots and the trap flag on every frozen thread one last time, right before letting go.
    std::string report_tids;
    for (HANDLE t : frozen) {
        CONTEXT w{}; w.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;
        GuardTouch touch(s, GetThreadId(t));                 // (frozen handles carry query rights)
        BOOL got = FALSE; DWORD why = 0;
        for (int attempt = 0; attempt < 200 && !(got = GetThreadContext(t, &w)); ++attempt) {
            why = GetLastError();
            DWORD code = 0;
            if (GetExitCodeThread(t, &code) && code != STILL_ACTIVE) break;   // exited: nothing to clear
            Sleep(1);                                                           // transient: retry
        }
        if (!got) {
            DWORD code = 0;
            bool gone = GetExitCodeThread(t, &code) && code != STILL_ACTIVE;
            if (!gone) report_tids += " " + std::to_string(GetThreadId(t)) + ":getfail=" + std::to_string(why);
            continue;
        }
        for (int slot = 0; slot < 4; ++slot) {
            if (!(s->dr_ever & (1u << slot))) continue;
            w.Dr7 &= ~((DWORD64)3 << (slot * 2)) & ~((DWORD64)0xF << (16 + slot * 4));
            switch (slot) { case 0: w.Dr0 = 0; break; case 1: w.Dr1 = 0; break; case 2: w.Dr2 = 0; break; default: w.Dr3 = 0; }
        }
        w.Dr6 = 0;
        // No slot left enabled: drop the exact-match bits too (WOW64 leaves LE set once a DR was
        // used, seen as dr7=0x100 on every thread of a detached 32-bit target).
        if (!(w.Dr7 & 0xFF)) w.Dr7 &= ~(decltype(w.Dr7))0x300;
        w.EFlags &= ~0x100u;
        BOOL set_ok = SetThreadContext(t, &w);
        CONTEXT v{}; v.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(t, &v);
        if (!set_ok || (v.Dr7 & 0xFF))
            report_tids += " " + std::to_string(GetThreadId(t)) + ":dr7=" + std::to_string((unsigned long long)v.Dr7) +
                           (set_ok ? "" : ":setfail");
    }
    {   // threads the debugger knows about but could not freeze
        std::unordered_set<DWORD> fz;
        for (HANDLE t : frozen) fz.insert(GetThreadId(t));
        for (DWORD tid : s->threads) if (!fz.count(tid)) report_tids += " " + std::to_string(tid) + ":notfrozen";
    }
    std::fprintf(stderr, "probe: detach: %zu thread(s) frozen;%s\n", frozen.size(),
                 report_tids.empty() ? " all clean" : report_tids.c_str());
    release_held(s, "detach (late)");                    // belt and braces: never leave a hold behind
    // No PROBE_IPC_LOG may be raised once the debugger is gone (it would reach the program).
    if (s->shared) { InterlockedExchange(&s->shared->log_ipc, 0); InterlockedExchange(&s->shared->ring_stalled, 0); }
    if (s->shared) {            // everything is restored: the guard has nothing left to protect
        auto &g = s->shared->guard;
        g.enabled = 0; g.step_count = g.held_count = g.block_count = 0;
        MemoryBarrier();
        // Its handle to us, if the agent never took it (no agent loaded): close it in the target.
        if (HANDLE h = (HANDLE)(uintptr_t)InterlockedExchange64(&g.controller_process, 0))
            DuplicateHandle(s->pi.hProcess, h, nullptr, nullptr, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
    }
    if (!s->exited) DebugActiveProcessStop(s->pi.dwProcessId);
    for (HANDLE t : frozen) { ResumeThread(t); CloseHandle(t); }
    s->detach_frozen.clear();
    // The final drain runs with the threads RUNNING: one the freeze caught between claiming a
    // ring slot and publishing it finishes the record first (frozen, it would be lost).
    stop_drainer(s);
    std::fprintf(stderr, "probe: detached from pid %lu\n", (unsigned long)s->pi.dwProcessId);
}

// Per-thread out-of-line step buffer in the target (executable), allocated on demand.

// Reserve+commit one 64 KiB block as close as possible to `site` (within +-2 GiB on x64).
static uint64_t alloc_block_near(probe_session *s, uint64_t site) {
#if defined(_WIN64)
    const uint64_t gran = 0x10000, span = 0x7FF00000ull;
    uint64_t lo = site > span ? site - span : gran, hi = site + span;
    for (int dir = 0; dir < 2; ++dir) {                  // search down from the site, then up
        uint64_t a = (site & ~(gran - 1));
        for (int steps = 0; steps < 4096; ++steps) {
            a = dir == 0 ? a - gran : a + gran;
            if (a < lo || a > hi) break;
            MEMORY_BASIC_INFORMATION mbi{};
            if (!VirtualQueryEx(s->pi.hProcess, (void *)(uintptr_t)a, &mbi, sizeof(mbi))) continue;
            if (mbi.State != MEM_FREE) {                   // skip the whole occupied region
                uint64_t rb = (uint64_t)(uintptr_t)mbi.BaseAddress, rs = mbi.RegionSize;
                a = dir == 0 ? (rb & ~(gran - 1)) : ((rb + rs + gran - 1) & ~(gran - 1)) - gran;
                continue;
            }
            void *m = VirtualAllocEx(s->pi.hProcess, (void *)(uintptr_t)a, gran, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (m) return (uint64_t)(uintptr_t)m;
        }
    }
#endif
    (void)site;
    void *m = VirtualAllocEx(s->pi.hProcess, nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    return m ? (uint64_t)(uintptr_t)m : 0;
}

#if defined(_WIN64)
// Per-site trampoline for an x64 SYSCALL / INT 2E site: `insn; mov rcx, site+len (SYSCALL
// only: the CPU leaves the return address there); jmp [rip+0]; dq site+len`. Shared by every
// thread and every nesting level (it holds no per-execution state), never freed (a thread may
// be blocked inside its syscall across a detach). 0 = not such a site / no memory.
static uint64_t syscall_trampoline(probe_session *s, Probe &p) {
    if (p.tramp) return p.tramp;
    if (p.insn_len != 2 || p.orig_insn.size() != 2) return 0;
    const bool sc = p.orig_insn[0] == 0x0F && p.orig_insn[1] == 0x05, i2e = p.orig_insn[0] == 0xCD && p.orig_insn[1] == 0x2E;
    if (!sc && !i2e) return 0;
    if (s->tramp_next + 32 > s->tramp_end) {
        void *m = VirtualAllocEx(s->pi.hProcess, nullptr, 0x10000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!m) return 0;
        s->tramp_next = (uint64_t)(uintptr_t)m; s->tramp_end = s->tramp_next + 0x10000;
    }
    const uint64_t back = p.address + 2;
    std::vector<unsigned char> code(p.orig_insn.begin(), p.orig_insn.end());
    if (sc) { code.push_back(0x48); code.push_back(0xB9); for (int b = 0; b < 8; ++b) code.push_back((unsigned char)(back >> (8 * b))); }
    const unsigned char jmp[6] = {0xFF, 0x25, 0, 0, 0, 0};
    code.insert(code.end(), jmp, jmp + 6);
    for (int b = 0; b < 8; ++b) code.push_back((unsigned char)(back >> (8 * b)));
    size_t wrote = 0;
    if (!remote_write(s->pi.hProcess, s->tramp_next, code.data(), code.size(), &wrote) || wrote != code.size()) return 0;
    FlushInstructionCache(s->pi.hProcess, (void *)(uintptr_t)s->tramp_next, code.size());
    p.tramp = s->tramp_next; s->tramp_next += 32;
    return p.tramp;
}
#endif

static uint64_t thread_scratch(probe_session *s, DWORD tid, uint64_t site) {
    uint64_t region = site >> 30;
    auto key = std::make_pair(tid, region);
    auto it = s->scratch.find(key);
    if (it != s->scratch.end()) return it->second;
    auto &pool = s->scratch_free[region];
    if (pool.empty()) {
        uint64_t block = alloc_block_near(s, site);
        if (!block) return 0;
        s->scratch_blocks.push_back(block);
        for (uint64_t off = 0x10000; off >= 64; off -= 64) pool.push_back(block + off - 64);
    }
    uint64_t slot = pool.back(); pool.pop_back();
    s->scratch[key] = slot;
    return slot;
}

// Fully release a hardware probe: clear its DR on every thread and free the slot.
static void release_hw(probe_session *s, Probe &p) {
    if (p.dr_slot < 0) return;
    for (DWORD tid : s->threads) {
        HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
        GuardTouch touch(s, tid);
        if (t) { set_dr_on_thread(t, p.dr_slot, 0, false); CloseHandle(t); }
    }
    if (p.address) retire_hw_address(s, p.address);
    s->dr_used &= (uint8_t)~(1u << p.dr_slot);
    if (s->hw_active > 0) --s->hw_active;
    p.active = false; p.dr_slot = -1;
    if (p.flags & PROBE_ONCE) p.retired = true;
}

// ---- Frozen hook writes (agent FREEZE / THAW) ------------------------------------------
// The agent writes inline hooks only while every other target thread is suspended here, so
// no thread can execute bytes mid-write and the page never has to be made non-executable
// (which faulted on ntdll's own syscall stubs and raised exceptions the target could see).
static void ipc_thaw(probe_session *s) {
    for (HANDLE t : s->ipc_frozen) { ResumeThread(t); CloseHandle(t); }
    s->ipc_frozen.clear();
    s->ipc_freezer = 0;
}

static void ipc_freeze_thread(probe_session *s, DWORD tid) {
    HANDLE t = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION,
                          FALSE, tid);                     // (QUERY_LIMITED: GetThreadId, guard_sync)
    if (!t) return;
    guard_note_hold(s, tid);
    if (SuspendThread(t) == (DWORD)-1) { CloseHandle(t); return; }
    s->ipc_frozen.push_back(t);
}

// A frozen thread stopped strictly inside a range the agent is about to overwrite would
// resume on torn bytes. Move it to the same instruction in that hook's trampoline, which
// holds relocated copies of exactly those instructions (one-to-one, in order) and then
// jumps back to site + patch_len.
static void move_into_trampoline(probe_session *s, HANDLE t) {
    CONTEXT c{}; c.ContextFlags = CONTEXT_CONTROL;
    GuardTouch touch(s, GetThreadId(t));
    if (!GetThreadContext(t, &c)) return;
#if defined(_WIN64)
    uint64_t ip = c.Rip;
#else
    uint64_t ip = c.Eip;
#endif
    for (uint32_t i = 0; i < PROBE_AGENT_MAX_PROBES; ++i) {
        const auto &r = s->shared->requests[i];
        if (!r.enabling) continue;                    // only ranges about to be overwritten
        const uint64_t site = r.site, tramp = r.trampoline; const uint32_t len = r.patch_len;
        if (!site || !tramp || !len || len > 32 || ip <= site || ip >= site + len) continue;
        unsigned char ob[48] = {}, tb[128] = {}; size_t on = 0, tn = 0;
        remote_read(s->pi.hProcess, site, ob, sizeof(ob), &on);
        remote_read(s->pi.hProcess, tramp, tb, sizeof(tb), &tn);
        ZydisDecoder dec;
#if defined(_WIN64)
        ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
        ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#endif
        size_t o = 0, q = 0;
        while (o < len && o < on && q < tn) {
            if (site + o == ip) {
#if defined(_WIN64)
                c.Rip = tramp + q;
#else
                c.Eip = (DWORD)(tramp + q);
#endif
                SetThreadContext(t, &c);
                return;
            }
            ZydisDecodedInstruction a{}, b{};
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&dec, nullptr, ob + o, on - o, &a)) ||
                !ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&dec, nullptr, tb + q, tn - q, &b))) break;
            o += a.length; q += b.length;
        }
        std::fprintf(stderr, "probe: freeze: thread at 0x%llx inside hook range 0x%llx+%u not mapped\n",
                     (unsigned long long)ip, (unsigned long long)site, len);
        return;
    }
}

static int32_t ipc_freeze(probe_session *s, DWORD self, uint64_t mask) {
    ipc_thaw(s);                                  // a stale freeze (agent thread died) never stacks
    for (DWORD tid : s->threads) {
        if (tid == self) continue;
        size_t before = s->ipc_frozen.size();
        ipc_freeze_thread(s, tid);
        if (mask && s->ipc_frozen.size() > before) move_into_trampoline(s, s->ipc_frozen.back());
    }
    s->ipc_freezer = self;
    return 1;
}

// Agent -> controller control-plane call (an inline callback used get_session(c)).
// The raising thread is stopped; service the request and write the result back.
// Trust boundary: the target is untrusted. A request is honoured only when an inline
// agent exists and it names a real inline probe as its origin, and the callback is
// resolved ONLY among the exports of that probe's controller-side callback module (so
// keep that module's exports to callbacks). Anything else is not ours: pass it through.
static bool handle_ipc(probe_session *s, const DEBUG_EVENT &event) {
    auto &ex = event.u.Exception.ExceptionRecord;
    if (!s->shared || ex.NumberParameters < 1) return false;
    {
        probe_ipc_request head{}; size_t n = 0;
        if (remote_read(s->pi.hProcess, (uint64_t)ex.ExceptionInformation[0], &head, offsetof(probe_ipc_request, address), &n) &&
            n == offsetof(probe_ipc_request, address) && (head.op == PROBE_IPC_FREEZE || head.op == PROBE_IPC_THAW)) {
            if (trace_enabled()) std::fprintf(stderr, "  ipc op=%u tid=%lu (freeze/thaw) t=%llu\n", head.op, (unsigned long)event.dwThreadId, (unsigned long long)GetTickCount64());
            uint64_t mask = 0; size_t m = 0;
            remote_read(s->pi.hProcess, (uint64_t)ex.ExceptionInformation[0] + offsetof(probe_ipc_request, address), &mask, sizeof(mask), &m);
            if (head.op == PROBE_IPC_THAW) { if (s->ipc_freezer == event.dwThreadId) ipc_thaw(s); return true; }
            int32_t result = ipc_freeze(s, event.dwThreadId, m == sizeof(mask) ? mask : 0);
            size_t wrote = 0;
            remote_write(s->pi.hProcess, (uint64_t)ex.ExceptionInformation[0] + offsetof(probe_ipc_request, result), &result, sizeof(result), &wrote);
            return true;
        }
        if (trace_enabled() && n == offsetof(probe_ipc_request, address))
            std::fprintf(stderr, "  ipc op=%u tid=%lu t=%llu\n", head.op, (unsigned long)event.dwThreadId, (unsigned long long)GetTickCount64());
        if (n == offsetof(probe_ipc_request, address) && head.op == PROBE_IPC_LOG) {
            // A producer could not get a ring slot (the ring is stalled behind a suspended
            // producer): the record comes over synchronously. Untrusted like the ring itself;
            // enqueue_agent_record bounds every field.
            uint64_t at = (uint64_t)ex.ExceptionInformation[0], where = 0;
            size_t m = 0, got = 0;
            auto rec = std::make_unique<probe_agent_log>();
            int32_t result = 0;
            if (remote_read(s->pi.hProcess, at + offsetof(probe_ipc_request, address), &where, sizeof(where), &m) &&
                m == sizeof(where) && remote_read(s->pi.hProcess, where, rec.get(), sizeof(*rec), &got) && got == sizeof(*rec)) {
                drain_agent_logs(s);                 // whatever the ring can still give goes first
                deliver_past_stall(s);
                enqueue_agent_record(s, *rec);
                result = 1;
            }
            size_t wrote = 0;
            remote_write(s->pi.hProcess, at + offsetof(probe_ipc_request, result), &result, sizeof(result), &wrote);
            return true;
        }
        if (n == offsetof(probe_ipc_request, address) && head.op == PROBE_IPC_INSTALL_DONE) {
            // Harmless if forged: acceptance re-checks every request status itself.
            if (!accept_agent_install(s)) { std::fprintf(stderr, "probe: %s\n", s->error.c_str()); }
            if (agent_has_pending(s)) kick_agent(s);
            else if (!inline_hold_needed(s)) release_held(s, "inline installs confirmed");
            return true;
        }
    }
    uint64_t at = (uint64_t)ex.ExceptionInformation[0];
    probe_ipc_request req{}; size_t got = 0;
    if (!remote_read(s->pi.hProcess, at, &req, sizeof(req), &got) || got != sizeof(req)) return false;
    // The name, symbol and config are read from the (stopped) calling thread's memory.
    auto fetch = [&](uint64_t from, uint64_t len, uint64_t cap, void *to) {
        size_t n = 0;
        return len <= cap && (!len || (remote_read(s->pi.hProcess, from, to, (size_t)len, &n) && n == len));
    };
    std::string name, symbol; std::vector<unsigned char> config;
    // The config limit is the API's, the same on every backend (probe_api.h: 4 GB); it used to
    // be 64 MiB here only, so a dynamic add accepted by breakpoint/hw was refused inline.
    const bool cfg_too_big = req.config_len > PROBE_IPC_CONFIG_MAX;
    bool fetched = req.callback_len <= PROBE_IPC_TEXT_MAX && req.symbol_len <= PROBE_IPC_TEXT_MAX && !cfg_too_big;
    if (fetched) {
        try {
            name.resize((size_t)req.callback_len); symbol.resize((size_t)req.symbol_len); config.resize((size_t)req.config_len);
        } catch (const std::bad_alloc &) { fetched = false; }
        fetched = fetched && fetch(req.callback, req.callback_len, PROBE_IPC_TEXT_MAX, name.data()) &&
                  fetch(req.symbol, req.symbol_len, PROBE_IPC_TEXT_MAX, symbol.data()) &&
                  fetch(req.config, req.config_len, PROBE_IPC_CONFIG_MAX, config.data());
    }
    // The callback is named; find the controller's copy of the same source. Prefer the
    // module that holds the originating inline probe's callback, then the executable.
    probe_callback cb = nullptr; bool origin = false;
    for (auto &p : s->probes)
        if ((p->flags & PROBE_INLINE) && p->agent_index == req.origin_site && p->callback) {
            origin = true;
            HMODULE m{};
            if (fetched && GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                              reinterpret_cast<LPCSTR>(p->callback), &m))
                for (size_t at0 = 0; !cb && at0 < name.size(); ) {          // '\n'-separated: any that resolves
                    size_t nl = name.find('\n', at0);
                    if (nl == std::string::npos) nl = name.size();
                    cb = reinterpret_cast<probe_callback>(GetProcAddress(m, name.substr(at0, nl - at0).c_str()));
                    at0 = nl + 1;
                }
            break;
        }
    if (!origin) return false;
    int32_t result = 0;
    struct CbTid { probe_session *s; ~CbTid() { s->cb_tid = 0; } } cb_tid_scope{s};
    s->cb_tid = event.dwThreadId;
    if (cfg_too_big) {
        std::fprintf(stderr, "probe: error: probe config is larger than 4 GB\n");   // as probe_add_symbol_cfg says it
    } else if (!fetched) {
        std::fprintf(stderr, "probe: dynamic add from inline callback: cannot read its arguments from the target\n");
    } else if (!cb) {
        std::fprintf(stderr, "probe: dynamic add from inline callback: no controller-side export '%s'\n", name.c_str());
    } else if (req.op == PROBE_IPC_ADD_ADDRESS) result = probe_add_address(s, req.address, cb, req.flags);
    else if (req.op == PROBE_IPC_WATCH)       result = probe_watch(s, req.address, cb, req.flags);
    else if (req.op == PROBE_IPC_ADD_SYMBOL)
        result = probe_add_symbol_cfg(s, req.symbol ? symbol.c_str() : nullptr, cb, req.flags,
                                      config.empty() ? nullptr : config.data(), config.size());
    std::fprintf(stderr, "probe: ipc op=%u from inline site %u cb=%s -> %d\n", req.op, req.origin_site, name.c_str(), result);
    size_t wrote = 0;
    remote_write(s->pi.hProcess, at + offsetof(probe_ipc_request, result), &result, sizeof(result), &wrote);
    return true;
}

// Write the debug-register state the session wants into a thread's context: every slot
// this session has ever owned is set to its active probe (address + DR7 enable/RW/LEN)
// or cleared if released. Slots never owned (the target's own) are left alone.
// Why: a DR change made with SetThreadContext while that thread is blocked with its own
// debug event still QUEUED behind the one being handled (two threads hitting probes at
// once) can be lost -- seen as a hw probe added from a callback (e.g. a return-address
// probe) that never fires on that thread. Re-asserting our slots at the thread's own
// event repairs it before it runs on.
static void enforce_owned_drs(const probe_session *s, DWORD tid, CONTEXT &c) {
    for (int slot = 0; slot < 4; ++slot) {
        if (!(s->dr_ever & (1u << slot))) continue;
        const Probe *owner = nullptr;
        for (const auto &p : s->probes)
            if (p->active && (p->flags & PROBE_HW) && p->dr_slot == slot) { owner = p.get(); break; }
        const DWORD64 ln = (DWORD64)1 << (slot * 2), fieldmask = (DWORD64)0xF << (16 + slot * 4);
        DWORD64 dr7 = c.Dr7;
        if (owner) {
            uint32_t rw = 0, len = 0; hw_rw_len(owner->flags, rw, len);
            switch (slot) {
            case 0: c.Dr0 = (decltype(c.Dr0))owner->address; break;
            case 1: c.Dr1 = (decltype(c.Dr1))owner->address; break;
            case 2: c.Dr2 = (decltype(c.Dr2))owner->address; break;
            default: c.Dr3 = (decltype(c.Dr3))owner->address; break;
            }
            dr7 = (dr7 & ~fieldmask) | ln | ((DWORD64)(((len & 3u) << 2) | (rw & 3u)) << (16 + slot * 4));
        } else if (!(s->dr_used & (1u << slot)) && !target_owns_slot(s, tid, c, slot)) {
            dr7 &= ~(ln | fieldmask);                           // our stale slot (never the target's own)
        }
        c.Dr7 = (decltype(c.Dr7))dr7;
    }
}

// While one callback's call_func runs its callee, another thread that hits a probe must
// not run ITS callback now: that callback may call call_func too, and only one call can be
// in flight (it used to get 0 -- the same callback source failed only under concurrency).
// Instead the hit is undone -- the thread is put back AT the probe address (an INT3 hit
// rewinds over the 0xCC; an execute #DB has not run the instruction) and suspended. When
// the call finishes it is resumed and hits the probe again, normally: counted once, its
// callback runs with call_func available.
static bool defer_hit_during_call(probe_session *s, DWORD tid, uint64_t address, bool rewind_ip) {
    HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION,
                          FALSE, tid);                     // (QUERY_LIMITED: GetThreadId, guard_sync)
    if (!t) return false;
    CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    bool ok = !!GetThreadContext(t, &w);
    if (ok) {
        if (rewind_ip) {
#if defined(_WIN64)
            w.Rip = address;
#else
            w.Eip = (DWORD)address;
#endif
        }
        w.Dr6 = 0;
        w.EFlags &= ~0x10000u;                   // no RF: the probe must fire again
        ok = !!SetThreadContext(t, &w);
    }
    if (ok) guard_note_hold(s, tid);
    if (ok && SuspendThread(t) != (DWORD)-1) {
        try { s->call_deferred.push_back(t); return true; } catch (...) { ResumeThread(t); }
    }
    CloseHandle(t);
    return false;
}

static void resume_deferred_hits(probe_session *s) {
    for (HANDLE t : s->call_deferred) { ResumeThread(t); CloseHandle(t); }
    s->call_deferred.clear();
}

// ---- Callback memory access (breakpoint/hw callbacks) ---------------------------------
// The SAME policy as the inline agent's range check, so get_mem/set_mem answer the same on
// every backend: the whole range must be committed, not PAGE_GUARD / PAGE_NOACCESS, readable
// (and writable for set_mem) -- checked BEFORE any byte moves, so a failure has no partial
// effect. Plain Read/WriteProcessMemory differ: WriteProcessMemory silently makes code
// pages writable (a set_mem into .text succeeded under breakpoint/hw, failed inline), and a
// range running into an inaccessible page was half-copied. Reads also show the ORIGINAL
// byte where a software breakpoint is armed (the program's code, not UHH's INT3).
static bool remote_range_ok(HANDLE h, uint64_t a, size_t n, bool write) {
    if (!n) return true;
    if (a + n < a) return false;
#if !defined(_WIN64)
    if (a + n > 0x100000000ull) return false;
#endif
    const uint64_t end = a + n;
    while (a < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(h, (const void *)(uintptr_t)a, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT) return false;
        const DWORD prot = mbi.Protect & 0xFF;
        if ((mbi.Protect & PAGE_GUARD) || prot == PAGE_NOACCESS || prot == 0) return false;
        const bool w = prot == PAGE_READWRITE || prot == PAGE_WRITECOPY || prot == PAGE_EXECUTE_READWRITE ||
                       prot == PAGE_EXECUTE_WRITECOPY;
        const bool r = w || prot == PAGE_READONLY || prot == PAGE_EXECUTE_READ;
        if (!r || (write && !w)) return false;
        a = (uint64_t)(uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    return true;
}
static int callback_read(void *backend, uint64_t a, void *b, size_t n, size_t *done) {
    auto *s = static_cast<probe_session *>(backend);
    *done = 0;
    if (!n) return 1;
    if (!remote_range_ok(s->pi.hProcess, a, n, false)) return 0;
    if (!remote_read(s->pi.hProcess, a, b, n, done) || *done != n) return 0;
    for (auto &p : s->probes)                           // our INT3s read as the original bytes
        if (p->active && (p->flags & PROBE_BREAKPOINT) && !p->orig_insn.empty() && p->address >= a && p->address < a + n &&
            static_cast<unsigned char *>(b)[p->address - a] == 0xCC)
            static_cast<unsigned char *>(b)[p->address - a] = p->original;
    // ...and installed inline hooks as the bytes they overwrote (published by the agent), as
    // an inline callback reads them (it read the hook's jump here).
    if (s->shared) {
        const uint32_t count = s->shared->request_count < PROBE_AGENT_MAX_PROBES ? s->shared->request_count : PROBE_AGENT_MAX_PROBES;
        for (uint32_t i = 0; i < count; ++i) {
            const auto &r = s->shared->requests[i];
            const uint32_t len = r.original_len <= sizeof(r.original) ? r.original_len : 0;
            if (r.status != PROBE_AGENT_INSTALLED || !len || !r.site || r.site >= a + n || r.site + len <= a) continue;
            for (uint64_t x = r.site > a ? r.site : a; x < r.site + len && x < a + n; ++x)
                static_cast<unsigned char *>(b)[x - a] = r.original[x - r.site];
        }
    }
    return 1;
}
// The agent's copy of the armed INT3s (probe_agent_shared::int3): rewritten whole after any
// breakpoint probe is armed or disarmed.
static void sync_int3_table(probe_session *s) {
    if (!s->shared) return;
    auto *sh = s->shared;
    InterlockedIncrement(&sh->int3_seq);                // odd: being rewritten
    MemoryBarrier();
    LONG n = 0;
    for (auto &p : s->probes)
        if (int3_entry(*p) && n < (LONG)PROBE_AGENT_INT3_CAP) {
            sh->int3[n].address = p->address; sh->int3[n].original = p->original; ++n;
        }
    // Sorted by address: the agent finds the entries in a read's range by binary search.
    std::sort(sh->int3, sh->int3 + n, [](const probe_agent_int3 &x, const probe_agent_int3 &y) { return x.address < y.address; });
    sh->int3_count = n;
    MemoryBarrier();
    InterlockedIncrement(&sh->int3_seq);
}
static int callback_write(void *backend, uint64_t a, const void *b, size_t n, size_t *done) {
    auto *s = static_cast<probe_session *>(backend);
    *done = 0;
    if (!n) return 1;
    if (!remote_range_ok(s->pi.hProcess, a, n, true)) return 0;
    return remote_write(s->pi.hProcess, a, b, n, done);
}
static const probe_ops callback_ops = {callback_read, callback_write};

// Raised by call_original (breakpoint/hw) to end a callback whose original left without
// returning (it raised, longjmp'd or ran past the call timeout): the thread runs on natively.
static const DWORD UHH_CALL_RELEASED = 0xE0554843u;
// Runs a breakpoint/hw callback in the controller under SEH, the way the inline agent runs
// it inside the target: a callback that faults (a bad pointer, a target address used as a
// controller pointer, ...) is abandoned -- the hit still counts, its register changes are
// discarded, the target continues -- instead of killing the controller (and with it the
// target). A C++ exception thrown out of the callback is treated the same way, exactly as
// the agent's SEH guard treats it inline (it used to end the whole session with "probe
// callback threw" on breakpoint/hw only). Caught by SEH on purpose: under /EHsc a C++
// try/catch around a call through an extern "C" callback pointer may be elided.
static bool seh_callback(probe_callback cb, probe_context *c, DWORD *code) {
    __try { cb(c); return true; }
    __except (*code = GetExceptionCode(), EXCEPTION_EXECUTE_HANDLER) {}
    if (*code == EXCEPTION_STACK_OVERFLOW) _resetstkoflw();      // the guard page, for the next overflow
    return false;
}
static void run_callback(probe_session *s, Probe *probe, probe_context *c) {
    const probe_regs before = c->regs;
    DWORD code = 0;
    if (seh_callback(probe->callback, c, &code)) return;
    if (code == UHH_CALL_RELEASED) { c->regs = before; return; }   // call_original ended the callback (see there)
    // A faulting callback is a no-op: its register changes are discarded and a return_from it
    // asked for is dropped (the hit falls through into the original) -- exactly as inline
    // (agent.cpp call_mid). Unless call_original already RAN the original: falling through
    // would run it a second time (a double free / double close), so the hooked function
    // returns to its caller as with return_from -- return_from's value if one was set, else
    // the original's own result (x86: EDX:EAX and the bytes its `ret N` popped) -- with
    // everything else the original left (apply_return_from, CallbackState::faulted).
    auto *st = static_cast<CallbackState *>(c->controller);
    const bool ran = c->called_original && st && st->have_post;
    const bool was_returned = c->returned != 0;
    const uint64_t ax = was_returned ? c->regs.rax : ran ? (uint64_t)st->post.UHH_POST_AX : 0;
    const uint64_t dx = was_returned ? c->regs.rdx : c->orig_edx;
    c->regs = before;
    c->returned = 0;
    if (ran) {
        bool ok = true;
#if !defined(_WIN64)
        if (!was_returned) {
            if (c->orig_pop < 0 || c->orig_pop > 1020 || (c->orig_pop & 3)) ok = false;   // not measured: as inline
            else c->ret_pop = (uint32_t)c->orig_pop;
        }
        if (ok) c->regs.rdx = dx;
#else
        (void)dx;
#endif
        if (ok) { c->regs.rax = ax; c->returned = 1; st->faulted = true; }
    }
    if (!s->warned_cb_fault) {
        s->warned_cb_fault = true;
        std::fprintf(stderr, "probe: warning: callback for %s raised 0x%08lx; abandoned (hit counted, no register "
                     "changes applied). Further faults are not reported.\n", probe->location.c_str(), (unsigned long)code);
    }
}

// return_from resumes the hit thread at a real `ret` (x86 stdcall: `ret N`) with SP at the
// hit's return address, so the CPU pops the stack and any CET shadow stack together.
// One page in the target: offset 0 holds C3, offset 4k holds C2 imm16(4k) -- the gadget
// for `pop` bytes is at base + pop.
static uint64_t ret_gadget(probe_session *s, uint32_t pop) {
    if (pop % 4 || pop > 1020) return 0;
    if (!s->ret_gadgets) {
        unsigned char code[1024]; std::memset(code, 0xCC, sizeof(code));
        code[0] = 0xC3;
        for (uint32_t k = 4; k < sizeof(code); k += 4) { code[k] = 0xC2; code[k + 1] = (unsigned char)k; code[k + 2] = (unsigned char)(k >> 8); }
        void *mem = VirtualAllocEx(s->pi.hProcess, nullptr, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        size_t w = 0; DWORD old = 0;
        if (!mem) return 0;
        if (!remote_write(s->pi.hProcess, (uint64_t)(uintptr_t)mem, code, sizeof(code), &w) || w != sizeof(code) ||
            !VirtualProtectEx(s->pi.hProcess, mem, sizeof(code), PAGE_EXECUTE_READ, &old)) {
            VirtualFreeEx(s->pi.hProcess, mem, 0, MEM_RELEASE); return 0;
        }
        FlushInstructionCache(s->pi.hProcess, mem, sizeof(code));
        s->ret_gadgets = (uint64_t)(uintptr_t)mem;
        s->scratch_blocks.push_back(s->ret_gadgets);
    }
    return s->ret_gadgets + pop;
}
// The first call_original / return_from warning of a probe also goes to the LOG as one
// "uhh warning: <text>" record -- the record the inline agent emits (it has no stderr), so
// a log carries the same records on every backend.
static void warn_record(probe_context *c, Probe *probe, const char *text) {
    if (!c || !probe || probe->warned_log) return;
    probe->warned_log = true;
    send_log(c, "uhh warning: %s", text);
}
// After a callback: apply return_from (resume at the gadget, SP = the hit's) and return
// true; or warn once when call_original ran but the hit will fall through into the body.
static bool apply_return_from(probe_session *s, Probe *probe, const probe_context &c, CONTEXT &native) {
    if (!c.returned) {
        if (c.called_original) warn_record(const_cast<probe_context *>(&c), probe,
                                           "call_original without return_from -- the original runs again on fall-through");
        if (c.called_original && !probe->warned_double_run) {
            probe->warned_double_run = true;
            std::fprintf(stderr, "probe: warning: %s: call_original without return_from -- the original runs again "
                         "on fall-through. Further cases are not reported.\n", probe->location.c_str());
        }
        return false;
    }
    uint64_t g = ret_gadget(s, c.ret_pop);
    auto *st = static_cast<CallbackState *>(c.controller);
    if (g && c.called_original && st && st->have_post) {
        // The caller gets what the original left (see CallbackState::post): its whole FP state
        // as it returned (XMM0 / x87 ST0 results; the nonvolatile parts are the hit's anyway,
        // ABI) and the volatile GPRs the callback did not set_reg after the call. x86 EDX is
        // already the original's unless return_from set a high half (probe_x86_return_regs).
        const CONTEXT &a = st->post;
#define UHH_KEEP(f, r) if (st->faulted || c.regs.r == st->post_seen.r) native.f = a.f;
#if defined(_WIN64)
        UHH_KEEP(Rcx, rcx) UHH_KEEP(Rdx, rdx) UHH_KEEP(R8, r8) UHH_KEEP(R9, r9) UHH_KEEP(R10, r10) UHH_KEEP(R11, r11)
        native.FltSave = a.FltSave; native.MxCsr = a.MxCsr;
#else
        UHH_KEEP(Ecx, rcx)
        native.FloatSave = a.FloatSave;
        std::memcpy(native.ExtendedRegisters, a.ExtendedRegisters, sizeof(native.ExtendedRegisters));
#endif
#undef UHH_KEEP
        native.ContextFlags |= UHH_CONTEXT_FP;
    }
    if (!g) {
        warn_record(const_cast<probe_context *>(&c), probe, "return_from could not be applied (no return thunk); the original runs");
        if (!probe->warned_double_run) {
            probe->warned_double_run = true;
            std::fprintf(stderr, "probe: warning: %s: return_from could not be applied (no return gadget); falling through\n",
                         probe->location.c_str());
        }
        return false;
    }
#if defined(_WIN64)
    native.Rip = g; native.Rsp = c.hit_sp;
#else
    native.Eip = (DWORD)g; native.Esp = (DWORD)c.hit_sp;
#endif
    return true;
}

// Service a hardware-breakpoint #DB (a single-step exception carrying a DR status
// bit, not one of our software single-steps). Returns false on error; sets handled
// when a DR we own fired. RF lets the flagged instruction run once without re-trapping.
static bool handle_hw(probe_session *s, const DEBUG_EVENT &event, bool &handled) {
    handled = false;
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
    if (!thread) { set_error(s, win_error("open hw event thread")); return false; }
    CONTEXT native{}; native.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(thread, &native)) { CloseHandle(thread); set_error(s, win_error("get hw context")); return false; }
    const uint8_t theirs = target_slots(s, event.dwThreadId, native);       // the target's own slots on this thread
    if (!(native.Dr6 & 0xF & s->dr_used) && !(native.Dr6 & 0xF & theirs) && !(native.Dr6 & 0x4000) &&
        !(native.EFlags & 0x100u)) {
        // A #DB that is neither a trap-flag step (BS clear, TF clear) nor flagged in DR6 for
        // one of our slots, AT the address of one of our execute probes: ours, but DR6 was
        // overwritten by the target writing a thread context it captured earlier (Suspend +
        // GetThreadContext / SetThreadContext round-trip racing this event). Passing it on
        // killed the target with an unhandled single step; recover the slot from the address.
#if defined(_WIN64)
        const uint64_t pc = native.Rip;
#else
        const uint64_t pc = native.Eip;
#endif
        for (auto &p : s->probes)
            if (p->active && (p->flags & PROBE_HW) && p->dr_slot >= 0 && !(p->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW)) &&
                p->address == pc)
                native.Dr6 |= (DWORD64)1 << p->dr_slot;
    }
    if (s->in_call_tid && event.dwThreadId != s->in_call_tid && (native.Dr6 & 0xF)) {
        // Only pure execute hits can be replayed (a data watch has already happened).
        bool exec_only = true;
#if defined(_WIN64)
        const uint64_t pc = native.Rip;
#else
        const uint64_t pc = native.Eip;
#endif
        for (int slot = 0; slot < 4 && exec_only; ++slot) {
            if (!(native.Dr6 & (1u << slot))) continue;
            Probe *p = nullptr;
            for (auto &q : s->probes) if (q->active && (q->flags & PROBE_HW) && q->dr_slot == slot) { p = q.get(); break; }
            if (!p || p->internal || (p->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW)) || p->address != pc) exec_only = false;
        }
        if (exec_only && s->stepping.find(event.dwThreadId) == s->stepping.end() &&
            defer_hit_during_call(s, event.dwThreadId, pc, false)) {
            CloseHandle(thread); handled = true; return true;
        }
    }
    // Service EVERY debug-status bit that fired, not just the lowest: two probes can
    // share an address (both B-bits set), and clearing DR6 after handling only one
    // would silently drop the other. Callbacks compose on one context in slot order.
    bool any = false, exec_hit = false;
    DWORD64 consumed = 0;
    DWORD64 fired = native.Dr6 & 0xF;
    if (!fired) {
        // An execute breakpoint whose status was lost: a debug-register write from the
        // controller (arming another hardware probe on every thread) reached this thread
        // while its #DB was still waiting to be reported, and that write carries DR6 too,
        // so the B-bit reads 0 here. Found by examples/famous retval_override (the target
        // then died of an "unhandled" STATUS_SINGLE_STEP). An execute DR is unambiguous by
        // address: a trap exactly at an active hardware execute probe whose slot is
        // enabled on this thread is that probe's hit.
#if defined(_WIN64)
        const uint64_t pc = native.Rip;
#else
        const uint64_t pc = native.Eip;
#endif
        for (auto &p : s->probes)
            if (p->active && (p->flags & PROBE_HW) && !(p->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW)) &&
                p->address == pc && p->dr_slot >= 0 && p->dr_slot < 4 && ((native.Dr7 >> (p->dr_slot * 2)) & 1))
                fired |= (DWORD64)1 << p->dr_slot;
        if (fired && trace_enabled())
            std::fprintf(stderr, "  hw-dr6-lost tid=%lu pc=0x%llx inferred=0x%llx\n", (unsigned long)event.dwThreadId,
                         (unsigned long long)pc, (unsigned long long)fired);
    }
    for (int slot = 0; slot < 4; ++slot) {
        if (!(fired & (1u << slot))) continue;
        Probe *probe = nullptr;
        for (auto &p : s->probes) if (p->active && (p->flags & PROBE_HW) && p->dr_slot == slot) { probe = p.get(); break; }
        if (!probe) {
            // A slot we owned but have since released (PROBE_ONCE / unload): a #DB that was
            // already in flight on another thread. Swallow it rather than crash the app.
            if ((s->dr_ever & (1u << slot)) && !(theirs & (1u << slot))) { any = true; consumed |= (1u << slot); }
            continue;
        }
        consumed |= (1u << slot);
        any = true;
        #if defined(_WIN64)
        uint64_t hit_pc = native.Rip;
#else
        uint64_t hit_pc = native.Eip;
#endif
        // A watch hit while this thread runs a displaced copy: report the real code address.
        auto st = s->stepping.find(event.dwThreadId);
        if (st != s->stepping.end() && st->second.displaced && st->second.scratch &&
            hit_pc >= st->second.scratch && hit_pc <= st->second.scratch + st->second.insn_len)
            hit_pc = st->second.site + (hit_pc - st->second.scratch);
        if (!(probe->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW))) exec_hit = true;
        // Execute probes: pc == the probe address. Watchpoints trap AFTER the access, so
        // pc is the instruction following the store/load -- the real code location.
        if (!(probe->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW)) && hit_pc != probe->address) {
            any = true; continue;                                    // stale: slot was reassigned
        }
        probe_context context = from_context(native, probe_index(s, probe), hit_pc, &callback_ops, s);
        context.config = probe->config.empty() ? nullptr : probe->config.data();
        context.tid = event.dwThreadId;
        CallbackState state{s, probe, event.dwProcessId, event.dwThreadId}; context.controller = &state;
        if (event.dwThreadId == s->in_call_tid) {                                 // inside call_func: no re-entry
            if (s->co_addr && !(probe->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW))) {
#if defined(_WIN64)
                const uint64_t sp = native.Rsp;
#else
                const uint64_t sp = native.Esp;
#endif
                if (sp >= s->co_sp && defer_hit_during_call(s, event.dwThreadId, hit_pc, false)) {
                    s->co_left = true; CloseHandle(thread); handled = true; return true;   // left the call (see breakpoint)
                }
            }
            count_hit(probe); continue;
        }
        s->cb_tid = event.dwThreadId;
        try { run_callback(s, probe, &context); s->cb_tid = 0; }
        catch (const std::exception &e) { CloseHandle(thread); set_error(s, std::string("probe callback: ") + e.what()); return false; }
        catch (...) { CloseHandle(thread); set_error(s, "probe callback threw an unknown exception"); return false; }
        count_hit(probe);
        if (state.released) { CloseHandle(thread); s->skip_continue = true; handled = true; return true; }
        if (probe->flags & PROBE_ONCE) release_hw(s, *probe);
        to_context(context, native);                                 // fold each callback's changes forward
#if defined(_WIN64)
        native.Rsp = context.regs.rsp;
#else
        native.Esp = (DWORD)context.regs.rsp;
#endif
        apply_return_from(s, probe, context, native);               // Rip -> ret gadget, Rsp -> the hit's
    }
    if (!any) {                                                      // none of our DRs fired
        if (trace_enabled())
            std::fprintf(stderr, "  hw-not-ours tid=%lu dr6=0x%llx dr7=0x%llx dr0=0x%llx dr1=0x%llx dr2=0x%llx dr3=0x%llx "
                                 "used=0x%x ever=0x%x eflags=0x%lx\n", (unsigned long)event.dwThreadId,
                         (unsigned long long)native.Dr6, (unsigned long long)native.Dr7, (unsigned long long)native.Dr0,
                         (unsigned long long)native.Dr1, (unsigned long long)native.Dr2, (unsigned long long)native.Dr3,
                         s->dr_used, s->dr_ever, (unsigned long)native.EFlags);
        CloseHandle(thread); return true;
    }
    // RF only for EXECUTE breakpoints (fault-type: the instruction has not run yet). Data
    // watchpoints are trap-type -- the access already happened -- and RF would wrongly
    // suppress an execute breakpoint on the very next instruction.
    if (exec_hit) native.EFlags |= 0x10000u;
    // Callbacks may have armed/released hardware probes (probe_watch, PROBE_ONCE), which
    // rewrote THIS thread's debug registers. Take the live DR image, not the stale one
    // captured before the callbacks, so the write-back below does not undo them.
    {
        CONTEXT dr{}; dr.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(thread, &dr)) {
            native.Dr0 = dr.Dr0; native.Dr1 = dr.Dr1; native.Dr2 = dr.Dr2; native.Dr3 = dr.Dr3; native.Dr7 = dr.Dr7;
        }
    }
    {                              // repair a DR write lost while this thread's event was queued
        const auto d7 = native.Dr7, d0 = native.Dr0, d1 = native.Dr1, d2 = native.Dr2, d3 = native.Dr3;
        enforce_owned_drs(s, event.dwThreadId, native);
        if (d7 != native.Dr7 || d0 != native.Dr0 || d1 != native.Dr1 || d2 != native.Dr2 || d3 != native.Dr3)
            std::fprintf(stderr, "probe: repaired hardware breakpoint state on thread %lu (dr7 0x%llx -> 0x%llx)\n",
                         (unsigned long)event.dwThreadId, (unsigned long long)d7, (unsigned long long)native.Dr7);
    }
    native.Dr6 &= ~consumed;     // clear only the status bits of slots we own
    if (!SetThreadContext(thread, &native)) { CloseHandle(thread); set_error(s, win_error("resume hw breakpoint")); return false; }
    CloseHandle(thread);
    // The same #DB also reports one of the target's OWN debug registers: it is the target's
    // exception too -- pass it on (our callbacks ran; their changes are applied above).
    handled = !(native.Dr6 & 0xF & theirs);
    return true;
}

// "exception 0xc0000005 at msvcp140.dll+0x1234 (read 0x0)" plus a hint for known causes.
// What an address in the target IS, from its memory map: "thing.dll+0x41a0" inside a loaded
// image; otherwise the raw address plus the kind of memory (unmapped, reserved, heap/stack
// /private, mapped file) and, for committed memory, its protection -- e.g. why a write
// faulted. `module` receives the image's name (empty if none).
// Local wall-clock time "2026-11-05 15:40:12.345", for crash reports.
static std::string wall_clock() {
    SYSTEMTIME st{}; GetLocalTime(&st);
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%04u-%02u-%02u %02u:%02u:%02u.%03u", st.wYear, st.wMonth, st.wDay,
                  st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    return buf;
}

static const char *protect_name(DWORD p) {
    switch (p & 0xFF) {
    case PAGE_NOACCESS: return "PAGE_NOACCESS"; case PAGE_READONLY: return "PAGE_READONLY";
    case PAGE_READWRITE: return "PAGE_READWRITE"; case PAGE_WRITECOPY: return "PAGE_WRITECOPY";
    case PAGE_EXECUTE: return "PAGE_EXECUTE"; case PAGE_EXECUTE_READ: return "PAGE_EXECUTE_READ";
    case PAGE_EXECUTE_READWRITE: return "PAGE_EXECUTE_READWRITE"; case PAGE_EXECUTE_WRITECOPY: return "PAGE_EXECUTE_WRITECOPY";
    default: return "?";
    }
}

static std::string module_offset(probe_session *s, uint64_t address, std::string *module = nullptr,
                                 bool with_protect = false) {
    if (module) module->clear();
    char buf[200];
    MEMORY_BASIC_INFORMATION m{};
    if (!s->pi.hProcess || !VirtualQueryEx(s->pi.hProcess, (void *)(uintptr_t)address, &m, sizeof(m))) {
        std::snprintf(buf, sizeof(buf), "0x%llx (not a valid address)", (unsigned long long)address);
        return buf;
    }
    const uint64_t alloc = (uint64_t)(uintptr_t)m.AllocationBase;
    if (m.State == MEM_COMMIT && m.Type == MEM_IMAGE) {
        std::string name;
        for (const auto &kv : s->module_bases) if (kv.second == alloc) { name = kv.first; break; }
        if (name.empty()) { char b[32]; std::snprintf(b, sizeof(b), "image@0x%llx", (unsigned long long)alloc); name = b; }
        if (module) *module = name;
        std::snprintf(buf, sizeof(buf), "%s+0x%llx", name.c_str(), (unsigned long long)(address - alloc));
        if (with_protect && (m.Protect & (PAGE_READONLY | PAGE_EXECUTE_READ | PAGE_EXECUTE | PAGE_NOACCESS))) {
            std::string out = buf;
            return out + " [" + protect_name(m.Protect) + "]";
        }
        return buf;
    }
    const char *kind = m.State == MEM_FREE ? "unmapped" : m.State == MEM_RESERVE ? "reserved, not committed"
                     : m.Type == MEM_MAPPED ? "mapped view" : "private memory (heap/stack/VirtualAlloc)";
    if (m.State == MEM_COMMIT)
        std::snprintf(buf, sizeof(buf), "0x%llx (%s, %s%s)", (unsigned long long)address, kind, protect_name(m.Protect),
                      (m.Protect & PAGE_GUARD) ? "|PAGE_GUARD" : "");
    else
        std::snprintf(buf, sizeof(buf), "0x%llx (%s%s)", (unsigned long long)address, kind,
                      address < 0x10000 ? ", null page" : "");
    return buf;
}

static std::string describe_fault(probe_session *s, const EXCEPTION_RECORD &ex, DWORD code, uint64_t address) {
    std::string where;
    char buf[256];
    std::snprintf(buf, sizeof(buf), "exception 0x%08lx at %s", (unsigned long)code, module_offset(s, address, &where).c_str());
    std::string out = buf;
    if (code == EXCEPTION_ACCESS_VIOLATION && ex.NumberParameters >= 2) {
        const ULONG_PTR kind = ex.ExceptionInformation[0];
        out += std::string(" (") + (kind == 8 ? "execute" : kind ? "write" : "read") + " of " +
               module_offset(s, (uint64_t)ex.ExceptionInformation[1], nullptr, true) + ")";
    }
    std::string lower = where;
    for (auto &ch : lower) ch = (char)std::tolower((unsigned char)ch);
    if (lower.rfind("msvcp140", 0) == 0 || lower.rfind("vcruntime140", 0) == 0)
        out += " -- the target's MSVC runtime is older than the one probe_api_agent.dll was built "
               "against; rebuild UHH with -DUHH_STATIC_CRT=ON (the default)";
    return out;
}

// The crashing thread's call stack, one frame per line as module+offset (raw return
// addresses, no symbol lookup on this thread), so a crash is diagnosable from stderr alone.
static void print_crash_stack(probe_session *s, DWORD tid) {
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, tid);
    CONTEXT w{}; w.ContextFlags = CONTEXT_FULL;
    if (!thread || !GetThreadContext(thread, &w)) { if (thread) CloseHandle(thread); return; }
#if defined(_WIN64)
    const uint64_t pc = w.Rip, sp = w.Rsp, fp = w.Rbp;
#else
    const uint64_t pc = w.Eip, sp = w.Esp, fp = w.Ebp;
#endif
    std::vector<uint64_t> frames;
    if (!s->sym_ready || !uhh_sym::walk_stack(s->pi.hProcess, thread, w, pc, sp, fp, frames, PROBE_STACK_MAX_FRAMES))
        frames.assign(1, pc);
    CloseHandle(thread);
    for (size_t i = 0; i < frames.size(); ++i)
        std::fprintf(stderr, "probe:   #%zu %s\n", i, module_offset(s, frames[i]).c_str());
}

// PROBE_TRACE diagnostics: every target thread's symbolized stack (each thread briefly
// suspended for its context), e.g. when an install hold does not confirm -- shows what the
// agent's service thread is waiting on and what the held threads own.
static void trace_thread_stacks(probe_session *s, const char *why) {
    std::fprintf(stderr, "  thread stacks (%s) t=%llu:\n", why, (unsigned long long)GetTickCount64());
    for (DWORD tid : s->threads) {
        HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, tid);
        if (!thread) continue;
        const DWORD prev = SuspendThread(thread);
        CONTEXT w{}; w.ContextFlags = CONTEXT_FULL;
        if (GetThreadContext(thread, &w)) {
#if defined(_WIN64)
            const uint64_t pc = w.Rip, sp = w.Rsp, fp = w.Rbp;
#else
            const uint64_t pc = w.Eip, sp = w.Esp, fp = w.Ebp;
#endif
            std::vector<uint64_t> frames;
            if (!s->sym_ready || !uhh_sym::walk_stack(s->pi.hProcess, thread, w, pc, sp, fp, frames, 24))
                frames.assign(1, pc);
            std::fprintf(stderr, "  tid=%lu suspend=%lu%s\n", (unsigned long)tid, (unsigned long)prev,
                         agent_thread(s, tid) ? " (agent)" : "");
            for (size_t i = 0; i < frames.size(); ++i)
                std::fprintf(stderr, "    #%zu %s %s\n", i, module_offset(s, frames[i]).c_str(),
                             s->sym_ready ? uhh_sym::symbolize(s->pi.hProcess, frames[i]).c_str() : "");
        }
        if (prev != (DWORD)-1) ResumeThread(thread);
        CloseHandle(thread);
    }
}

static bool handle_exception(probe_session *s, const DEBUG_EVENT &event,
                             std::unordered_map<DWORD, StepState> &stepping,
                             bool &initial_break, DWORD &disposition) {
    auto &ex = event.u.Exception.ExceptionRecord; DWORD code = ex.ExceptionCode;
    // A 32-bit (WOW64) target's traps can arrive in their WOW64 form; they are the same
    // events as far as the probes are concerned.
    if (code == 0x4000001Eu /*STATUS_WX86_SINGLE_STEP*/) code = EXCEPTION_SINGLE_STEP;
    else if (code == 0x4000001Fu /*STATUS_WX86_BREAKPOINT*/) code = EXCEPTION_BREAKPOINT;
    disposition = DBG_EXCEPTION_NOT_HANDLED;
    // A REP string instruction ran out-of-line to completion and reached the INT3 placed
    // after its copy: land on the instruction after the probe site (no trap flag was used).
    if (code == EXCEPTION_BREAKPOINT) {
        auto st = stepping.find(event.dwThreadId);
        const uint64_t at = (uint64_t)(uintptr_t)ex.ExceptionAddress;
        if (st != stepping.end() && st->second.tail_int3 && st->second.scratch &&
            at == st->second.scratch + st->second.insn_len) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
            CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL;
            bool ok = t && GetThreadContext(t, &w);
#if defined(_WIN64)
            w.Rip = st->second.site + st->second.insn_len;
#else
            w.Eip = (DWORD)(st->second.site + st->second.insn_len);
#endif
            ok = ok && SetThreadContext(t, &w);
            if (t) CloseHandle(t);
            if (!ok) { set_error(s, win_error("complete out-of-line string instruction")); return false; }
            stepping.erase(st);
            disposition = DBG_CONTINUE; return true;
        }
        // Another thread has an in-place window open (our INT3 lifted at its site): this hit
        // was raised before the window and queued. Rewind it onto the INT3 -- the thread is
        // held in the window and hits it again afterwards, counted then, exactly once.
        if (s->inplace_owner && event.dwThreadId != s->inplace_owner && probe_at(s, at)) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
            CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL;
            bool ok = t && GetThreadContext(t, &w);
            EMU_IP(w) = (decltype(EMU_IP(w)))at;
            ok = ok && SetThreadContext(t, &w);
            if (t) CloseHandle(t);
            if (!ok) { set_error(s, win_error("replay a hit after the in-place window")); return false; }
            disposition = DBG_CONTINUE; return true;
        }
    }
    // The loader's initial breakpoint -- but only if it is not one of OUR INT3s: a probe
    // can fire during loader initialisation (e.g. ntdll!NtCreateFile from the shim engine),
    // before the loader breakpoint, and must be handled as a probe hit, not swallowed.
    if (code == EXCEPTION_BREAKPOINT && !initial_break &&
        !probe_at(s, (uint64_t)(uintptr_t)ex.ExceptionAddress) && !s->retired_bps.count((uint64_t)(uintptr_t)ex.ExceptionAddress)) {
        initial_break = true; disposition = DBG_CONTINUE; return true;
    }
    if (code == PROBE_IPC_CODE && handle_ipc(s, event)) { disposition = DBG_CONTINUE; return true; }
    auto step = stepping.find(event.dwThreadId);
    uint64_t address = (uint64_t)(uintptr_t)ex.ExceptionAddress;
    if (step != stepping.end() && step->second.refire &&
        (address != step->second.site || code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP)) {
        // A faulted instruction re-run without our trap flag (see refire) that did NOT fault
        // again: the thread ran on with the byte lifted. Arm the site again; this event is new.
        end_inplace_step(s, event.dwThreadId, step->second.site);
        stepping.erase(step);
        step = stepping.end();
    }
    bool restart = false;            // this INT3 is a faulted in-place step restarting (see refault)
    if (auto rf = s->refault.find(event.dwThreadId); rf != s->refault.end() && step == stepping.end()) {
        const uint64_t site = rf->second.site;
        s->refault.erase(rf);                              // one event decides
        if (code == EXCEPTION_BREAKPOINT || code == EXCEPTION_SINGLE_STEP) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
            CONTEXT w{}; w.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
            const bool got = t && GetThreadContext(t, &w);
            const bool tf = got && (w.EFlags & 0x100u);
            // The fault reached the program WITHOUT our trap flag (the in-place step re-runs a
            // faulting instruction without it; WOW64 drops it anyway), and this is the thread's
            // next event: an INT3 at the site is its handler retrying the same execution,
            // whatever registers it changed to repair the fault (comparing them took a repaired
            // retry for a new hit: 2 callbacks).
            const bool same = true;
            if ((tf || same) && code == EXCEPTION_BREAKPOINT && address == site) {
                restart = true;                            // same execution: no new hit
            } else if (tf && code == EXCEPTION_SINGLE_STEP) {
                // The handler continued elsewhere with our trap flag: one instruction ran,
                // this is its trap. Drop the flag and let the thread run on.
                w.EFlags &= ~0x100u;
                const bool ok = !!SetThreadContext(t, &w);
                CloseHandle(t);
                if (!ok) { set_error(s, win_error("clear stray trap flag")); return false; }
                disposition = DBG_CONTINUE; return true;
            }
            if (t) CloseHandle(t);
        }
    }
    Probe *probe = code == EXCEPTION_BREAKPOINT ? probe_at(s, address) : nullptr;
    if (code == EXCEPTION_BREAKPOINT && !probe && !s->retired_bps.count(address))
        probe = adopt_relocated_breakpoint(s, address);   // our INT3, copied by another hooking tool
    if (code == EXCEPTION_BREAKPOINT && !probe && s->retired_bps.count(address)) {
        // Another thread hit a one-shot INT3 that has since been removed: the original
        // byte is back, so rewind to it and continue as if the breakpoint never existed.
        unsigned char now = 0; size_t got = 0;
        if (remote_read(s->pi.hProcess, address, &now, 1, &got) && got == 1 && now != 0xcc) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
            CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL;
            bool ok = t && GetThreadContext(t, &w);
#if defined(_WIN64)
            w.Rip = address;
#else
            w.Eip = (DWORD)address;
#endif
            ok = ok && SetThreadContext(t, &w);
            if (t) CloseHandle(t);
            if (!ok) { set_error(s, win_error("rewind stale breakpoint")); return false; }
            disposition = DBG_CONTINUE; return true;
        }
    }
    if (trace_enabled())
        std::fprintf(stderr, "EV code=0x%lx tid=%lu addr=0x%llx step=%d probe=%d first=%lu\n",
                     (unsigned long)code, (unsigned long)event.dwThreadId,
                     (unsigned long long)address, step != stepping.end(), probe != nullptr,
                     (unsigned long)event.u.Exception.dwFirstChance);
    if (code == EXCEPTION_SINGLE_STEP && step == stepping.end() && !s->gates.empty() && handle_gate(s, event)) {
        disposition = DBG_CONTINUE; return true;
    }
    if (code == EXCEPTION_SINGLE_STEP && step == stepping.end() && (s->hw_active || s->dr_ever)) {
        bool handled = false;
        if (!handle_hw(s, event, handled)) return false;
        if (handled) { disposition = DBG_CONTINUE; return true; }   // else fall through (not our DR)
        // A trap at the address of a hardware probe we have RELEASED, raised before the
        // release reached this thread (its debug status no longer names the slot): ours,
        // stale. Clear our slots on the thread, step over with RF, and swallow it.
        if (hw_released_on(s, event.dwThreadId, address) && !probe_any_at(s, address)) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
            CONTEXT w{}; w.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;
            if (t && GetThreadContext(t, &w)) {
                for (int slot = 0; slot < 4; ++slot) {
                    if (!(s->dr_ever & (1u << slot)) || (s->dr_used & (1u << slot))) continue;   // keep live probes
                    if (target_owns_slot(s, event.dwThreadId, w, slot)) continue;                                 // and the target's own
                    w.Dr7 &= ~((DWORD64)3 << (slot * 2)) & ~((DWORD64)0xF << (16 + slot * 4));
                }
                w.Dr6 = 0;
                w.EFlags |= 0x10000u;                                  // RF: run the instruction once
                SetThreadContext(t, &w);
            }
            if (t) CloseHandle(t);
            disposition = DBG_CONTINUE; return true;
        }
    }
    if (event.dwThreadId == s->remote_tid && s->remote_tid && event.u.Exception.dwFirstChance &&
        code != EXCEPTION_BREAKPOINT && code != EXCEPTION_SINGLE_STEP && code != PROBE_IPC_CODE &&
        s->remote_fault.empty()) {
        // The agent's load/init thread faulted. If the target's own unhandled-exception
        // filter swallows it, all we would see is the thread's exit code: keep where it was.
        s->remote_fault = describe_fault(s, ex, code, address);
        std::fprintf(stderr, "probe: %s agent thread %s\n", wall_clock().c_str(), s->remote_fault.c_str());
    } else if (!event.u.Exception.dwFirstChance && code != PROBE_IPC_CODE) {
        // Unhandled: the target is about to die. Say where, whatever the cause.
        std::fprintf(stderr, "probe: %s target crashed: tid=%lu %s\n", wall_clock().c_str(), (unsigned long)event.dwThreadId,
                     describe_fault(s, ex, code, address).c_str());
        print_crash_stack(s, event.dwThreadId);
    }
    // A stray trap-flag step inside our scratch slots with no step in progress: the target
    // wrote back a context it captured mid-step (see the jump-back after each displaced
    // copy). Ours, not the target's: drop TF and let the thread run the jump back.
    if (code == EXCEPTION_SINGLE_STEP && step == stepping.end()) {
        bool in_scratch = false;
        for (uint64_t b : s->scratch_blocks) if (address >= b && address < b + 0x10000) { in_scratch = true; break; }
        if (in_scratch) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
            CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL;
            if (t && GetThreadContext(t, &w)) { w.EFlags &= ~0x100u; SetThreadContext(t, &w); }
            if (t) CloseHandle(t);
            disposition = DBG_CONTINUE; return true;
        }
    }
    if (trace_enabled() && code == EXCEPTION_ACCESS_VIOLATION && ex.NumberParameters >= 2) {
        unsigned char around[24] = {0}; size_t got = 0;
        remote_read(s->pi.hProcess, address - 8, around, sizeof(around), &got);
        std::fprintf(stderr, "  AV %s 0x%llx first=%lu bytes[-8..+16]=%s\n",
                     ex.ExceptionInformation[0] == 8 ? "execute" : ex.ExceptionInformation[0] ? "write" : "read",
                     (unsigned long long)ex.ExceptionInformation[1], (unsigned long)event.u.Exception.dwFirstChance,
                     hex_bytes(around, got).c_str());
    }
    if (code != EXCEPTION_SINGLE_STEP && !probe && step != stepping.end() && step->second.displaced &&
        event.u.Exception.dwFirstChance) {
        // The displaced copy faulted. The target must see that fault at the REAL
        // instruction (its own SEH/C++ handlers and unwind data are keyed to it), so
        // swallow this one and re-run the instruction in place: lift our byte, step it
        // there; it faults again at the right address and is passed through below.
        uint64_t scratch = step->second.scratch;
        if (scratch && address >= scratch && address < scratch + step->second.insn_len + 16) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
            CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL;
            bool ok = t && GetThreadContext(t, &w);
            bool armed = still_armed(s, step->second.site);
            Probe *owner = armed ? probe_at(s, step->second.site) : nullptr;
            if (ok && owner) restore_original(s->pi.hProcess, step->second.site, owner->original);
            if (ok && owner && code == STATUS_GUARD_PAGE_VIOLATION && ex.NumberParameters >= 2) {
                // The copy's access consumed the page's one-shot guard: put it back, so the
                // re-run raises the guard violation the program expects at the real instruction.
                MEMORY_BASIC_INFORMATION m{};
                void *page = (void *)(uintptr_t)ex.ExceptionInformation[1];
                DWORD old = 0;
                if (VirtualQueryEx(s->pi.hProcess, page, &m, sizeof(m)) && m.State == MEM_COMMIT && !(m.Protect & PAGE_GUARD))
                    VirtualProtectEx(s->pi.hProcess, page, 1, m.Protect | PAGE_GUARD, &old);
            }
#if defined(_WIN64)
            w.Rip = step->second.site;
#else
            w.Eip = (DWORD)step->second.site;
#endif
            if (owner) w.EFlags |= 0x100u; else w.EFlags &= ~0x100u;
            ok = ok && SetThreadContext(t, &w);
            if (t) CloseHandle(t);
            if (!ok) { set_error(s, win_error("re-run faulting displaced instruction")); return false; }
            if (owner) {
                step->second.displaced = false; step->second.tail_int3 = false;
                step->second.windowed = true; inplace_begin(s, event.dwThreadId);   // lifted: hold the others
            } else {
                stepping.erase(step);
            }
            disposition = DBG_CONTINUE; return true;
        }
    }
    // Exceptions Windows raises ONLY because a debugger is attached (closing an invalid or
    // protected handle): without UHH the call just returns an error, so continue them.
    if ((code == 0xC0000008u /*STATUS_INVALID_HANDLE*/ || code == 0xC0000235u /*HANDLE_NOT_CLOSABLE*/) &&
        event.u.Exception.dwFirstChance && !probe) {
        disposition = DBG_CONTINUE; return true;
    }
    if ((code != EXCEPTION_SINGLE_STEP || step == stepping.end()) && !probe) {
        // An unexpected exception (a fault in the out-of-line copy, or any app
        // exception) reached a thread still mid-step. Drop its stale StepState so a
        // later stray single-step can't teleport it to site+insn_len; re-arm the byte
        // if the step was in-place. Pass the exception through unchanged.
        if (step != stepping.end()) {
            if (!step->second.displaced && event.u.Exception.dwFirstChance && address == step->second.site &&
                code != EXCEPTION_BREAKPOINT && step->second.windowed && !step->second.refire && !step->second.prog_tf) {
                // The instruction faulted during its in-place step: the kernel hands the program's
                // handler the context AS IT FAULTED -- with OUR trap flag (x64; WOW64 drops it),
                // which the program must never see. Swallow this one and run the instruction once
                // more without the flag (byte still lifted, window still held): it faults again,
                // and THAT fault, with the program's own flags, is the one passed on (below). A
                // guard page the faulting access consumed is put back first. Should the re-run
                // not fault after all, the window's watchdog re-arms the site (inplace_watchdog).
                HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
                CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL;
                if (t && GetThreadContext(t, &w) && (w.EFlags & 0x100u) && (uint64_t)EMU_IP(w) == address) {
                    if (code == STATUS_GUARD_PAGE_VIOLATION && ex.NumberParameters >= 2) {
                        MEMORY_BASIC_INFORMATION m{};
                        void *page = (void *)(uintptr_t)ex.ExceptionInformation[1];
                        DWORD old = 0;
                        if (VirtualQueryEx(s->pi.hProcess, page, &m, sizeof(m)) && m.State == MEM_COMMIT && !(m.Protect & PAGE_GUARD))
                            VirtualProtectEx(s->pi.hProcess, page, 1, m.Protect | PAGE_GUARD, &old);
                    }
                    w.EFlags &= ~0x100u;
                    if (SetThreadContext(t, &w)) {
                        CloseHandle(t);
                        step->second.refire = true;
                        disposition = DBG_CONTINUE; return true;
                    }
                }
                if (t) CloseHandle(t);
            }
            if (!step->second.displaced) {
                end_inplace_step(s, event.dwThreadId, step->second.site);
                // The instruction itself raised during its in-place step (e.g. the re-run of a
                // faulting displaced copy; re-run once more without our trap flag, above).
                // Remember it, to tell a restart of this same execution (the handler continues
                // at the site: the INT3 again) from a new hit.
                if (event.u.Exception.dwFirstChance && address == step->second.site) {
                    probe_session::Refault rf; rf.site = step->second.site;
                    s->refault[event.dwThreadId] = rf;
                }
            }
            stepping.erase(step);
        }
        return true;
    }
    if (code == EXCEPTION_BREAKPOINT && step != stepping.end() && !step->second.displaced &&
        step->second.site == address) {
        // This thread is mid in-place step AT this site: its own hit was queued while another
        // thread had the byte lifted, it was set up to run the original instruction, and that
        // other thread's step completion re-armed the INT3 first. It executed our INT3 instead
        // of the instruction: the same execution, not a new hit (it was a double callback).
        // Put it back on the site, lift the byte again, and let its step run.
        HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
        CONTEXT w{}; w.ContextFlags = CONTEXT_CONTROL;
        bool ok = t && GetThreadContext(t, &w);
#if defined(_WIN64)
        w.Rip = address;
#else
        w.Eip = (DWORD)address;
#endif
        w.EFlags |= 0x100u;
        ok = ok && patch(s->pi.hProcess, address, probe->original) && SetThreadContext(t, &w);
        if (t) CloseHandle(t);
        if (!ok) { set_error(s, win_error("re-lift in-place step")); return false; }
        if (step->second.windowed) inplace_begin(s, event.dwThreadId);
        disposition = DBG_CONTINUE; return true;
    }
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
    if (!thread) { set_error(s, win_error("open event thread")); return false; }
    CONTEXT native{}; native.ContextFlags = CONTEXT_ALL;
    if (code == EXCEPTION_SINGLE_STEP && step != stepping.end()) {
        // The stepped instruction (displaced or in place) may itself have touched a
        // watched address: then this #DB carries B-bits as well as BS. Service those
        // hardware hits first (their callbacks run, DR6 is cleared), then finish the step.
        bool hw_hit = false;
        if (s->hw_active || s->dr_ever) {
            CONTEXT dr{}; dr.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            if (GetThreadContext(thread, &dr) && (dr.Dr6 & 0xF)) {
                bool handled = false;
                if (!handle_hw(s, event, handled)) { CloseHandle(thread); return false; }
                hw_hit = handled;
            }
        }
        if (step->second.tail_int3) {
            // No trap flag is set for a string instruction running out-of-line: this #DB is a
            // watchpoint it touched (serviced above) -- the copy keeps running to its INT3.
            CloseHandle(thread);
            if (hw_hit) { disposition = DBG_CONTINUE; return true; }
            return true;                                   // not ours: pass it through
        }
        bool ok = !!GetThreadContext(thread, &native);
        if (ok && !step->second.displaced && step->second.rep_string &&
            (uint64_t)EMU_IP(native) == step->second.site) {
            // An in-place REP string step traps after each iteration: keep stepping (INT3
            // still lifted, trap flag kept) until the instruction completes, so the callback
            // runs once per execution, as on every other backend.
            native.EFlags |= 0x100u;
            ok = !!SetThreadContext(thread, &native);
            CloseHandle(thread);
            if (!ok) { set_error(s, win_error("continue string instruction step")); return false; }
            disposition = DBG_CONTINUE; return true;
        }
        if (step->second.displaced) {
            // The instruction ran out-of-line; the INT3 was never lifted, so there is
            // nothing to re-arm — just land on the instruction after the probe site.
            uint64_t next = step->second.site + step->second.insn_len;
#if defined(_WIN64)
            native.Rip = next;
#else
            native.Eip = (DWORD)next;
#endif
        } else if (ok) {
            end_inplace_step(s, event.dwThreadId, step->second.site);                                   // in-place: re-arm
            if (step->second.pushf_insn && !step->second.prog_tf &&
                (uint64_t)EMU_IP(native) == step->second.site + step->second.insn_len) {
                // PUSHF ran with OUR trap flag: the program's flags image must not show it
                // (RtlCaptureContext starts with pushfq).
                uint64_t v = 0; size_t n = 0; const size_t w = sizeof(void *);
                const uint64_t sp = (uint64_t)EMU_SP(native);
                if (remote_read(s->pi.hProcess, sp, &v, w, &n) && n == w && (v & 0x100)) {
                    v &= ~(uint64_t)0x100;
                    remote_write(s->pi.hProcess, sp, &v, w, &n);
                }
            }
        }
        native.EFlags &= ~0x100u;
#if defined(_WIN64)
        // SYSCALL saves RFLAGS in R11 -- with the trap flag WE set for the step. The program
        // can read R11 after the syscall; give it the flags image it would have had.
        if (!step->second.displaced && step->second.syscall_insn) native.R11 &= ~(DWORD64)0x100;
#endif
        if (ok) ok = !!SetThreadContext(thread, &native);
        CloseHandle(thread);
        if (!ok) { set_error(s, win_error("complete breakpoint single-step")); return false; }
        if (trace_enabled())
            std::fprintf(stderr, "  step-done tid=%lu displaced=%d\n",
                         (unsigned long)event.dwThreadId, step->second.displaced);
        stepping.erase(step); disposition = DBG_CONTINUE; return true;
    }
    if (!GetThreadContext(thread, &native)) {
        CloseHandle(thread); set_error(s, win_error("get breakpoint context")); return false;
    }
    if (s->in_call_tid && event.dwThreadId != s->in_call_tid && !probe->internal &&
        defer_hit_during_call(s, event.dwThreadId, address, true)) {
        CloseHandle(thread); disposition = DBG_CONTINUE; return true;
    }
    bool co_pass = false;                            // call_original's own entry pass: not a hit
    if (s->co_addr && event.dwThreadId == s->in_call_tid && !probe->internal) {
#if defined(_WIN64)
        const uint64_t sp = native.Rsp;
#else
        const uint64_t sp = native.Esp;
#endif
        if (s->co_entry_pending && address == s->co_addr && sp == s->co_sp) {
            s->co_entry_pending = false; co_pass = true;
        } else if (sp >= s->co_sp && defer_hit_during_call(s, event.dwThreadId, address, true)) {
            // The call_original thread is back at (or above) the hit's frame without having
            // returned: the original was left by an exception or longjmp. This hit is a NEW
            // one -- rewind it; it is serviced normally once the call is released.
            s->co_left = true; CloseHandle(thread); disposition = DBG_CONTINUE; return true;
        }
    }
    if (s->entry_reapply && address == s->entry_reapply && !probe->internal) reapply_all_hw(s);
    bool at_entry = s->entry_addr && address == s->entry_addr && !s->entry_seen;
    if (at_entry) s->entry_seen = true;
    probe_context context = from_context(native, probe_index(s, probe),
                                         address, &callback_ops, s);
    context.config = probe->config.empty() ? nullptr : probe->config.data();
    context.tid = event.dwThreadId;
    CallbackState state{s, probe, event.dwProcessId, event.dwThreadId}; context.controller = &state;
    s->cb_tid = event.dwThreadId;
    if (event.dwThreadId != s->in_call_tid && !restart)   // a probe hit INSIDE call_func's callee: step over it
    try { run_callback(s, probe, &context); s->cb_tid = 0; }
    catch (const std::exception &e) {
        CloseHandle(thread); set_error(s, std::string("probe callback: ") + e.what()); return false;
    } catch (...) {
        CloseHandle(thread); set_error(s, "probe callback threw an unknown exception"); return false;
    }
    if (!co_pass && !restart) count_hit(probe);
    if (state.released) {        // call_original released the thread: it runs on, nothing to write back
        CloseHandle(thread); s->skip_continue = true; return true;
    }
    to_context(context, native);
#if defined(_WIN64)
    native.Rsp = context.regs.rsp;
#else
    native.Esp = (DWORD)context.regs.rsp;
#endif
    if (apply_return_from(s, probe, context, native)) {
        // The body is skipped: resume at the `ret` gadget, the INT3 stays armed (a
        // one-shot is retired here instead).
        if ((probe->flags & PROBE_ONCE) && patch(s->pi.hProcess, probe->address, probe->original)) {
            probe->active = false; probe->retired = true; s->retired_bps.insert(probe->address); sync_int3_table(s);
        }
        native.ContextFlags = CONTEXT_FULL | UHH_CONTEXT_FP;      // FP: the original's result (see apply_return_from)
        bool ok = !!SetThreadContext(thread, &native);
        CloseHandle(thread);
        if (!ok) { set_error(s, win_error("resume at return_from")); return false; }
        if (at_entry && inline_hold_needed(s)) { hold_thread(s, event.dwThreadId); if (!kick_agent(s)) return false; }
        disposition = DBG_CONTINUE; return true;
    }
    if (probe->flags & PROBE_ONCE) {
        // One-shot: put the original byte back for good and resume AT the site -- the
        // real instruction runs in place, no single-step needed. Stale hits from other
        // threads are rewound via retired_bps above.
        if (!patch(s->pi.hProcess, probe->address, probe->original)) {
            CloseHandle(thread); set_error(s, win_error("retire one-shot breakpoint")); return false;
        }
        probe->active = false; probe->retired = true; s->retired_bps.insert(probe->address); sync_int3_table(s);
#if defined(_WIN64)
        native.Rip = probe->address;
#else
        native.Eip = (DWORD)probe->address;
#endif
        native.ContextFlags = CONTEXT_FULL;   // keep any DRs the callback armed
        bool ok = !!SetThreadContext(thread, &native);
        CloseHandle(thread);
        if (!ok) { set_error(s, win_error("resume after one-shot")); return false; }
        if (at_entry && inline_hold_needed(s)) { hold_thread(s, event.dwThreadId); if (!kick_agent(s)) return false; }
        disposition = DBG_CONTINUE; return true;
    }
#if defined(_WIN64)
    // SYSCALL / INT 2E: run from the site's trampoline -- the INT3 stays armed, no trap flag
    // (R11 gets the program's flags), and a syscall that blocks or returns elsewhere (APC,
    // NtContinue, a user-mode callback that hits probes on this thread) needs nothing from us.
    if (uint64_t tr = syscall_trampoline(s, *probe)) {
        native.Rip = tr;
        native.ContextFlags = CONTEXT_FULL;
        bool ok = !!SetThreadContext(thread, &native);
        CloseHandle(thread);
        if (!ok) { set_error(s, win_error("enter syscall trampoline")); return false; }
        if (at_entry && inline_hold_needed(s)) { hold_thread(s, event.dwThreadId); if (!kick_agent(s)) return false; }
        disposition = DBG_CONTINUE; return true;
    }
#endif
    // Branches, call/ret, loop, pushf/popf: executed here on the context -- the INT3 stays
    // armed (exact under threads) and no trap flag is ever set (nothing leaks).
    if (!probe->displaced_ok && emulate_site(s, *probe, native)) {
        native.ContextFlags = CONTEXT_FULL;               // keep any DRs the callback armed
        bool ok = !!SetThreadContext(thread, &native);
        CloseHandle(thread);
        if (!ok) { set_error(s, win_error("apply emulated instruction")); return false; }
        if (at_entry && inline_hold_needed(s)) { hold_thread(s, event.dwThreadId); if (!kick_agent(s)) return false; }
        disposition = DBG_CONTINUE; return true;
    }
    // Displaced stepping (default for ordinary instructions): run the original
    // instruction out-of-line with the INT3 left armed, so no other thread can cross
    // this site unobserved (no re-arm race) and no thread is suspended (no deadlock).
    bool displaced = probe->displaced_ok;
    uint64_t scratch_addr = displaced ? thread_scratch(s, event.dwThreadId, probe->address) : 0;
    if (displaced && scratch_addr) {
        std::vector<unsigned char> code = probe->orig_insn;
        if (probe->riprel_disp_off >= 0) {
            int32_t disp; std::memcpy(&disp, code.data() + probe->riprel_disp_off, sizeof(disp));
            // Preserve the same absolute target when the copy runs from scratch.
            int64_t nd = (int64_t)disp + (int64_t)(probe->address - scratch_addr);
            if (nd < INT32_MIN || nd > INT32_MAX) displaced = false;
            else { int32_t v = (int32_t)nd; std::memcpy(code.data() + probe->riprel_disp_off, &v, sizeof(v)); }
        }
        if (probe->rep_string) code.push_back(0xCC);       // the copy runs to completion, then traps here
        // Follow the copy with a jump back to the next real instruction. Normally never
        // executed (the single-step lands us there), but a target that captures a thread's
        // context while it reports the step (Suspend + GetThreadContext, e.g. a GC or its own
        // context round-trip) and writes it back after we moved it, resumes the thread HERE:
        // it must continue correctly instead of running whatever follows in the slot.
        if (displaced) {
            const uint64_t back = probe->address + probe->insn_len;
#if defined(_WIN64)
            const unsigned char jmp[6] = {0xFF, 0x25, 0, 0, 0, 0};   // jmp [rip+0]; dq back
            code.insert(code.end(), jmp, jmp + 6);
            for (int b = 0; b < 8; ++b) code.push_back((unsigned char)(back >> (8 * b)));
#else
            const uint32_t rel = (uint32_t)(back - (scratch_addr + code.size() + 5));
            code.push_back(0xE9);                                     // jmp rel32
            for (int b = 0; b < 4; ++b) code.push_back((unsigned char)(rel >> (8 * b)));
#endif
        }
        size_t wrote = 0;
        if (displaced && (!remote_write(s->pi.hProcess, scratch_addr, code.data(), code.size(), &wrote) ||
                          wrote != code.size())) {
            CloseHandle(thread); set_error(s, win_error("stage displaced instruction")); return false;
        }
        if (displaced) FlushInstructionCache(s->pi.hProcess, (void *)(uintptr_t)scratch_addr, code.size());
    } else {
        displaced = false;   // no scratch available -> in-place fallback
    }
    if (displaced) {
#if defined(_WIN64)
        native.Rip = scratch_addr;
#else
        native.Eip = (DWORD)scratch_addr;
#endif
    } else {
        // In-place fallback (sites neither displaced nor emulated, or scratch/reach failure):
        // lift the byte, step over it at the real address, re-arm on the single-step. Every
        // other thread is held meanwhile (in-place window, inplace_begin below).
        if (!patch(s->pi.hProcess, probe->address, probe->original)) {
            CloseHandle(thread); set_error(s, win_error("restore probed instruction")); return false;
        }
#if defined(_WIN64)
        native.Rip = probe->address;
#else
        native.Eip = (DWORD)probe->address;
#endif
    }
    const bool tail = displaced && probe->rep_string;
    const bool prog_tf = native.EFlags & 0x100u;
    if (!tail) native.EFlags |= 0x100u;
    // Preserve debug registers: the callback may have armed a hardware probe/watchpoint on
    // THIS thread (probe_watch/probe_add_at); writing CONTEXT_ALL with the pre-callback DR
    // image would clobber it. CONTEXT_FULL writes control/integer/segment only.
    native.ContextFlags = CONTEXT_FULL;
    if (!SetThreadContext(thread, &native)) {
        CloseHandle(thread); set_error(s, win_error("apply callback context")); return false;
    }
    CloseHandle(thread);
    if (trace_enabled())
        std::fprintf(stderr, "  setup tid=%lu displaced=%d scratch=0x%llx rip=0x%llx\n",
                     (unsigned long)event.dwThreadId, displaced,
                     (unsigned long long)scratch_addr, (unsigned long long)(displaced ? scratch_addr : probe->address));
    const bool is_syscall = probe->orig_insn.size() == 2 && probe->orig_insn[0] == 0x0F && probe->orig_insn[1] == 0x05;
    StepState st{probe, displaced, probe->address, probe->insn_len, displaced ? scratch_addr : 0,
                 tail, probe->rep_string, is_syscall};
    st.prog_tf = prog_tf;          // (also kept for a displaced copy that faults and re-runs in place)
#if defined(UHH_TEST_HOOKS)
    if (tail && !probe->internal) test_note_repcopy();
#endif
    if (!displaced) {
        bool pushf = false, may_block = false;
        site_traits(*probe, pushf, may_block);
        st.pushf_insn = pushf;
        st.windowed = !may_block;
        if (st.windowed) inplace_begin(s, event.dwThreadId);    // the byte is lifted: hold every other thread
    }
    stepping[event.dwThreadId] = st;
    if (at_entry && inline_hold_needed(s)) { hold_thread(s, event.dwThreadId); if (!kick_agent(s)) return false; }
    disposition = DBG_CONTINUE; return true;
}

static bool start_remote(probe_session *s, LPTHREAD_START_ROUTINE entry,
                         void *argument, probe_session::RemoteWork work) {
    s->remote_fault.clear();
    s->remote_thread = CreateRemoteThread(s->pi.hProcess, nullptr, 0, entry, argument, 0, &s->remote_tid);
    if (!s->remote_thread) { set_error(s, win_error("create agent thread")); return false; }
    if (trace_enabled()) std::fprintf(stderr, "  remote work=%d tid=%lu\n", (int)work, (unsigned long)s->remote_tid);
    s->remote_work = work; return true;
}

static bool start_agent_load(probe_session *s) {
    if (s->detaching) return true;                 // never inject into a target we are leaving
    if (s->remote_work != probe_session::REMOTE_NONE || s->remote_agent) return true;
    HMODULE local_kernel = GetModuleHandleW(L"kernel32.dll");
    auto local_load = reinterpret_cast<uintptr_t>(GetProcAddress(local_kernel, "LoadLibraryW"));
    if (!local_kernel || !local_load) { set_error(s, win_error("resolve LoadLibraryW")); return false; }
    HMODULE load_owner{};
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCSTR>(local_load), &load_owner)) {
        set_error(s, win_error("resolve LoadLibraryW owner")); return false;
    }
    std::string owner_name = module_name_from_module(load_owner); uint64_t remote_owner = 0;
    for (const auto &module : s->module_bases)
        if (iequals(module.first, owner_name)) { remote_owner = module.second; break; }
    if (!remote_owner) {
        set_error(s, "target module owning LoadLibraryW was not observed"); return false;
    }
    size_t bytes = (s->agent_path.size() + 1) * sizeof(wchar_t);
    s->remote_path = VirtualAllocEx(s->pi.hProcess, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!s->remote_path) { set_error(s, win_error("allocate remote agent path")); return false; }
    SIZE_T written{};
    if (!WriteProcessMemory(s->pi.hProcess, s->remote_path, s->agent_path.c_str(), bytes, &written) ||
        written != bytes) {
        set_error(s, win_error("write remote agent path")); return false;
    }
    uint64_t remote_load = remote_owner + local_load - reinterpret_cast<uintptr_t>(load_owner);
    return start_remote(s, reinterpret_cast<LPTHREAD_START_ROUTINE>((uintptr_t)remote_load),
                        s->remote_path, probe_session::REMOTE_LOAD_AGENT);
}

static bool vet_pending_inline(probe_session *s) {
    // Vet every inline site about to be installed: the bytes may have changed since the
    // site was resolved (a TLS callback or another tool can patch during loader init).
    for (size_t i = 0; i < s->probes.size(); ++i) {
        Probe &p = *s->probes[i];
        if (!(p.flags & PROBE_INLINE) || !p.address || p.active || p.retired || p.vetted) continue;
        // (Re-judged here even if judged at resolve time: a foreign hook may have been
        //  placed in between, e.g. by a TLS callback during loader initialisation.)
        auto &request = s->shared->requests[p.agent_index];
        if (request.status != PROBE_AGENT_PENDING) continue;
        p.vetted = true;
        bool moved = false;
        if (!vet_site(s, p, moved)) {
            if (p.runtime) { std::fprintf(stderr, "probe: %s\n", s->error.c_str()); s->error.clear(); }
            InterlockedExchange(&request.status, PROBE_AGENT_BAD_REQUEST); p.retired = true;
            if (!p.runtime) return false;
            continue;
        }
        if (moved) {
            InterlockedExchange(&request.status, PROBE_AGENT_BAD_REQUEST);   // agent must not install it
            uint64_t base = p.base; p.address = 0;
            if (!arm_hw(s, p, base)) return false;
        }
    }
    return true;
}

static bool start_agent_init(probe_session *s) {
    if (s->detaching) return true;                 // an init now would hook a target we are leaving
    if (s->remote_work != probe_session::REMOTE_NONE || !s->remote_agent || !s->local_agent) {
        set_error(s, "inline agent is not ready for initialization"); return false;
    }
    if (!vet_pending_inline(s)) return false;
    s->agent_init_started = true;
    // Nothing to install yet: still run init once if the agent's service thread is not up --
    // it is what installs hooks in modules that load later (whose loading thread holds the
    // loader lock, so no new thread could do it then).
    if (!agent_has_pending(s) && s->shared && s->shared->service_ready) return accept_agent_install(s);
    auto local_init = reinterpret_cast<uintptr_t>(GetProcAddress(s->local_agent, "probe_agent_init"));
    uint64_t remote_init = s->remote_agent + local_init - reinterpret_cast<uintptr_t>(s->local_agent);
    return start_remote(s, reinterpret_cast<LPTHREAD_START_ROUTINE>((uintptr_t)remote_init), nullptr,
                        probe_session::REMOTE_INIT_AGENT);
}

static bool agent_has_pending(const probe_session *s) {
    if (!s->shared) return false;
    for (const auto &p : s->probes) if ((p->flags & PROBE_INLINE) && p->address &&
        s->shared->requests[p->agent_index].status == PROBE_AGENT_PENDING) return true;
    return false;
}

static bool accept_agent_install(probe_session *s) {
    MemoryBarrier();
    std::string first_failure;      // every probe is accepted or retired, THEN a boot-time failure is reported
    for (auto &p : s->probes) if ((p->flags & PROBE_INLINE) && p->address && !p->active && !p->retired) {
        LONG status = s->shared->requests[p->agent_index].status;
        if (status == PROBE_AGENT_PENDING || status == PROBE_AGENT_INSTALLING) continue;   // next round
        if (status != PROBE_AGENT_INSTALLED) {
            std::string why = "inline agent failed to install " + p->location +
                              " (status=" + std::to_string(status) + ")";
            std::fprintf(stderr, "probe: %s\n", why.c_str());
            p->retired = true;
            if (!p->runtime && first_failure.empty()) first_failure = why;
            continue;
        }
        p->active = true;
        std::fprintf(stderr, "probe: active %s -> addr=0x%llx (inline)\n",
                     p->location.c_str(), (unsigned long long)p->address);
    }
    if (!first_failure.empty()) { set_error(s, first_failure); return false; }
    s->inline_ready = true;
    return true;
}

static bool complete_remote_thread(probe_session *s, DWORD result) {
    // The exit code comes from EXIT_THREAD_DEBUG_EVENT, not GetExitCodeThread: at
    // the instant that event is delivered the thread handle can still report
    // STILL_ACTIVE, which is the race that made agent init look like it failed.
    CloseHandle(s->remote_thread); s->remote_thread = nullptr;
    auto work = s->remote_work; s->remote_work = probe_session::REMOTE_NONE; s->remote_tid = 0;
    if (work == probe_session::REMOTE_LOAD_AGENT) {
        if (s->remote_path) {
            VirtualFreeEx(s->pi.hProcess, s->remote_path, 0, MEM_RELEASE); s->remote_path = nullptr;
        }
        if (result == 0 || !s->remote_agent) {
            const std::string why = "LoadLibraryW failed for probe_api_agent.dll" + (s->remote_fault.empty() ? std::string() : ": " + s->remote_fault);
            if (!has_inline(s)) return guard_set_ready(s, why.c_str());
            set_error(s, why);
            return false;
        }
        return start_agent_init(s);
    }
    if (work == probe_session::REMOTE_INIT_AGENT) {
        if (result != 0) {
            char code[16]; std::snprintf(code, sizeof(code), "0x%lx", (unsigned long)result);
            const std::string why = std::string("probe_agent_init failed (code=") + code + ")" +
                                    (s->remote_fault.empty() ? std::string() : ": " + s->remote_fault);
            if (!has_inline(s)) return guard_set_ready(s, why.c_str());
            set_error(s, why);
            return false;
        }
        if (!accept_agent_install(s)) return false;
        if (!guard_set_ready(s, nullptr)) return false;
        // Requests registered while that round ran (runtime inline adds) go next.
        if (agent_has_pending(s)) return kick_agent(s);
        // Release only once the service thread runs too (it reports itself with an
        // INSTALL_DONE): a module with inline sites may load the moment the threads go.
        if (!inline_hold_needed(s)) release_held(s, "inline installs confirmed");
        return true;
    }
    return true;
}

// One ring record (or a PROBE_IPC_LOG copy of one) -> the writer's queue. Never touches
// s->probes (the debug loop may be growing it); does not hold agent_mu while a full stdout
// queue applies backpressure.
static void enqueue_agent_record(probe_session *s, const probe_agent_log &rec) {
    try {
        LogRecord r;
        uint32_t len = rec.text_len < PROBE_AGENT_LOG_TEXT_CAP ? rec.text_len : PROBE_AGENT_LOG_TEXT_CAP - 1;
        r.text.assign(rec.text, len);
        r.tid = rec.tid; r.has_stack = rec.has_stack != 0;
        {
            std::lock_guard<std::mutex> map_lock(s->agent_mu);
            r.probe = rec.probe < PROBE_AGENT_MAX_PROBES && s->agent_map[rec.probe] != UINT32_MAX
                          ? s->agent_map[rec.probe] : rec.probe;
        }
        uint32_t n = rec.frame_count > PROBE_STACK_MAX_FRAMES ? PROBE_STACK_MAX_FRAMES : rec.frame_count;
        r.frames.assign(rec.frames, rec.frames + n);
        enqueue_log(s, std::move(r));
    } catch (...) {
        s->controller_dropped.fetch_add(1, std::memory_order_relaxed);   // out of memory: count it, keep going
    }
}

// Move published inline-log records out of the shared ring (single consumer). Called
// every debug-loop turn, on idle timeouts, and at report, so the ring never fills
// just because the run is long.
static size_t drain_agent_logs(probe_session *s) {
    if (!s->shared) return 0;
    auto *sh = s->shared;
    size_t moved = 0;
    std::lock_guard<std::mutex> consume(s->drain_mu);
    for (;;) {
        LONG64 tail = sh->log_tail;
        auto &rec = sh->logs[(uint64_t)tail % PROBE_AGENT_LOG_CAP];
        LONG64 seq = rec.seq;
        if (seq != tail + 1 && seq != -(tail + 1)) break;
        MemoryBarrier();
        if (seq == tail + 1) enqueue_agent_record(s, rec);    // -(tail + 1): delivered past a stall already
        rec.owner = 0;
        MemoryBarrier();
        InterlockedExchange64(&rec.seq, tail + PROBE_AGENT_LOG_CAP);    // slot free again
        sh->log_tail = tail + 1;
        ++moved;
    }
    return moved;
}

// The thread that claimed a ring slot is gone (it can never publish it): no such thread,
// exited, or the id now names a thread of another process.
static bool ring_owner_gone(probe_session *s, DWORD tid) {
    HANDLE t = OpenThread(SYNCHRONIZE | THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!t) return GetLastError() == ERROR_INVALID_PARAMETER;
    bool gone = WaitForSingleObject(t, 0) == WAIT_OBJECT_0 || GetProcessIdOfThread(t) != s->pi.dwProcessId;
    CloseHandle(t);
    return gone;
}

// The tail is stuck behind an unpublished slot: deliver the PUBLISHED records after it now,
// in ring order, marking each seq = -(pos + 1) (delivered; drain_agent_logs frees it when the
// tail gets there). Stops at the next unpublished slot: a record beyond THAT could belong to
// the same producer as a later one published during the scan (per-thread order).
static void deliver_past_stall(probe_session *s) {
    auto *sh = s->shared;
    std::lock_guard<std::mutex> consume(s->drain_mu);
    LONG64 tail = sh->log_tail, head = sh->log_head;
    if (head <= tail || sh->logs[(uint64_t)tail % PROBE_AGENT_LOG_CAP].seq != tail) return;
    for (LONG64 pos = tail + 1; pos < head; ++pos) {
        auto &rec = sh->logs[(uint64_t)pos % PROBE_AGENT_LOG_CAP];
        LONG64 seq = rec.seq;
        if (seq == -(pos + 1)) continue;
        if (seq != pos + 1) break;
        MemoryBarrier();
        enqueue_agent_record(s, rec);
        InterlockedExchange64(&rec.seq, -(pos + 1));
    }
}

// The drainer found nothing to move. If that is because the slot at the tail is CLAIMED (its
// owner set) but not published, the ring cannot move until its producer publishes:
//  - producer dead (TerminateThread / ExitProcess mid-send_log): skip the slot. Its callback
//    stays counted in flight (callbacks_interrupted), so the hit is accounted; nothing else
//    is lost. (Dead while only holding the owner of a free slot: give the slot back.)
//  - producer alive but not running (the program suspended it): the records behind it are
//    delivered past it, and after 200 ms producers are told the ring is stalled -- they hand
//    records over by PROBE_IPC_LOG instead of waiting for a free slot.
struct RingStall { LONG64 tail = -1; ULONGLONG since = 0; };
static void check_ring_stall(probe_session *s, RingStall &st) {
    auto *sh = s->shared;
    LONG64 tail = sh->log_tail, head = sh->log_head;
    auto &rec = sh->logs[(uint64_t)tail % PROBE_AGENT_LOG_CAP];
    DWORD owner = (DWORD)rec.owner;
    ULONGLONG now = GetTickCount64();
    bool blocked = rec.seq == tail && owner != 0;
    if (!blocked || tail != st.tail) {
        st.tail = blocked ? tail : -1; st.since = now;
        if (sh->ring_stalled) InterlockedExchange(&sh->ring_stalled, 0);
        return;
    }
    if (now - st.since < 20) return;
    if (ring_owner_gone(s, owner)) {
        std::lock_guard<std::mutex> consume(s->drain_mu);
        if (sh->log_tail != tail || rec.seq != tail || (DWORD)rec.owner != owner) return;
        if (sh->log_head == tail) {                       // died between the owner and head CAS
            InterlockedCompareExchange(&rec.owner, 0, (LONG)owner);
            return;
        }
        rec.owner = 0;
        MemoryBarrier();
        InterlockedExchange64(&rec.seq, tail + PROBE_AGENT_LOG_CAP);
        sh->log_tail = tail + 1;
        if (s->abandoned_slots++ == 0)
            std::fprintf(stderr, "probe: warning: thread %lu was killed while writing a log record; its callback "
                                 "is counted as interrupted and the log ring moves on\n", (unsigned long)owner);
        return;
    }
    if (head > tail) deliver_past_stall(s);
    if (now - st.since >= 200 && head > tail && sh->log_ipc && !sh->ring_stalled) InterlockedExchange(&sh->ring_stalled, 1);
}

// Producers in the target can log at ~1M records/s; the debug loop only gets to the
// ring between events. A dedicated consumer keeps the ring near empty so producers
// rarely see it full (and when they do they wait -- logs are never dropped by design).
static void start_drainer(probe_session *s) {
    if (s->drainer.joinable() || !s->shared) return;
    s->drain_stop = false;
    s->drainer = std::thread([s] {
        unsigned idle = 0;
        RingStall stall;
        while (!s->drain_stop.load(std::memory_order_relaxed)) {
            InterlockedIncrement64(&s->shared->drain_beat);           // "controller alive"
            if (drain_agent_logs(s)) { idle = 0; continue; }
            check_ring_stall(s, stall);
            if (++idle < 64) SwitchToThread(); else Sleep(1);
        }
    });
}

// The controller stops consuming (controller_gone is set). Claimed slots are waited for
// briefly while the target runs (a producer between claim and publish finishes in
// nanoseconds); then every PUBLISHED record is delivered, also those behind a slot that will
// never be published. Such a slot's producer was killed or is suspended mid-callback: that
// callback is still counted in flight (callbacks_interrupted at exit; "in flight" in the
// detach summary), so the slot is not counted again as dropped --
// logs + log_dropped + callbacks_interrupted == hits.
static void drain_final(probe_session *s) {
    if (!s->shared) return;
    auto *sh = s->shared;
    drain_agent_logs(s);
    if (!s->exited)
        for (ULONGLONG until = GetTickCount64() + 500; sh->log_head != sh->log_tail && GetTickCount64() < until; ) {
            if (!drain_agent_logs(s)) Sleep(1);
        }
    std::lock_guard<std::mutex> consume(s->drain_mu);
    // head and tail live in memory the TARGET can write: never trust them for the loop
    // bound. At most one ring's worth of slots can hold unread records.
    const LONG64 tail = sh->log_tail;
    LONG64 head = sh->log_head;
    if ((uint64_t)head - (uint64_t)tail > PROBE_AGENT_LOG_CAP) head = (LONG64)((uint64_t)tail + PROBE_AGENT_LOG_CAP);
    for (LONG64 pos = tail; pos != head; pos = (LONG64)((uint64_t)pos + 1)) {
        auto &rec = sh->logs[(uint64_t)pos % PROBE_AGENT_LOG_CAP];
        if (rec.seq != (LONG64)((uint64_t)pos + 1)) continue;                 // its producer died / is stopped mid-callback (see above)
        MemoryBarrier();
        enqueue_agent_record(s, rec);
    }
    sh->log_tail = head;
}

// How many in-flight inline callbacks can still finish (probe_agent_shared::live_query),
// answered by the agent's service thread. False: no answer (no service thread, or it cannot
// run) -- the caller falls back to a bounded wait.
static bool query_live_callbacks(probe_session *s, LONG &live) {
    if (!s->svc_event || !s->shared) return false;
    auto *sh = s->shared;
    const LONG seq = sh->live_seq;
    InterlockedExchange(&sh->live_query, 1);
    SetEvent(s->svc_event);
    for (ULONGLONG until = GetTickCount64() + 1000; GetTickCount64() < until; Sleep(1)) {
        MemoryBarrier();
        if (sh->live_seq != seq) { MemoryBarrier(); live = sh->live_callbacks; return true; }
    }
    return false;
}

static void stop_drainer(probe_session *s) {
    // Detached from a live target: its hooks are gone, but a callback that was already running
    // (e.g. blocked in call_original longer than the agent's 2 s unhook wait) may still log.
    // Keep draining BEFORE telling producers nobody listens, so its logs are delivered rather
    // than dropped -- for as long as any in-flight callback can still finish (no time bound: a
    // slow detach is reported, never cut short). Callbacks that cannot finish now -- their
    // thread is gone, or suspended by the program, or left through a non-unwinding longjmp --
    // are not waited for: they stay counted in flight (the detach summary's in_flight), and a
    // log one sends if the program resumes it later is counted dropped in the target. Without
    // an answer from the agent (no service thread) the wait is bounded (15 s), as before.
    if (s->shared && !s->exited && s->drainer.joinable()) {
        MemoryBarrier();
        if (const uint64_t running = probe_agent_inflight(s->shared))
            std::fprintf(stderr, "probe: %s: %llu callback(s) still running; delivering their logs\n",
                         s->detached_hooks ? "detach" : "close", (unsigned long long)running);
    }
    if (s->shared && s->detached_hooks && !s->exited && s->drainer.joinable()) {
        const ULONGLONG start = GetTickCount64();
        ULONGLONG next_note = start + 15000;
        int idle_answers = 0;
        ULONGLONG last_answer = start;
        for (;;) {
            MemoryBarrier();
            const uint64_t inflight = probe_agent_inflight(s->shared);
            if (!inflight && s->shared->log_head == s->shared->log_tail) break;
            const ULONGLONG now = GetTickCount64();
            if (inflight) {
                LONG live = 0;
                if (query_live_callbacks(s, live)) {
                    last_answer = GetTickCount64();
                    // Three answers in a row (~50 ms apart): a callback between its in-flight
                    // count and its record (nanoseconds) is not missed.
                    if (live > 0) idle_answers = 0;
                    else if (++idle_answers >= 3) {
                        std::fprintf(stderr, "probe: detach: %llu callback(s) cannot finish now (thread gone or suspended); "
                                             "not waiting for them\n", (unsigned long long)inflight);
                        break;
                    }
                } else if (now - last_answer >= 15000) {
                    break;                                      // nobody answers (any more): the old bound
                }
            } else if (now - start >= 15000) {
                break;                                          // ring not empty with nothing in flight
            }
            if (now >= next_note) {
                next_note += 15000;
                std::fprintf(stderr, "probe: detach: still waiting for %llu running callback(s) to finish (%llus)\n",
                             (unsigned long long)inflight, (unsigned long long)((now - start) / 1000));
            }
            Sleep(inflight ? 50 : 5);
        }
    }
    if (s->shared) {
        InterlockedExchange(&s->shared->log_ipc, 0);
        InterlockedExchange(&s->shared->ring_stalled, 0);
        InterlockedExchange(&s->shared->controller_gone, 1);   // producers stop waiting
    }
    if (!s->drainer.joinable()) { drain_final(s); return; }
    s->drain_stop = true; s->drainer.join();
    drain_final(s);
}

// One debug event -> library state changes. Shared by probe_run and the detach path.
static bool dispatch_event_impl(probe_session *s, DEBUG_EVENT &event, DWORD &disposition);
static bool dispatch_event(probe_session *s, DEBUG_EVENT &event, DWORD &disposition) {
    s->handling.push_back(event.dwThreadId);
    struct Handling {
        probe_session *s;
        ~Handling() { s->handling.pop_back(); }
    } handling{s};
    guard_note_hold(s, event.dwThreadId);            // see guard_sync: until the event is continued
    const bool ok = dispatch_event_impl(s, event, disposition);
    inplace_sync(s, event);
    // The guard's mirror, after EVERYTHING this event changed (an in-place window's holds are
    // taken / handed over just above) and before the thread runs again. The event's thread
    // stays listed until the next sync (its context may still be written before it continues).
    if (!s->exited) guard_sync(s);
    return ok;
}
static bool dispatch_event_impl(probe_session *s, DEBUG_EVENT &event, DWORD &disposition) {
    disposition = DBG_CONTINUE; bool ok = true;
    settle_hw_thread(s, event.dwThreadId);           // released hardware probes: still ours on it?
    switch (event.dwDebugEventCode) {
    case CREATE_PROCESS_DEBUG_EVENT: {
        s->threads.insert(event.dwThreadId);                 // initial thread (for HW DRs)
        std::string name = module_name_from_handle(event.u.CreateProcessInfo.hFile);
        uint64_t base = (uint64_t)(uintptr_t)event.u.CreateProcessInfo.lpBaseOfImage;
        if (!name.empty()) s->module_bases[name] = base;
        sym_register(s, event.u.CreateProcessInfo.hFile, base);
        ok = arm_module(s, name, base);
        if (ok && !s->attached) arm_entry_fixup(s, (uint64_t)(uintptr_t)event.u.CreateProcessInfo.lpStartAddress);
        if (event.u.CreateProcessInfo.hFile) CloseHandle(event.u.CreateProcessInfo.hFile);
        break;
    }
    case CREATE_THREAD_DEBUG_EVENT:
        s->threads.insert(event.dwThreadId);
        if (s->ipc_freezer) ipc_freeze_thread(s, event.dwThreadId);   // born during a hook write: hold it too
        if (event.u.CreateThread.hThread && !s->detaching)     // new thread inherits the gates
            for (auto &g : s->gates) set_dr_on_thread(event.u.CreateThread.hThread, g.second, g.first, true);
        if (s->hw_active && event.u.CreateThread.hThread)     // new thread inherits the DRs
            for (auto &p : s->probes)
                if (p->active && (p->flags & PROBE_HW)) {
                    uint32_t rw = 0, len = 0; hw_rw_len(p->flags, rw, len);
                    set_dr_on_thread(event.u.CreateThread.hThread, p->dr_slot, p->address, true, rw, len);
                }
        // A launched target's thread born while inline installs are outstanding (e.g. started
        // by a TLS callback or a static DLL's DllMain(PROCESS_ATTACH) during process init,
        // before the main thread reaches the entry hold) could reach a site before its hook
        // is in. Hold it from its first instruction (it owns no lock yet) until the same
        // confirmation releases the others. Attached targets: only while a hold is already in
        // progress (a callback's runtime add) and the agent is up -- attach holds nothing while
        // the agent is injected. Never our own agent threads (they do the install).
        if (s->initial_break && event.dwThreadId != s->remote_tid &&
            (!s->attached || (!s->held.empty() && s->shared && s->shared->service_ready)) &&
            inline_hold_needed(s) && !agent_thread(s, event.dwThreadId))
            hold_thread(s, event.dwThreadId);
        // Do NOT close hThread: the debug subsystem owns it and closes it itself when the
        // thread's EXIT_THREAD event is continued. Closing it here made that later close hit
        // whatever handle had reused the value (e.g. a held thread's -> left suspended).
        break;
    case EXIT_THREAD_DEBUG_EVENT: {
        if (event.dwThreadId == s->remote_tid) ok = complete_remote_thread(s, event.u.ExitThread.dwExitCode);
        if (event.dwThreadId == s->ipc_freezer) ipc_thaw(s);       // agent thread died mid-write: never strand the rest
        s->threads.erase(event.dwThreadId);
        s->refault.erase(event.dwThreadId);
        s->hw_unsettled.erase(event.dwThreadId);
        auto it = s->stepping.find(event.dwThreadId);
        if (ok && it != s->stepping.end()) {
            // Only the in-place path lifted the byte; a displaced step left it armed.
            if (!it->second.displaced) end_inplace_step(s, event.dwThreadId, it->second.site);
            s->stepping.erase(it);
            if (!ok) set_error(s, win_error("re-arm probe after thread exit"));
        }
        for (auto sc = s->scratch.begin(); sc != s->scratch.end(); ) {   // return its step slots
            if (sc->first.first == event.dwThreadId) {
                s->scratch_free[sc->first.second].push_back(sc->second);
                sc = s->scratch.erase(sc);
            } else ++sc;
        }
        break;
    }
    case LOAD_DLL_DEBUG_EVENT: {
        std::string name = module_name_from_handle(event.u.LoadDll.hFile);
        uint64_t base = (uint64_t)(uintptr_t)event.u.LoadDll.lpBaseOfDll;
        if (!name.empty()) s->module_bases[name] = base;
        sym_register(s, event.u.LoadDll.hFile, base);
        ok = arm_module(s, name, base);
        if (iequals(name, "probe_api_agent.dll")) {
            s->remote_agent = base;
        }
        if (!s->held.empty()) s->held_since = GetTickCount64();   // symbol work above may have been slow
        if (trace_enabled()) std::fprintf(stderr, "  load_dll %s tid=%lu pending=%d t=%llu\n", name.c_str(),
                                          (unsigned long)event.dwThreadId, (int)agent_has_pending(s), (unsigned long long)GetTickCount64());
        if (ok && agent_has_pending(s)) {
            if (s->shared->service_ready && s->svc_event) {
                // Gate the new sites with debug registers and let the loading thread run on
                // (it holds loader state the install may need). Only if no DR is free, park
                // the loading thread as before.
                if (!arm_gates_for_pending(s)) hold_thread(s, event.dwThreadId);
                ok = kick_agent(s);
            } else if (s->remote_agent && s->remote_work == probe_session::REMOTE_NONE) {
                ok = start_agent_init(s);
            }
        }
        if (event.u.LoadDll.hFile) CloseHandle(event.u.LoadDll.hFile);
        break;
    }
    case UNLOAD_DLL_DEBUG_EVENT: {
        uint64_t base = (uint64_t)(uintptr_t)event.u.UnloadDll.lpBaseOfDll;
        // The unmapping thread reports AFTER the view is gone, so another thread can map the
        // same DLL again at the same base and report ITS load first. Seen under load/unload
        // churn: the late unload then retired probes just armed in the NEW instance -- its
        // INT3 / hook stayed in live code, was never removed at detach, and the detached
        // target died on it (0x80000003). An image mapped at this base right now means this
        // unload is stale: keep the probes (and the module) as they are.
        {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQueryEx(s->pi.hProcess, (void *)(uintptr_t)base, &mbi, sizeof(mbi)) && mbi.State == MEM_COMMIT &&
                mbi.Type == MEM_IMAGE && (uint64_t)(uintptr_t)mbi.AllocationBase == base) {
                if (trace_enabled()) std::fprintf(stderr, "  stale unload at 0x%llx ignored\n", (unsigned long long)base);
                break;
            }
        }
        sym_unload(s, base);
        uint64_t size = 0;
        if (auto sz = s->module_sizes.find(base); sz != s->module_sizes.end()) { size = sz->second; s->module_sizes.erase(sz); }
        for (auto it = s->module_bases.begin(); it != s->module_bases.end(); )
            if (it->second == base) it = s->module_bases.erase(it); else ++it;
        for (auto &p : s->probes) {
            // Absolute-address probes (probe_add_address / probe_watch: base 0) inside the
            // module go with it, for good: there is no module to re-resolve them against, and
            // a stale one would keep its debug register, shadow a new probe at a reused address
            // (its saved instruction bytes run instead) and mask the new code's bytes.
            if (!p->active || p->base || !size || p->address < base || p->address - base >= size) continue;
            std::fprintf(stderr, "probe: %s retired: its module unloaded\n", p->location.c_str());
            if (p->flags & PROBE_INLINE) {
                if (s->shared && p->agent_index < PROBE_AGENT_MAX_PROBES)
                    InterlockedExchange(&s->shared->requests[p->agent_index].status, PROBE_AGENT_UNLOADED);
                p->active = false;
            } else if (p->flags & PROBE_HW) {
                release_hw(s, *p);
            } else {
                p->active = false;
                sync_int3_table(s);      // the agent's copy too: a stale entry masks reused memory
            }
            p->retired = true;
        }
        for (auto &p : s->probes) if (p->active && p->base == base) {
            if (p->flags & PROBE_INLINE) {
                // The hooked code went away with its module. The probe goes back to pending,
                // exactly like breakpoint/hw probes: if the module loads again (anywhere),
                // the agent installs a fresh hook at the new address.
                std::fprintf(stderr, "probe: %s unloaded with its module; pending until it loads again\n", p->location.c_str());
                p->active = false; p->vetted = false; p->base = p->address = 0;
                // Tell the agent: its hook there now points at unmapped (or reused) memory,
                // so detach must not write the original bytes back.
                if (s->shared && p->agent_index < PROBE_AGENT_MAX_PROBES)
                    InterlockedExchange(&s->shared->requests[p->agent_index].status, PROBE_AGENT_UNLOADED);
            } else if (p->flags & PROBE_HW) {
                // Fully release the hardware breakpoint: clear its DR on every thread,
                // free the slot, and drop the active count. A half-disarm (just
                // clearing active/address) leaks the DR slot and strands the physical
                // breakpoint on the unloaded address -> later slot exhaustion / crash.
                release_hw(s, *p);
                p->base = p->address = 0;
            } else { p->active = false; p->base = p->address = 0; sync_int3_table(s); }
        }
        break;
    }
    case EXCEPTION_DEBUG_EVENT:
        ok = handle_exception(s, event, s->stepping, s->initial_break, disposition);
        s->cb_tid = 0;
        for (DWORD tid : s->pending_hold) hold_thread(s, tid);
        s->pending_hold.clear();
        // (Attach does NOT hold the target's threads while the agent is injected: the target
        //  was already running, so a call before the hook lands is no different from one
        //  before the attach -- a probe reports "active" only once its hook is confirmed --
        //  while a held thread that owns the loader lock blocked the agent's LoadLibrary and
        //  froze the target until the install timeout (seen attaching to PowerShell). The
        //  hook write itself is safe without it: FREEZE suspends every thread for the patch.)
        if (ok && s->initial_break && needs_agent(s) && s->remote_work == probe_session::REMOTE_NONE &&
            (!s->remote_agent || (s->attached && !s->agent_init_started))) {
            // (Re-attach: the agent is still loaded from an earlier session -- just init it.)
            ok = !s->remote_agent ? start_agent_load(s) : start_agent_init(s);
            if (!ok && !has_inline(s)) { std::string why = s->error; s->error.clear(); ok = guard_set_ready(s, why.c_str()); }
        }
        break;
    case EXIT_PROCESS_DEBUG_EVENT:
        ipc_thaw(s);
        s->exit_code = event.u.ExitProcess.dwExitCode; s->exited = true; break;
    default: break;
    }
    return ok;
}

// Ctrl+C / Ctrl+Break / console close while a session runs (probe_run through
// probe_wait_for_exit) ends the SESSION, not the tool: probe_run lets go of the target --
// an attached one is detached (probes removed, it keeps running), a launched one ended --
// and returns normally, so the caller still flushes the logs and writes its report. A
// second press, or one while no session runs, gets the default handling (the tool exits).
static std::atomic<int> g_ctrl_sessions{0};
static std::atomic<bool> g_ctrl_hit{false};

// probe_run loops still running (any session); g_runs_done is set when the last one has let
// go of its target (detached / ended) after a ctrl event.
static std::atomic<int> g_ctrl_runs{0};
static HANDLE g_runs_done = CreateEventW(nullptr, TRUE, FALSE, nullptr);

static BOOL WINAPI on_console_ctrl(DWORD type) {
    const bool mine = g_ctrl_sessions.load() > 0 && !g_ctrl_hit.exchange(true);
    if (trace_enabled()) std::fprintf(stderr, "  console ctrl %lu sessions=%d -> %s\n", (unsigned long)type,
                                      g_ctrl_sessions.load(), mine ? "session stop" : "default");
    // Console closed / logoff / shutdown: Windows ends this process as soon as the handler
    // returns, which would leave an attached target with live INT3s, debug registers and
    // hooks (it dies at its next hit). Hold the handler until probe_run has let go (the
    // system allows ~5 s for CTRL_CLOSE).
    if (mine && (type == CTRL_CLOSE_EVENT || type == CTRL_LOGOFF_EVENT || type == CTRL_SHUTDOWN_EVENT) &&
        g_ctrl_runs.load() > 0 && g_runs_done)
        WaitForSingleObject(g_runs_done, 4500);
    return mine;
}

static void ctrl_enter(probe_session *s) {
    static const BOOL installed = SetConsoleCtrlHandler(on_console_ctrl, TRUE);
    if (trace_enabled()) std::fprintf(stderr, "  console ctrl handler installed=%d err=%lu\n", installed, GetLastError());
    if (!s->ctrl_counted) { s->ctrl_counted = true; g_ctrl_sessions.fetch_add(1); }
}

static void ctrl_leave(probe_session *s) {
    if (!s->ctrl_counted) return;
    s->ctrl_counted = false;
    if (g_ctrl_sessions.fetch_sub(1) == 1) g_ctrl_hit = false;   // the next session starts clean
}

extern "C" int probe_run(probe_session *s) {
    if (!s || !s->launched) { if (s) set_error(s, "session is not launched"); return 0; }
    if (s->ran) { set_error(s, "session already ran"); return 0; }
    if (s->debug_tid && s->debug_tid != GetCurrentThreadId()) {
        // Windows binds the debug object to the thread that created the process or attached.
        set_error(s, "probe_run must be called on the thread that called probe_launch/probe_attach");
        return 0;
    }
    s->running = true;                     // before `ran`: probe_close waits on (ran && !running)
    s->ran = true;
    ctrl_enter(s);
    if (g_ctrl_runs.fetch_add(1) == 0 && g_runs_done) ResetEvent(g_runs_done);
    DEBUG_EVENT event{};
    while (!s->exited) {
        if (g_ctrl_hit && !s->interrupted) {
            s->interrupted = true; s->stop_requested = true;
            std::fprintf(stderr, "probe: interrupted: %s\n", s->attached
                         ? "detaching (probes removed, the target keeps running)" : "ending the target");
        }
        if (s->stop_requested) {
            // probe_close was called on another thread. The debug API binds the debug object
            // to THIS thread, so the detach (or termination) happens here.
            if (s->attached) { detach(s); s->detached = true; }
            else if (s->pi.hProcess) { TerminateProcess(s->pi.hProcess, 3); s->stop_requested = false; continue; }
            break;
        }
        drain_agent_logs(s);
        if (guard_pending(s) && s->guard_since && GetTickCount64() - s->guard_since > 5000 &&
            !guard_set_ready(s, "agent not ready within 5 s")) break;
        if (!s->held.empty() && GetTickCount64() - s->held_since > 5000) {
            // Never wedge the target: an install that does not confirm in 5 s is reported
            // and the threads run on (the affected probes simply stay inactive).
            std::fprintf(stderr, "probe: warning: inline install not confirmed within 5 s\n");
            if (trace_enabled()) trace_thread_stacks(s, "install timeout");
            release_held(s, "install timeout");
        }
        if (!WaitForDebugEvent(&event, 20)) {                         // short: also polls stop requests
            if (GetLastError() == ERROR_SEM_TIMEOUT) {      // idle: drain and wait again
                inplace_watchdog(s);
                if (!s->exited) guard_sync(s);              // holds released outside an event
                continue;
            }
            set_error(s, win_error("wait for debug event")); break;
        }
        if (continue_foreign_event(s, event)) continue;
        DWORD disposition = DBG_CONTINUE;
        bool ok = dispatch_event(s, event, disposition);
        if (s->skip_continue) { s->skip_continue = false; if (!ok) break; continue; }
        if (!ContinueDebugEvent(event.dwProcessId, event.dwThreadId, disposition)) {
            set_error(s, win_error("continue debug event")); ok = false;
        }
#if defined(UHH_TEST_HOOKS)
        if (g_test_die_on_continue) { std::fflush(nullptr); TerminateProcess(GetCurrentProcess(), 97); }
#endif
        if (!ok) break;
    }
    // An attached target is still running and the loop is leaving for some other reason
    // than a detach (an error: agent load/init failure, a failed context get/set or debug
    // wait): let go of it HERE, on the thread that owns the debug object -- INT3s restored,
    // debug registers cleared, inline hooks removed, logs drained -- instead of leaving live
    // traps behind a dead event loop (the target would freeze at its next debug event and die
    // when the controller exits) for a probe_close on a thread that cannot detach.
    if (s->attached && !s->exited && !s->detached && s->pi.hProcess) {
        const std::string why = s->error;
        std::fprintf(stderr, "probe: session failed (%s): detaching from the target\n", why.c_str());
        detach(s); s->detached = true;
        if (!why.empty()) s->error = why;
    }
    release_held(s, "session end");
    stop_drainer(s);
    flush_log_writer(s);
    if (!s->exited && s->pi.hProcess && !s->attached) TerminateProcess(s->pi.hProcess, 3);
    if (s->exited && has_inline(s) && !s->inline_ready) set_error(s, "target exited before inline probes were ready");
    int result = (s->exited || s->detached) && s->error.empty();
    if (g_ctrl_runs.fetch_sub(1) == 1 && g_runs_done) SetEvent(g_runs_done);   // a closing console may go on
    s->running = false;                                   // last touch of s on this thread
    return result;
}

extern "C" int probe_wait_for_exit(probe_session *s) {
    if (!s || !s->ran) { if (s) set_error(s, "session has not been run"); return 0; }
    if (s->exited) stop_drainer(s);             // includes recovery past a dead producer's ring slot
    flush_log_writer(s);
    ctrl_leave(s);
    return s->error.empty() && (s->interrupted || (s->exited && s->exit_code == 0));
}

static void json_string(FILE *out, const std::string &value) {
    std::string text;
    append_json_string(text, value);
    std::fputs(text.c_str(), out);
}

extern "C" void probe_report(probe_session *s, FILE *out) {
    if (!s || !out) return;
    if (s->shared) {
        MemoryBarrier();
        for (auto &p : s->probes) if (p->flags & PROBE_INLINE)
            p->hits = probe_agent_hits(s->shared, p->agent_index);
    }
    if (s->exited) stop_drainer(s); else drain_agent_logs(s);
    flush_log_writer(s);                         // all probe_log lines precede report records
    // Report lines and log batches never interleave mid-line on a shared stdout.
    std::unique_lock<std::mutex> out_lock(s->stdout_mu, std::defer_lock);
    if (out == stdout) out_lock.lock();
    // The forwarded target left its last line unfinished: report records start on their own line.
    if (out == stdout && s->fwd_out_active && s->out_midline) { std::fputc('\n', out); s->out_midline = false; }
    for (const auto &j : s->prehooks) { std::fputs(j.c_str(), out); std::fputc('\n', out); }
    for (const auto &p : s->probes) {
        if (p->internal) continue;
        std::fputs("{\"kind\":\"probe\",\"location\":", out); json_string(out, p->location);
        std::fprintf(out, ",\"backend\":\"%s\",\"active\":%s,\"hits\":%llu}\n",
                     p->flags & PROBE_INLINE ? "inline" : p->flags & PROBE_HW ? "hw" : "breakpoint",
                     p->active ? "true" : "false", (unsigned long long)p->hits);
    }
    uint64_t hits = 0, active = 0;
    size_t visible = 0;
    for (const auto &p : s->probes) if (!p->internal) { hits += p->hits; active += p->active; ++visible; }
    PROCESS_MEMORY_COUNTERS memory{}; memory.cb = (DWORD)sizeof(memory);
    uint64_t peak_mb = GetProcessMemoryInfo(GetCurrentProcess(), &memory, (DWORD)sizeof(memory))
                           ? ((uint64_t)memory.PeakWorkingSetSize + (1024 * 1024 - 1)) / (1024 * 1024) : 0;
    uint64_t dropped = (uint64_t)(s->shared ? s->shared->log_dropped : 0) +
                       s->controller_dropped.load(std::memory_order_relaxed);
    // Inline callbacks still in flight when the target died: ExitProcess/TerminateProcess
    // kill threads mid-callback (breakpoint/hw callbacks always complete -- the debugger
    // holds the thread). Their hits are counted; any log they would have sent never existed.
    uint64_t interrupted = 0;
    if (s->exited && s->shared)
        interrupted = probe_agent_inflight(s->shared);
    bool live_closed;
    {
        std::lock_guard<std::mutex> lock(s->tail_mu);
        live_closed = s->live_output_closed;
    }
    std::fprintf(out, "{\"kind\":\"probe_report\",\"probes\":%llu,\"active\":%llu,"
                 "\"hits\":%llu,\"overrides\":%llu,\"log_dropped\":%llu,\"callbacks_interrupted\":%llu,"
                 "\"logs_written\":%llu,\"controller_peak_ws_mb\":%llu,\"app_exit\":%lu,"
                 "\"live_output_closed\":%s,\"error\":",
                 (unsigned long long)visible, (unsigned long long)active,
                 (unsigned long long)hits, (unsigned long long)(s->overrides + (s->shared ? (uint64_t)s->shared->overrides : 0)),
                 (unsigned long long)dropped, (unsigned long long)interrupted,
                 (unsigned long long)s->logs_written.load(std::memory_order_relaxed),
                 (unsigned long long)peak_mb, s->exit_code, live_closed ? "true" : "false");
    if (s->error.empty()) std::fputs("null", out); else json_string(out, s->error);
    std::fputs("}\n", out); std::fflush(out);
}

extern "C" void probe_close(probe_session *s) {
    if (!s) return;
    // probe_run is executing on another thread -- or is about to: the session was launched
    // or attached there and its probe_run has not started yet (e.g. Ctrl+C right after the
    // attach). Either way that thread owns the debug object: ask it to detach/stop and wait
    // for it to finish before tearing the session down.
    const bool owner_elsewhere = s->launched && !s->exited && s->debug_tid &&
                                 s->debug_tid != GetCurrentThreadId();
    if (s->running || (owner_elsewhere && !s->ran)) {
        s->stop_requested = true;
        // Wait until probe_run has really returned: tearing the session down (or detaching
        // from this thread, which does not own the debug object) while it still runs would
        // be a use-after-free. A slow detach is reported, never cut short.
        for (ULONGLONG start = GetTickCount64(), warned = 0; s->running || !s->ran; Sleep(10)) {
            ULONGLONG waited = (GetTickCount64() - start) / 15000;
            if (waited > warned) { warned = waited; std::fprintf(stderr, "probe: close: still waiting for probe_run to stop (%llus)\n", waited * 15); }
        }
    }
    ctrl_leave(s);                         // closed without probe_wait_for_exit
    if (s->detached) {
        // already detached by probe_run
    } else if (s->attached && !s->exited && s->pi.hProcess) {
        detach(s); s->detached = true;
    } else if (s->launched && !s->exited && s->pi.hProcess) {
        for (auto &p : s->probes)
            if (p->active && (p->flags & PROBE_BREAKPOINT)) restore_original(s->pi.hProcess, p->address, p->original);
        TerminateProcess(s->pi.hProcess, 3);
        if (WaitForSingleObject(s->pi.hProcess, 5000) == WAIT_OBJECT_0) s->exited = true;
        // On the debugger thread, consume the dead target's remaining events (through its
        // EXIT_PROCESS) so none is left queued for a later session on this thread.
        if (GetCurrentThreadId() == s->debug_tid) {
            for (ULONGLONG until = GetTickCount64() + 2000; GetTickCount64() < until; ) {
                DEBUG_EVENT ev{};
                if (!WaitForDebugEvent(&ev, 50)) continue;
                if (ev.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT && ev.u.CreateProcessInfo.hFile) CloseHandle(ev.u.CreateProcessInfo.hFile);
                if (ev.dwDebugEventCode == LOAD_DLL_DEBUG_EVENT && ev.u.LoadDll.hFile) CloseHandle(ev.u.LoadDll.hFile);
                ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                if (ev.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT && ev.dwProcessId == s->pi.dwProcessId) break;
            }
        }
    }
    stop_drainer(s);
    stop_log_output(s);                         // symbolization needs dbghelp and the process handle
    if (s->detached) {
        // The final counts AFTER the detach (a report taken before probe_close races the
        // still-running target): every hit, and every log already written out.
        uint64_t hits = 0;
        for (auto &p : s->probes) {
            if (s->shared && (p->flags & PROBE_INLINE)) p->hits = probe_agent_hits(s->shared, p->agent_index);
            if (!p->internal) hits += p->hits;
        }
        // in_flight: inline callbacks still running (or killed/suspended mid-callback by the
        // program) at the detach -- hits == logs_written + log_dropped + in_flight.
        std::fprintf(stderr, "probe: detached: hits=%llu logs_written=%llu log_dropped=%llu in_flight=%llu\n",
                     (unsigned long long)hits, (unsigned long long)s->logs_written.load(std::memory_order_relaxed),
                     (unsigned long long)((uint64_t)(s->shared ? s->shared->log_dropped : 0) +
                                          s->controller_dropped.load(std::memory_order_relaxed)),
                     (unsigned long long)(s->shared ? probe_agent_inflight(s->shared) : 0));
    }
    inplace_release_all(s);
    if (s->pi.hProcess) {
        for (uint64_t b : s->scratch_blocks) VirtualFreeEx(s->pi.hProcess, (void *)(uintptr_t)b, 0, MEM_RELEASE);
        // A config block stays in a detached target while any inline callback is still in flight
        // there (its thread suspended by the program, or past the drain): that callback's
        // get_config points into it. Freed, it read freed (or reused) memory.
        const uint64_t left = s->detached && !s->exited && s->shared ? probe_agent_inflight(s->shared) : 0;
        if (left && !s->config_blocks.empty())
            std::fprintf(stderr, "probe: detach: %zu config block(s) left in the target for %llu callback(s) still in flight\n",
                         s->config_blocks.size(), (unsigned long long)left);
        else
            for (uint64_t b : s->config_blocks) VirtualFreeEx(s->pi.hProcess, (void *)(uintptr_t)b, 0, MEM_RELEASE);
    }
    if (s->sym_ready) uhh_sym::cleanup(s->pi.hProcess);
    if (s->remote_thread) CloseHandle(s->remote_thread);
    if (s->svc_event) CloseHandle(s->svc_event);
    if (s->remote_path && s->pi.hProcess) VirtualFreeEx(s->pi.hProcess, s->remote_path, 0, MEM_RELEASE);
    if (s->shared) UnmapViewOfFile(s->shared);
    if (s->mapping) CloseHandle(s->mapping);
    if (s->local_agent) FreeLibrary(s->local_agent);
    if (!s->agent_copy.empty()) {             // fails if the (detached) target still has it loaded
        DeleteFileW(s->agent_copy.c_str());
        RemoveDirectoryW(s->agent_copy.substr(0, s->agent_copy.find_last_of(L'\\')).c_str());
    }
    if (s->pi.hThread) CloseHandle(s->pi.hThread);
    if (s->pi.hProcess) CloseHandle(s->pi.hProcess);
    delete s;
}

static uint64_t *register_slot(probe_context *c, enum probe_register reg) {
    if (!c) return nullptr;
    switch (reg) {
    case PROBE_REG_AX: return &c->regs.rax; case PROBE_REG_BX: return &c->regs.rbx;
    case PROBE_REG_CX: return &c->regs.rcx; case PROBE_REG_DX: return &c->regs.rdx;
    case PROBE_REG_SI: return &c->regs.rsi; case PROBE_REG_DI: return &c->regs.rdi;
    case PROBE_REG_BP: return &c->regs.rbp; case PROBE_REG_SP: return &c->regs.rsp;
#if defined(_WIN64)
    case PROBE_REG_R8: return &c->regs.r8; case PROBE_REG_R9: return &c->regs.r9;
    case PROBE_REG_R10: return &c->regs.r10; case PROBE_REG_R11: return &c->regs.r11;
    case PROBE_REG_R12: return &c->regs.r12; case PROBE_REG_R13: return &c->regs.r13;
    case PROBE_REG_R14: return &c->regs.r14; case PROBE_REG_R15: return &c->regs.r15;
#endif
    default: return nullptr;  /* x86: R8..R15 are unsupported -> null slot */
    }
}

extern "C" uint64_t get_reg(probe_context *c, enum probe_register reg) {
    uint64_t *slot = register_slot(c, reg);
    if (!slot) return 0;
    return *slot;
}

extern "C" int set_reg(probe_context *c, enum probe_register reg, uint64_t value) {
    uint64_t *slot = register_slot(c, reg); if (!slot) return 0;
#if defined(_WIN64)
    uint64_t next = value;
#else
    uint64_t next = (uint32_t)value;   // x86: the register keeps the low 32 bits; get_reg says so (TH3)
#endif
    if (*slot != next) {
        *slot = next;
        auto *state = static_cast<CallbackState *>(c->controller);
        if (state && state->session) ++state->session->overrides;
    }
    return 1;
}

extern "C" int get_mem(probe_context *c, uint64_t address, void *buffer, size_t size) {
    if (!c || !c->ops || !c->ops->read || (!buffer && size)) return 0;
    size_t done = 0; return c->ops->read(c->backend, address, buffer, size, &done) && done == size;
}

extern "C" int set_mem(probe_context *c, uint64_t address, const void *buffer, size_t size) {
    if (!c || !c->ops || !c->ops->write || (!buffer && size)) return 0;
    size_t done = 0; return c->ops->write(c->backend, address, buffer, size, &done) && done == size;
}

extern "C" uint64_t get_func_arg(probe_context *c, size_t index) {
    if (!c) return 0;
#if defined(_WIN64)
    /* x64 __fastcall: first four args in registers, rest above the shadow space. */
    switch (index) {
    case 0: return c->regs.rcx; case 1: return c->regs.rdx;
    case 2: return c->regs.r8; case 3: return c->regs.r9;
    default: {
        if (c->regs.rsp > UINT64_MAX - 8 || index > (UINT64_MAX - c->regs.rsp - 8) / 8) return 0;
        uint64_t value = 0, address = c->regs.rsp + 8 + 8 * index;
        return get_mem(c, address, &value, sizeof(value)) ? value : 0;
    }
    }
#else
    /* x86 __stdcall: every arg on the stack at [esp+4+4*i], read exactly 4 bytes. */
    if (c->regs.rsp > UINT64_MAX - 4 || index > (UINT64_MAX - c->regs.rsp - 4) / 4) return 0;
    uint32_t value = 0; uint64_t address = c->regs.rsp + 4 + 4 * index;
    return get_mem(c, address, &value, sizeof(value)) ? value : 0;
#endif
}

extern "C" const void *get_config(probe_context *c) { return c ? c->config : nullptr; }

// ---- call_func: run a target function on the stopped thread -------------------------
// The debugger way (like gdb's `call`): save the thread's context, build an ABI-correct
// call frame below its stack whose return address is a library INT3, let it run, catch
// the INT3, read the return register and restore the context exactly. The original
// debug event is continued to start the call; the trap event on the same thread takes
// its place, so the caller's handler finishes and continues as if nothing happened.
static uint64_t resolve_symbol(probe_session *s, const char *symbol) {
    if (!symbol || !*symbol) return 0;
    if (symbol[0] == '0' && (symbol[1] == 'x' || symbol[1] == 'X')) return std::strtoull(symbol + 2, nullptr, 16);
    Probe tmp; std::string saved = s->error;
    if (!parse_location(s, symbol, tmp)) { s->error = saved; return 0; }
    // tmp.module is already in module_of_location's form ("kernel32!X" -> kernel32.dll),
    // the same match a probe location gets.
    for (auto &kv : s->module_bases)
        if (iequals(kv.first, tmp.module)) {
            uint64_t rva = tmp.rva;
            if (!tmp.export_name.empty()) {
                uint64_t exp = 0;
                if (!resolve_export(s, kv.second, tmp.export_name, exp)) {
                    // A forwarded export (kernel32!HeapAlloc -> ntdll!RtlAllocateHeap, or into an
                    // API set): follow it the way the loader does, via this process's copy of the
                    // same system DLL (same bitness as the target, so the same files), then map
                    // the final function to the target module of the same name.
                    const bool forwarded = s->error.find("forwarded") != std::string::npos;
                    s->error = saved;
                    if (!forwarded) return 0;
                    uint64_t target = forwarded_export_target(s, tmp.module, tmp.export_name);
                    return target ? target + tmp.sym_offset : 0;
                }
                rva = exp + tmp.sym_offset;
            }
            s->error = saved; return kv.second + rva;
        }
    s->error = saved; return 0;
}

// The stopped thread's TEB in the target (0 if unknown): call_func restores the thread's
// last error / last status there, as the inline agent does around every callback -- the
// callee's Win32 calls must not leak into the program (GetLastError after the probed code).
static uint64_t thread_teb(HANDLE thread, const CONTEXT &ctx) {
#if defined(_WIN64)
    (void)ctx;
    struct { LONG status; PVOID teb; ULONG_PTR pid, tid, affinity; LONG prio, base; } tbi{};
    using QueryFn = LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static auto query = reinterpret_cast<QueryFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
    return query && query(thread, 0 /* ThreadBasicInformation */, &tbi, sizeof(tbi), nullptr) >= 0 ? (uint64_t)(uintptr_t)tbi.teb : 0;
#else
    LDT_ENTRY e{};                               // FS base = the 32-bit TEB (WOW64 too)
    if (!GetThreadSelectorEntry(thread, ctx.SegFs, &e)) return 0;
    return (uint64_t)((DWORD)e.BaseLow | ((DWORD)e.HighWord.Bytes.BaseMid << 16) | ((DWORD)e.HighWord.Bytes.BaseHi << 24));
#endif
}
#if defined(_WIN64)
static const uint64_t TEB_LAST_ERROR = 0x68, TEB_LAST_STATUS = 0x1250;
#else
static const uint64_t TEB_LAST_ERROR = 0x34, TEB_LAST_STATUS = 0xBF4;
#endif
struct TebErrors {
    uint64_t teb = 0; DWORD error = 0, status = 0; bool ok = false;
    void save(HANDLE process, HANDLE thread, const CONTEXT &ctx) {
        size_t n1 = 0, n2 = 0;
        teb = thread_teb(thread, ctx);
        ok = teb && remote_read(process, teb + TEB_LAST_ERROR, &error, 4, &n1) && n1 == 4 &&
             remote_read(process, teb + TEB_LAST_STATUS, &status, 4, &n2) && n2 == 4;
    }
    void restore(HANDLE process) const {
        size_t n = 0;
        if (!ok) return;
        remote_write(process, teb + TEB_LAST_ERROR, &error, 4, &n);
        remote_write(process, teb + TEB_LAST_STATUS, &status, 4, &n);
    }
};

static int call_in_target(probe_session *s, CallbackState *st, uint64_t fn, uint64_t *ret, int nargs, const uint64_t *args,
                          const probe_context *seed = nullptr) {
    if (s->in_call_tid || nargs < 0 || nargs > 8) return 0;           // no nesting
    // Hardware shadow stacks (CET): the callee is entered by SetThreadContext, not a CALL,
    // so its `ret` to call_trap does not match the shadow stack -> #CP in the target
    // (fatal in strict mode and when the callee's module is CETCOMPAT). Refuse cleanly
    // rather than risk the target; inline call_func (a real call) is unaffected.
    if (target_has_shadow_stack(s)) {
        if (!s->call_cet_warned) {
            s->call_cet_warned = true;
            std::fprintf(stderr, "probe: call_func refused on breakpoint/hw: target has hardware shadow stacks (CET)\n");
        }
        return 0;
    }
    if (!s->call_trap) {
        void *mem = VirtualAllocEx(s->pi.hProcess, nullptr, 16, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        unsigned char cc = 0xcc; size_t w = 0;
        if (!mem || !remote_write(s->pi.hProcess, (uint64_t)(uintptr_t)mem, &cc, 1, &w)) return 0;
        s->call_trap = (uint64_t)(uintptr_t)mem;
    }
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, st->tid);
    if (!thread) return 0;
    CONTEXT saved{}; saved.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT;
#if !defined(_WIN64)
    saved.ContextFlags |= CONTEXT_EXTENDED_REGISTERS;                  // x86: XMM0-7 live here, not in FloatSave
#endif
    if (!GetThreadContext(thread, &saved)) { CloseHandle(thread); return 0; }
    TebErrors teb_errors; teb_errors.save(s->pi.hProcess, thread, saved);
    CONTEXT w = saved; size_t wrote = 0; bool ok = true;
    if (seed) to_context(*seed, w);                                    // call_original: the callback's registers
#if defined(_WIN64)
    uint64_t sp = ((saved.Rsp - 512) & ~(uint64_t)0xF) - 8;           // entry rsp == 8 mod 16
    uint64_t frame[13] = {s->call_trap};                               // ret, shadow x4, stack args
    for (int i = 4; i < nargs; ++i) frame[5 + (i - 4)] = args[i];
    ok = remote_write(s->pi.hProcess, sp, frame, sizeof(frame), &wrote) && wrote == sizeof(frame);
    w.Rsp = sp; w.Rip = fn;
    w.Rcx = nargs > 0 ? args[0] : 0; w.Rdx = nargs > 1 ? args[1] : 0;
    w.R8 = nargs > 2 ? args[2] : 0;  w.R9 = nargs > 3 ? args[3] : 0;
#else
    uint32_t sp = ((uint32_t)saved.Esp - 512) & ~0xFu;
    uint32_t frame[9] = {(uint32_t)s->call_trap};                      // ret, then args (stdcall/cdecl both
    for (int i = 0; i < nargs; ++i) frame[1 + i] = (uint32_t)args[i];  // fine: esp is restored after)
    ok = remote_write(s->pi.hProcess, sp, frame, sizeof(frame), &wrote) && wrote == sizeof(frame);
    w.Esp = sp; w.Eip = (DWORD)fn;
#endif
    w.EFlags &= ~0x100u;
    w.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
    if (!ok || !SetThreadContext(thread, &w)) { CloseHandle(thread); return 0; }
    s->in_call_tid = st->tid;
    if (!ContinueDebugEvent(st->pid, st->tid, DBG_CONTINUE)) { s->in_call_tid = 0; SetThreadContext(thread, &saved); CloseHandle(thread); return 0; }
    int result = 0; bool trapped = false;
    ULONGLONG until = GetTickCount64() + 5000;
    DEBUG_EVENT ev{};
    while (!s->exited) {
        if (!WaitForDebugEvent(&ev, 20)) {
            if (GetTickCount64() > until) break;
            continue;
        }
        if (continue_foreign_event(s, ev)) continue;
        if (ev.dwThreadId == st->tid && ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            auto &er = ev.u.Exception.ExceptionRecord;
            if (er.ExceptionCode == EXCEPTION_BREAKPOINT && (uint64_t)(uintptr_t)er.ExceptionAddress == s->call_trap) {
                CONTEXT r{}; r.ContextFlags = CONTEXT_INTEGER;
                if (GetThreadContext(thread, &r)) {
#if defined(_WIN64)
                    if (ret) *ret = r.Rax;
#else
                    if (ret) *ret = r.Eax;                     // pointer-sized return (EAX)
#endif
                    result = 1;
                }
                trapped = true; break;                             // leave this event pending
            }
            if (!(er.ExceptionCode == EXCEPTION_BREAKPOINT || er.ExceptionCode == EXCEPTION_SINGLE_STEP)) {
                if (trace_enabled())
                    std::fprintf(stderr, "  call_func: callee raised 0x%08lx at 0x%llx; abandoned\n", (unsigned long)er.ExceptionCode,
                                 (unsigned long long)(uintptr_t)er.ExceptionAddress);
                trapped = true; break;                             // the callee faulted: abandon the call
            }
            if (trace_enabled())
                std::fprintf(stderr, "  call_func: own-thread event 0x%08lx at 0x%llx\n", (unsigned long)er.ExceptionCode,
                             (unsigned long long)(uintptr_t)er.ExceptionAddress);
        }
        DWORD disposition = DBG_CONTINUE;
        dispatch_event(s, ev, disposition);                        // other threads keep working
        if (s->skip_continue) { s->skip_continue = false; continue; }
        ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, disposition);
    }
    s->in_call_tid = 0;
    resume_deferred_hits(s);                                       // they hit their probes again now
    if (trapped) {
        SetThreadContext(thread, &saved);                          // exactly as it was at the hit
        teb_errors.restore(s->pi.hProcess);                        // and its last error / status
        // The pending trap/fault event on this thread now stands in for the original one.
    } else if (!s->exited) {
        // Timed out with the callee still running: stop it, put the context back, and tell
        // the loop the original event is already continued (there is nothing to continue).
        SuspendThread(thread); SetThreadContext(thread, &saved); teb_errors.restore(s->pi.hProcess); ResumeThread(thread);
        s->skip_continue = true;
        std::fprintf(stderr, "probe: call_func timed out after 5 s; thread restored\n");
    } else {
        s->skip_continue = true;
    }
    CloseHandle(thread);
    return result;
}

static int call_func_args(probe_context *c, const char *symbol, uint64_t *ret, int nargs, const uint64_t *in) {
    auto *st = c ? static_cast<CallbackState *>(c->controller) : nullptr;
    if (!st || !st->session || !st->tid) return 0;
    if (nargs < 0 || nargs > 8) return 0;
    uint64_t fn = resolve_symbol(st->session, symbol);
    if (!fn) return 0;
    uint64_t args[8] = {0};
    for (int i = 0; i < nargs; ++i) args[i] = in[i];
    return call_in_target(st->session, st, fn, ret, nargs, args);
}

extern "C" int call_func(probe_context *c, const char *symbol, uint64_t *ret, int nargs, ...) {
    if (nargs < 0 || nargs > 8) return 0;
    uint64_t args[8] = {0};
    va_list ap; va_start(ap, nargs);
    for (int i = 0; i < nargs; ++i) args[i] = va_arg(ap, uint64_t);
    va_end(ap);
    return call_func_args(c, symbol, ret, nargs, args);
}

// call_original on breakpoint/hw: the original runs IN PLACE -- on the hit's own stack, from
// the probe address, with the callback's registers -- exactly as the program would have run
// it, returning to its real return address. A debug register set on THIS thread only, at
// that return address, stops it there (SP just above the hit's: the matching return); the
// thread is then put back at the hit, so the callback continues and return_from applies.
// Nothing on the stack is rewritten, so an exception or longjmp inside the original unwinds
// natively into the program's own handlers (and CET shadow stacks stay in sync). Such an
// exit -- the thread seen at or above the hit's frame without having returned -- RELEASES
// the call: the thread runs on, the program sees exactly what it would have seen, and the
// rest of the callback is abandoned (as on inline, where the exception propagates through
// the callback). The probe's own entry is passed through without counting a hit; probes
// hit inside the original are counted but run no callback; other threads' hits wait.
static bool hit_is_function_entry(probe_context *c, uint64_t *ret_addr) {
    uint64_t r = 0; unsigned char pre[8];
    if (!get_mem(c, c->hit_sp, &r, sizeof(void *)) || r < 8 || !get_mem(c, r - 8, pre, sizeof(pre))) return false;
    if (ret_addr) *ret_addr = r;
    return looks_like_return_site(pre);
}
static void co_warn(bool &flag, const Probe *probe, const char *text) {
    if (flag) return;
    flag = true;
    std::fprintf(stderr, "probe: warning: %s: %s. Further cases are not reported.\n", probe->location.c_str(), text);
}
static int call_original_in_place(probe_session *s, CallbackState *st, probe_context *c, uint64_t *out) {
    Probe *probe = st->probe;
    const uint64_t ptr = sizeof(void *);
    uint64_t ret_addr = 0;
    if (!hit_is_function_entry(c, &ret_addr)) {
        warn_record(c, probe, "call_original refused: not at a function entry ([SP] is no return address)");
        co_warn(s->co_warned_entry, probe, "call_original refused: not at a function entry ([SP] is no return address)");
        return 0;
    }
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, st->tid);
    if (!thread) return 0;
    CONTEXT saved{}; saved.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | UHH_CONTEXT_FP | CONTEXT_DEBUG_REGISTERS;
    if (!GetThreadContext(thread, &saved)) { CloseHandle(thread); return 0; }
    int slot = -1;
    for (int k = 0; k < 4 && slot < 0; ++k)
        if (!(s->dr_used & (1u << k)) && !((saved.Dr7 >> (k * 2)) & 3)) slot = k;
    // All four in use, but the hit is a hardware EXECUTE probe: borrow its own slot on THIS
    // thread only (re-pointed at the return address for the call, put back after). Other
    // threads keep the probe; this thread is inside the original meanwhile, so only a
    // recursive entry of the same function on it goes uncounted. (gated_config with every
    // probe on hw: flag + NtOpenProcess + NtClose + NtReadVirtualMemory = 4 DRs.)
    bool borrowed = false;
    if (slot < 0 && (probe->flags & PROBE_HW) && !(probe->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW)) &&
        probe->dr_slot >= 0 && probe->dr_slot < 4) {
        slot = probe->dr_slot; borrowed = true;
    }
    if (slot < 0) {
        CloseHandle(thread);
        co_warn(s->co_warned_dr, probe, "call_original refused: needs one free debug register (all 4 in use)");
        return 0;
    }
    CONTEXT w = saved;
    to_context(*c, w);                                                 // the callback's registers
    auto *dr = slot == 0 ? &w.Dr0 : slot == 1 ? &w.Dr1 : slot == 2 ? &w.Dr2 : &w.Dr3;   // DWORD64 / DWORD
    *dr = (std::remove_reference_t<decltype(*dr)>)ret_addr;
    w.Dr7 = (decltype(w.Dr7))((w.Dr7 & ~((DWORD64)0xF << (16 + slot * 4))) | ((DWORD64)1 << (slot * 2)));   // execute, local
    w.Dr6 = 0;
#if defined(_WIN64)
    w.Rip = probe->address; w.Rsp = c->hit_sp;
#else
    w.Eip = (DWORD)probe->address; w.Esp = (DWORD)c->hit_sp;
#endif
    w.EFlags &= ~0x100u;
    if (probe->flags & PROBE_HW) w.EFlags |= 0x10000u;                 // RF: the entry's own DR stays quiet once
    w.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
    if (!SetThreadContext(thread, &w)) { CloseHandle(thread); return 0; }
    s->dr_used |= (uint8_t)(1u << slot);                               // reserved: no probe arms it meanwhile
    s->dr_ever |= (uint8_t)(1u << slot);                               // ours: detach / the guard clear it too
    guard_sync(s);                                                     // mirrored BEFORE the thread runs with it
    s->in_call_tid = st->tid; s->co_addr = probe->address; s->co_sp = c->hit_sp;
    s->co_entry_pending = !(probe->flags & PROBE_HW); s->co_left = false;
    auto clear_slot = [&](bool running) {
        if (running) guard_note_hold(s, st->tid);
        if (running && SuspendThread(thread) == (DWORD)-1) return;
        if (borrowed) {                                                // the probe's own DR, back at its site
            uint32_t rw = 0, len = 0; hw_rw_len(probe->flags, rw, len);
            set_dr_on_thread(thread, slot, probe->address, probe->active, rw, len);
        } else {
            set_dr_on_thread(thread, slot, 0, false);
        }
        if (running) ResumeThread(thread);
    };
    if (!ContinueDebugEvent(st->pid, st->tid, DBG_CONTINUE)) {
        saved.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
        SetThreadContext(thread, &saved);
        if (!borrowed) s->dr_used &= (uint8_t)~(1u << slot);
        s->in_call_tid = 0; s->co_addr = 0;
        CloseHandle(thread); return 0;
    }
    bool done = false, thread_gone = false;
    const char *why = "the original left without returning (exception or longjmp)";
    uint64_t result = 0;
    ULONGLONG until = GetTickCount64() + 5000, next_poll = GetTickCount64() + 20;
    DEBUG_EVENT ev{};
    while (!s->exited && !s->co_left && !thread_gone) {
        if (WaitForDebugEvent(&ev, 20)) {
            if (continue_foreign_event(s, ev)) continue;
            if (ev.dwThreadId == st->tid && ev.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
                ev.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP &&
                (uint64_t)(uintptr_t)ev.u.Exception.ExceptionRecord.ExceptionAddress == ret_addr) {
                CONTEXT &r = st->post; r.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | UHH_CONTEXT_FP;
                if (GetThreadContext(thread, &r)) {
#if defined(_WIN64)
                    const uint64_t sp = r.Rsp, rax = r.Rax;
#else
                    const uint64_t sp = r.Esp, rax = r.Eax;
#endif
                    if (sp > s->co_sp && sp <= s->co_sp + ptr + 1024) {   // x86 stdcall: ret N popped the args
                        result = rax; done = true;                         // this event now stands in for the hit
                        st->have_post = true;
                        st->post_seen = c->regs;
#if !defined(_WIN64)
                        c->orig_edx = r.Edx;                               // an EDX:EAX result's high half
                        c->orig_pop = (int32_t)(sp - (s->co_sp + ptr));    // the bytes its `ret N` popped
#endif
                        break;
                    }
                    r.EFlags |= 0x10000u; SetThreadContext(thread, &r);    // some other return there: run on
                }
                ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                continue;
            }
            if (ev.dwThreadId == st->tid && ev.dwDebugEventCode == EXIT_THREAD_DEBUG_EVENT) {
                thread_gone = true; why = "the thread exited inside the original";
            }
            DWORD disposition = DBG_CONTINUE;
            dispatch_event(s, ev, disposition);                            // everything else as usual
            if (s->skip_continue) s->skip_continue = false;
            else ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, disposition);
        }
        const ULONGLONG now = GetTickCount64();
        if (now >= next_poll && !s->co_left && !thread_gone && !s->exited) {
            // Left without a probe hit to show it (e.g. an exception caught by the caller):
            // the thread is above the hit's frame and not at the return address.
            next_poll = now + 20;
            guard_note_hold(s, st->tid);
            if (SuspendThread(thread) != (DWORD)-1) {
                CONTEXT r{}; r.ContextFlags = CONTEXT_CONTROL;
                if (GetThreadContext(thread, &r)) {
#if defined(_WIN64)
                    const uint64_t sp = r.Rsp, pc = r.Rip;
#else
                    const uint64_t sp = r.Esp, pc = r.Eip;
#endif
                    if (sp >= s->co_sp + ptr && pc != ret_addr) s->co_left = true;
                }
                ResumeThread(thread);
            }
        }
        if (!done && now > until && !s->co_left) {
            s->co_left = true; why = "the original did not return within 5 s (released, it runs on)";
        }
    }
    s->in_call_tid = 0; s->co_addr = 0; s->co_entry_pending = false; s->co_left = false;
    if (done) {
        CONTEXT cur{}; cur.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(thread, &cur)) {          // keep any DR armed meanwhile, drop ours
            const DWORD64 mask = ((DWORD64)3 << (slot * 2)) | ((DWORD64)0xF << (16 + slot * 4));
            const auto keep = slot == 0 ? saved.Dr0 : slot == 1 ? saved.Dr1 : slot == 2 ? saved.Dr2 : saved.Dr3;
            cur.Dr7 = (decltype(cur.Dr7))(cur.Dr7 & ~mask);
            if (borrowed) {                            // the probe's own DR: as it was at the hit
                cur.Dr7 = (decltype(cur.Dr7))(cur.Dr7 | (saved.Dr7 & mask));
                (slot == 0 ? cur.Dr0 : slot == 1 ? cur.Dr1 : slot == 2 ? cur.Dr2 : cur.Dr3) = keep;
            }
            saved.Dr0 = cur.Dr0; saved.Dr1 = cur.Dr1; saved.Dr2 = cur.Dr2; saved.Dr3 = cur.Dr3; saved.Dr7 = cur.Dr7;
        }
        saved.Dr6 = 0;
        saved.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | UHH_CONTEXT_FP | CONTEXT_DEBUG_REGISTERS;
        SetThreadContext(thread, &saved);              // exactly as it was at the hit
    } else if (!s->exited && !thread_gone) {
        clear_slot(true);
    }
    if (!borrowed) s->dr_used &= (uint8_t)~(1u << slot);
    resume_deferred_hits(s);                           // they hit their probes again now
    CloseHandle(thread);
    if (done) {
        c->called_original = 1;
        if (out) *out = result;
        return 1;
    }
    // Released: the original ran (or runs on) natively, and the program sees exactly its
    // outcome. There is no stopped thread left to write back to; end the callback here.
    st->released = true;
    s->skip_continue = true;
    if (!s->exited) co_warn(s->co_warned_left, probe, why);
    RaiseException(UHH_CALL_RELEASED, 0, 0, nullptr);
    return 0;
}
extern "C" int call_original(probe_context *c, int nargs, uint64_t *out) {
    auto *st = c ? static_cast<CallbackState *>(c->controller) : nullptr;
    if (!st || !st->session || !st->tid || !st->probe || st->released) return 0;
    if (nargs < 0 || nargs > 16) {                                     // same contract as inline
        warn_record(c, st->probe, "call_original refused: nargs must be 0..16");
        co_warn(st->session->co_warned_nargs, st->probe, "call_original refused: nargs must be 0..16"); return 0;
    }
    if (st->probe->flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW)) return 0;
    if (st->session->in_call_tid) return 0;                            // no nesting
    return call_original_in_place(st->session, st, c, out);
}
extern "C" void return_from(probe_context *c, uint64_t value, int nargs) {
    if (!c || nargs < 0 || nargs > 255) return;
    auto *st = static_cast<CallbackState *>(c->controller);
    if (!st || st->released) return;
    if (!hit_is_function_entry(c, nullptr)) {
        warn_record(c, st->probe, "return_from refused: not at a function entry ([SP] is no return address)");
        if (st->session && st->probe)
            co_warn(st->session->co_warned_entry, st->probe,
                    "return_from refused: not at a function entry ([SP] is no return address)");
        return;
    }
#if defined(_WIN64)
    (void)nargs; c->regs.rax = value; c->ret_pop = 0;
#else
    uint32_t pop = (uint32_t)nargs * 4;
    if (probe_x86_return_regs(c, value, &pop) && st->probe && !st->probe->warned_pop) {
        st->probe->warned_pop = true;
        send_log(c, "uhh warning: return_from nargs=%d but the original popped %d bytes (ret %d); the original's "
                    "count is used", nargs, (int)c->orig_pop, (int)c->orig_pop);   // as inline logs it
        std::fprintf(stderr, "probe: warning: %s: return_from nargs=%d but the original popped %d bytes (ret %d); "
                     "the original's count is used. Further cases are not reported.\n",
                     st->probe->location.c_str(), nargs, (int)c->orig_pop, (int)c->orig_pop);
    }
    c->ret_pop = pop;
#endif
    c->returned = 1;
}

extern "C" probe_session *get_session(probe_context *c) {
    auto *state = c ? static_cast<CallbackState *>(c->controller) : nullptr;
    return state ? state->session : nullptr;
}

// Raw stack snapshot at the hit: return addresses only (StackWalk64 over the stopped
// target with the hit's register image). No symbol lookup here -- deferred to report.
static void capture_stack(probe_session *s, probe_context *c, std::vector<uint64_t> &frames) {
    frames.clear();
    if (!s->sym_ready) { frames.push_back(c->regs.pc); return; }
    CONTEXT w{}; w.ContextFlags = CONTEXT_FULL;
    to_context(*c, w);
#if defined(_WIN64)
    w.Rip = c->regs.pc; w.Rsp = c->regs.rsp; w.Rbp = c->regs.rbp;
#else
    w.Eip = (DWORD)c->regs.pc; w.Esp = (DWORD)c->regs.rsp; w.Ebp = (DWORD)c->regs.rbp;
#endif
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION, FALSE, c->tid);
    if (!uhh_sym::walk_stack(s->pi.hProcess, thread, w, c->regs.pc, c->regs.rsp, c->regs.rbp, frames,
                             PROBE_STACK_MAX_FRAMES) || frames.empty())
        frames.assign(1, c->regs.pc);
#if !defined(_WIN64)
    // x86 at a function's first instructions: EBP still frames the CALLER, so a walk can
    // skip the immediate caller. If [esp] is a genuine return address (the bytes before
    // it encode a call) and is not already frame 1, insert it -- same rule as the agent.
    uint32_t top = 0; size_t got = 0; unsigned char pre[8] = {0};
    if (remote_read(s->pi.hProcess, c->regs.rsp, &top, 4, &got) && got == 4 && top > 8 &&
        remote_read(s->pi.hProcess, top - 8, pre, 8, &got) && got == 8) {
        const unsigned char *p = pre + 8;
        bool call = p[-5] == 0xE8 ||
                    (p[-2] == 0xFF && ((p[-1] >> 3) & 7) == 2 && ((p[-1] >> 6) == 3 || ((p[-1] >> 6) == 0 && (p[-1] & 7) != 4 && (p[-1] & 7) != 5))) ||
                    (p[-3] == 0xFF && ((p[-2] >> 3) & 7) == 2 && (p[-2] >> 6) == 1) ||
                    (p[-6] == 0xFF && ((p[-5] >> 3) & 7) == 2 && ((p[-5] >> 6) == 2 || (p[-5] & 0xC7) == 5)) ||
                    (p[-7] == 0xFF && ((p[-6] >> 3) & 7) == 2 && (p[-6] >> 6) == 2 && (p[-6] & 7) == 4);
        if (call && (frames.size() < 2 || frames[1] != top)) frames.insert(frames.begin() + 1, top);
        if (frames.size() > PROBE_STACK_MAX_FRAMES) frames.resize(PROBE_STACK_MAX_FRAMES);
    }
#endif
    if (thread) CloseHandle(thread);
}

static std::string symbolize(probe_session *s, uint64_t addr) {
    if (!s->sym_ready) { char buf[32]; std::snprintf(buf, sizeof(buf), "0x%llx", (unsigned long long)addr); return buf; }
    return uhh_sym::symbolize(s->pi.hProcess, addr);
}

static void log_common(probe_context *c, bool stack, const char *format, va_list ap) {
    if (!format) return;
    char line[PROBE_AGENT_LOG_TEXT_CAP];                      // the same limit inline uses
    // Same formatter as the agent: truncation marked, an invalid format or a faulting
    // argument logged as "[unformattable] <format>" -- never dropped, never fatal.
    int len = uhh_format_log(line, sizeof(line), format, ap);
    if (len < 0) return;
    auto *state = c ? static_cast<CallbackState *>(c->controller) : nullptr;
    if (!state || !state->session) { std::fprintf(stderr, "probe: %s\n", line); return; }
    // Per-thread order across backends: this thread's earlier INLINE logs are already in the
    // ring (it is stopped here, so its send_log calls have returned) -- move them to the
    // queue before this one. (Only a record behind another thread's unfinished slot can
    // still come later; see docs/ROADMAP.md, "Log delivery findings".)
    if (state->session->shared) { drain_agent_logs(state->session); deliver_past_stall(state->session); }
    try {
        LogRecord r; r.text.assign(line, (size_t)len); r.tid = c->tid; r.probe = c->site; r.has_stack = stack;
        if (stack) capture_stack(state->session, c, r.frames);
        if (trace_enabled()) {
            if (stack) std::fprintf(stderr, "probe: %s [+stack %zu frames]\n", line, r.frames.size());
            else std::fprintf(stderr, "probe: %s\n", line);
        }
        enqueue_log(state->session, std::move(r));
    } catch (...) {
        state->session->controller_dropped.fetch_add(1, std::memory_order_relaxed);
    }
}

extern "C" void send_log(probe_context *c, const char *format, ...) {
    va_list ap; va_start(ap, format); log_common(c, false, format, ap); va_end(ap);
}

extern "C" void send_log_stack(probe_context *c, const char *format, ...) {
    va_list ap; va_start(ap, format); log_common(c, true, format, ap); va_end(ap);
}

// The table the controller's copy of the agent DLL forwards to (UHH_SHARED callbacks).
static void vlog_entry(probe_context *c, int stack, const char *format, va_list ap) { log_common(c, stack != 0, format, ap); }
static const probe_controller_api g_controller_api = {
    get_reg, set_reg, get_func_arg, get_mem, set_mem, vlog_entry, get_config, call_func_args, get_session,
    probe_add_address, probe_watch, probe_add_symbol, probe_add_symbol_cfg, call_original, return_from,
};
const probe_controller_api *controller_api_table() { return &g_controller_api; }

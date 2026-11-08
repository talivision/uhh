// The log pipeline: line formatting, the writer / file appender / stdout tailer threads, the
// forwarded target stdout/stderr, the agent log ring drainer, and send_log.
#include "session_internal.hpp"

namespace uhh_session {
struct LogPackHdr { uint32_t probe, tid, len, nframes, has_stack; };
constexpr uint32_t LOG_PACK = 256;
// Log records a queue entry stands for (an unload marker: none).
static size_t records_of(const LogRecord &r) { return r.sym_unload ? 0 : r.packed ? r.packed : 1; }
// One record as the writer formats it (a single LogRecord, or one entry of a pack).
struct LogView {
    uint32_t probe, tid;
    std::string_view text;
    bool has_stack;
    const unsigned char *frames;     // nframes x uint64_t, unaligned
    size_t nframes;
};
static bool enqueue_log(probe_session *s, LogRecord &&record);
struct AgentMapCache;
static void stop_log_filer(probe_session *s);
static void forward_finish(probe_session *s);

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
// Writes `value` as a quoted JSON string at p (room for 6 * size + 2 bytes); returns the end.
static char *json_string_to(char *out, std::string_view value) {
    static const char hex[] = "0123456789abcdef";
    *out++ = '"';
    const auto *p = reinterpret_cast<const unsigned char *>(value.data());
    for (size_t i = 0, n = value.size(); i < n; ) {
        size_t run = i;                                  // printable ASCII needing no escape: one copy
        while (run < n && p[run] >= 0x20 && p[run] < 0x80 && p[run] != '"' && p[run] != '\\') ++run;
        if (run > i) { std::memcpy(out, p + i, run - i); out += run - i; i = run; continue; }
        unsigned char ch = p[i];
        if (ch == '"' || ch == '\\') { *out++ = '\\'; *out++ = (char)ch; ++i; continue; }
        if (ch == '\n') { *out++ = '\\'; *out++ = 'n'; ++i; continue; }
        if (ch == '\r') { *out++ = '\\'; *out++ = 'r'; ++i; continue; }
        if (ch == '\t') { *out++ = '\\'; *out++ = 't'; ++i; continue; }
        if (ch >= 0x80) {
            if (size_t len = utf8_sequence(p + i, n - i)) { std::memcpy(out, p + i, len); out += len; i += len; continue; }
        }
        *out++ = '\\'; *out++ = 'u'; *out++ = '0'; *out++ = '0';
        *out++ = hex[ch >> 4]; *out++ = hex[ch & 15]; ++i;
    }
    *out++ = '"';
    return out;
}
void append_json_string(std::string &out, std::string_view value) {
    const size_t at = out.size();
    out.resize_and_overwrite(at + 6 * value.size() + 2, [&](char *buf, size_t) {
        return (size_t)(json_string_to(buf + at, value) - buf);
    });
}

template <size_t N> static char *put_lit(char *p, const char (&lit)[N]) {
    std::memcpy(p, lit, N - 1);
    return p + N - 1;
}

// Appends the record's JSON line to `line` (the writer's batch): no temporary string and no
// printf per record -- the x86 (WOW64) controller's per-record formatting showed in profiles of
// a log-bound inline target (send_log there waits on this pipeline: the ring's backpressure).
// A line without a stack is written in place in one step (its size is bounded: 6 bytes per
// message byte at most); a stack line appends its symbol names as they come.
static void append_log_line(std::string &line, probe_session *s, const LogView &r) {
    const size_t at = line.size();
    line.resize_and_overwrite(at + 6 * r.text.size() + 160, [&](char *buf, size_t) {
        char *p = buf + at;
        p = put_lit(p, "{\"kind\":\"probe_log\",\"probe\":");
        p = std::to_chars(p, p + 24, r.probe).ptr;
        p = put_lit(p, ",\"tid\":");
        p = std::to_chars(p, p + 24, r.tid).ptr;
        p = put_lit(p, ",\"message\":");
        p = json_string_to(p, r.text);
        if (!r.has_stack) {
            // Last, so every consumer matching the line's start keeps working (fields only added).
            p = put_lit(p, ",\"seq\":");
            p = std::to_chars(p, p + 24, (unsigned long long)s->log_seq++).ptr;
            p = put_lit(p, "}\n");
        }
        return (size_t)(p - buf);
    });
    if (!r.has_stack) return;
    line += ",\"stack\":[";
    for (size_t i = 0; i < r.nframes; ++i) {
        if (i) line.push_back(',');
        uint64_t frame;
        std::memcpy(&frame, r.frames + i * sizeof(frame), sizeof(frame));
        append_json_string(line, symbolize(s, frame));
    }
    line.push_back(']');
    char num[24];
    line += ",\"seq\":";
    line.append(num, (size_t)(std::to_chars(num, num + sizeof(num), (unsigned long long)s->log_seq++).ptr - num));
    line += "}\n";
}

void writer_failed(probe_session *s, const std::string &message, uint64_t unwritten) {
    std::lock_guard<std::mutex> lock(s->queue_mu);
    if (!s->writer_failed) {
        s->writer_failed = true;
        s->writer_error = message;
        for (const LogRecord &r : s->log_queue) {
            if (r.sym_unload) uhh_sym::unregister_module(s->pi.hProcess, r.sym_unload);
            else unwritten += records_of(r);
        }
        s->log_queue.clear();
        s->log_queue_records = 0;
        s->sym_pending.clear();
        s->controller_dropped.fetch_add(unwritten, std::memory_order_relaxed);
        std::fprintf(stderr, "probe: error: %s\n", message.c_str());
    }
    s->writer_busy = false;
    s->queue_writable.notify_all();
    s->queue_flushed.notify_all();
}

static bool write_stdout_chunk(probe_session *s, const char *bytes, size_t size, uint64_t records);
static void tail_catch_up_locked(probe_session *s, const char *fresh, size_t fresh_size, uint64_t fresh_end);
static bool write_stdout_locked(probe_session *s, const char *bytes, size_t size, uint64_t records);
#if defined(UHH_TEST_HOOKS)
// Test-only (probe_api_testhooks): UHH_TEST_FILE_STALL_MS=<ms> stalls the session file's
// UHH_TEST_FILE_STALL_AT-th append (default 8) that long, as a cache-manager flush or an AV scan
// of the file does (regress stream-filestall-*).
static void test_file_stall() {
    static const long ms = [] { const char *v = std::getenv("UHH_TEST_FILE_STALL_MS"); return v ? std::atol(v) : 0L; }();
    static const long at = [] { const char *v = std::getenv("UHH_TEST_FILE_STALL_AT"); return v ? std::atol(v) : 8L; }();
    static std::atomic<long> n{0};
    if (ms > 0 && ++n == at) Sleep((DWORD)ms);
}
// UHH_TEST_FILE_FAIL_AT=<n>: the session file's n-th append fails (ERROR_DISK_FULL), as on a
// full disk or an exceeded quota (regress stream-filefail-*). After the stall above, if both hit
// the same append: chunks queue up behind it meanwhile.
static bool test_file_fail() {
    static const long at = [] { const char *v = std::getenv("UHH_TEST_FILE_FAIL_AT"); return v ? std::atol(v) : 0L; }();
    static std::atomic<long> n{0};
    return at > 0 && ++n == at;
}
// UHH_TEST_FILE_THROW_AT=<n>: the appender thread throws std::bad_alloc at its n-th chunk, where
// UHH_TEST_FILE_THROW_IN says: "spare" (default: recycling the appended chunk, codex4 #3) or
// "append" (before appending it) (regress stream-filefail-throw-*).
static void test_file_throw(uint64_t nth, bool append_site) {
    static const long at = [] { const char *v = std::getenv("UHH_TEST_FILE_THROW_AT"); return v ? std::atol(v) : 0L; }();
    static const bool in_append = [] { const char *v = std::getenv("UHH_TEST_FILE_THROW_IN"); return v && !std::strcmp(v, "append"); }();
    if (at > 0 && nth == (uint64_t)at && append_site == in_append) throw std::bad_alloc();
}
#endif
// A batch into the session file, here and now. tail_mu not held.
static bool append_log_file(probe_session *s, const char *bytes, size_t size, std::string *error) {
#if defined(UHH_TEST_HOOKS)
    test_file_stall();
    if (test_file_fail()) {
        SetLastError(ERROR_DISK_FULL);
        if (error) *error = win_error("write probe log file");
        return false;
    }
#endif
    DWORD wrote = 0;
    if (s->log_file == nullptr || s->log_file == INVALID_HANDLE_VALUE || size > MAXDWORD ||
        !WriteFile(s->log_file, bytes, (DWORD)size, &wrote, nullptr) || (size_t)wrote != size) {
        if (error) *error = win_error("write probe log file");
        return false;
    }
    g_diag_file_writes++; g_diag_file_bytes += size;
    return true;
}

// The error of a session file that stopped growing: what failed, then what the file holds.
// logs_written counts the records IN THE FILE -- as at 0fb6cee, where a batch whose file write
// failed was counted in log_dropped although stdout already had it -- so the file is exactly
// seq 0..logs_written-1, and every later record is in log_dropped; the ones of those that
// reached stdout anyway are stdout_logs - logs_written (stdout's seq 0..stdout_logs-1).
static std::string file_incomplete(const std::string &why, uint64_t in_file) {
    return why + "; the session log file is incomplete: it holds " +
           (in_file ? "records seq 0.." + std::to_string(in_file - 1) : std::string("no records")) +
           " (logs_written); every later record is counted in log_dropped, those that reached stdout too"
           " (stdout_logs - logs_written of them)";
}

// The session file takes no more batches (file_failed, with `message`; a first failure wins) and
// the tail's waits stop waiting for bytes that will never be in it. file_mu, tail_mu not held.
static void break_log_file(probe_session *s, const std::string &message) {
    {
        std::lock_guard<std::mutex> lock(s->file_mu);
        if (!s->file_failed) { s->file_failed = true; s->file_error = message; }
    }
    { std::lock_guard<std::mutex> lock(s->tail_mu); s->file_broken = true; }
    s->file_idle.notify_all();
    s->tail_caught_up.notify_all();
}

// The appender could not append a chunk of `records` records (codex4 #1/#2): neither it nor any
// chunk queued behind it will be in the file (never a gap: the file stays a prefix of the
// records). Their records were counted in logs_written when they were handed over; they move to
// log_dropped (controller_dropped), under stdout_mu so a report sees them moved or not yet.
// No lock held.
static void file_lost(probe_session *s, uint64_t records, const std::string &why) {
    std::string message;
    {
        std::lock_guard<std::mutex> out_lock(s->stdout_mu);
        std::lock_guard<std::mutex> lock(s->file_mu);
        for (const auto &c : s->file_queue) { records += c.records; s->file_queued -= c.bytes.size(); }
        s->file_queue.clear();
        s->controller_dropped.fetch_add(records, std::memory_order_relaxed);
        s->logs_written.fetch_sub(records, std::memory_order_relaxed);
        message = file_incomplete(why, s->logs_written.load());
    }
    break_log_file(s, message);
}

// Live tail: the session file's appender thread. Appends the batches the writer handed over, in
// order; then, if stdout is behind the file (records deferred while the target was inside one of
// its lines), replays them as the forwarder would (tail_catch_up_locked reads the file).
// Bytes handed over and not appended yet; beyond, the writer waits (stdout with it). 1 MB: thousands of
// live records ride out a stalled file, and a full-speed stream keeps a flat footprint -- the chunks
// are recycled (file_spare), never allocated per batch (regress stream-volume-inline: peak <= 1.2x
// from 2M to 20M records; a 16 MB, then a 2 MB queue of fresh copies grew x86 18 -> 24 MB on CI).
// An append that fails ends the file there (file_lost); nothing escapes this thread (an exception
// before the append counts as a failed append, one after it costs the recycling only).
static constexpr size_t FILE_QUEUE_CAP = 1u << 20;
static constexpr size_t FILE_SPARE_MAX = 24;   // file_spare is reserved this big: recycling never allocates
static void log_filer_main(probe_session *s) {
    uint64_t nth = 0;
    for (;;) {
        probe_session::FileChunk chunk;
        {
            std::unique_lock<std::mutex> lock(s->file_mu);
            s->file_cv.wait(lock, [s] { return s->file_stop || !s->file_queue.empty(); });
            if (s->file_queue.empty()) break;
            chunk = std::move(s->file_queue.front());
            s->file_queue.pop_front();
            s->file_busy = true;
        }
        ++nth;
        bool appended = false;
        std::string error;
        try {
#if defined(UHH_TEST_HOOKS)
            test_file_throw(nth, true);
#endif
            appended = append_log_file(s, chunk.bytes.data(), chunk.bytes.size(), &error);
            bool behind = false;
            if (appended) {
                std::lock_guard<std::mutex> lock(s->tail_mu);
                s->log_bytes_written += chunk.bytes.size();
                behind = s->log_bytes_tailed < s->log_bytes_written && s->tail_enabled && !s->tail_failed;
            }
            if (behind && s->fwd_out_active) {
                std::lock_guard<std::mutex> out_lock(s->stdout_mu);
                tail_catch_up_locked(s, nullptr, 0, 0);
            }
        } catch (const std::exception &e) {
            if (!appended) error = std::string("probe log file appender failed: ") + e.what();
        } catch (...) {
            if (!appended) error = "probe log file appender failed";
        }
        if (!appended) file_lost(s, chunk.records, error);
        {
            std::lock_guard<std::mutex> lock(s->file_mu);
            s->file_queued -= chunk.bytes.size();
            s->file_busy = false;
            try {
#if defined(UHH_TEST_HOOKS)
                test_file_throw(nth, false);
#endif
                chunk.bytes.clear();                      // keeps its capacity
                if (s->file_spare.size() < FILE_SPARE_MAX) s->file_spare.push_back(std::move(chunk.bytes));
            } catch (...) {}                              // not recycled: the writer allocates one
        }
        s->file_idle.notify_all();
        { std::lock_guard<std::mutex> lock(s->tail_mu); }  // no lost wakeup for flush_log_writer
        s->tail_caught_up.notify_all();
    }
}

// Wait until the appender has appended everything handed to it (the file is complete up to now).
// False: an append failed (file_error says why).
static bool wait_log_file(probe_session *s) {
    if (!s->log_filer.joinable()) return true;
    std::unique_lock<std::mutex> lock(s->file_mu);
    s->file_idle.wait(lock, [s] { return s->file_queue.empty() && !s->file_busy; });
    return !s->file_failed;
}

static bool write_log_batch(probe_session *s, const std::string &bytes, uint64_t records) {
    if (bytes.empty()) return true;
    // Live output: the SAME batch goes to stdout right away, from this thread (the
    // separate tailer let stdout fall seconds behind under load). A slow stdout (a
    // console) back-pressures the producers instead -- nothing is dropped.
    // A stdout that stops taking data (the reader closed the pipe: `| head`) ends the live
    // tail only -- reported once -- never the file: the file stays the complete record and
    // no log is counted lost for a reader that went away.
    // stdout BEFORE the file, and the file NOT on this thread: a session-file WriteFile that
    // extends the file can block for as long as the cache manager is flushing it -- 16 ms to
    // 1.5 s seen on the VM, mostly ~1 s after the file was created (the lazy writer's first
    // pass; real-time AV scanning a file in %TEMP% did the same, 0.1-2.5 s) -- and every record
    // queued meanwhile waited behind it, then all went out at once (regress
    // stream-latency-breakpoint: records #8-#10 held 110-330 ms, codex3 #5). The writer now
    // writes stdout and hands the batch to the appender thread (log_filer_main), so a stalled
    // file holds only the file. Also through a forwarded target stdout: the batch goes out at
    // once when stdout is at a line boundary of the target and nothing is deferred; otherwise
    // it waits in the file and the appender (or the forwarder, at the target's newline) replays
    // it. stdout_mu is held from the stdout write to logs_written, so a report (which holds
    // stdout_mu) sees a batch on stdout and in logs_written, or in neither. Without a live tail
    // (stdout is NUL) the file is the output and is written here, as before.
    // A file that fails (an append, or no memory to hand a batch over) takes no later batch and
    // stops the writer, as a failed synchronous write did at 0fb6cee: logs_written counts the
    // records in the file, the rest go to log_dropped (file_incomplete says so in the error).
    bool tail;
    {
        std::lock_guard<std::mutex> lock(s->tail_mu);
        tail = s->tail_enabled && !s->tail_failed;
    }
    if (!tail || !s->log_filer.joinable()) {
        if (!wait_log_file(s)) { writer_failed(s, s->file_error, records); return false; }   // in order behind the appender
        std::string error;
        if (!append_log_file(s, bytes.data(), bytes.size(), &error)) {
            error = file_incomplete(error, s->logs_written.load());
            break_log_file(s, error);
            writer_failed(s, error, records);
            return false;
        }
        s->logs_written.fetch_add(records, std::memory_order_relaxed);
        { std::lock_guard<std::mutex> lock(s->queue_mu); }   // no lost wakeup: a live probe_report waits for a mark
        s->queue_flushed.notify_all();
        uint64_t end = 0;
        bool direct = false;
        {
            std::lock_guard<std::mutex> lock(s->tail_mu);
            end = s->log_bytes_produced = s->log_bytes_written += bytes.size();
            direct = tail && !s->tail_failed;
        }
        if (direct && s->fwd_out_active) {               // (no appender thread: the old path)
            std::lock_guard<std::mutex> fwd_lock(s->stdout_mu);
            tail_catch_up_locked(s, bytes.data(), bytes.size(), end);
        } else if (direct) {
            std::lock_guard<std::mutex> out_lock(s->stdout_mu);
            if (write_stdout_locked(s, bytes.data(), bytes.size(), records)) {
                std::lock_guard<std::mutex> lock(s->tail_mu);
                s->log_bytes_tailed = s->log_bytes_written;
            }
        }
        s->tail_changed.notify_one();
        s->tail_caught_up.notify_all();
        return true;
    }
    std::string copy;
    {   // room in the appender's queue (never waited for under stdout_mu: the appender takes it)
        std::unique_lock<std::mutex> lock(s->file_mu);
        s->file_idle.wait(lock, [s] { return s->file_queued < FILE_QUEUE_CAP || s->file_failed; });
        if (s->file_failed) {
            const std::string error = s->file_error;
            lock.unlock();
            writer_failed(s, error, records);
            return false;
        }
        if (!s->file_spare.empty()) { copy = std::move(s->file_spare.back()); s->file_spare.pop_back(); }
    }
    try { copy.assign(bytes); }
    catch (...) { writer_failed(s, "probe log writer: out of memory", records); return false; }
    std::unique_lock<std::mutex> out_lock(s->stdout_mu);
    bool now;
    {
        std::lock_guard<std::mutex> lock(s->tail_mu);
        now = s->log_bytes_tailed == s->log_bytes_produced && !s->tail_failed;
    }
    if (now && s->fwd_out_active && s->out_midline.load()) now = false;   // deferred: replayed at the target's newline
    if (now && !write_stdout_locked(s, bytes.data(), bytes.size(), records)) now = false;   // tail_failed() said why
    {
        std::lock_guard<std::mutex> lock(s->tail_mu);
        s->log_bytes_produced += bytes.size();
        if (now) s->log_bytes_tailed = s->log_bytes_produced;
    }
    // Handed over with its records counted in logs_written, in one step under file_mu: the
    // appender moves them back out (file_lost) if it cannot append them. Not handed over: the
    // file failed meanwhile, or no memory for the queue entry.
    bool handed = false, failed = false;
    try {
        std::lock_guard<std::mutex> lock(s->file_mu);
        failed = s->file_failed;
        if (!failed) {
            s->file_queue.push_back({std::move(copy), records});
            s->file_queued += s->file_queue.back().bytes.size();
            s->logs_written.fetch_add(records, std::memory_order_relaxed);
            handed = true;
        }
    } catch (...) {}
    if (!handed) {
        out_lock.unlock();
        if (!failed) {                                  // out of memory: the file ends after what is queued
            wait_log_file(s);
            break_log_file(s, file_incomplete("probe log writer: out of memory", s->logs_written.load()));
        }
        std::string error;
        {
            std::lock_guard<std::mutex> lock(s->file_mu);
            error = s->file_error;
        }
        writer_failed(s, error, records);
        return false;
    }
    s->file_cv.notify_one();
    out_lock.unlock();
    { std::lock_guard<std::mutex> lock(s->queue_mu); }   // no lost wakeup: a live probe_report waits for a mark
    s->queue_flushed.notify_all();
    s->tail_changed.notify_one();
    s->tail_caught_up.notify_all();
    return true;
}

static void log_writer_main(probe_session *s) {
    // Bytes per write (stdout and the session file get the same batch). Bench knob, not API:
    // UHH_BENCH_LOG_BATCH_KB.
    static const size_t BATCH_BYTES = [] {
        char v[16] = {};
        const DWORD n = GetEnvironmentVariableA("UHH_BENCH_LOG_BATCH_KB", v, sizeof(v));
        const unsigned long kb = n && n < sizeof(v) ? std::strtoul(v, nullptr, 10) : 0;
        return kb >= 4 && kb <= 16384 ? (size_t)kb * 1024 : (size_t)64 * 1024;
    }();
    // Write coalescing. The drainer hands over whatever one ring pass found -- under a steady
    // stream of records a few dozen at a time -- and an empty queue used to end the batch at
    // once: two WriteFile calls (stdout and the session file) per small handful of records, the
    // controller's main per-record cost. Now a batch that comes less than HOLD after the
    // previous write waits until HOLD has passed since it (more records join it), so a stream
    // costs at most one write pair per HOLD; the first record after a quiet spell is written at
    // once (live latency unchanged). Ended early by a flush, a stop, or a half-full queue (a fast
    // stream must not fill the bounded queue: the drainer would wait). Measured: ending it at one
    // pack (256 records) instead cost a single fast producer ~25% of its logs/s (sink/inline/file).
    // Bench knob, not API: UHH_BENCH_WRITE_HOLD_US (0 = off).
    static const auto HOLD = [] {
        char v[16] = {};
        const DWORD n = GetEnvironmentVariableA("UHH_BENCH_WRITE_HOLD_US", v, sizeof(v));
        const unsigned long us = n && n < sizeof(v) ? std::strtoul(v, nullptr, 10) : 500;
        return std::chrono::microseconds(us <= 100000 ? us : 500);
    }();
    auto last_write = std::chrono::steady_clock::now() - std::chrono::seconds(1);
    uint64_t unwritten = 0;
    try {
        std::string batch;
        batch.reserve(BATCH_BYTES + 2048);
        for (;;) {
            {
                std::unique_lock<std::mutex> lock(s->queue_mu);
                s->queue_readable.wait(lock, [s] { return s->writer_stop || !s->log_queue.empty(); });
                if (s->log_queue.empty() && s->writer_stop) break;
                s->writer_busy = true;
            }

            batch.clear();
            uint64_t batch_records = 0;
            auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(10);
            // A failed write: write_log_batch counted the batch's records (writer_failed); the
            // rest of what this thread popped and had not written yet is counted here.
            auto failed = [&] {
                s->controller_dropped.fetch_add(unwritten - batch_records, std::memory_order_relaxed);
            };
            // One record into the batch; false: a write failed (the writer stops).
            auto put = [&](const LogView &v) -> bool {
                const size_t before = batch.size();
                append_log_line(batch, s, v);
                if (before && batch.size() > BATCH_BYTES) {             // over: write what was there first
                    std::string line = batch.substr(before);
                    batch.resize(before);
                    last_write = std::chrono::steady_clock::now();
                    if (!write_log_batch(s, batch, batch_records)) { failed(); return false; }
                    unwritten -= batch_records;
                    batch.assign(line); batch_records = 0;
                    deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(10);
                }
                ++batch_records;
                if (batch.size() >= BATCH_BYTES || std::chrono::steady_clock::now() >= deadline) {
                    last_write = std::chrono::steady_clock::now();
                    if (!write_log_batch(s, batch, batch_records)) { failed(); return false; }
                    unwritten -= batch_records;
                    batch.clear(); batch_records = 0;
                    deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(10);
                }
                return true;
            };
            // Records are taken in chunks (one lock and one wake-up per chunk, not per record).
            // A popped record counts as unwritten until its batch is written, so a writer
            // failure mid-chunk still accounts for every one of them.
            std::vector<LogRecord> chunk;
            for (;;) {
                if (chunk.empty()) {
                    std::unique_lock<std::mutex> lock(s->queue_mu);
                    if (s->log_queue.empty() && !batch.empty() && HOLD.count() && !s->writer_stop && !s->flush_waiters) {
                        const auto until = last_write + HOLD;
                        if (std::chrono::steady_clock::now() < until) {
                            s->writer_holding = true;
                            s->writer_hold.wait_until(lock, until, [s] {
                                return s->writer_stop || s->flush_waiters ||
                                       s->log_queue_records >= probe_session::LOG_QUEUE_CAP / 2;
                            });
                            s->writer_holding = false;
                        }
                    }
                    if (s->log_queue.empty()) break;
                    size_t taken = 0;
                    while (!s->log_queue.empty() && taken < LOG_PACK) {
                        const size_t n = records_of(s->log_queue.front());
                        unwritten += n; taken += n ? n : 1;
                        s->log_queue_records -= n;
                        chunk.push_back(std::move(s->log_queue.front()));
                        s->log_queue.pop_front();
                    }
                    std::reverse(chunk.begin(), chunk.end());           // taken from the back below, in order
                    s->queue_writable.notify_all();
                }
                LogRecord record = std::move(chunk.back());
                chunk.pop_back();
                if (record.sym_unload) {
                    // Every record queued before this unload is formatted (symbolized) by now.
                    uhh_sym::unregister_module(s->pi.hProcess, record.sym_unload);
                    std::lock_guard<std::mutex> lock(s->queue_mu);
                    for (auto it = s->sym_pending.begin(); it != s->sym_pending.end(); ++it)
                        if (it->first == record.sym_unload) { s->sym_pending.erase(it); break; }
                    s->queue_flushed.notify_all();
                    continue;
                }
                if (!record.packed) {
                    const LogView v{record.probe, record.tid, record.text, record.has_stack,
                                    reinterpret_cast<const unsigned char *>(record.frames.data()), record.frames.size()};
                    if (!put(v)) return;
                    continue;
                }
                const auto *p = reinterpret_cast<const unsigned char *>(record.text.data());
                const auto *end = p + record.text.size();
                for (uint32_t k = 0; k < record.packed; ++k) {
                    // Every entry is bounds-checked against the pack (pack_agent_record rolls a
                    // failed append back, so this never trips; if it did, the rest of the pack is
                    // counted as dropped instead of being read past its end).
                    LogPackHdr h;
                    size_t body = 0;
                    const bool fits = (size_t)(end - p) >= sizeof(h) && (std::memcpy(&h, p, sizeof(h)), true) &&
                                      h.len < PROBE_AGENT_LOG_TEXT_CAP && h.nframes <= PROBE_STACK_MAX_FRAMES &&
                                      (body = (size_t)h.len + (size_t)h.nframes * sizeof(uint64_t)) <= (size_t)(end - p) - sizeof(h);
                    if (!fits) {
                        s->controller_dropped.fetch_add(record.packed - k, std::memory_order_relaxed);
                        unwritten -= record.packed - k;
                        break;
                    }
                    p += sizeof(h);
                    const LogView v{h.probe, h.tid, std::string_view(reinterpret_cast<const char *>(p), h.len),
                                    h.has_stack != 0, p + h.len, h.nframes};
                    p += body;
                    if (!put(v)) return;
                }
            }
            // An empty queue is an idle boundary: do not hold a short batch for the timer.
            if (!batch.empty()) last_write = std::chrono::steady_clock::now();
            if (!write_log_batch(s, batch, batch_records)) { failed(); return; }
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

void tail_failed(probe_session *s, const std::string &message) {
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

// records: the probe_log lines in bytes; counted in stdout_logs while stdout_mu is still held,
// so a report (which holds stdout_mu) never sees records on stdout that it does not count.
static bool write_stdout_chunk(probe_session *s, const char *bytes, size_t size, uint64_t records) {
    std::lock_guard<std::mutex> out_lock(s->stdout_mu);
    return write_stdout_locked(s, bytes, size, records);
}

// stdout_mu held.
static bool write_stdout_locked(probe_session *s, const char *bytes, size_t size, uint64_t records) {
    if (!size) return true;
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
    {
        std::lock_guard<std::mutex> lock(s->tail_mu);
        s->stdout_logs += records;
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
    uint64_t records = 0;
    while (tailed < file_end) {
        char buffer[64 * 1024];
        OVERLAPPED at{}; at.Offset = (DWORD)tailed; at.OffsetHigh = (DWORD)(tailed >> 32);
        DWORD want = (DWORD)std::min<uint64_t>(sizeof(buffer), file_end - tailed), got = 0;
        if (!ReadFile(s->log_reader, buffer, want, &got, &at) || !got) {
            tail_failed(s, win_error("replay probe log file to stdout")); return;
        }
        if (!write_all(s->stdout_handle, buffer, got)) { tail_write_failed(s, "tail probe logs to stdout"); return; }
        tailed += got;
        records += (uint64_t)std::count(buffer, buffer + got, '\n');   // one '\n' per record (JSON escapes the rest)
    }
    if (tailed < fresh_end) {
        size_t skip = (size_t)(fresh_size - (fresh_end - tailed));
        if (!write_all(s->stdout_handle, fresh + skip, fresh_size - skip)) {
            tail_write_failed(s, "tail probe logs to stdout"); return;
        }
        tailed = fresh_end;
        records += (uint64_t)std::count(fresh + skip, fresh + fresh_size, '\n');
    }
    {
        std::lock_guard<std::mutex> lock(s->tail_mu);
        s->log_bytes_tailed = tailed;
        s->stdout_logs += records;
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
bool make_forward_pipe(HANDLE &server, HANDLE &client) {
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
bool forwardable(HANDLE h) {
    if (h == nullptr || h == INVALID_HANDLE_VALUE) return false;
    DWORD type = GetFileType(h);
    return type == FILE_TYPE_PIPE || type == FILE_TYPE_DISK;
}

bool same_object(HANDLE a, HANDLE b) {
    if (a == b) return true;
    using compare_fn = BOOL(WINAPI *)(HANDLE, HANDLE);
    static compare_fn compare = (compare_fn)(void *)GetProcAddress(GetModuleHandleW(L"kernelbase.dll"), "CompareObjectHandles");
    return compare && compare(a, b);
}

// Start a forwarder thread for an already-created pipe.
bool forward_start(probe_session *s, probe_session::StdForward *f) {
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

void forward_stop(probe_session *s) {
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
                    if (!write_stdout_chunk(s, pending.data(), chunk, (uint64_t)std::count(pending.data(), pending.data() + chunk, '\n'))) return;
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

bool start_log_output(probe_session *s) {
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
        // The session file's own appender, with a live tail (write_log_batch). None (no thread):
        // the writer appends itself, as before.
        if (s->tail_enabled) {
            try { s->file_spare.reserve(FILE_SPARE_MAX); s->log_filer = std::thread(log_filer_main, s); } catch (...) {}
        }
        s->log_writer = std::thread(log_writer_main, s);
        (void)log_tailer_main;               // kept for reference; the writer writes stdout directly
    } catch (...) {
        {
            std::lock_guard<std::mutex> lock(s->queue_mu); s->writer_stop = true;
        }
        s->queue_readable.notify_one();
        s->writer_hold.notify_all();
        if (s->log_writer.joinable()) s->log_writer.join();
        stop_log_filer(s);
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
    bool blocked = s->log_queue_records >= probe_session::LOG_QUEUE_CAP && !s->writer_failed;
    auto blocked_at = std::chrono::steady_clock::now();
    s->queue_writable.wait(lock, [s] {
        return s->log_queue_records < probe_session::LOG_QUEUE_CAP || s->writer_failed;
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
    ++s->logs_enqueued; ++s->log_queue_records;
    lock.unlock();
    if (warned) warn_console_once(s);
    s->queue_readable.notify_one();
    return true;
}

// enqueue_log for many records at once (the agent-ring drainer): one queue lock and one writer
// wake-up per chunk instead of per record -- per record, the wake-up of a writer that had just
// emptied the queue was most of the controller's cost per inline log (the producers in the target
// wait on that pipeline: the ring's backpressure). Same backpressure and accounting as enqueue_log;
// `records` is left empty. Entries may be packs (LogRecord::packed): the cap counts records, and
// a pack goes in whole while the queue holds fewer than the cap.
static void enqueue_logs(probe_session *s, std::vector<LogRecord> &records) {
    if (!records.empty()) g_diag_enqueues++;
    size_t i = 0;
    while (i < records.size()) {
        std::unique_lock<std::mutex> lock(s->queue_mu);
        bool blocked = s->log_queue_records >= probe_session::LOG_QUEUE_CAP && !s->writer_failed;
        auto blocked_at = std::chrono::steady_clock::now();
        s->queue_writable.wait(lock, [s] {
            return s->log_queue_records < probe_session::LOG_QUEUE_CAP || s->writer_failed;
        });
        if (s->writer_failed) {
            uint64_t n = 0;
            for (; i < records.size(); ++i) n += records_of(records[i]);
            s->controller_dropped.fetch_add(n, std::memory_order_relaxed);
            break;
        }
        bool warned = blocked && std::chrono::steady_clock::now() - blocked_at >= std::chrono::seconds(1);
        for (; i < records.size() && s->log_queue_records < probe_session::LOG_QUEUE_CAP; ++i) {
            const size_t n = records_of(records[i]);
            try { s->log_queue.push_back(std::move(records[i])); s->logs_enqueued += n; s->log_queue_records += n; }
            catch (...) { s->controller_dropped.fetch_add(n, std::memory_order_relaxed); }
        }
        const bool end_hold = s->writer_holding && s->log_queue_records >= probe_session::LOG_QUEUE_CAP / 2;
        lock.unlock();
        if (end_hold) s->writer_hold.notify_all();
        if (warned) warn_console_once(s);
        s->queue_readable.notify_one();
    }
    records.clear();
}

// up_to_now: wait only for the records queued when the call started, not for an empty queue
// -- a report on a target that is still running (an attach reported before its detach) would
// otherwise wait as long as the target keeps logging faster than stdout takes it (seen: a
// report that came 5.3M records later, its hit snapshot far below its logs_written).
void flush_log_writer(probe_session *s, bool up_to_now) {
    if (s->log_file == INVALID_HANDLE_VALUE) return;
    std::string error;
    {
        std::unique_lock<std::mutex> lock(s->queue_mu);
        const uint64_t mark = s->logs_enqueued;
        ++s->flush_waiters;                          // a held batch is written now (log_writer_main)
        if (s->writer_holding) s->writer_hold.notify_all();
        s->queue_flushed.wait(lock, [s, up_to_now, mark] {
            return (s->log_queue.empty() && !s->writer_busy) || s->writer_failed ||
                   (up_to_now && s->logs_written.load() >= mark);
        });
        --s->flush_waiters;
        error = s->writer_error;
    }
    if (!error.empty()) set_error(s, error);
    if (!wait_log_file(s)) {                   // the session file complete up to here (log_filer_main)
        std::lock_guard<std::mutex> lock(s->file_mu);
        set_error(s, s->file_error);
    }
    if (s->exited) forward_finish(s);          // the target's last bytes, then the waiting records

    std::string tail_error;
    if (s->tail_enabled) {
        std::unique_lock<std::mutex> lock(s->tail_mu);
        uint64_t target = s->log_bytes_produced;
        // While the (running) target is inside a line, records wait for its newline. A session
        // file that stopped growing (file_broken) ends at log_bytes_written: records deferred
        // past it never reach stdout -- waiting for them hung probe_report/probe_close (codex4 #1).
        s->tail_caught_up.wait(lock, [s, target] {
            return s->log_bytes_tailed >= (s->file_broken ? std::min(target, s->log_bytes_written) : target) ||
                   s->tail_failed || s->out_midline.load();
        });
        tail_error = s->tail_error;
    }
    if (!tail_error.empty()) set_error(s, tail_error);
}

// A module unloaded. Stack frames are captured as raw addresses at the hit and symbolized
// later on the writer thread, so records captured BEFORE the unload may still be queued (or,
// inline, in the agent's ring): dbghelp keeps the module until the writer has passed them.
// The unregister travels through the log queue, behind those records.
void sym_unload(probe_session *s, uint64_t base) {
    if (!s->sym_ready) return;
    auto sz = s->module_sizes.find(base);
    const uint64_t size = sz != s->module_sizes.end() ? sz->second : 1;
    if (s->log_writer.joinable()) {
        drain_agent_logs(s);                               // inline records captured before the unload
        std::unique_lock<std::mutex> lock(s->queue_mu);
        s->queue_writable.wait(lock, [s] {
            return s->log_queue_records < probe_session::LOG_QUEUE_CAP || s->writer_failed;
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
void wait_sym_unloads(probe_session *s, uint64_t base, uint64_t size) {
    std::unique_lock<std::mutex> lock(s->queue_mu);
    s->queue_flushed.wait(lock, [&] {
        if (s->writer_failed) return true;
        for (auto &p : s->sym_pending)
            if (p.first < base + size && base < p.first + p.second) return false;
        return true;
    });
}

static void stop_log_filer(probe_session *s) {
    if (!s->log_filer.joinable()) return;
    {
        std::lock_guard<std::mutex> lock(s->file_mu); s->file_stop = true;
    }
    s->file_cv.notify_one();
    s->log_filer.join();
}

void stop_log_output(probe_session *s) {
    if (s->log_writer.joinable()) {
        {
            std::lock_guard<std::mutex> lock(s->queue_mu); s->writer_stop = true;
        }
        s->queue_readable.notify_one();
        s->writer_hold.notify_all();
        s->log_writer.join();
        flush_log_writer(s);
    }
    stop_log_filer(s);                          // after the flush: the file is complete
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

// The agent request index -> probes[] index map (agent_map) as one drain pass sees it: an entry is
// read under agent_mu the first time the pass needs it. A mapped entry never changes during a
// session (indices are only assigned), so the copy is exact; an unmapped one is read again.
struct AgentMapCache {
    uint32_t map[PROBE_AGENT_MAX_PROBES];
    AgentMapCache() { std::fill(std::begin(map), std::end(map), UINT32_MAX); }
    uint32_t probe_of(probe_session *s, uint32_t index) {
        if (index >= PROBE_AGENT_MAX_PROBES) return index;
        if (map[index] == UINT32_MAX) {
            std::lock_guard<std::mutex> map_lock(s->agent_mu);
            map[index] = s->agent_map[index];
        }
        return map[index] != UINT32_MAX ? map[index] : index;
    }
};

// One ring record (or a PROBE_IPC_LOG copy of one) -> the writer's queue. Never touches
// s->probes (the debug loop may be growing it); does not hold agent_mu while a full stdout
// queue applies backpressure.
void enqueue_agent_record(probe_session *s, const probe_agent_log &rec) {
    // A callback's first record carries its hit's unaccounted unit: taken now, the hit is
    // accounted by this record (logs_written, or controller_dropped below), not as interrupted.
    if (s->shared) probe_agent_retire_carry(s->shared, rec);
    try {
        LogRecord r;
        uint32_t len = rec.text_len < PROBE_AGENT_LOG_TEXT_CAP ? rec.text_len : PROBE_AGENT_LOG_TEXT_CAP - 1;
        r.text.assign(rec.text, len);
        r.tid = rec.tid; r.has_stack = rec.has_stack != 0;
        AgentMapCache map;
        r.probe = map.probe_of(s, rec.probe);
        uint32_t n = rec.frame_count > PROBE_STACK_MAX_FRAMES ? PROBE_STACK_MAX_FRAMES : rec.frame_count;
        r.frames.assign(rec.frames, rec.frames + n);
        enqueue_log(s, std::move(r));
    } catch (...) {
        s->controller_dropped.fetch_add(1, std::memory_order_relaxed);   // out of memory: count it, keep going
    }
}

// A ring record appended to the drain pass's pack (LogRecord::packed): the same fields and
// bounds as enqueue_agent_record, without a string and a queue entry per record.
#if defined(UHH_TEST_HOOKS)
// Test-only (probe_api_testhooks): UHH_TEST_PACK_FAIL=n makes every n-th record's pack append
// throw std::bad_alloc after its header is in the pack (regress ctrl-pack-oom).
static bool test_pack_fail() {
    static const long n = [] { const char *v = std::getenv("UHH_TEST_PACK_FAIL"); return v ? std::atol(v) : 0L; }();
    static std::atomic<long> k{0};
    if (n <= 0 || ++k % n) return false;
    std::fprintf(stderr, "probe: test: pack append failed\n");
    return true;
}
#endif
// A record whose append fails (out of memory) leaves the pack exactly as it was: the bytes it
// appended so far are cut off again (a header without its text and frames made every later entry
// of the pack misparse -- regress ctrl-pack-oom), and a pack it had just started is removed (an
// empty pack counted as one record and was written as an empty log line).
static void pack_agent_record(probe_session *s, const probe_agent_log &rec, std::vector<LogRecord> &batch,
                              AgentMapCache &map) {
    if (s->shared) probe_agent_retire_carry(s->shared, rec);
    const size_t packs = batch.size();
    const bool fresh = batch.empty() || batch.back().packed >= LOG_PACK;     // this record starts a pack
    const size_t mark = fresh ? 0 : batch.back().text.size();
    try {
        if (fresh) {
            batch.emplace_back();
            batch.back().text.reserve(LOG_PACK * 96);
        }
        LogRecord &pack = batch.back();
        LogPackHdr h;
        h.len = rec.text_len < PROBE_AGENT_LOG_TEXT_CAP ? rec.text_len : PROBE_AGENT_LOG_TEXT_CAP - 1;
        h.probe = map.probe_of(s, rec.probe);
        h.tid = rec.tid;
        h.has_stack = rec.has_stack != 0;
        h.nframes = !h.has_stack ? 0 : rec.frame_count > PROBE_STACK_MAX_FRAMES ? PROBE_STACK_MAX_FRAMES : rec.frame_count;
        pack.text.append(reinterpret_cast<const char *>(&h), sizeof(h));
#if defined(UHH_TEST_HOOKS)
        if (test_pack_fail()) throw std::bad_alloc();
#endif
        pack.text.append(rec.text, h.len);
        if (h.nframes) pack.text.append(reinterpret_cast<const char *>(rec.frames), (size_t)h.nframes * sizeof(uint64_t));
        ++pack.packed;
    } catch (...) {
        if (fresh) { if (batch.size() > packs) batch.pop_back(); }     // the pack this record started
        else batch.back().text.resize(mark);                            // never throws (shrinks)
        s->controller_dropped.fetch_add(1, std::memory_order_relaxed);   // out of memory: count it, keep going
    }
}

// drain_mu, taken FAIRLY. The drainer thread releases it between passes and takes it again
// nanoseconds later; a std::mutex (an SRW lock) has no handoff, so another thread waiting for
// it -- the debug loop's per-turn drain, a report, a module unload -- could lose that race for
// minutes while the target kept the ring full (CI: a live detach not even started 240 s after
// its request, probe_run starved in its drain while 8.7M records streamed). A thread that
// finds it taken says so here; the drainer does not start another pass while one waits.
static std::unique_lock<std::mutex> lock_drain(probe_session *s) {
    std::unique_lock<std::mutex> lock(s->drain_mu, std::try_to_lock);
    if (!lock.owns_lock()) {
        s->drain_waiters.fetch_add(1);
        lock.lock();
        s->drain_waiters.fetch_sub(1);
    }
    return lock;
}

// Move published inline-log records out of the shared ring (single consumer). Called
// every debug-loop turn, on idle timeouts, and at report, so the ring never fills
// just because the run is long.
// One pass: up to the records claimed when the call started. On a target that keeps logging
// into a full ring (stdout slower than the producers) every freed slot is refilled at once,
// so "until the ring is empty" never ended -- holding drain_mu all the while (a report before
// a detach never came). Callers that need more call again (the drainer loops).
size_t drain_agent_logs(probe_session *s) {
    if (!s->shared) return 0;
    auto *sh = s->shared;
    size_t moved = 0;
    auto consume = lock_drain(s);
    // Records go to the writer in packs (enqueue_logs), each before drain_mu is released: a
    // flush that drains first (report, unload, detach) still finds every record queued.
    // log_tail is written once per pack and at the end of the pass, not per record: producers find
    // free slots by their seq, and every reader of log_tail is this thread, holds drain_mu, or only
    // waits for it to reach the head.
    std::vector<LogRecord> batch;
    AgentMapCache map;
    // The pass ends at the head read once here (bounded by one ring: memory the target can write).
    // (Measured: bounding it by the ring alone, without reading the head, made an idle drainer
    // poll the next slot's line -- the one the next producer claims and writes -- and a single
    // producer's send_log took ~20% longer on x86.)
    LONG64 tail = sh->log_tail;
    LONG64 stop = sh->log_head;
    if ((uint64_t)stop - (uint64_t)tail > PROBE_AGENT_LOG_CAP) stop = tail + PROBE_AGENT_LOG_CAP;
    for (;;) {
        if (tail >= stop) break;
        auto &rec = sh->logs[(uint64_t)tail % PROBE_AGENT_LOG_CAP];
        LONG64 seq = probe_agent_load64(&rec.seq);
        if (seq != tail + 1 && seq != -(tail + 1)) break;
        // x86/x64 (TSO) order loads with loads and stores after older loads: reading the record
        // after its seq, and freeing the slot after reading it, need only the compiler barriers --
        // not a fence and a LOCKed exchange per record (the producer publishes the same way).
        _ReadWriteBarrier();
        if (seq == tail + 1) pack_agent_record(s, rec, batch, map);    // -(tail + 1): delivered past a stall already
        _ReadWriteBarrier();
        rec.owner = 0;
        probe_agent_store64(&rec.seq, tail + PROBE_AGENT_LOG_CAP);     // slot free again (after owner: store order)
        ++tail;
        ++moved;
        if (!batch.empty() && batch.back().packed >= LOG_PACK) { sh->log_tail = tail; enqueue_logs(s, batch); }
    }
    sh->log_tail = tail;
    enqueue_logs(s, batch);
    if (moved) { g_diag_passes++; g_diag_moved += moved; }
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
void deliver_past_stall(probe_session *s) {
    auto *sh = s->shared;
    auto consume = lock_drain(s);
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
        auto consume = lock_drain(s);
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
void start_drainer(probe_session *s) {
    if (s->drainer.joinable() || !s->shared) return;
    s->drain_stop = false;
    s->drainer = std::thread([s] {
        unsigned idle = 0, yields = 0;
        RingStall stall;
        // Idle waits of 0.5 ms (a high-resolution timer) while records came recently: Sleep(1)
        // lasts a whole timer tick (15.6 ms unless something raised the resolution), and a ring
        // of PROBE_AGENT_LOG_CAP records fills in a few ms at full speed -- every logging thread
        // then waited out the rest of the tick (profiles: producers yielding in agent_log behind
        // a sleeping drainer). After 50 ms without a record, back to Sleep(1) (no 2 kHz wakeups
        // on an idle target). No such timer (before Windows 10 1803): Sleep(1) throughout.
        // After those 50 ms, with the agent holding the drain event, the drainer SLEEPS until a
        // producer publishes (probe_agent_drain_wait) instead of polling every timer tick: the
        // first record after a quiet spell reached stdout one tick (15.6 ms) late, and the idle
        // drainer woke 64 times a second. It still wakes every IDLE_WAKE_MS (the heartbeat; a
        // wake-up lost to anything unforeseen costs at most that).
        constexpr DWORD IDLE_WAKE_MS = 100;
        HANDLE timer = CreateWaitableTimerExW(nullptr, nullptr, 0x00000002 /* CREATE_WAITABLE_TIMER_HIGH_RESOLUTION */,
                                              TIMER_ALL_ACCESS);
        auto *sh = s->shared;
        ULONGLONG last_record = GetTickCount64();
        LONG64 beat = probe_agent_load64(&sh->drain_beat);
        static const unsigned DRAIN_PAUSE = [] {
            char v[16] = {};
            const DWORD n = GetEnvironmentVariableA("UHH_BENCH_DRAIN_PAUSE", v, sizeof(v));
            const unsigned long p = n && n < sizeof(v) ? std::strtoul(v, nullptr, 10) : 64;
            return (unsigned)(p <= 100000 ? p : 64);
        }();
        while (!s->drain_stop.load(std::memory_order_relaxed)) {
            // "Controller alive". This thread is its only writer: a plain store (on x86 a LOCKed
            // 64-bit increment is a CMPXCHG8B loop, once per loop).
            probe_agent_store64(&sh->drain_beat, ++beat);
            if (s->drain_waiters.load()) {           // another consumer goes first (lock_drain)
                // (It may wait behind a third holder that is itself held up by a slow stdout:
                // after a few yields, sleep rather than spin.)
                if (++yields < 64) SwitchToThread(); else Sleep(1);
                continue;
            }
            yields = 0;
            if (const size_t moved = drain_agent_logs(s)) {
                idle = 0; last_record = GetTickCount64();
                // A pass that found only a few records: wait a moment before the next one. A drainer
                // that comes straight back reads the head and the next slot -- the lines the producers
                // are writing -- several times per record (x86 single producer: see ROADMAP perf5).
                // Bench knob, not API: UHH_BENCH_DRAIN_PAUSE (PAUSE instructions, 0 = off).
                if (moved < 32) for (unsigned k = 0; k < DRAIN_PAUSE; ++k) YieldProcessor();
                continue;
            }
            check_ring_stall(s, stall);
            if (++idle < 64) { SwitchToThread(); continue; }
            LARGE_INTEGER due; due.QuadPart = -5000;                   // 0.5 ms, relative
            if (timer && GetTickCount64() - last_record < 50 && SetWaitableTimer(timer, &due, 0, nullptr, nullptr, FALSE)) {
                WaitForSingleObject(timer, 1);   // never longer than Sleep(1) would have been
            } else if (s->drain_event && sh->drain_wait.agent_ready && sh->log_head == sh->log_tail) {
                // (Only an EMPTY ring sleeps: one stuck behind an unpublished slot keeps the
                // Sleep(1) polling of check_ring_stall below.)
                InterlockedExchange(&sh->drain_wait.waiting, 1);
                // The ring once more AFTER announcing the sleep (a LOCKed store first, see
                // probe_agent_drain_wait): a record claimed before it is seen here, one claimed after
                // finds `waiting` set and signals.
                if (sh->log_head == sh->log_tail && !s->drain_stop.load())
                    WaitForSingleObject(s->drain_event, IDLE_WAKE_MS);
                InterlockedExchange(&sh->drain_wait.waiting, 0);
            } else {
                Sleep(1);
            }
        }
        if (timer) CloseHandle(timer);
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
    auto consume = lock_drain(s);
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
// run) -- the caller keeps waiting, within its bound.
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

void stop_drainer(probe_session *s) {
    // Detached from a live target: its hooks are gone, but a callback that was already running
    // (e.g. blocked in call_original longer than the agent's 2 s unhook wait) may still log.
    // Keep draining BEFORE telling producers nobody listens, so its logs are delivered rather
    // than dropped -- for at most PROBE_DETACH_CALLBACK_WAIT_MS (owner decision 2026-11-07: the
    // program's correctness does not need the wait, and an unbounded detach is worse). Callbacks
    // that cannot finish now -- their thread is gone, or suspended by the program, or left
    // through a non-unwinding longjmp -- are not waited for at all. Past the bound, or for those,
    // the detach completes and accounts them: `running` in the detach line, and those that had
    // not logged yet `in_flight` (hits == logs_written + log_dropped + in_flight); any log they
    // write later is lost (counted dropped only in the target, which nobody reads any more).
    // Their config blocks stay allocated (probe_close), so the program is unaffected.
    constexpr ULONGLONG PROBE_DETACH_CALLBACK_WAIT_MS = 15000;
    if (s->shared && !s->exited && s->drainer.joinable()) {
        MemoryBarrier();
        if (const uint64_t running = probe_agent_running(s->shared))
            std::fprintf(stderr, "probe: %s: %llu callback(s) still running; delivering their logs (up to %llu s)\n",
                         s->detached_hooks ? "detach" : "close", (unsigned long long)running,
                         (unsigned long long)(PROBE_DETACH_CALLBACK_WAIT_MS / 1000));
    }
    if (s->shared && s->detached_hooks && !s->exited && s->drainer.joinable()) {
        const ULONGLONG start = GetTickCount64();
        int idle_answers = 0;
        for (;;) {
            MemoryBarrier();
            const uint64_t inflight = probe_agent_running(s->shared);     // callbacks that may still log
            if (!inflight && s->shared->log_head == s->shared->log_tail) break;
            if (GetTickCount64() - start >= PROBE_DETACH_CALLBACK_WAIT_MS) {
                if (inflight)
                    std::fprintf(stderr, "probe: detach: %llu callback(s) still running after %llu s; not waiting longer "
                                         "(any log they write from now on is lost; see running=/in_flight= below)\n",
                                 (unsigned long long)inflight, (unsigned long long)(PROBE_DETACH_CALLBACK_WAIT_MS / 1000));
                break;
            }
            if (inflight) {
                LONG live = 0;
                if (query_live_callbacks(s, live)) {
                    // Three answers in a row (~50 ms apart): a callback between its in-flight
                    // count and its record (nanoseconds) is not missed.
                    if (live > 0) idle_answers = 0;
                    else if (++idle_answers >= 3) {
                        std::fprintf(stderr, "probe: detach: %llu callback(s) cannot finish now (thread gone or suspended); "
                                             "not waiting for them\n", (unsigned long long)inflight);
                        break;
                    }
                }
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
    s->drain_stop = true;
    if (s->drain_event) SetEvent(s->drain_event);   // a sleeping drainer (probe_agent_drain_wait)
    s->drainer.join();
    drain_final(s);
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

std::string symbolize(probe_session *s, uint64_t addr) {
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

} // namespace uhh_session

using namespace uhh_session;

extern "C" void send_log(probe_context *c, const char *format, ...) {
    va_list ap; va_start(ap, format); log_common(c, false, format, ap); va_end(ap);
}

extern "C" void send_log_stack(probe_context *c, const char *format, ...) {
    va_list ap; va_start(ap, format); log_common(c, true, format, ap); va_end(ap);
}

namespace uhh_session {

// The table the controller's copy of the agent DLL forwards to (UHH_SHARED callbacks).
void vlog_entry(probe_context *c, int stack, const char *format, va_list ap) { log_common(c, stack != 0, format, ap); }

} // namespace uhh_session

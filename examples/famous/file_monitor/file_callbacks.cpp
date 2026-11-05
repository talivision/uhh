// File-activity monitor (Process Monitor "File System" lite; the Frida NtCreateFile/
// NtReadFile/NtWriteFile tracer every blog post starts with).
//
//   ntdll!NtCreateFile entry   decode OBJECT_ATTRIBUTES -> UNICODE_STRING path; remember
//                              {PHANDLE, path} under the return-site SP; probe the call site
//   <call site> (return)       NTSTATUS in AX; on success read *PHANDLE: handle -> path
//   ntdll!NtReadFile  entry    handle -> path, requested Length  (one log per call)
//   ntdll!NtWriteFile entry    handle -> path, Length
//
// The handle map is UHH_SHARED, so the create probe (whichever backend) and the read/
// write probes (whichever backend) see one map. Handles opened another way (NtOpenFile,
// inherited stdio) log as path=?.
#include "../common/famous_common.h"

namespace {
constexpr size_t kHandles = 128;
struct handle_slot {
    std::atomic<uint64_t> handle{0};    // 0 free, 1 being written, else a handle value
    char path[244]{};
};
} // namespace

UHH_SHARED famous_site g_file_sites[8]{};
UHH_SHARED famous_pending g_file_pending[64]{};
UHH_SHARED handle_slot g_file_handles[kHandles]{};
UHH_SHARED std::atomic<int64_t> g_file_unmatched{0};

static void map_put(uint64_t handle, const char *path) {
    // Replace an existing entry for a reused handle value, else take a free slot.
    for (int pass = 0; pass < 2; ++pass) {
        for (size_t i = 0; i < kHandles; ++i) {
            uint64_t expected = pass == 0 ? handle : 0;
            if (!g_file_handles[i].handle.compare_exchange_strong(expected, 1, std::memory_order_acq_rel)) continue;
            strncpy_s(g_file_handles[i].path, sizeof(g_file_handles[i].path), path, _TRUNCATE);
            g_file_handles[i].handle.store(handle, std::memory_order_release);
            return;
        }
    }
}

static bool map_get(uint64_t handle, char *out, size_t cap) {
    for (size_t i = 0; i < kHandles; ++i) {
        if (g_file_handles[i].handle.load(std::memory_order_acquire) != handle) continue;
        strncpy_s(out, cap, g_file_handles[i].path, _TRUNCATE);
        // the slot may have been rewritten while we copied: accept only if still ours
        if (g_file_handles[i].handle.load(std::memory_order_acquire) == handle) return true;
    }
    strncpy_s(out, cap, "?", _TRUNCATE);
    return false;
}

FAMOUS_EXPORT void famous_file_on_create_return(probe_context *c) {
    uint64_t phandle = 0, unused = 0;
    char path[256];
    if (!famous_pending_take(g_file_pending, 64, get_reg(c, PROBE_REG_SP), phandle, unused, path, sizeof(path))) {
        g_file_unmatched.fetch_add(1, std::memory_order_relaxed);
        return;
    }
    uint32_t status = (uint32_t)get_reg(c, PROBE_REG_AX);
    uint64_t handle = 0;
    if ((int32_t)status >= 0) {
        handle = famous_read_ptr(c, phandle);
        if (handle) map_put(handle, path);
    }
    send_log(c, "file-open path=%s handle=0x%llx status=0x%08x", path, (unsigned long long)handle, status);
}

// NtCreateFile(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER,
//              ULONG, ULONG, ULONG Disposition, ULONG Options, PVOID, ULONG)  -- 11 args
FAMOUS_EXPORT void famous_file_on_create(probe_context *c) {
    char path[256];
    if (!famous_read_object_name(c, get_func_arg(c, 2), path, sizeof(path)) || !path[0])
        strncpy_s(path, sizeof(path), "?", _TRUNCATE);
    const famous_config *cfg = famous_cfg(c);
    if (cfg && !famous_contains(path, cfg->filter)) return;   // Procmon "Path contains" filter
    uint64_t ret = famous_return_address(c);
    if (!famous_pending_put(g_file_pending, 64, famous_return_sp(c, 11), get_func_arg(c, 0), 0, path)) {
        send_log(c, "file-open path=%s PENDING-FULL", path);
        return;
    }
    if (!famous_arm_return(c, g_file_sites, 8, ret, famous_file_on_create_return, famous_ret_flags(c)))
        send_log(c, "file-open path=%s UNTRACKED (return site not armed)", path);
}

// NtReadFile/NtWriteFile(HANDLE, HANDLE Event, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK,
//                        PVOID Buffer, ULONG Length, PLARGE_INTEGER, PULONG)
static void log_io(probe_context *c, const char *op) {
    uint64_t handle = get_func_arg(c, 0);
    char path[256];
    const famous_config *cfg = famous_cfg(c);
    // With a filter, only handles whose open matched it are in the map: skip the rest.
    if (!map_get(handle, path, sizeof(path)) && cfg && cfg->filter[0]) return;
    send_log(c, "file-%s path=%s handle=0x%llx len=%llu", op, path, (unsigned long long)handle,
             (unsigned long long)(uint32_t)get_func_arg(c, 6));
}

FAMOUS_EXPORT void famous_file_on_read(probe_context *c) { log_io(c, "read"); }
FAMOUS_EXPORT void famous_file_on_write(probe_context *c) { log_io(c, "write"); }

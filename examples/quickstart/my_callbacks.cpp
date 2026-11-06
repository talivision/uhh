#include "my_callbacks.h"

// Turn the disabled feature on. The library counts the register change in the
// report's "overrides" field.
extern "C" void my_enable_reads(probe_context *c) {
    if (get_reg(c, PROBE_REG_AX) == 0) set_reg(c, PROBE_REG_AX, 1);
}

// NtReadVirtualMemory(handle, address, buffer, size, done): arguments 0, 1 and 3.
extern "C" void my_log_read(probe_context *c) {
    uint64_t handle = get_func_arg(c, 0), addr = get_func_arg(c, 1), size = get_func_arg(c, 3);
    send_log(c, "read handle=0x%llx addr=0x%llx size=%llu", (unsigned long long)handle,
             (unsigned long long)addr, (unsigned long long)size);
}

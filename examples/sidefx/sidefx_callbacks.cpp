// Compiled unchanged into the controller and probe_api_agent. It intentionally
// dirties process/thread state but never calls set_reg or set_mem.
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <cstdint>

#include "probe_api.h"

#define SIDEFX_EXPORT extern "C" __declspec(dllexport)

namespace {

alignas(8) volatile LONG64 g_hits;

} // namespace

SIDEFX_EXPORT void sidefx_on_site(probe_context *context) {
    volatile double one = 1.0;
    volatile double zero = GetCurrentThreadId() == 0 ? 1.0 : 0.0;
    volatile double three = 3.0;
    volatile double divide_by_zero = one / zero;
    volatile double inexact = one / three;
    std::uint8_t stack_bytes[256]{};
    const std::uint64_t sp = get_reg(context, PROBE_REG_SP);
    const std::uint64_t ax = get_reg(context, PROBE_REG_AX);
    const std::uint64_t bx = get_reg(context, PROBE_REG_BX);
    const std::uint64_t si = get_reg(context, PROBE_REG_SI);
    const std::uint64_t r15 = get_reg(context, PROBE_REG_R15);
    const int stack_ok = get_mem(context, sp, stack_bytes, sizeof(stack_bytes));
    const LONG64 hit = InterlockedIncrement64(&g_hits);

    SetLastError(ERROR_SUCCESS);
    const DWORD attributes = GetFileAttributesA("Z:\\uhh-sidefx-no-such\\missing");
    const DWORD api_error = GetLastError();

    send_log(context,
             "sidefx hit=%lld value=%.17g divzero=%.1f stack=%s ax=%llx bx=%llx "
             "si=%llx r15=%llx attrs=%lu error=%lu",
             static_cast<long long>(hit), static_cast<double>(inexact),
             static_cast<double>(divide_by_zero), stack_ok ? "ok" : "fail",
             static_cast<unsigned long long>(ax), static_cast<unsigned long long>(bx),
             static_cast<unsigned long long>(si), static_cast<unsigned long long>(r15),
             static_cast<unsigned long>(attributes), static_cast<unsigned long>(api_error));
    if ((hit & 63) == 0) send_log_stack(context, "sidefx stack hit=%lld", static_cast<long long>(hit));
}

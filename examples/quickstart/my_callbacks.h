#pragma once
#include "probe_api.h"

extern "C" {
/* configparse.dll!ParseConfig+0x16: the parsed flag is in EAX; 0 -> 1. */
__declspec(dllexport) void my_enable_reads(probe_context *);
/* ntdll!NtReadVirtualMemory entry: log handle/address/size. */
__declspec(dllexport) void my_log_read(probe_context *);
}

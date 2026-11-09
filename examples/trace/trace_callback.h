#pragma once
#include "probe_api.h"
#include <stdint.h>
/* Per-probe config for the generic tracer: which function and how to print its args.
   fmt has one character per argument (maximum 15):
     x hex   d signed 32-bit int   s ANSI string   W wide string   S sockaddr (IPv4/IPv6 port)
     O OBJECT_ATTRIBUTES (prints its ObjectName, e.g. NtCreateFile's path)
     - skip */
struct trace_config {
    char name[96];
    char fmt[16];
    uint32_t stack;      /* 1 = attach a call stack to each log */
    uint32_t reserved;
};
extern "C" __declspec(dllexport) void uhh_trace_call(probe_context *c);

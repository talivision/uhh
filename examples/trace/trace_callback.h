#pragma once
#include "probe_api.h"
#include <stdint.h>
/* Per-probe config for the generic tracer: which function and how to print its args.
   fmt has one character per argument:
     x hex   d signed int   s ANSI string   W wide string   S sockaddr (IPv4/IPv6 port)
     - skip */
struct trace_config {
    char name[96];
    char fmt[16];
    uint32_t stack;      /* 1 = attach a call stack to each log */
    uint32_t reserved;
};
extern "C" __declspec(dllexport) void uhh_trace_call(probe_context *c);

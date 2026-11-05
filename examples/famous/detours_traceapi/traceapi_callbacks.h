#pragma once
#include "probe_api.h"
#include <stdint.h>
#define DTRACE_EXPORT __declspec(dllexport)

/* Which API a probe sits on: decides how the callback decodes the arguments. */
enum dtrace_kind {
    DTRACE_CREATEFILEW, DTRACE_READFILE, DTRACE_WRITEFILE, DTRACE_CLOSEHANDLE,
    DTRACE_REGOPENKEYEXW, DTRACE_REGQUERYVALUEEXW, DTRACE_CREATEPROCESSINTERNALW,
    DTRACE_LOADLIBRARYW, DTRACE_LOADLIBRARYEXW, DTRACE_KIND_COUNT
};

struct dtrace_config { uint32_t kind; uint32_t stack; };

/* The probe set (Detours' traceapi hooks ~1400 APIs; these are the classic file /
   registry / process / module ones). All on KernelBase: on Windows 10+ kernel32 and
   advapi32 only forward these into KernelBase (or jump there through an import stub),
   so every caller -- whatever DLL or API set it imported from -- is seen exactly once.
   CreateProcessW is traced at CreateProcessInternalW: x64 kernel32!CreateProcessW calls
   that directly and never reaches KernelBase!CreateProcessW. */
struct dtrace_api { const char *location; uint32_t kind; const char *name; };
static const dtrace_api DTRACE_APIS[] = {
    {"KernelBase.dll!CreateFileW",            DTRACE_CREATEFILEW,            "CreateFileW"},
    {"KernelBase.dll!ReadFile",               DTRACE_READFILE,               "ReadFile"},
    {"KernelBase.dll!WriteFile",              DTRACE_WRITEFILE,              "WriteFile"},
    {"KernelBase.dll!CloseHandle",            DTRACE_CLOSEHANDLE,            "CloseHandle"},
    {"KernelBase.dll!RegOpenKeyExW",          DTRACE_REGOPENKEYEXW,          "RegOpenKeyExW"},
    {"KernelBase.dll!RegQueryValueExW",       DTRACE_REGQUERYVALUEEXW,       "RegQueryValueExW"},
    {"KernelBase.dll!CreateProcessInternalW", DTRACE_CREATEPROCESSINTERNALW, "CreateProcessInternalW"},
    {"KernelBase.dll!LoadLibraryW",           DTRACE_LOADLIBRARYW,           "LoadLibraryW"},
    {"KernelBase.dll!LoadLibraryExW",         DTRACE_LOADLIBRARYEXW,         "LoadLibraryExW"},
};

extern "C" DTRACE_EXPORT void dtrace_on_call(probe_context *c);

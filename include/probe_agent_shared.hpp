#pragma once
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <cstdint>
#include <cstdio>

constexpr uint32_t PROBE_AGENT_MAGIC = 0x50424131; // "PBA1"
constexpr uint32_t PROBE_AGENT_VERSION = 1;
constexpr uint32_t PROBE_AGENT_MAX_PROBES = 32;
constexpr uint32_t PROBE_AGENT_EXPORT_CAP = 128;
constexpr uint32_t PROBE_AGENT_CONFIG_CAP = 256;
constexpr uint32_t PROBE_AGENT_LOG_CAP = 512;
constexpr uint32_t PROBE_AGENT_LOG_TEXT_CAP = 160;

enum probe_agent_status : LONG {
    PROBE_AGENT_PENDING = 0,
    PROBE_AGENT_INSTALLING = 1,
    PROBE_AGENT_INSTALLED = 2,
    PROBE_AGENT_BAD_REQUEST = -1,
    PROBE_AGENT_CALLBACK_MISSING = -2,
    PROBE_AGENT_HOOK_FAILED = -3
};

struct probe_agent_request {
    uint64_t site;
    uint32_t flags;
    uint32_t config_len;
    char callback[PROBE_AGENT_EXPORT_CAP];
    unsigned char config[PROBE_AGENT_CONFIG_CAP];
    volatile LONG status;
    LONG reserved;
    volatile LONG64 hits;
};

struct probe_agent_log {
    volatile LONG committed;
    uint32_t probe;
    uint32_t tid;
    char text[PROBE_AGENT_LOG_TEXT_CAP];
};

struct probe_agent_shared {
    uint32_t magic;
    uint32_t version;
    uint32_t request_count;
    uint32_t reserved;
    volatile LONG log_reserve;
    volatile LONG log_dropped;
    probe_agent_request requests[PROBE_AGENT_MAX_PROBES];
    probe_agent_log logs[PROBE_AGENT_LOG_CAP];
};

inline void probe_agent_mapping_name(DWORD pid, wchar_t (&name)[64]) {
    _snwprintf_s(name, _countof(name), _TRUNCATE, L"Local\\probe_api_%lu", pid);
}

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
constexpr uint32_t PROBE_AGENT_VERSION = 3;
constexpr uint32_t PROBE_AGENT_MAX_PROBES = 32;
constexpr uint32_t PROBE_AGENT_EXPORT_CAP = 128;
constexpr uint32_t PROBE_AGENT_CONFIG_CAP = 256;
constexpr uint32_t PROBE_AGENT_LOG_CAP = 4096;      /* ring slots; the controller drains continuously */
constexpr uint32_t PROBE_AGENT_LOG_TEXT_CAP = 256;

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

/* Bounded MPMC ring (Vyukov): slot i starts with seq == i. A producer owns position
   pos when logs[pos % CAP].seq == pos, claims it by CAS on log_head, fills the slot,
   then publishes seq = pos + 1. The single consumer (the controller) reads while
   seq == tail + 1 and frees the slot with seq = tail + CAP. A full ring drops (counted)
   instead of blocking a hooked thread. */
struct probe_agent_log {
    volatile LONG64 seq;
    uint32_t probe;
    uint32_t tid;
    char text[PROBE_AGENT_LOG_TEXT_CAP];
    uint32_t frame_count;          /* 0 = plain log; else frames[] is a stack snapshot */
    uint32_t has_stack;
    uint64_t frames[32];           /* == PROBE_STACK_MAX_FRAMES */
};

/* Agent -> controller control-plane call from an INLINE callback (which runs inside the
   target). The agent fills this on its stack and RaiseException(PROBE_IPC_CODE, ptr); the
   controller (the debugger) gets it first-chance, services it while the thread is stopped,
   writes result, and continues -- a synchronous call, no polling, no extra thread. */
constexpr DWORD PROBE_IPC_CODE = 0xE0554848u;   /* 'UHH' */
enum probe_ipc_op : uint32_t { PROBE_IPC_ADD_ADDRESS = 1, PROBE_IPC_WATCH = 2, PROBE_IPC_ADD_SYMBOL = 3 };
struct probe_ipc_request {
    uint32_t op, flags, origin_site;
    int32_t result;
    uint64_t address;
    char callback[PROBE_AGENT_EXPORT_CAP];
    char symbol[256];
};

struct probe_agent_shared {
    uint32_t magic;
    uint32_t version;
    uint32_t request_count;
    uint32_t reserved;
    volatile LONG64 log_head;      /* next position producers claim */
    volatile LONG64 log_tail;      /* next position the controller consumes */
    volatile LONG log_dropped;
    LONG log_pad;
    probe_agent_request requests[PROBE_AGENT_MAX_PROBES];
    probe_agent_log logs[PROBE_AGENT_LOG_CAP];
};

inline void probe_agent_mapping_name(DWORD pid, wchar_t (&name)[64]) {
    _snwprintf_s(name, _countof(name), _TRUNCATE, L"Local\\probe_api_%lu", pid);
}

// Library-private layout of the opaque probe_context (controller + agent share it).
#pragma once
#include "probe_api.h"

#define PROBE_STACK_MAX_FRAMES 32

typedef struct probe_regs {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15, pc, flags;
} probe_regs;
typedef struct probe_ops {
    int (*read)(void *, uint64_t, void *, size_t, size_t *);
    int (*write)(void *, uint64_t, const void *, size_t, size_t *);
} probe_ops;
struct probe_context {
    void *config;
    probe_regs regs;
    const probe_ops *ops;
    void *backend;
    void *controller;
    uint32_t tid, site;
};

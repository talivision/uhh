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
/* The controller's implementation of the callback API. A callback that uses UHH_SHARED
   state runs, for breakpoint/hw probes, from the CONTROLLER's copy of the agent DLL; that
   copy's API entry points forward here (the agent DLL's own implementations are for code
   running inside the target). Set once per process by probe_agent_bind_controller. */
#include <stdarg.h>
typedef struct probe_controller_api {
    uint64_t (*get_reg)(probe_context *, enum probe_register);
    int (*set_reg)(probe_context *, enum probe_register, uint64_t);
    uint64_t (*get_func_arg)(probe_context *, size_t);
    int (*get_mem)(probe_context *, uint64_t, void *, size_t);
    int (*set_mem)(probe_context *, uint64_t, const void *, size_t);
    void (*vlog)(probe_context *, int stack, const char *, va_list);
    const void *(*get_config)(probe_context *);
    int (*call_func_args)(probe_context *, const char *, uint64_t *, int, const uint64_t *);
    probe_session *(*get_session)(probe_context *);
    int (*add_address)(probe_session *, uint64_t, probe_callback, uint32_t);
    int (*watch)(probe_session *, uint64_t, probe_callback, uint32_t);
    int (*add_symbol)(probe_session *, const char *, probe_callback, uint32_t);
    int (*add_symbol_cfg)(probe_session *, const char *, probe_callback, uint32_t, const void *, size_t);
    int (*call_original)(probe_context *, int, uint64_t *);
    void (*return_from)(probe_context *, uint64_t, int);
} probe_controller_api;
struct probe_context {
    void *config;
    probe_regs regs;
    const probe_ops *ops;
    void *backend;
    void *controller;
    uint32_t tid, site;
    /* call_original / return_from (per hit): the hit's own stack pointer (return_from
       resumes there, at a `ret`/`ret N` gadget), whether the original already ran, and
       whether the callback asked to return. */
    uint64_t hit_sp;
    uint32_t ret_pop;                 /* x86: bytes the callee pops (nargs * 4) */
    uint8_t called_original, returned;
};

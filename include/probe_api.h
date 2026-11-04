#ifndef PROBE_API_H
#define PROBE_API_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct probe_session probe_session;
typedef struct probe_context probe_context;
typedef void (*probe_callback)(probe_context *);

enum probe_flags {
    PROBE_BREAKPOINT      = 1u << 0,
    PROBE_INLINE          = 1u << 1,
    PROBE_HW              = 1u << 2,
    PROBE_AT_RETURN       = 1u << 3,
    PROBE_ALLOW_PREHOOKED = 1u << 4,
    PROBE_FALLBACK_HW     = 1u << 5,
    /* Hardware DATA watchpoints (PROBE_HW only): the callback fires when the probed
       ADDRESS is written (or read+written). No code is modified and no execution is
       hooked -- this observes DATA access, which inline/trampoline hooking cannot do.
       The address is a data location (module+RVA of a variable) aligned to the word
       size. Exactly one of WRITE/RW; absent = an ordinary execute breakpoint. */
    PROBE_WATCH_WRITE     = 1u << 6,
    PROBE_WATCH_RW        = 1u << 7
};

/* AX is the 32-bit EAX view: writes zero-extend into RAX. Other IDs expose the
   full x64 register named by the corresponding CONTEXT member. */
enum probe_register {
    PROBE_REG_AX,
    PROBE_REG_BX,
    PROBE_REG_CX,
    PROBE_REG_DX,
    PROBE_REG_SI,
    PROBE_REG_DI,
    PROBE_REG_BP,
    PROBE_REG_SP,
    PROBE_REG_R8,
    PROBE_REG_R9,
    PROBE_REG_R10,
    PROBE_REG_R11,
    PROBE_REG_R12,
    PROBE_REG_R13,
    PROBE_REG_R14,
    PROBE_REG_R15
};

/* Controller-private fields remain visible so the C context has a fixed ABI.
   Callbacks use the accessors below; config is the one public data member. */
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

probe_session *probe_session_create(void);
int probe_add(probe_session *, const char *location, probe_callback, uint32_t flags);
int probe_add_cfg(probe_session *, const char *location, probe_callback, uint32_t flags,
                  const void *config, size_t config_len);
int probe_launch(probe_session *, char *const argv[]);
int probe_run(probe_session *);
int probe_wait_for_exit(probe_session *);
void probe_report(probe_session *, FILE *);
void probe_close(probe_session *);

uint64_t probe_reg(probe_context *, enum probe_register);
int probe_set_reg(probe_context *, enum probe_register, uint64_t value);
int probe_read(probe_context *, uint64_t address, void *buffer, size_t size);
int probe_write(probe_context *, uint64_t address, const void *buffer, size_t size);
uint64_t probe_arg(probe_context *, size_t index);
uint64_t probe_retval(probe_context *);
void probe_log(probe_context *, const char *format, ...);

#define PROBE_LOG(c, ...) probe_log((c), __VA_ARGS__)

#ifdef __cplusplus
}
#endif
#endif

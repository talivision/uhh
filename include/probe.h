#ifndef PROBE_H
#define PROBE_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* First ABI: Windows x64 integer state only. PC/SP are observational. */
typedef struct probe_regs {
    uint64_t rax, rbx, rcx, rdx, rsi, rdi, rbp, rsp;
    uint64_t r8, r9, r10, r11, r12, r13, r14, r15, pc, flags;
} probe_regs;
typedef struct probe_context probe_context;
typedef struct probe_ops {
    int (*read)(void *, uint64_t, void *, size_t, size_t *);
    int (*write)(void *, uint64_t, const void *, size_t, size_t *);
} probe_ops;
struct probe_context {
    probe_regs regs;
    const probe_ops *ops;
    void *backend;
    uint32_t tid, site;
};
enum { PROBE_FLAG = 1, PROBE_READ = 2 };
enum { CALLBACK_NOOP, CALLBACK_FILTER, CALLBACK_MUTATE, CALLBACK_LOG };
enum { MUTATE_REGISTER, MUTATE_MEMORY };
#define PROBE_RECORD_CAPACITY 8192
/* Records describe attempted reads, not completion. */
typedef struct probe_record { uint64_t handle, address, size, sequence; } probe_record;
typedef struct probe_config {
    uint64_t selected_handle, range_start, range_size;
    uint32_t callback_kind, mutation;
} probe_config;
typedef struct probe_stats {
    uint64_t flag_hits, read_hits, matches, errors, recorded, dropped;
    probe_record records[PROBE_RECORD_CAPACITY];
} probe_stats;
static inline int probe_read(probe_context *c, uint64_t a, void *b, size_t n) {
    size_t done = 0;
    return c->ops->read(c->backend, a, b, n, &done) && done == n;
}
static inline int probe_write(probe_context *c, uint64_t a, const void *b, size_t n) {
    size_t done = 0;
    return c->ops->write(c->backend, a, b, n, &done) && done == n;
}
/* Same C source is linked into controller and agent DLL. Single-thread prototype. */
void example_callback(probe_context *, const probe_config *, probe_stats *);
#ifdef __cplusplus
}
#endif
#endif

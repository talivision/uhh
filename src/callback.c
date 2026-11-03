#include "probe.h"
static void record(probe_stats *s, uint64_t handle, uint64_t address,
                   uint64_t size, uint64_t sequence) {
    if (s->recorded == PROBE_RECORD_CAPACITY) { ++s->dropped; return; }
    probe_record *r = &s->records[s->recorded++];
    r->handle = handle; r->address = address; r->size = size; r->sequence = sequence;
}
void example_callback(probe_context *c, const probe_config *cfg, probe_stats *s) {
    if (c->site == PROBE_FLAG) {
        ++s->flag_hits;
        if (cfg->callback_kind == CALLBACK_MUTATE) {
            uint32_t flag;
            if (!probe_read(c, c->regs.rcx, &flag, sizeof(flag)) || flag != 0) {
                ++s->errors; return;
            }
            flag = 1;
            if (cfg->mutation == MUTATE_MEMORY) {
                if (!probe_write(c, c->regs.rcx, &flag, sizeof(flag))) ++s->errors;
            } else c->regs.rax = flag;
        } else if (cfg->callback_kind == CALLBACK_FILTER || cfg->callback_kind == CALLBACK_LOG) {
            if (c->regs.rdx % 100 == 0) {
                ++s->matches;
                if (cfg->callback_kind == CALLBACK_LOG)
                    record(s, 0, c->regs.pc, c->regs.rax, c->regs.rdx);
            }
        }
    } else if (c->site == PROBE_READ) {
        ++s->read_hits;
        if (cfg->callback_kind == CALLBACK_NOOP) return;
        /* Complete containment; subtraction avoids range-end overflow. */
        uint64_t address = c->regs.rdx, size = c->regs.r9;
        if (c->regs.rcx != cfg->selected_handle || address < cfg->range_start) return;
        uint64_t offset = address - cfg->range_start;
        if (offset > cfg->range_size || size > cfg->range_size - offset) return;
        ++s->matches;
        if (cfg->callback_kind == CALLBACK_LOG || cfg->callback_kind == CALLBACK_MUTATE)
            record(s, c->regs.rcx, address, size, s->read_hits - 1);
    }
}

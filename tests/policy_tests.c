#include "probe.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define CHECK(x) do { if (!(x)) {fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#x); exit(1);} } while(0)
static unsigned char memory[16];
static int rd(void *unused,uint64_t a,void *b,size_t n,size_t *done) {
    (void)unused; *done=0;
    if (a<0x1000 || a-0x1000>sizeof(memory) || n>sizeof(memory)-(size_t)(a-0x1000)) return 0;
    memcpy(b,memory+(size_t)(a-0x1000),n); *done=n; return 1;
}
static int wr(void *unused,uint64_t a,const void *b,size_t n,size_t *done) {
    (void)unused; *done=0;
    if (a<0x1000 || a-0x1000>sizeof(memory) || n>sizeof(memory)-(size_t)(a-0x1000)) return 0;
    memcpy(memory+(size_t)(a-0x1000),b,n); *done=n; return 1;
}
static probe_stats stats;
int main(void) {
    probe_ops ops={rd,wr}; probe_context c={0}; c.ops=&ops; c.site=PROBE_FLAG; c.regs.rcx=0x1000;
    probe_config cfg={0}; cfg.callback_kind=CALLBACK_MUTATE; cfg.mutation=MUTATE_REGISTER;
    example_callback(&c,&cfg,&stats); CHECK(c.regs.rax==1 && stats.errors==0 && memory[0]==0);
    cfg.mutation=MUTATE_MEMORY; example_callback(&c,&cfg,&stats); CHECK(memory[0]==1);
    c.regs.rcx=0x9999; example_callback(&c,&cfg,&stats); CHECK(stats.errors==1);
    memset(&stats,0,sizeof(stats)); c.site=PROBE_READ;
    cfg.callback_kind=CALLBACK_LOG; cfg.selected_handle=7; cfg.range_start=0x2000; cfg.range_size=32;
    c.regs.rcx=7; c.regs.rdx=0x2000; c.regs.r9=16;
    example_callback(&c,&cfg,&stats); CHECK(stats.matches==1 && stats.recorded==1);
    c.regs.rcx=8; example_callback(&c,&cfg,&stats); CHECK(stats.matches==1);
    c.regs.rcx=7; c.regs.rdx=0x1fff; example_callback(&c,&cfg,&stats); CHECK(stats.matches==1);
    c.regs.rdx=0x2018; example_callback(&c,&cfg,&stats); CHECK(stats.matches==1);
    c.regs.rdx=0x2010; example_callback(&c,&cfg,&stats); CHECK(stats.matches==2);
    c.regs.r9=UINT64_MAX; example_callback(&c,&cfg,&stats); CHECK(stats.matches==2);
    c.regs.r9=16; c.regs.rdx=0x2000;
    for(size_t i=0;i<PROBE_RECORD_CAPACITY;++i) example_callback(&c,&cfg,&stats);
    CHECK(stats.recorded==PROBE_RECORD_CAPACITY && stats.dropped==2);
    memset(&stats,0,sizeof(stats)); cfg.callback_kind=CALLBACK_NOOP;
    example_callback(&c,&cfg,&stats); CHECK(stats.read_hits==1 && stats.matches==0);
    puts("PASS: register mutation, memory mutation, invalid access, handle/range filters, overflow, bounded logs, noop");
    return 0;
}

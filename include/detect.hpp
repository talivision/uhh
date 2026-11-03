#pragma once
#include "probe.h"
#include <cstdio>
#include <cstring>
/* Observation only: common entry redirections, not universal hook detection.
   The fixture's clean sites have 16 NOPs. Unknown bytes are not declared clean. */
inline const char *classify_entry(const unsigned char *b) {
    if (b[0]==0xe9) return "relative-jump";
    if (b[0]==0xeb) return "short-jump";
    if (b[0]==0xff && b[1]==0x25) return "indirect-jump";
    if (b[0]==0x48 && b[1]==0xb8 && b[10]==0xff && b[11]==0xe0) return "movabs-jump";
    for (unsigned i=0;i<16;++i) if (b[i]!=0x90) return "unknown";
    return "fixture-clean";
}
inline bool report_entry(const probe_ops *ops,void *backend,uint64_t address,const char *name) {
    unsigned char b[16]; size_t done=0;
    if (!ops->read(backend,address,b,sizeof(b),&done) || done!=sizeof(b)) return false;
    std::fprintf(stderr,"probe: %s @ 0x%llx: %s; bytes=",name,(unsigned long long)address,classify_entry(b));
    if (std::strcmp(classify_entry(b),"fixture-clean") && std::strcmp(classify_entry(b),"unknown"))
        std::fprintf(stderr,"[pre-existing redirect detected] ");
    for (auto v:b) std::fprintf(stderr,"%02x",v);
    std::fputc('\n',stderr); return true;
}

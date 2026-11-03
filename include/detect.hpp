#pragma once
#include "probe.h"
#include "pe_image.hpp"
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
// Compare the live bytes at a probe site against the clean on-disk image. Any
// difference (for a site with no relocations) means code was modified before we
// arrived: a pre-existing hook. Logs to stderr. `modified` is set when the bytes
// differ and both reads succeeded; returns false only if a read failed.
inline bool compare_to_disk(const probe_ops *ops, void *backend, uint64_t address,
                            const std::string &module_path, uint32_t rva,
                            const char *name, bool &modified) {
    modified = false;
    unsigned char live[16]{}, disk[16]{}; size_t done = 0;
    if (!ops->read(backend, address, live, sizeof(live), &done) || done != sizeof(live)) {
        std::fprintf(stderr, "probe: %s @ 0x%llx: cannot read live bytes\n", name, (unsigned long long)address);
        return false;
    }
    DiskImage img;
    if (!img.load(module_path) || !img.read_rva(rva, disk, sizeof(disk))) {
        std::fprintf(stderr, "probe: %s @ 0x%llx: cannot read on-disk image %s+0x%x\n",
                     name, (unsigned long long)address, module_path.c_str(), rva);
        return false;
    }
    modified = std::memcmp(live, disk, sizeof(live)) != 0;
    std::fprintf(stderr, "probe: %s @ 0x%llx %s on-disk %s+0x%x; mem=",
                 name, (unsigned long long)address,
                 modified ? "PRE-EXISTING HOOK (differs from)" : "matches",
                 module_path.c_str(), rva);
    for (auto v : live) std::fprintf(stderr, "%02x", v);
    if (modified) {
        std::fprintf(stderr, " disk="); for (auto v : disk) std::fprintf(stderr, "%02x", v);
        std::fprintf(stderr, " classify=%s", classify_entry(live));
    }
    std::fputc('\n', stderr);
    return true;
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

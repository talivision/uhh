// Site analysis: pre-hook detection, inline patch length, entry points near a site,
// instruction boundaries, site vetting.
#include "session_internal.hpp"

// ---- Foreign-hook ("pre-hooked site") detection -------------------------------------
// Compare the live bytes at a probe site with the same RVA in the module's file on disk
// (bytes covered by base relocations are ignored: they legitimately differ). If they
// differ, someone patched the site: report both byte strings disassembled, the hook
// pattern and where it leads, and weakly suggest alternative probe points.
std::string hex_bytes(const unsigned char *b, size_t n) {
    std::string r; char t[4];
    for (size_t i = 0; i < n; ++i) { std::snprintf(t, sizeof(t), i ? " %02x" : "%02x", b[i]); r += t; }
    return r;
}

void zydis_init(ZydisDecoder &dec) {
#if defined(_WIN64)
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#endif
}

static std::vector<std::string> disasm(const unsigned char *b, size_t n, uint64_t at, size_t max_insns) {
    std::vector<std::string> out;
    ZydisDecoder dec; zydis_init(dec);
    ZydisFormatter fmt; ZydisFormatterInit(&fmt, ZYDIS_FORMATTER_STYLE_INTEL);
    size_t off = 0;
    while (off < n && out.size() < max_insns) {
        ZydisDecodedInstruction insn; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, b + off, n - off, &insn, ops))) { out.push_back("(undecodable)"); break; }
        char text[96];
        if (!ZYAN_SUCCESS(ZydisFormatterFormatInstruction(&fmt, &insn, ops, insn.operand_count_visible, text,
                                                          sizeof(text), at + off, nullptr))) std::snprintf(text, sizeof(text), "?");
        char line[160];
        std::snprintf(line, sizeof(line), "+%zu: %-24s %s", off, hex_bytes(b + off, insn.length).c_str(), text);
        out.emplace_back(line);
        off += insn.length;
    }
    return out;
}

struct DiskImage {          // just enough of the PE file to map RVAs and find relocations
    std::vector<IMAGE_SECTION_HEADER> sections;
    IMAGE_DATA_DIRECTORY reloc{};
    HANDLE file = INVALID_HANDLE_VALUE;
    ~DiskImage() { if (file != INVALID_HANDLE_VALUE) CloseHandle(file); }
    bool read_at(uint64_t off, void *buf, size_t n) const {
        LARGE_INTEGER li; li.QuadPart = (LONGLONG)off; DWORD got = 0;
        return SetFilePointerEx(file, li, nullptr, FILE_BEGIN) && ReadFile(file, buf, (DWORD)n, &got, nullptr) && got == n;
    }
    bool rva_to_off(uint32_t rva, size_t n, uint64_t &off) const {
        for (auto &sec : sections) {
            uint32_t size = sec.SizeOfRawData;
            if (rva >= sec.VirtualAddress && (uint64_t)rva + n <= (uint64_t)sec.VirtualAddress + size) {
                off = (uint64_t)sec.PointerToRawData + (rva - sec.VirtualAddress); return true;
            }
        }
        return false;
    }
    bool open(const std::string &path) {
        file = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, 0, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;
        IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS nt{};
        if (!read_at(0, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
        if (!read_at((uint32_t)dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE) return false;
        uint32_t count = nt.FileHeader.NumberOfSections;
        if (count > 96) return false;
        sections.resize(count);
        uint64_t sec_off = (uint32_t)dos.e_lfanew + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;
        if (count && !read_at(sec_off, sections.data(), count * sizeof(IMAGE_SECTION_HEADER))) return false;
        reloc = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
        return true;
    }
    // Mark bytes of [rva, rva+n) that a base relocation rewrites at load time.
    void reloc_mask(uint32_t rva, size_t n, std::vector<bool> &mask) const {
        mask.assign(n, false);
        if (!reloc.VirtualAddress || !reloc.Size || reloc.Size > (16u << 20)) return;
        uint64_t off = 0;
        if (!rva_to_off(reloc.VirtualAddress, reloc.Size, off)) return;
        std::vector<unsigned char> blob(reloc.Size);
        if (!read_at(off, blob.data(), blob.size())) return;
        size_t at = 0;
        while (at + sizeof(IMAGE_BASE_RELOCATION) <= blob.size()) {
            auto *blk = reinterpret_cast<const IMAGE_BASE_RELOCATION *>(blob.data() + at);
            if (blk->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || at + blk->SizeOfBlock > blob.size()) break;
            size_t entries = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / 2;
            auto *e = reinterpret_cast<const WORD *>(blk + 1);
            for (size_t i = 0; i < entries; ++i) {
                int type = e[i] >> 12; uint32_t where = blk->VirtualAddress + (e[i] & 0xfff);
                size_t width = type == IMAGE_REL_BASED_DIR64 ? 8 : type == IMAGE_REL_BASED_HIGHLOW ? 4 : 0;
                for (size_t k = 0; k < width; ++k) {
                    uint64_t b = (uint64_t)where + k;
                    if (b >= rva && b < (uint64_t)rva + n) mask[(size_t)(b - rva)] = true;
                }
            }
            at += blk->SizeOfBlock;
        }
    }
};

// Returns true when the site is modified relative to disk; fills a JSON report and
// prints a readable one. Sites in modules we have no file for are not judged.
static bool detect_prehook(probe_session *s, const Probe &p, std::string &json) {
    if (p.module.empty() || !p.address || p.address < p.base) return false;
    std::string path;
    for (auto &kv : s->module_paths) if (iequals(kv.first, p.module)) { path = kv.second; break; }
    if (trace_enabled()) std::fprintf(stderr, "  prehook-check %s path=%s\n", p.location.c_str(), path.c_str());
    if (path.empty()) return false;
    constexpr size_t N = 24;
    unsigned char live[N]{}, disk[N]{}; size_t got = 0;
    if (!remote_read(s->pi.hProcess, p.address, live, N, &got) || got != N) return false;
    DiskImage img; uint64_t off = 0;
    uint32_t rva = (uint32_t)(p.address - p.base);
    if (!img.open(path) || !img.rva_to_off(rva, N, off) || !img.read_at(off, disk, N)) return false;
    std::vector<bool> mask; img.reloc_mask(rva, N, mask);
    // Our own INT3 (a breakpoint probe on the same site) is not a foreign hook.
    size_t first = N, last = 0;
    for (size_t i = 0; i < 16; ++i) {
        if (mask[i] || live[i] == disk[i]) continue;
        if (i == 0 && live[0] == 0xcc) { Probe *own = probe_at(s, p.address); if (own && own != &p && !(own->flags & PROBE_INLINE)) continue; }
        if (first == N) first = i;
        last = i;
    }
    if (first == N) return false;
    size_t patched = last + 1;
    // Pattern + destination from the live bytes.
    ZydisDecoder dec; zydis_init(dec);
    ZydisDecodedInstruction insn; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    std::string pattern = "unknown modification"; uint64_t dest = 0;
    if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, live, N, &insn, ops))) {
        if (insn.mnemonic == ZYDIS_MNEMONIC_JMP && insn.operand_count_visible >= 1) {
            ZyanU64 target = 0;
            if (ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[0], p.address, &target))) {
                pattern = insn.length == 2 ? "jmp rel8" : "jmp rel32 (5-byte detour)"; dest = target;
            } else if (ops[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                       ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&insn, &ops[0], p.address, &target))) {
                uint64_t ptr = 0; size_t w = sizeof(void *);
                if (remote_read(s->pi.hProcess, target, &ptr, w, &got) && got == w) dest = ptr;
                pattern = "jmp [mem] (indirect detour)";
            }
        } else if (insn.mnemonic == ZYDIS_MNEMONIC_INT3) {
            pattern = "int3 (another debugger/instrumenter's breakpoint)";
        } else if (insn.mnemonic == ZYDIS_MNEMONIC_PUSH && ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
                   live[insn.length] == 0xc3) {
            pattern = "push imm; ret (detour)"; dest = (uint32_t)ops[0].imm.value.u;
        } else if (insn.mnemonic == ZYDIS_MNEMONIC_MOV && ops[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                   ops[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            ZydisDecodedInstruction j; ZydisDecodedOperand jo[ZYDIS_MAX_OPERAND_COUNT];
            if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, live + insn.length, N - insn.length, &j, jo)) &&
                j.mnemonic == ZYDIS_MNEMONIC_JMP && jo[0].type == ZYDIS_OPERAND_TYPE_REGISTER) {
                pattern = "mov reg, imm; jmp reg (absolute detour)"; dest = ops[1].imm.value.u;
                patched = (std::max)(patched, (size_t)insn.length + j.length);
            }
        }
    }
    // Follow the jump chain (hooking libraries usually jump to a small relay stub that
    // jumps on to the replacement): up to 4 hops through jmp rel/[mem]/reg-imm, stopping
    // at the first address inside a loaded module, which is what the user can act on.
    std::vector<uint64_t> hops;
    for (int hop = 0; dest && hop < 4; ++hop) {
        bool in_module = false;
        for (auto &kv : s->module_bases) {
            IMAGE_DOS_HEADER d{}; IMAGE_NT_HEADERS n{}; size_t g = 0;
            if (dest < kv.second) continue;
            if (remote_read(s->pi.hProcess, kv.second, &d, sizeof(d), &g) && g == sizeof(d) &&
                remote_read(s->pi.hProcess, kv.second + (uint32_t)d.e_lfanew, &n, sizeof(n), &g) && g == sizeof(n) &&
                dest < kv.second + n.OptionalHeader.SizeOfImage) { in_module = true; break; }
        }
        if (in_module) break;
        unsigned char code[24]{};
        if (!remote_read(s->pi.hProcess, dest, code, sizeof(code), &got) || got != sizeof(code)) break;
        ZydisDecodedInstruction ji; ZydisDecodedOperand jo[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code, sizeof(code), &ji, jo))) break;
        uint64_t next = 0; ZyanU64 t = 0;
        if (ji.mnemonic == ZYDIS_MNEMONIC_JMP && jo[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE &&
            ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ji, &jo[0], dest, &t))) next = t;
        else if (ji.mnemonic == ZYDIS_MNEMONIC_JMP && jo[0].type == ZYDIS_OPERAND_TYPE_MEMORY &&
                 ZYAN_SUCCESS(ZydisCalcAbsoluteAddress(&ji, &jo[0], dest, &t))) {
            uint64_t ptr = 0;
            if (remote_read(s->pi.hProcess, t, &ptr, sizeof(void *), &got) && got == sizeof(void *)) next = ptr;
        } else if (ji.mnemonic == ZYDIS_MNEMONIC_MOV && jo[0].type == ZYDIS_OPERAND_TYPE_REGISTER &&
                   jo[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
            ZydisDecodedInstruction j2; ZydisDecodedOperand o2[ZYDIS_MAX_OPERAND_COUNT];
            if (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code + ji.length, sizeof(code) - ji.length, &j2, o2)) &&
                j2.mnemonic == ZYDIS_MNEMONIC_JMP && o2[0].type == ZYDIS_OPERAND_TYPE_REGISTER) next = jo[1].imm.value.u;
        }
        if (!next || next == dest) break;
        hops.push_back(dest);
        dest = next;
    }
    // First unmodified instruction boundary in the ORIGINAL code at/after the patch.
    size_t resume = 0;
    while (resume < patched && resume < N) {
        ZydisDecodedInstruction d; ZydisDecodedOperand dops[ZYDIS_MAX_OPERAND_COUNT];
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, disk + resume, N - resume, &d, dops))) { resume = 0; break; }
        resume += d.length;
    }
    auto live_d = disasm(live, (std::max)(patched, (size_t)8), p.address, 4);
    auto disk_d = disasm(disk, resume ? resume : 8, p.address, 4);
    std::string dest_s = dest ? symbolize(s, dest) : std::string();
    std::string via;
    for (uint64_t h : hops) { char b[32]; std::snprintf(b, sizeof(b), "%s0x%llx", via.empty() ? "" : " -> ", (unsigned long long)h); via += b; }
    std::vector<std::string> suggest;
    char line[256];
    std::snprintf(line, sizeof(line), "PROBE_HW at %s (debug register; modifies no code, coexists with the existing hook)", p.location.c_str());
    suggest.emplace_back(line);
    if (dest) {
        std::snprintf(line, sizeof(line), "probe the detour target %s (runs before the other hook's logic)", dest_s.c_str());
        suggest.emplace_back(line);
    }
    if (resume && resume < N) {
        std::snprintf(line, sizeof(line), "%s+0x%x: first unmodified original instruction; usually reached when the existing hook resumes the original code",
                      p.module.c_str(), rva + (uint32_t)resume);
        suggest.emplace_back(line);
    }
    // Human-readable report.
    std::fprintf(stderr, "probe: PRE-HOOKED SITE %s (0x%llx): %zu byte(s) differ from %s\n",
                 p.location.c_str(), (unsigned long long)p.address, patched, path.c_str());
    std::fprintf(stderr, "probe:   pattern: %s%s%s%s%s\n", pattern.c_str(), dest ? " -> " : "", dest_s.c_str(),
                 via.empty() ? "" : "  (via ", via.empty() ? "" : (via + ")").c_str());
    std::fprintf(stderr, "probe:   live (in memory):\n");
    for (auto &l : live_d) std::fprintf(stderr, "probe:     %s\n", l.c_str());
    std::fprintf(stderr, "probe:   original (on disk):\n");
    for (auto &l : disk_d) std::fprintf(stderr, "probe:     %s\n", l.c_str());
    std::fprintf(stderr, "probe:   you could instead (suggestions, not verified):\n");
    for (auto &l : suggest) std::fprintf(stderr, "probe:     - %s\n", l.c_str());
    // JSON for the report.
    auto q = [](const std::string &v) {
        std::string r = "\"";
        for (char ch : v) { if (ch == '"' || ch == '\\') r += '\\'; if ((unsigned char)ch >= 0x20) r += ch; }
        return r + "\"";
    };
    auto arr = [&](const std::vector<std::string> &v) {
        std::string r = "["; for (size_t i = 0; i < v.size(); ++i) { if (i) r += ","; r += q(v[i]); } return r + "]";
    };
    char addr[32]; std::snprintf(addr, sizeof(addr), "0x%llx", (unsigned long long)p.address);
    json = std::string("{\"kind\":\"prehook\",\"location\":") + q(p.location) + ",\"address\":" + q(addr) +
           ",\"patched_bytes\":" + std::to_string(patched) + ",\"pattern\":" + q(pattern) +
           ",\"destination\":" + (dest ? q(dest_s) : std::string("null")) +
           ",\"via\":" + q(via) +
           ",\"live\":" + q(hex_bytes(live, (std::max)(patched, (size_t)8))) + ",\"original\":" + q(hex_bytes(disk, (std::max)(patched, (size_t)8))) +
           ",\"live_disasm\":" + arr(live_d) + ",\"original_disasm\":" + arr(disk_d) + ",\"suggest\":" + arr(suggest) + "}";
    return true;
}

// Decide what to do with a pre-hooked site for a code-modifying probe. Inline probes are
// refused by default (installing over an unknown detour chains through code we did not
// inspect); PROBE_ALLOW_PREHOOKED chains anyway, PROBE_FALLBACK_HW moves the probe to a
// debug register. Breakpoint probes still work (the jmp is stepped in place): report only.
// Returns false when the probe must not be armed; sets moved_to_hw when converted.
// An inline hook replaces the first instructions at the site (>= 5 bytes) with a jump.
// That is only safe if nothing else can arrive INSIDE those bytes later:
//  1. a CALL among them that is not the last one: a thread inside the callee when the
//     hook is written returns into the middle of the jump (no freeze can fix a return
//     address on a stack);
//  2. another exported function starting inside them (a probe on a function's final
//     `ret` overwrites its neighbour: e.g. the next ntdll syscall stub on x86);
//  3. a branch elsewhere in the same function landing inside them (x64: the function's
//     bounds come from .pdata; e.g. a syscall stub's `jne` into its `int 2e; ret` tail);
//  4. an exit (ret/jmp) followed, still inside them, by anything but padding: that code
//     is reachable only by a jump (the same stub tail, even without .pdata).
// Such sites go to the hardware backend with PROBE_FALLBACK_HW, else are refused.
static uint32_t inline_patch_len(const unsigned char *b, size_t n, int64_t *call_end, bool *code_after_exit,
                                 size_t *exit_at = nullptr) {
    ZydisDecoder dec;
#if defined(_WIN64)
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#endif
    size_t off = 0; *call_end = -1; *code_after_exit = false;
    bool exited = false;
    while (off < 5) {
        ZydisDecodedInstruction insn{};
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&dec, nullptr, b + off, n - off, &insn))) return 0;
        off += insn.length;
        if (exited && insn.mnemonic != ZYDIS_MNEMONIC_NOP && insn.mnemonic != ZYDIS_MNEMONIC_INT3)
            *code_after_exit = true;                   // reachable only by a jump into the patch
        if (insn.meta.category == ZYDIS_CATEGORY_CALL) *call_end = (int64_t)off;
        if (!exited && (insn.meta.category == ZYDIS_CATEGORY_RET || insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                        insn.mnemonic == ZYDIS_MNEMONIC_INT3 || insn.mnemonic == ZYDIS_MNEMONIC_UD2)) {
            exited = true;
            if (exit_at) *exit_at = off - insn.length;
        }
    }
    return (uint32_t)off;
}

static bool read_image_dir(probe_session *s, uint64_t base, int which, IMAGE_DATA_DIRECTORY &dir,
                           uint32_t *size_of_image = nullptr) {
    IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS nt{}; size_t got = 0;
    if (!remote_read(s->pi.hProcess, base, &dos, sizeof(dos), &got) || got != sizeof(dos) || dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (!remote_read(s->pi.hProcess, base + (uint32_t)dos.e_lfanew, &nt, sizeof(nt), &got) || got != sizeof(nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE || nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) return false;
    if (size_of_image) *size_of_image = nt.OptionalHeader.SizeOfImage;
    dir = nt.OptionalHeader.DataDirectory[which];
    return dir.VirtualAddress && dir.Size;
}

// ---- Entry points near an inline site --------------------------------------------------
// Every address control can ARRIVE at (other than by falling through): function starts
// from every source we have, plus -- inside the function that holds the site -- branch
// targets, return points after calls, and switch-table targets. Over-collecting is the
// safe direction: an extra entry point can only make a hook refuse, never clobber code.
struct SiteAnalysis {
    uint64_t func_start = 0, func_end = 0;      // 0/0: function bounds unknown
    const char *bounds_from = "none";
    std::vector<uint64_t> insns;                // instruction starts in the function (linear)
    std::set<uint64_t> entries;                 // entry points (absolute)
    int tables = 0;                             // switch tables recovered
    std::vector<uint64_t> indirect_jumps;       // jmp reg / jmp [reg...]: targets unknown unless a table explains them
};

static void add_export_starts(probe_session *s, uint64_t base, std::set<uint64_t> &out) {
    IMAGE_DATA_DIRECTORY dir{};
    if (!read_image_dir(s, base, IMAGE_DIRECTORY_ENTRY_EXPORT, dir) || dir.Size < sizeof(IMAGE_EXPORT_DIRECTORY)) return;
    IMAGE_EXPORT_DIRECTORY ex{}; size_t got = 0;
    if (!remote_read(s->pi.hProcess, base + dir.VirtualAddress, &ex, sizeof(ex), &got) || got != sizeof(ex)) return;
    if (!ex.NumberOfFunctions || ex.NumberOfFunctions > (1u << 20)) return;
    std::vector<DWORD> funcs(ex.NumberOfFunctions);
    if (!remote_read(s->pi.hProcess, base + ex.AddressOfFunctions, funcs.data(), funcs.size() * 4, &got) || got != funcs.size() * 4) return;
    for (DWORD r : funcs)
        if (r && !(r >= dir.VirtualAddress && r < dir.VirtualAddress + dir.Size)) out.insert(base + r);   // skip forwarders
}

// Control Flow Guard: every address-taken function (static ones included).
static void add_cfg_starts(probe_session *s, uint64_t base, std::set<uint64_t> &out) {
    IMAGE_DATA_DIRECTORY dir{};
    if (!read_image_dir(s, base, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, dir)) return;
#if defined(_WIN64)
    IMAGE_LOAD_CONFIG_DIRECTORY64 lc{};
#else
    IMAGE_LOAD_CONFIG_DIRECTORY32 lc{};
#endif
    size_t got = 0, want = (std::min)((size_t)dir.Size, sizeof(lc));
    if (!remote_read(s->pi.hProcess, base + dir.VirtualAddress, &lc, want, &got) || got != want) return;
    if (lc.Size < offsetof(decltype(lc), GuardFlags) + sizeof(lc.GuardFlags)) return;
    if (!lc.GuardCFFunctionTable || !lc.GuardCFFunctionCount || lc.GuardCFFunctionCount > (1u << 22)) return;
    const size_t stride = 4 + ((lc.GuardFlags & IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_MASK) >> IMAGE_GUARD_CF_FUNCTION_TABLE_SIZE_SHIFT);
    std::vector<unsigned char> t((size_t)lc.GuardCFFunctionCount * stride);
    if (!remote_read(s->pi.hProcess, (uint64_t)lc.GuardCFFunctionTable, t.data(), t.size(), &got) || got != t.size()) return;
    for (size_t i = 0; i < (size_t)lc.GuardCFFunctionCount; ++i) {
        DWORD rva; std::memcpy(&rva, t.data() + i * stride, 4); out.insert(base + rva);
    }
}

#if defined(_WIN64)
// x64 .pdata: the start of every non-leaf function; also the bounds of the site's own.
static void add_pdata(probe_session *s, uint64_t base, uint64_t site, std::set<uint64_t> &out,
                      uint64_t &fs, uint64_t &fe) {
    IMAGE_DATA_DIRECTORY dir{};
    if (!read_image_dir(s, base, IMAGE_DIRECTORY_ENTRY_EXCEPTION, dir)) return;
    const size_t count = dir.Size / sizeof(RUNTIME_FUNCTION);
    if (!count || count > (1u << 22)) return;
    std::vector<RUNTIME_FUNCTION> rf(count); size_t got = 0;
    if (!remote_read(s->pi.hProcess, base + dir.VirtualAddress, rf.data(), count * sizeof(RUNTIME_FUNCTION), &got) ||
        got != count * sizeof(RUNTIME_FUNCTION)) return;
    for (const auto &f : rf) {
        out.insert(base + f.BeginAddress);
        if (site >= base + f.BeginAddress && site < base + f.EndAddress) { fs = base + f.BeginAddress; fe = base + f.EndAddress; }
    }
}
#endif

static void analyse_site(probe_session *s, uint64_t base, uint64_t site, SiteAnalysis &a) {
    uint32_t image_size = 0; IMAGE_DATA_DIRECTORY unused{};
    read_image_dir(s, base, IMAGE_DIRECTORY_ENTRY_EXPORT, unused, &image_size);
    add_export_starts(s, base, a.entries);
    add_cfg_starts(s, base, a.entries);
#if defined(_WIN64)
    add_pdata(s, base, site, a.entries, a.func_start, a.func_end);
    if (a.func_start) a.bounds_from = ".pdata";
#endif
    if (s->sym_ready) {                                            // PDB: every function, statics included
        uint64_t fs = 0; uint32_t fz = 0;
        if (uhh_sym::containing_function(s->pi.hProcess, site, fs, fz) && fz <= (1u << 20)) {
            a.entries.insert(fs);
            if (!a.func_start || fs + fz > a.func_end) { a.func_start = fs; a.func_end = fs + fz; a.bounds_from = "pdb"; }
        }
        for (uint64_t x = site + 1; x < site + 32; ++x)            // a PDB function starting just after the site
            if (uhh_sym::containing_function(s->pi.hProcess, x, fs, fz) && fs == x) a.entries.insert(fs);
    }
    if (!a.func_start || a.func_end - a.func_start > (1u << 16)) { a.func_start = a.func_end = 0; return; }
    std::vector<unsigned char> code(a.func_end - a.func_start); size_t got = 0;
    if (!remote_read(s->pi.hProcess, a.func_start, code.data(), code.size(), &got) || got != code.size()) { a.func_start = a.func_end = 0; return; }
    ZydisDecoder dec;
#if defined(_WIN64)
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
    ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#endif
    ZydisDecodedInstruction in; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
    const uint64_t fs = a.func_start, fe = a.func_end;
    auto inside = [&](uint64_t t) { return t >= fs && t < fe; };
    for (size_t off = 0; off < code.size();) {
        if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code.data() + off, code.size() - off, &in, ops))) { ++off; continue; }
        const uint64_t at = fs + off, next = at + in.length;
        a.insns.push_back(at);
        if (in.mnemonic == ZYDIS_MNEMONIC_JMP && in.operand_count_visible >= 1) {
            const auto &o = ops[0];
            const bool via_import = o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.mem.index == ZYDIS_REGISTER_NONE &&
                (o.mem.base == ZYDIS_REGISTER_NONE || o.mem.base == ZYDIS_REGISTER_RIP);   // jmp [IAT]: leaves the function
            if (o.type == ZYDIS_OPERAND_TYPE_REGISTER || (o.type == ZYDIS_OPERAND_TYPE_MEMORY && !via_import))
                a.indirect_jumps.push_back(at);
        }
        if (in.meta.category == ZYDIS_CATEGORY_CALL) a.entries.insert(next);               // return point
        for (int k = 0; k < in.operand_count_visible; ++k) {
            const auto &o = ops[k];
            if (o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && o.imm.is_relative && in.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE) {
                uint64_t t = next + (uint64_t)o.imm.value.s;
#if !defined(_WIN64)
                t = (uint32_t)t;
#endif
                a.entries.insert(t);                                                      // direct branch/call target
            }
            // Switch tables: [reg*4 + disp32] (x86: absolute entries; x64 MSVC: image-base
            // relative, base register = image base). Read entries while they land in this
            // function; every one is an entry point.
            if (o.type == ZYDIS_OPERAND_TYPE_MEMORY && o.mem.index != ZYDIS_REGISTER_NONE &&
                o.mem.scale == 4 && o.mem.disp.has_displacement && o.mem.disp.value > 0) {
#if defined(_WIN64)
                const uint64_t table = base + (uint64_t)o.mem.disp.value;
                if ((uint64_t)o.mem.disp.value >= image_size) continue;
#else
                const uint64_t table = (uint32_t)o.mem.disp.value;
                if (table < base || table - base >= image_size) continue;
#endif
                int found = 0;
                for (int e = 0; e < 4096; ++e) {
                    uint32_t v = 0; size_t n = 0;
                    if (!remote_read(s->pi.hProcess, table + 4ull * e, &v, 4, &n) || n != 4) break;
#if defined(_WIN64)
                    const uint64_t t = base + v;
#else
                    const uint64_t t = v;
#endif
                    if (!inside(t)) break;
                    a.entries.insert(t); ++found;
                }
                if (found) ++a.tables;
            }
        }
        off += in.length;
    }
}

// The section holding [lo, hi): false when the patch would leave executable code.
static bool patch_in_code_section(probe_session *s, uint64_t base, uint64_t lo, uint64_t hi, std::string &name) {
    IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS nt{}; size_t got = 0;
    if (!remote_read(s->pi.hProcess, base, &dos, sizeof(dos), &got) || got != sizeof(dos)) return true;
    const uint64_t nth = base + (uint32_t)dos.e_lfanew;
    if (!remote_read(s->pi.hProcess, nth, &nt, sizeof(nt), &got) || got != sizeof(nt)) return true;
    const uint16_t nsec = nt.FileHeader.NumberOfSections;
    if (!nsec || nsec > 96) return true;
    std::vector<IMAGE_SECTION_HEADER> sec(nsec);
    const uint64_t first = nth + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;
    if (!remote_read(s->pi.hProcess, first, sec.data(), nsec * sizeof(IMAGE_SECTION_HEADER), &got) ||
        got != nsec * sizeof(IMAGE_SECTION_HEADER)) return true;
    for (const auto &h : sec) {
        const uint64_t st = base + h.VirtualAddress, en = st + (std::max)(h.Misc.VirtualSize, h.SizeOfRawData);
        if (lo < st || lo >= en) continue;
        name.assign((const char *)h.Name, strnlen((const char *)h.Name, 8));
        return (h.Characteristics & IMAGE_SCN_MEM_EXECUTE) && hi <= en;
    }
    return true;                                     // not in a mapped image section: nothing to say
}

// Inline hooks overwrite >= 5 bytes; they are refused where code could ARRIVE inside those
// bytes, with one clear reason per case:
//   [exit]     the patch runs past a ret/jmp into code only a jump can reach
//   [call]     a call inside the patch returns into it
//   [entry]    a function start, branch target, return point or switch-table target is inside it
//   [indirect] the function has an indirect jump whose targets cannot be resolved
//   [section]  the patch runs past the end of the executable section
//   [reloc]    a rel8-only branch (jrcxz/jecxz/loop*) inside it cannot be relocated
// (Threads executing inside the patch when it is written are handled by the freeze.)
// Not visible to any static check: jumps into this function from OTHER code.
// A probe added BY ADDRESS has no module base of its own: the image mapped around the
// address (if any) is analysed the same way -- otherwise only the bytes of the patch itself
// would be judged (a return site followed by a loop head was hooked without a word).
static uint64_t image_base_of(probe_session *s, uint64_t address) {
    for (auto &kv : s->module_bases) {
        if (address < kv.second) continue;
        auto sz = s->module_sizes.find(kv.second);
        const uint64_t size = sz != s->module_sizes.end() ? sz->second : remote_image_size(s->pi.hProcess, kv.second);
        if (address - kv.second < size) return kv.second;
    }
    return 0;
}
static bool inline_site_unsafe(probe_session *s, const Probe &p, std::string &why) {
    const uint64_t base = p.base ? p.base : image_base_of(s, p.address);
    unsigned char b[32] = {}; size_t n = 0;
    if (!remote_read(s->pi.hProcess, p.address, b, sizeof(b), &n) || n < 5) return false;
    // Decode the PROGRAM's bytes: our own INT3s read as the instruction they replace.
    uint64_t own_bp = UINT64_MAX;
    for (auto &q : s->probes)
        if (q->active && (q->flags & PROBE_BREAKPOINT) && !q->orig_insn.empty() && q->address >= p.address &&
            q->address < p.address + n && b[q->address - p.address] == 0xCC) {
            b[q->address - p.address] = q->original;
            own_bp = std::min(own_bp, q->address);
        }
    int64_t call_end = -1; bool code_after_exit = false; size_t exit_at = 0;
    const uint32_t len = inline_patch_len(b, n, &call_end, &code_after_exit, &exit_at);
    if (!len) return false;
    char buf[320];
    std::string reason;          // "<N>-byte hook would be written across <what> at +0xK"
    std::string secname;
    if (own_bp < p.address + len) {
        // The hook would relocate a live UHH INT3 into its trampoline, where it would no
        // longer be recognised (an unknown breakpoint in the target).
        std::snprintf(buf, sizeof(buf), "%u-byte hook would be written over a software-breakpoint probe at +0x%llx "
                      "(probe that instruction with one of breakpoint / inline, or use hw with either)",
                      len, (unsigned long long)(own_bp - p.address));
        reason = buf;
    } else if (base && !patch_in_code_section(s, base, p.address, p.address + len, secname)) {
        std::snprintf(buf, sizeof(buf), "%u-byte hook would be written across the end of section %s", len, secname.c_str());
        reason = buf;
    } else if (code_after_exit) {
        std::snprintf(buf, sizeof(buf), "%u-byte hook would be written across the end of the function (ret/jmp at +0x%zx)",
                      len, exit_at);
        reason = buf;
    } else if (call_end >= 0 && call_end != (int64_t)len) {
        std::snprintf(buf, sizeof(buf), "%u-byte hook would be written across a call's return point at +0x%llx",
                      len, (unsigned long long)call_end);
        reason = buf;
    }
    if (reason.empty()) {
        // [reloc] jrcxz/jecxz/loop* exist only with a rel8 displacement: copied into a
        // trampoline they cannot reach their target (the hook engine does not rewrite them).
        ZydisDecoder dec;
#if defined(_WIN64)
        ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
        ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#endif
        ZydisDecodedInstruction in{};
        for (size_t off = 0; off < len && ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&dec, nullptr, b + off, n - off, &in));
             off += in.length) {
            const ZydisMnemonic m = in.mnemonic;
            if (m == ZYDIS_MNEMONIC_JCXZ || m == ZYDIS_MNEMONIC_JECXZ || m == ZYDIS_MNEMONIC_JRCXZ ||
                m == ZYDIS_MNEMONIC_LOOP || m == ZYDIS_MNEMONIC_LOOPE || m == ZYDIS_MNEMONIC_LOOPNE) {
                std::snprintf(buf, sizeof(buf), "%u-byte hook would relocate %s at +0x%zx (rel8-only branch: cannot be "
                              "relocated)", len, ZydisMnemonicGetString(m), off);
                reason = buf;
                break;
            }
        }
    }
    SiteAnalysis a;
    if (base) analyse_site(s, base, p.address, a);
    if (reason.empty()) {
        auto it = a.entries.upper_bound(p.address);
        if (it != a.entries.end() && *it < p.address + len) {
            std::snprintf(buf, sizeof(buf), "%u-byte hook would be written across a jump/call target at +0x%llx",
                          len, (unsigned long long)(*it - p.address));
            reason = buf;
        }
    }
    // Unresolved indirect jumps make MID-function sites unverifiable. At the function's own
    // start they do not: a switch/jump table targets case labels in the body, never the
    // entry's first bytes (direct back-edges to the entry were checked above).
    if (reason.empty() && a.func_start && a.func_start != p.address && !a.indirect_jumps.empty() && !a.tables) {
        std::snprintf(buf, sizeof(buf), "%u-byte hook cannot be verified: the function has an indirect jump at 0x%llx "
                      "with unknown targets", len, (unsigned long long)a.indirect_jumps.front());
        reason = buf;
    }
    if (reason.empty() && !a.func_start) {
        // No function bounds (no .pdata/PDB entry, or no image at all): walk forward from the
        // site to the end of its block and check every direct branch met there (catches
        // loops back into it).
        ZydisDecoder dec;
#if defined(_WIN64)
        ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
        ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#endif
        unsigned char w[512] = {}; size_t wn = 0;
        remote_read(s->pi.hProcess, p.address, w, sizeof(w), &wn);
        ZydisDecodedInstruction in; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
        for (size_t off = 0; off < wn && reason.empty();) {
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, w + off, wn - off, &in, ops))) break;
            const uint64_t at = p.address + off, next = at + in.length;
            if (in.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE && in.operand_count_visible >= 1 &&
                ops[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE && ops[0].imm.is_relative) {
                uint64_t t = next + (uint64_t)ops[0].imm.value.s;
#if !defined(_WIN64)
                t = (uint32_t)t;
#endif
                if (t > p.address && t < p.address + len) {
                    std::snprintf(buf, sizeof(buf), "%u-byte hook would be written across a jump target at +0x%llx",
                                  len, (unsigned long long)(t - p.address));
                    reason = buf;
                }
            }
            if (in.meta.category == ZYDIS_CATEGORY_RET || in.meta.category == ZYDIS_CATEGORY_UNCOND_BR) break;
            off += in.length;
        }
    }
    if (reason.empty()) return false;
    // Suggest instruction boundaries in this function where the whole patch passes the same
    // checks, nearest first. The callback would run at a different instruction there.
    std::string modname;
    for (auto &kv : s->module_bases) if (kv.second == base) { modname = kv.first; break; }
    std::vector<std::pair<uint64_t, uint64_t>> cands;    // (distance, address)
    const bool fn_ok = !(!a.indirect_jumps.empty() && !a.tables);
    for (uint64_t x : a.insns) {
        if (x == p.address || !fn_ok) continue;
        unsigned char c[32] = {}; size_t cn = 0;
        if (!remote_read(s->pi.hProcess, x, c, sizeof(c), &cn) || cn < 5) continue;
        int64_t ce = -1; bool cx = false;
        const uint32_t cl = inline_patch_len(c, cn, &ce, &cx);
        if (!cl || cx || (ce >= 0 && ce != (int64_t)cl) || x + cl > a.func_end) continue;
        auto it = a.entries.upper_bound(x);
        if (it != a.entries.end() && *it < x + cl) continue;
        cands.push_back({x > p.address ? x - p.address : p.address - x, x});
    }
    std::sort(cands.begin(), cands.end());
    std::string sugg;
    for (size_t i = 0; i < cands.size() && i < 3; ++i) {
        const uint64_t x = cands[i].second;
        std::snprintf(buf, sizeof(buf), "%s%s+0x%llx (%s%llu bytes)", sugg.empty() ? "" : ", ",
                      modname.empty() ? "module" : modname.c_str(), (unsigned long long)(x - base),
                      x < p.address ? "-" : "+", (unsigned long long)cands[i].first);
        sugg += buf;
    }
    why = reason;
    if (!sugg.empty()) std::fprintf(stderr, "probe: %s: inline-safe nearby: %s\n", p.location.c_str(), sugg.c_str());
    return true;
}

// ---- Instruction boundaries (every backend) ---------------------------------------------
// A site INSIDE an instruction is wrong on every backend: breakpoint writes its INT3 over an
// operand byte (the instruction changes), inline makes the program execute the hook jump's
// displacement bytes, hw execute never fires (the CPU only matches instruction starts). It is
// refused, with the nearest boundaries, wherever the instruction stream is KNOWN: decoded by
// following control flow -- fall-through, direct branches and calls, switch tables -- from
// trusted code starts: the start of the site's function (its extent from .pdata on x64, the
// PDB on both arches) and the .pdata/PDB/CFG starts inside it; with no extent, the symbol the
// location names. Never a linear sweep (data in code would mis-decode real instructions). No
// verdict -- today's behaviour -- when the site is itself an export or trusted start, when no
// decoded instruction covers it (code reached only through an unknown indirect jump, or no
// extent and no symbol), when decoded instructions overlap anywhere in the region
// (overlapping code: obfuscation, hand-written tricks), or when the covering instruction was
// reached only through a call's fall-through (the call may not return: data after it) while
// the region has an indirect jump that is not a resolved switch (it may reach the site).
static bool exec_section_bounds(probe_session *s, uint64_t base, uint64_t addr, uint64_t &lo, uint64_t &hi) {
    IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS nt{}; size_t got = 0;
    if (!remote_read(s->pi.hProcess, base, &dos, sizeof(dos), &got) || got != sizeof(dos) ||
        dos.e_magic != IMAGE_DOS_SIGNATURE) return false;
    const uint64_t nth = base + (uint32_t)dos.e_lfanew;
    if (!remote_read(s->pi.hProcess, nth, &nt, sizeof(nt), &got) || got != sizeof(nt) ||
        nt.Signature != IMAGE_NT_SIGNATURE) return false;
    const uint16_t nsec = nt.FileHeader.NumberOfSections;
    if (!nsec || nsec > 96) return false;
    std::vector<IMAGE_SECTION_HEADER> sec(nsec);
    const uint64_t first = nth + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + nt.FileHeader.SizeOfOptionalHeader;
    if (!remote_read(s->pi.hProcess, first, sec.data(), nsec * sizeof(IMAGE_SECTION_HEADER), &got) ||
        got != nsec * sizeof(IMAGE_SECTION_HEADER)) return false;
    for (const auto &h : sec) {
        const uint64_t st = base + h.VirtualAddress, en = st + (std::max)(h.Misc.VirtualSize, h.SizeOfRawData);
        if (addr < st || addr >= en) continue;
        if (!(h.Characteristics & IMAGE_SCN_MEM_EXECUTE)) return false;
        lo = st; hi = en;
        return true;
    }
    return false;
}

// `anchor`: the address of the symbol the location names (0: none). True = refused (why set).
static bool site_inside_instruction(probe_session *s, const Probe &p, uint64_t site, uint64_t anchor, std::string &why) {
    const uint64_t base = image_base_of(s, site);
    uint64_t sec_lo = 0, sec_hi = 0;
    if (!base || !exec_section_bounds(s, base, site, sec_lo, sec_hi)) return false;   // no image / not code
    // Trusted code starts. The site being one of them ends it: an instruction starts there.
    std::set<uint64_t> starts, exports;
    add_export_starts(s, base, exports);
    if (exports.count(site)) return false;
    add_cfg_starts(s, base, starts);
    uint64_t fs = 0, fe = 0;
    const char *src = nullptr;
#if defined(_WIN64)
    add_pdata(s, base, site, starts, fs, fe);
    if (fs) src = ".pdata";
#endif
    if (s->sym_ready) {
        uint64_t ps = 0; uint32_t pz = 0;
        if (uhh_sym::containing_function(s->pi.hProcess, site, ps, pz) && pz && pz <= (1u << 20)) {
            starts.insert(ps);
            if (!fs) { fs = ps; fe = ps + pz; src = "the PDB"; }
        }
    }
    if (anchor) starts.insert(anchor);
    if (starts.count(site)) return false;
    // The region decoded: the site's function; with no extent, from the symbol the location
    // names to just past the site (never from ANOTHER function's start: its code can run on
    // into data -- a no-return call before a switch table -- and decode it over a real site).
    uint64_t lo = fs, hi = fe;
    std::string from = src ? src : "";
    if (!fs || fe - fs > (1u << 16)) {
        if (!anchor || anchor > site || site - anchor > 4096) return false;
        lo = anchor; hi = site + 16; from = p.export_name;
    }
    lo = (std::max)(lo, sec_lo); hi = (std::min)(hi, sec_hi);
    if (site < lo || site >= hi) return false;
    std::vector<unsigned char> code((size_t)(hi - lo)); size_t got = 0;
    if (!remote_read(s->pi.hProcess, lo, code.data(), code.size(), &got) || got != code.size()) return false;
    for (auto &q : s->probes)                       // the PROGRAM's bytes: our INT3s read as the original
        if (q->active && (q->flags & PROBE_BREAKPOINT) && !q->orig_insn.empty() && q->address >= lo &&
            q->address < hi && code[(size_t)(q->address - lo)] == 0xCC)
            code[(size_t)(q->address - lo)] = q->original;
    uint32_t image_size = 0; IMAGE_DATA_DIRECTORY unused{};
    read_image_dir(s, base, IMAGE_DIRECTORY_ENTRY_EXPORT, unused, &image_size);
    ZydisDecoder dec; zydis_init(dec);
    // Decoded twice: `insns` follows every edge, a call's fall-through included; `direct`
    // never passes a call's fall-through. A call may not return (ExitProcess, a throw helper,
    // a no-return routine of the program), and the bytes after it can be data that decodes
    // over a real block reached only through an indirect jump UHH cannot resolve -- a false
    // refusal (never overridable). So an instruction known only through a fall-through
    // refuses only when every indirect jump decoded in the region was resolved (a switch
    // table): then a real block there would have been decoded too, and shown as an overlap.
    std::map<uint64_t, ZydisDecodedInstruction> insns, direct;
    std::set<uint64_t> indirect_jumps, resolved_jumps;
    auto decode = [&](bool through_calls, std::map<uint64_t, ZydisDecodedInstruction> &out) {
        std::vector<uint64_t> work;
        for (auto it = starts.lower_bound(lo); it != starts.end() && *it < hi; ++it) work.push_back(*it);
        auto push = [&](uint64_t t) { if (t >= lo && t < hi && !out.count(t)) work.push_back(t); };
        // Switch tables (entries pushed while they land in the region): x86 `jmp [idx*4 + table]`
        // (absolute entries); x64 MSVC `mov r32, [rB + idx*4 + rva]` then `add r, rB` / `jmp r`
        // within the next few instructions (image-relative entries, rB = image base).
        // Returns the number of entries found.
        auto table = [&](uint64_t at) {
            int e = 0;
            for (; e < 4096; ++e) {
                uint32_t v = 0; size_t n = 0;
                if (!remote_read(s->pi.hProcess, at + 4ull * e, &v, 4, &n) || n != 4) break;
#if defined(_WIN64)
                const uint64_t t = base + v;
#else
                const uint64_t t = v;
#endif
                if (t < lo || t >= hi) break;
                push(t);
            }
            return e;
        };
        while (!work.empty()) {
            const uint64_t at = work.back(); work.pop_back();
            if (out.count(at)) continue;
            ZydisDecodedInstruction in; ZydisDecodedOperand ops[ZYDIS_MAX_OPERAND_COUNT];
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code.data() + (size_t)(at - lo), code.size() - (size_t)(at - lo), &in, ops)))
                continue;                               // (a path into undecodable bytes just ends)
            out.emplace(at, in);
            const uint64_t next = at + in.length;
            if (in.mnemonic == ZYDIS_MNEMONIC_JMP && in.operand_count_visible >= 1 && ops[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE)
                indirect_jumps.insert(at);
            for (int k = 0; k < in.operand_count_visible; ++k) {
                const auto &o = ops[k];
                if (o.type == ZYDIS_OPERAND_TYPE_IMMEDIATE && o.imm.is_relative && in.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE) {
                    uint64_t t = next + (uint64_t)o.imm.value.s;
#if !defined(_WIN64)
                    t = (uint32_t)t;
#endif
                    push(t);
                }
                if (o.type != ZYDIS_OPERAND_TYPE_MEMORY || o.mem.index == ZYDIS_REGISTER_NONE || o.mem.scale != 4 ||
                    !o.mem.disp.has_displacement || o.mem.disp.value <= 0) continue;
#if defined(_WIN64)
                if (in.mnemonic != ZYDIS_MNEMONIC_MOV && in.mnemonic != ZYDIS_MNEMONIC_MOVSXD) continue;
                if ((uint64_t)o.mem.disp.value >= image_size || o.mem.base == ZYDIS_REGISTER_NONE) continue;
                uint64_t jmp_at = 0;
                for (uint64_t f = next, i = 0; i < 4 && f < hi; ++i) {
                    ZydisDecodedInstruction fi; ZydisDecodedOperand fo[ZYDIS_MAX_OPERAND_COUNT];
                    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&dec, code.data() + (size_t)(f - lo), code.size() - (size_t)(f - lo), &fi, fo))) break;
                    if (fi.mnemonic == ZYDIS_MNEMONIC_JMP) { if (fo[0].type == ZYDIS_OPERAND_TYPE_REGISTER) jmp_at = f; break; }
                    if (fi.meta.branch_type != ZYDIS_BRANCH_TYPE_NONE) break;
                    f += fi.length;
                }
                if (jmp_at && table(base + (uint64_t)o.mem.disp.value)) resolved_jumps.insert(jmp_at);
#else
                const uint64_t t = (uint32_t)o.mem.disp.value;
                if (in.mnemonic == ZYDIS_MNEMONIC_JMP && t >= base && t - base < image_size && table(t)) resolved_jumps.insert(at);
#endif
            }
            const bool ends = in.meta.category == ZYDIS_CATEGORY_RET || in.meta.category == ZYDIS_CATEGORY_UNCOND_BR ||
                              in.mnemonic == ZYDIS_MNEMONIC_INT3 || in.mnemonic == ZYDIS_MNEMONIC_UD2 ||
                              in.mnemonic == ZYDIS_MNEMONIC_HLT ||
                              (!through_calls && in.meta.category == ZYDIS_CATEGORY_CALL);
            if (!ends) push(next);
        }
    };
    decode(true, insns);
    // Overlapping decoded code anywhere in the region: the stream is not one stream.
    uint64_t prev_end = 0;
    for (const auto &kv : insns) {
        if (kv.first < prev_end) return false;
        prev_end = kv.first + kv.second.length;
    }
    auto cover = insns.upper_bound(site);
    if (cover == insns.begin()) return false;
    --cover;
    const uint64_t at = cover->first, end = at + cover->second.length;
    if (at == site || site >= end) return false;    // a boundary, or bytes nothing decoded covers: no verdict
    // Covered only by code decoded through a call's fall-through (see above): no verdict
    // unless every indirect jump in the region is a resolved switch.
    decode(false, direct);
    if (!direct.count(at)) {
        for (uint64_t j : indirect_jumps)
            if (!resolved_jumps.count(j)) return false;
    }
    std::string modname;
    for (auto &kv : s->module_bases) if (kv.second == base) { modname = kv.first; break; }
    auto name = [&](uint64_t a) {
        char b[160];
        if (anchor && !p.export_name.empty() && a >= anchor) {
            const size_t plus = p.location.find('+');
            std::snprintf(b, sizeof(b), "%s+0x%llx", p.location.substr(0, plus).c_str(), (unsigned long long)(a - anchor));
        } else {
            std::snprintf(b, sizeof(b), "%s+0x%llx", modname.empty() ? "module" : modname.c_str(), (unsigned long long)(a - base));
        }
        return std::string(b);
    };
    char buf[512];
    std::snprintf(buf, sizeof(buf), "site is inside an instruction: %llu byte(s) into the %u-byte %s at %s "
                  "(instruction stream decoded from %s); nearest instruction boundaries %s, %s",
                  (unsigned long long)(site - at), (unsigned)cover->second.length,
                  ZydisMnemonicGetString(cover->second.mnemonic), name(at).c_str(), from.c_str(),
                  name(at).c_str(), name(end).c_str());
    why = buf;
    return true;
}

// Refuse a probe whose site is inside an instruction (any backend; no flag overrides it).
// A data watchpoint (PROBE_WATCH_*) watches bytes, not an instruction: any aligned dword is a
// valid site, an operand byte in code included (self-modifying code, a variable in a code
// section) -- never judged, on every path (absolute, module+RVA, symbol+offset).
bool refuse_mid_instruction(probe_session *s, Probe &p, uint64_t site) {
    if (p.flags & (PROBE_WATCH_WRITE | PROBE_WATCH_RW)) return false;
    if (!p.export_name.empty() && !p.sym_offset) return false;     // the named symbol itself
    const uint64_t anchor = !p.export_name.empty() && site >= p.sym_offset ? site - p.sym_offset : 0;
    std::string why;
    if (!site_inside_instruction(s, p, site, anchor, why)) return false;
    const std::string msg = "probe " + p.location + " refused: " + why;
    std::fprintf(stderr, "probe: %s\n", msg.c_str());
    set_error(s, msg);
    p.retired = true;
    return true;
}

// Two inline hooks whose patches overlap corrupt each other: the second decodes (and
// relocates) the first one's jump bytes, and removing either restores bytes under the
// other. Same address included. Never overridable: refused, or hw with PROBE_FALLBACK_HW.
static bool inline_overlaps_probe(probe_session *s, Probe &p, std::string &why) {
    unsigned char b[32] = {}; size_t n = 0; int64_t call_end = -1; bool after_exit = false;
    if (remote_read(s->pi.hProcess, p.address, b, sizeof(b), &n) && n >= 5)
        p.patch_len = inline_patch_len(b, n, &call_end, &after_exit);
    const uint64_t lo = p.address, hi = p.address + (p.patch_len ? p.patch_len : 5);
    for (const auto &o : s->probes) {
        if (!(o->flags & PROBE_INLINE) || o->retired || !o->address || o->agent_index == p.agent_index) continue;
        const uint64_t olo = o->address, ohi = o->address + (o->patch_len ? o->patch_len : 5);
        if (olo < hi && lo < ohi) {
            char buf[256];
            std::snprintf(buf, sizeof(buf), "its %llu-byte hook would overlap the hook of inline probe %s at 0x%llx",
                          (unsigned long long)(hi - lo), o->location.c_str(), (unsigned long long)olo);
            why = buf;
            return true;
        }
    }
    return false;
}

bool vet_site(probe_session *s, Probe &p, bool &moved_to_hw) {
    moved_to_hw = false;
    if (p.flags & PROBE_HW) return true;
    std::string inner;
    if ((p.flags & PROBE_INLINE) && inline_overlaps_probe(s, p, inner)) {
        if (p.flags & PROBE_FALLBACK_HW) {
            p.flags = (p.flags & ~(uint32_t)PROBE_INLINE) | PROBE_HW; moved_to_hw = true;
            std::fprintf(stderr, "probe: %s -> hardware fallback (%s)\n", p.location.c_str(), inner.c_str());
            return true;
        }
        std::string msg = "inline probe " + p.location + " refused: " + inner + ".";
        std::fprintf(stderr, "probe: %s\n", msg.c_str());
        set_error(s, msg);
        return false;
    }
    if ((p.flags & PROBE_INLINE) && inline_site_unsafe(s, p, inner)) {
        if (p.flags & PROBE_ALLOW_UNSAFE_SITE) {
            std::fprintf(stderr, "probe: warning: inline probe %s: %s (installed: PROBE_ALLOW_UNSAFE_SITE)\n",
                         p.location.c_str(), inner.c_str());
        } else if (p.flags & PROBE_FALLBACK_HW) {
            p.flags = (p.flags & ~(uint32_t)PROBE_INLINE) | PROBE_HW; moved_to_hw = true;
            std::fprintf(stderr, "probe: %s -> hardware fallback (%s)\n", p.location.c_str(), inner.c_str());
            return true;
        } else {
            std::string msg = "inline probe " + p.location + " refused: " + inner + ". Override with PROBE_ALLOW_UNSAFE_SITE.";
            std::fprintf(stderr, "probe: %s\n", msg.c_str());
            set_error(s, msg);
            return false;
        }
    }
    std::string json;
    if (!detect_prehook(s, p, json)) return true;
    s->prehooks.push_back(json);
    if (!(p.flags & PROBE_INLINE) || (p.flags & PROBE_ALLOW_PREHOOKED)) return true;
    if (p.flags & PROBE_FALLBACK_HW) {
        p.flags = (p.flags & ~(uint32_t)PROBE_INLINE) | PROBE_HW; moved_to_hw = true;
        std::fprintf(stderr, "probe: %s -> hardware fallback (pre-hooked site)\n", p.location.c_str());
        return true;
    }
    set_error(s, "inline probe " + p.location + " is on a pre-hooked site (see the prehook report; "
                 "use PROBE_ALLOW_PREHOOKED to chain, PROBE_FALLBACK_HW or PROBE_HW to avoid)");
    return false;
}

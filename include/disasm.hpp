#pragma once
#include "win_common.hpp"
#include "pe_image.hpp"
#include <Zydis/Zydis.h>
// Minimal disassembly for surfacing a hook: format a byte range as
// "+offset  mnemonic" lines. Zydis is already in the build (SafetyHook's dep).
// Pass the runtime address so relative jump/call targets resolve to absolute
// addresses in the mnemonic text. x64 only for now; Win32 will pass LEGACY_32.
inline void disasm_lines(const unsigned char *bytes, size_t len, uint64_t runtime_address,
                         const char *indent = "    ", bool x64 = true) {
    ZydisMachineMode mode = x64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
    size_t offset = 0;
    while (offset < len) {
        ZydisDisassembledInstruction insn;
        if (!ZYAN_SUCCESS(ZydisDisassembleIntel(mode, runtime_address + offset,
                                                bytes + offset, len - offset, &insn))) {
            // Ran past a whole instruction at the end of the window; stop cleanly.
            std::fprintf(stderr, "%s+0x%02zx  (%02x ... truncated)\n", indent, offset, bytes[offset]);
            break;
        }
        std::fprintf(stderr, "%s+0x%02zx  %s\n", indent, offset, insn.text);
        offset += insn.info.length;
    }
}
// First instruction boundary at or past `min_offset`, for the hedged rehook hint.
inline bool next_boundary(const unsigned char *bytes, size_t len, size_t min_offset,
                          size_t &boundary, bool x64 = true) {
    ZydisMachineMode mode = x64 ? ZYDIS_MACHINE_MODE_LONG_64 : ZYDIS_MACHINE_MODE_LEGACY_32;
    size_t offset = 0;
    while (offset < len) {
        if (offset >= min_offset) { boundary = offset; return true; }
        ZydisDisassembledInstruction insn;
        if (!ZYAN_SUCCESS(ZydisDisassembleIntel(mode, offset, bytes + offset, len - offset, &insn)))
            return false;
        offset += insn.info.length;
    }
    return false;
}
// Surface a pre-existing hook: show the live bytes vs the clean on-disk image as
// disassembly, so a human can see what was patched. Reads both; prints nothing if
// either read fails. A hedged "maybe rehook" hint points at the first clean
// boundary past a 5-byte patch (not verified reachable). NOTE: direct jmp/call
// targets appear in the Zydis text; an indirect `jmp [rip+disp]` shows only the
// operand - resolving its actual target means reading that pointer from the
// target process, which this does not do yet.
inline void show_hook_disasm(const probe_ops *ops, void *backend, uint64_t address,
                             const std::string &module_path, uint32_t rva, bool x64 = true) {
    unsigned char live[32]{}, disk[32]{}; size_t done = 0;
    if (!ops->read(backend, address, live, sizeof(live), &done) || done != sizeof(live)) return;
    DiskImage img;
    if (!img.load(module_path) || !img.read_rva(rva, disk, sizeof(disk))) return;
    std::fprintf(stderr, "probe: in memory (hooked):\n");
    disasm_lines(live, sizeof(live), address, "    ", x64);
    std::fprintf(stderr, "probe: on disk (clean):\n");
    disasm_lines(disk, sizeof(disk), address, "    ", x64);
    size_t boundary = 0;
    if (next_boundary(disk, sizeof(disk), 5, boundary, x64))
        std::fprintf(stderr, "probe: maybe rehook at +0x%zx? "
                     "(first clean boundary past a 5-byte patch; not verified reachable)\n",
                     boundary);
}

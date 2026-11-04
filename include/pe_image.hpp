#pragma once
#include "win_common.hpp"
#include <vector>
// Read bytes from a PE file ON DISK by RVA, for comparing a live site against the
// clean image. RVA->file-offset uses the section table. NOTE: this does not apply
// base relocations, so a site whose bytes are a relocation target can differ from
// disk legitimately. The fixture's probe sites contain none (a plain store, a NOP
// sled, a RIP-relative jump), so any difference there is a genuine modification.
struct DiskImage {
    std::vector<unsigned char> bytes;
    bool load(const std::string &path) {
        HANDLE f = CreateFileA(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (f == INVALID_HANDLE_VALUE) return false;
        LARGE_INTEGER size{}; bool ok = GetFileSizeEx(f, &size) && size.QuadPart > 0 && size.QuadPart < (64 << 20);
        if (ok) {
            bytes.resize((size_t)size.QuadPart); DWORD got = 0;
            ok = ReadFile(f, bytes.data(), (DWORD)bytes.size(), &got, nullptr) && got == bytes.size();
        }
        CloseHandle(f); return ok;
    }
    // Translate an RVA to a file offset via the section headers.
    bool rva_to_offset(uint32_t rva, uint32_t &offset) const {
        if (bytes.size() < sizeof(IMAGE_DOS_HEADER)) return false;
        auto *dos = (const IMAGE_DOS_HEADER *)bytes.data();
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > bytes.size()) return false;
        auto *nt = (const IMAGE_NT_HEADERS *)(bytes.data() + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
        if (rva < nt->OptionalHeader.SizeOfHeaders) { offset = rva; return true; }
        auto *sec = IMAGE_FIRST_SECTION(nt);
        for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
            uint32_t va = sec[i].VirtualAddress, vsize = sec[i].Misc.VirtualSize;
            if (rva >= va && rva < va + vsize) { offset = sec[i].PointerToRawData + (rva - va); return true; }
        }
        return false;
    }
    bool read_rva(uint32_t rva, void *out, size_t n) const {
        uint32_t off = 0;
        if (!rva_to_offset(rva, off) || off + n > bytes.size()) return false;
        std::memcpy(out, bytes.data() + off, n); return true;
    }
};

// The inline agent: UHH_SHARED callback DLLs, the trimmed local agent copy and warm copies,
// injection (remote LoadLibrary / init), the shared section, install gates, frozen hook writes (IPC).
#include "session_internal.hpp"
#include <stdexcept>

namespace uhh_session {

// ---- UHH_SHARED: one callbacks DLL file, loaded by controller and target ---------------
static bool image_has_section(const unsigned char *base, const char *name) {
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i)
        if (!strncmp(reinterpret_cast<const char *>(sec[i].Name), name, 8)) return true;
    return false;
}

bool module_of(const void *address, HMODULE &m) {
    return GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                              reinterpret_cast<LPCSTR>(address), &m) != 0;
}

static std::wstring sibling_agent_path() {
    wchar_t path[MAX_PATH]; DWORD n = GetModuleFileNameW(nullptr, path, MAX_PATH);
    if (!n || n >= MAX_PATH) return L"probe_api_agent.dll";
    std::wstring result(path, n); size_t slash = result.find_last_of(L"\\/");
    result.resize(slash == std::wstring::npos ? 0 : slash + 1);
    return result + L"probe_api_agent.dll";
}

static bool file_has_section(const std::wstring &path, const char *name) {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    std::vector<unsigned char> head(8192); DWORD got = 0;
    BOOL ok = ReadFile(f, head.data(), (DWORD)head.size(), &got, nullptr);
    CloseHandle(f);
    if (!ok || got < 1024) return false;
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(head.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || (DWORD)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > got) return false;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(head.data() + dos->e_lfanew);
    auto sec = IMAGE_FIRST_SECTION(nt);
    if ((const unsigned char *)(sec + nt->FileHeader.NumberOfSections) > head.data() + got) return false;
    return image_has_section(head.data(), name);
}

// The agent DLL this session loads into BOTH processes. If it carries UHH_SHARED state,
// every session gets its own copy of the file (a shared section is shared by everyone who
// maps the same file): %TEMP%\uhh\<pid>-<n>\probe_api_agent.dll, deleted at close; stale
// copies of dead sessions are swept here.
// The per-session copy of the agent DLL, written with its UHH_SHARED section's trailing zero bytes
// left out of the file (SizeOfRawData < VirtualSize: the loader zero-fills the rest of the
// section's pages, as for a .data section's .bss tail -- the section stays shared). That section
// holds every UHH_SHARED global of every callback module linked into the agent, nearly all
// zero: 7.5 MB of the 8.3 MB file. Real-time antivirus scans a new DLL file when it is first
// mapped -- every session, since every session gets a new copy -- and the scan time follows the
// file size (VM, Defender: ~90 ms for the full copy). Same bytes otherwise; anything this does
// not expect (a signed image, a section's data inside the dropped range) falls back to a plain
// copy (false).
static bool read_whole_file(HANDLE f, std::vector<unsigned char> &img) {
    LARGE_INTEGER size{};
    if (!GetFileSizeEx(f, &size) || size.QuadPart <= 4096 || size.QuadPart >= (1ll << 30)) return false;
    img.resize((size_t)size.QuadPart);
    DWORD got = 0;
    return ReadFile(f, img.data(), (DWORD)img.size(), &got, nullptr) && got == img.size();
}
// The trimming, in place. False (img untouched): not an image this expects -- a plain copy then.
static bool trim_agent_image(std::vector<unsigned char> &img);
static bool write_trimmed_agent(const std::wstring &src, const std::wstring &dst) {
    HANDLE f = CreateFileW(src.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    std::vector<unsigned char> img;
    const bool ok = read_whole_file(f, img);
    CloseHandle(f);
    if (!ok || !trim_agent_image(img)) return false;
    HANDLE o = CreateFileW(dst.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (o == INVALID_HANDLE_VALUE) return false;
    DWORD wrote = 0;
    const bool written = WriteFile(o, img.data(), (DWORD)img.size(), &wrote, nullptr) && wrote == img.size();
    CloseHandle(o);
    if (!written) DeleteFileW(dst.c_str());
    return written;
}
static bool trim_agent_image(std::vector<unsigned char> &img) {
    auto in = [&](uint64_t off, uint64_t n) { return off <= img.size() && n <= img.size() - off; };
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER *>(img.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || !in((uint64_t)dos->e_lfanew, sizeof(IMAGE_NT_HEADERS))) return false;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS *>(img.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) return false;
    const DWORD align = nt->OptionalHeader.FileAlignment;
    if (!align || (align & (align - 1))) return false;
    const DWORD ndirs = nt->OptionalHeader.NumberOfRvaAndSizes;
    if (ndirs > IMAGE_DIRECTORY_ENTRY_SECURITY && nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_SECURITY].Size) return false;
    auto sec = IMAGE_FIRST_SECTION(nt);
    const WORD nsec = nt->FileHeader.NumberOfSections;
    if (!in((uint64_t)((unsigned char *)sec - img.data()), (uint64_t)nsec * sizeof(IMAGE_SECTION_HEADER))) return false;
    IMAGE_SECTION_HEADER *shr = nullptr;
    for (WORD i = 0; i < nsec; ++i)
        if (!strncmp(reinterpret_cast<const char *>(sec[i].Name), "uhhshr", 8)) shr = &sec[i];
    if (!shr || !shr->SizeOfRawData || !in(shr->PointerToRawData, shr->SizeOfRawData)) return false;
    uint64_t used = shr->SizeOfRawData;
    while (used && img[shr->PointerToRawData + used - 1] == 0) --used;
    const uint64_t keep = (used + align - 1) & ~(uint64_t)(align - 1);
    if (keep >= shr->SizeOfRawData) return false;
    const uint64_t cut_at = shr->PointerToRawData + keep, cut_end = (uint64_t)shr->PointerToRawData + shr->SizeOfRawData;
    const DWORD delta = (DWORD)(cut_end - cut_at);
    // Every other section's data must be entirely before or after the dropped range.
    for (WORD i = 0; i < nsec; ++i) {
        if (&sec[i] == shr || !sec[i].SizeOfRawData) continue;
        const uint64_t a = sec[i].PointerToRawData, b = a + sec[i].SizeOfRawData;
        if (!(b <= cut_at || a >= cut_end)) return false;
    }
    // Debug directory entries name their data by FILE offset.
    std::vector<IMAGE_DEBUG_DIRECTORY *> dbg;
    if (ndirs > IMAGE_DIRECTORY_ENTRY_DEBUG) {
        const auto &d = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG];
        if (d.VirtualAddress && d.Size) {
            uint64_t off = UINT64_MAX;
            for (WORD i = 0; i < nsec; ++i)
                if (d.VirtualAddress >= sec[i].VirtualAddress && d.VirtualAddress < (uint64_t)sec[i].VirtualAddress + sec[i].SizeOfRawData)
                    off = (uint64_t)d.VirtualAddress - sec[i].VirtualAddress + sec[i].PointerToRawData;
            if (off == UINT64_MAX || !in(off, d.Size)) return false;
            for (DWORD k = 0; k + sizeof(IMAGE_DEBUG_DIRECTORY) <= d.Size; k += sizeof(IMAGE_DEBUG_DIRECTORY)) {
                auto *e = reinterpret_cast<IMAGE_DEBUG_DIRECTORY *>(img.data() + off + k);
                if (e->PointerToRawData && e->SizeOfData) {
                    const uint64_t a = e->PointerToRawData, b = a + e->SizeOfData;
                    if (!(b <= cut_at || a >= cut_end)) return false;
                    if (a >= cut_end) dbg.push_back(e);
                }
            }
        }
    }
    for (WORD i = 0; i < nsec; ++i)
        if (&sec[i] != shr && sec[i].SizeOfRawData && sec[i].PointerToRawData >= cut_end) sec[i].PointerToRawData -= delta;
    for (auto *e : dbg) e->PointerToRawData -= delta;
    shr->SizeOfRawData = (DWORD)keep;
    nt->OptionalHeader.CheckSum = 0;
    img.erase(img.begin() + (ptrdiff_t)cut_at, img.begin() + (ptrdiff_t)cut_end);
    {   // the PE checksum (as CheckSumMappedFile), for tools that look at it
        uint64_t sum = 0;
        const size_t words = img.size() / 2;
        for (size_t i = 0; i < words; ++i) {
            uint16_t w; std::memcpy(&w, img.data() + 2 * i, 2);
            sum += w; sum = (sum & 0xFFFF) + (sum >> 16);
        }
        if (img.size() & 1) { sum += img.back(); sum = (sum & 0xFFFF) + (sum >> 16); }
        sum = (sum & 0xFFFF) + (sum >> 16);
        reinterpret_cast<IMAGE_NT_HEADERS *>(img.data() + dos->e_lfanew)->OptionalHeader.CheckSum = (DWORD)(sum + img.size());
    }
    return true;
}

// ---- Warm agent copies (perf5) -------------------------------------------------------
// Every session needs a copy of the agent DLL of its own (UHH_SHARED: a shared section is shared
// by every process that maps the same FILE), and real-time antivirus scans each new copy when it
// is first mapped as an image (VM, Defender: ~50-100 ms, on the session's critical path). A
// scanned file is not scanned again, also after a rename. So a session takes a copy that an
// earlier session prepared and had scanned, if one is there, and leaves one for the next:
//   %TEMP%\uhh\warm\<sig>-<pid>-<tick>-<n>\probe_api_agent.dll   ready (sig: the source file's size
//                                                               and write time, so only a copy of
//                                                               the same agent build is taken)
//   %TEMP%\uhh\warm\t-<pid>-<tick>-<n>                         being prepared (a dead owner's is swept)
// A warm copy is created and its image section made once (CreateFileMapping SEC_IMAGE: that is
// what the scanner inspects), and NEVER loaded or run: its shared section is exactly the file's
// bytes, as a fresh copy's is. Taking one is an atomic directory rename into the session's own
// directory (two sessions cannot take the same one). At most WARM_KEEP ready copies per build.
// Identity (codex3 #2): <sig> is the SOURCE file's version stamp -- volume serial, file id, size,
// write time and change time (NTFS moves the change time on every change to the file, and a
// rebuilt file is a new file id; the old sig, size + write time, matched a different build with the
// same size and time: regress ctrl-warm-identity). A taken copy must also be a complete, unaltered
// trimmed image of that build: compare all bytes against a freshly trimmed source snapshot,
// not just PE fields and the copy's own checksum. Metadata can survive an in-place overwrite.
// Anything else is deleted and a fresh copy made. Warm copies are made and taken only while
// the uhh directory and its warm\ are private to this user (owner and DACL: nobody else can write
// there -- e.g. a SYSTEM controller's C:\Windows\Temp, where Users may create directories, gets
// none: regress ctrl-warm-acl). The verified copy stays open, deny-write, until the controller's
// LoadLibrary of it is done. A hit reads/trims the source once and compares bytes;
// it still avoids creating/scanning a new image file on the critical path.
static constexpr unsigned WARM_KEEP = 2;
struct AgentId { DWORD stamp = 0, size_of_image = 0, entry = 0; WORD sections = 0, major = 0, minor = 0; };
static bool image_id(const unsigned char *img, size_t n, AgentId &id, DWORD *checksum = nullptr, size_t *checksum_at = nullptr) {
    if (n < sizeof(IMAGE_DOS_HEADER)) return false;
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(img);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || (uint64_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS) > n) return false;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(img + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) return false;
    id.stamp = nt->FileHeader.TimeDateStamp; id.size_of_image = nt->OptionalHeader.SizeOfImage;
    id.entry = nt->OptionalHeader.AddressOfEntryPoint; id.sections = nt->FileHeader.NumberOfSections;
    id.major = nt->OptionalHeader.MajorImageVersion; id.minor = nt->OptionalHeader.MinorImageVersion;
    if (checksum) *checksum = nt->OptionalHeader.CheckSum;
    if (checksum_at) *checksum_at = (size_t)((const unsigned char *)&nt->OptionalHeader.CheckSum - img);
    return true;
}
static bool same_id(const AgentId &a, const AgentId &b) {
    return a.stamp == b.stamp && a.size_of_image == b.size_of_image && a.entry == b.entry &&
           a.sections == b.sections && a.major == b.major && a.minor == b.minor;
}
// The PE checksum (as CheckSumMappedFile, and as write_trimmed_agent computes it) of img; its
// CheckSum field is zeroed first. A ones'-complement sum: folding once at the end gives the same
// value as folding after every word.
static DWORD pe_checksum(std::vector<unsigned char> &img, size_t checksum_at) {
    const size_t n = img.size();
    if (checksum_at + 4 > n) return 0;
    std::memset(img.data() + checksum_at, 0, 4);
    uint64_t sum = 0;
    size_t i = 0;
    for (; i + 8 <= n; i += 8) {
        uint64_t v; std::memcpy(&v, img.data() + i, 8);
        sum += (v & 0xFFFF) + ((v >> 16) & 0xFFFF) + ((v >> 32) & 0xFFFF) + (v >> 48);
    }
    for (; i + 2 <= n; i += 2) { uint16_t w; std::memcpy(&w, img.data() + i, 2); sum += w; }
    if (n & 1) sum += img[n - 1];
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (DWORD)(sum + n);
}
// A directory nobody but this user (and SYSTEM / Administrators, who can do anything anyway) can
// write to: owned by one of them, a real directory (no reparse point), and no ACE -- inheritable
// ones included, which every copy made inside would get -- grants anyone else a right to add,
// change, delete or re-permission anything there.
static bool dir_private(const std::wstring &path) {
    const DWORD attr = GetFileAttributesW(path.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES || !(attr & FILE_ATTRIBUTE_DIRECTORY) || (attr & FILE_ATTRIBUTE_REPARSE_POINT)) return false;
    static const std::vector<unsigned char> me = [] {          // TokenUser's SID, then TokenOwner's
        std::vector<unsigned char> out;
        HANDLE tok = nullptr;
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) return out;
        for (TOKEN_INFORMATION_CLASS c : {TokenUser, TokenOwner}) {
            DWORD n = 0;
            GetTokenInformation(tok, c, nullptr, 0, &n);
            std::vector<unsigned char> buf(n ? n : 1);
            if (!n || !GetTokenInformation(tok, c, buf.data(), n, &n)) continue;
            PSID sid = c == TokenUser ? reinterpret_cast<TOKEN_USER *>(buf.data())->User.Sid
                                      : reinterpret_cast<TOKEN_OWNER *>(buf.data())->Owner;
            const DWORD len = GetLengthSid(sid);
            const size_t at = out.size();
            out.resize(at + sizeof(DWORD) + len);
            std::memcpy(out.data() + at, &len, sizeof(DWORD));
            CopySid(len, out.data() + at + sizeof(DWORD), sid);
        }
        CloseHandle(tok);
        return out;
    }();
    auto trusted = [](PSID sid) {
        if (!sid || !IsValidSid(sid)) return false;
        for (size_t at = 0; at + sizeof(DWORD) <= me.size(); ) {
            DWORD len; std::memcpy(&len, me.data() + at, sizeof(DWORD));
            if (EqualSid(sid, (PSID)(me.data() + at + sizeof(DWORD)))) return true;
            at += sizeof(DWORD) + len;
        }
        return IsWellKnownSid(sid, WinLocalSystemSid) || IsWellKnownSid(sid, WinBuiltinAdministratorsSid) ||
               IsWellKnownSid(sid, WinCreatorOwnerSid) || IsWellKnownSid(sid, WinCreatorOwnerRightsSid);
    };
    PSID owner = nullptr; PACL dacl = nullptr; PSECURITY_DESCRIPTOR sd = nullptr;
    if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                              &owner, nullptr, &dacl, nullptr, &sd) != ERROR_SUCCESS)
        return false;
    bool ok = !me.empty() && dacl && trusted(owner);              // a NULL DACL grants everyone everything
    constexpr ACCESS_MASK write_rights = FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY | FILE_DELETE_CHILD | DELETE | WRITE_DAC |
                                         WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;
    for (DWORD i = 0; ok && i < dacl->AceCount; ++i) {
        ACE_HEADER *ace = nullptr;
        if (!GetAce(dacl, i, reinterpret_cast<void **>(&ace))) { ok = false; break; }
        if (ace->AceType == ACCESS_DENIED_ACE_TYPE || ace->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE) continue;
        if (ace->AceType != ACCESS_ALLOWED_ACE_TYPE) { ok = false; break; }   // conditional/object/...: not ours
        auto *a = reinterpret_cast<ACCESS_ALLOWED_ACE *>(ace);
        if ((a->Mask & write_rights) && !trusted(reinterpret_cast<PSID>(&a->SidStart))) ok = false;
    }
    LocalFree(sd);
    return ok;
}
// The source agent's version stamp (the warm copies' name) and its build identity (headers).
static std::wstring agent_signature(const std::wstring &path, AgentId *id = nullptr,
                                   std::vector<unsigned char> *source = nullptr) {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return {};
    BY_HANDLE_FILE_INFORMATION bi{}; FILE_BASIC_INFO basic{};
    unsigned char head[4096]; DWORD got = 0;
    bool ok = GetFileInformationByHandle(f, &bi) && GetFileInformationByHandleEx(f, FileBasicInfo, &basic, sizeof(basic));
    if (ok && source) {
        // One sequential read, under the same deny-write handle as the metadata.
        ok = read_whole_file(f, *source) && (!id || image_id(source->data(), source->size(), *id));
        if (ok) trim_agent_image(*source); // already trimmed/unsupported: keep the original bytes
    } else if (ok && id) {
        ok = ReadFile(f, head, sizeof(head), &got, nullptr) && image_id(head, got, *id);
    }
    CloseHandle(f);
    if (!ok) return {};
    wchar_t sig[96];
    _snwprintf_s(sig, _countof(sig), _TRUNCATE, L"%08lx%08lx%08lx%08lx%08lx%08lx%08lx%016llx", bi.dwVolumeSerialNumber,
                 bi.nFileIndexHigh, bi.nFileIndexLow, bi.nFileSizeHigh, bi.nFileSizeLow,
                 bi.ftLastWriteTime.dwHighDateTime, bi.ftLastWriteTime.dwLowDateTime, (unsigned long long)basic.ChangeTime.QuadPart);
    return sig;
}
static bool pid_alive(DWORD pid) {
    HANDLE ph = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    DWORD code = 0;
    const bool alive = ph && GetExitCodeProcess(ph, &code) && code == STILL_ACTIVE;
    if (ph) CloseHandle(ph);
    return alive;
}
static void remove_copy_dir(const std::wstring &d) {
    if (DeleteFileW((d + L"\\probe_api_agent.dll").c_str()) || GetLastError() == ERROR_FILE_NOT_FOUND) RemoveDirectoryW(d.c_str());
}
// Moves a ready warm copy of this build to `dir` (the session's own directory) and verifies its
// content against `want`; `hold` is then the file, open deny-write (close it once loaded). A copy
// that is not exactly ours is deleted (it is in our own directory by then). False: none.
static bool take_warm_copy(const std::wstring &root, const std::wstring &sig, const std::wstring &dir,
                           const AgentId &want, const std::vector<unsigned char> &source, HANDLE &hold) {
    const std::wstring warm = root + L"\\warm";
    hold = INVALID_HANDLE_VALUE;
    if (!dir_private(warm)) return false;
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((warm + L"\\" + sig + L"-*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return false;
    bool got = false;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) continue;
        if (!MoveFileExW((warm + L"\\" + fd.cFileName).c_str(), dir.c_str(), 0)) continue;
        HANDLE f = CreateFileW((dir + L"\\probe_api_agent.dll").c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                               OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
        if (f != INVALID_HANDLE_VALUE) {
            std::vector<unsigned char> img; AgentId have; DWORD sum = 0; size_t sum_at = 0;
            BY_HANDLE_FILE_INFORMATION bi{};
            // One link only: a hard link to a file elsewhere could be changed through its other name.
            if (GetFileInformationByHandle(f, &bi) && bi.nNumberOfLinks == 1 && !(bi.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
                read_whole_file(f, img) && image_id(img.data(), img.size(), have, &sum, &sum_at) && same_id(have, want) &&
                img == source && sum != 0 && pe_checksum(img, sum_at) == sum) {
                hold = f; got = true; break;
            }
            CloseHandle(f);
        }
#if defined(UHH_TEST_HOOKS)
        if (std::getenv("UHH_TEST_REUSE_TRACE"))
            std::fprintf(stderr, "probe: test: reuse warm rejected path=%ls sig=%ls\n", dir.c_str(), sig.c_str());
#endif
        bench_phase("agent_warm_rejected", nullptr);
        remove_copy_dir(dir);                              // not exactly ours (or an empty leftover)
        if (GetFileAttributesW(dir.c_str()) != INVALID_FILE_ATTRIBUTES) {   // could not delete it: out of the way
            MoveFileExW(dir.c_str(), (warm + L"\\x-" + fd.cFileName).c_str(), 0);
            if (GetFileAttributesW(dir.c_str()) != INVALID_FILE_ATTRIBUTES) break;
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    return got;
}
// Prepares one warm copy for a later session (on a thread of its own: it never delays this
// session; a controller that exits meanwhile leaves a t-* directory that the next one sweeps).
static void make_warm_copy(std::wstring root, std::wstring sig, std::wstring src) {
    const std::wstring warm = root + L"\\warm";
    CreateDirectoryW(warm.c_str(), nullptr);
    if (!dir_private(warm)) return;
    unsigned ready = 0;
    WIN32_FIND_DATAW fd{};
    HANDLE h = FindFirstFileW((warm + L"\\*").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        FILETIME now_ft; GetSystemTimeAsFileTime(&now_ft);
        const ULONGLONG now = ((ULONGLONG)now_ft.dwHighDateTime << 32) | now_ft.dwLowDateTime;
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] == L'.') continue;
            const std::wstring name = fd.cFileName, d = warm + L"\\" + name;
            if (name.rfind(L"t-", 0) == 0) {                       // being prepared: by a live controller?
                if (!pid_alive((DWORD)wcstoul(name.c_str() + 2, nullptr, 10))) remove_copy_dir(d);
            } else if (name.rfind(sig + L"-", 0) == 0) {
                ++ready;
            } else {                                               // another build's: kept a day
                const ULONGLONG t = ((ULONGLONG)fd.ftCreationTime.dwHighDateTime << 32) | fd.ftCreationTime.dwLowDateTime;
                if (now > t && now - t > 864000000000ull) remove_copy_dir(d);
            }
        } while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    if (ready >= WARM_KEEP) return;
    static std::atomic<unsigned> counter{0};
    const std::wstring tail = std::to_wstring(GetCurrentProcessId()) + L"-" + std::to_wstring(GetTickCount64()) + L"-" +
                              std::to_wstring(counter++);
    const std::wstring tmp = warm + L"\\t-" + tail, file = tmp + L"\\probe_api_agent.dll";
    if (!CreateDirectoryW(tmp.c_str(), nullptr)) return;
    bool ok = write_trimmed_agent(src, file) || CopyFileW(src.c_str(), file.c_str(), TRUE);
    if (ok) {                                                      // the image section: the scan
        HANDLE f = CreateFileW(file.c_str(), GENERIC_READ | GENERIC_EXECUTE, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        HANDLE m = f != INVALID_HANDLE_VALUE ? CreateFileMappingW(f, nullptr, PAGE_READONLY | SEC_IMAGE, 0, 0, nullptr) : nullptr;
        ok = m != nullptr;
        if (m) CloseHandle(m);
        if (f != INVALID_HANDLE_VALUE) CloseHandle(f);
    }
    // The source unchanged meanwhile (else this copy may be of a newer build than its name says).
    if (ok && agent_signature(src) != sig) ok = false;
    if (!ok || !MoveFileExW(tmp.c_str(), (warm + L"\\" + sig + L"-" + tail).c_str(), 0)) remove_copy_dir(tmp);
}
static void start_warm_copy(const std::wstring &root, const std::wstring &sig, const std::wstring &src) {
    // The thread holds a reference to this library, so a host that unloads it meanwhile is safe.
    HMODULE self = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, reinterpret_cast<LPCWSTR>(&start_warm_copy), &self)) return;
    struct Job { std::wstring root, sig, src; HMODULE self; };
    Job *job = nullptr;
    try { job = new Job{root, sig, src, self}; } catch (...) { FreeLibrary(self); return; }
    HANDLE t = CreateThread(nullptr, 0, [](void *p) -> DWORD {
        Job *j = static_cast<Job *>(p);
        const HMODULE m = j->self;
        try { make_warm_copy(j->root, j->sig, j->src); } catch (...) {}
        delete j;
        FreeLibraryAndExitThread(m, 0);
    }, job, 0, nullptr);
    if (t) { SetThreadPriority(t, THREAD_PRIORITY_BELOW_NORMAL); CloseHandle(t); }
    else { delete job; FreeLibrary(self); }
}

// The body of the agent preparation (agent_prep's thread, or inline): the per-session copy, then
// the load. Touches only agent_path / agent_copy / agent_prep_*: nothing else reads them until
// ensure_local_agent has joined.
static void prepare_local_agent(probe_session *s) {
    bench_phase("agent_begin", nullptr);
    std::wstring warm_sig, warm_root, warm_src;
    HANDLE warm_hold = INVALID_HANDLE_VALUE;              // the verified warm copy, deny-write until loaded
    if (s->agent_path.empty()) {
        s->agent_path = sibling_agent_path();
        if (file_has_section(s->agent_path, "uhhshr")) {
            bench_phase("agent_sweep", nullptr);
            wchar_t tmp[MAX_PATH]; DWORD n = GetTempPathW(MAX_PATH, tmp);
            if (n && n < MAX_PATH - 64) {
                std::wstring root = std::wstring(tmp) + L"uhh";
                CreateDirectoryW(root.c_str(), nullptr);
                WIN32_FIND_DATAW fd{}; HANDLE h = FindFirstFileW((root + L"\\*").c_str(), &fd);   // sweep
                if (h != INVALID_HANDLE_VALUE) {
                    do {
                        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || fd.cFileName[0] == L'.') continue;
                        // Only copies of DEAD controllers: a live session may have just made its
                        // copy and not loaded it yet (it would look unused). Name: <pid>-<tick>-<n>.
                        // Nothing else here is touched: this runs on the agent-prep thread while the
                        // launch creates logs\ and its session file, and an empty logs\ removed between
                        // the two failed the launch ("create probe log file (Win32=3)", CI x86).
                        wchar_t *end = nullptr;
                        const DWORD owner = (DWORD)wcstoul(fd.cFileName, &end, 10);
                        if (!owner || !end || *end != L'-') continue;
                        if (pid_alive(owner)) continue;
                        std::wstring d = root + L"\\" + fd.cFileName;
                        if (DeleteFileW((d + L"\\probe_api_agent.dll").c_str()) || GetLastError() == ERROR_FILE_NOT_FOUND)
                            RemoveDirectoryW(d.c_str());          // in use by a live session: left alone
                    } while (FindNextFileW(h, &fd));
                    FindClose(h);
                }
                static std::atomic<unsigned> counter{0};
                std::wstring dir = root + L"\\" + std::to_wstring(GetCurrentProcessId()) + L"-" +
                                   std::to_wstring(GetTickCount64()) + L"-" + std::to_wstring(counter++);
                std::wstring copy = dir + L"\\probe_api_agent.dll";
                bench_phase("agent_copy", nullptr);
                static const bool no_warm = std::getenv("UHH_BENCH_NO_WARM") != nullptr;   // bench knob, not API
                AgentId want;
                std::vector<unsigned char> source;
                if (!no_warm && dir_private(root)) warm_sig = agent_signature(s->agent_path, &want, &source);
#if defined(UHH_TEST_HOOKS)
                if (std::getenv("UHH_TEST_REUSE_TRACE"))
                    std::fprintf(stderr, "probe: test: reuse source=%ls sig=%ls normalized_bytes=%zu\n",
                                 s->agent_path.c_str(), warm_sig.c_str(), source.size());
#endif
                bench_phase("agent_copy_checked", nullptr);
                warm_root = root; warm_src = s->agent_path;
                const bool warm = !warm_sig.empty() && take_warm_copy(root, warm_sig, dir, want, source, warm_hold);
#if defined(UHH_TEST_HOOKS)
                if (std::getenv("UHH_TEST_REUSE_TRACE"))
                    std::fprintf(stderr, "probe: test: reuse source=%ls sig=%ls selected=%s copy=%ls\n",
                                 warm_src.c_str(), warm_sig.c_str(), warm ? "content-verified warm" : "new", copy.c_str());
#endif
                bench_phase("agent_copy_kind", warm ? "warm" : "new");
                if (warm || (CreateDirectoryW(dir.c_str(), nullptr) &&
                             (write_trimmed_agent(s->agent_path, copy) || CopyFileW(s->agent_path.c_str(), copy.c_str(), TRUE)))) {
                    s->agent_path = copy; s->agent_copy = copy;
                } else {
                    std::fprintf(stderr, "probe: warning: could not make a per-session copy of the agent DLL; "
                                         "UHH_SHARED state is shared with other sessions using the same file\n");
                }
            }
        }
    }
    bench_phase("agent_load", nullptr);
    s->agent_prep_module = LoadLibraryW(s->agent_path.c_str());
    s->agent_prep_error = s->agent_prep_module ? 0 : GetLastError();
    if (warm_hold != INVALID_HANDLE_VALUE) CloseHandle(warm_hold);
    bench_phase("agent_loaded", nullptr);
    // The next session's warm copy, once this one's agent is loaded (measured: started before
    // this load, its scan queued in front of it and the launch took 128 ms instead of 53).
    if (s->agent_prep_module && !warm_sig.empty()) start_warm_copy(warm_root, warm_sig, warm_src);
}

void start_agent_prep(probe_session *s) {
    if (s->local_agent || s->agent_prep.joinable() || s->agent_prep_module || s->agent_prep_error) return;
    try { s->agent_prep = std::thread(prepare_local_agent, s); }
    catch (...) { prepare_local_agent(s); }                  // no thread: here and now
}

static bool ensure_local_agent(probe_session *s) {
    if (s->local_agent) return true;
    if (!s->agent_prep.joinable() && !s->agent_prep_module && !s->agent_prep_error) prepare_local_agent(s);
    if (s->agent_prep.joinable()) s->agent_prep.join();
    s->local_agent = s->agent_prep_module;
    if (!s->local_agent) SetLastError(s->agent_prep_error);
    if (!s->local_agent || !GetProcAddress(s->local_agent, "probe_agent_init")) {
        s->agent_prep_error = s->agent_prep_error ? s->agent_prep_error : GetLastError();
        set_error(s, win_error("map probe_api_agent.dll exports")); return false;
    }
    // Callbacks this process runs from its copy of the agent DLL must reach THIS library.
    using bind_fn = void (*)(const probe_controller_api *);
    if (auto bind = reinterpret_cast<bind_fn>(GetProcAddress(s->local_agent, "probe_agent_bind_controller")))
        bind(controller_api_table());
    // UHH_SHARED callbacks added before the agent was loaded: bound to its copy now.
    for (auto &p : s->probes) {
        if (p->shared_export.empty()) continue;
        auto shared_cb = reinterpret_cast<probe_callback>(GetProcAddress(s->local_agent, p->shared_export.c_str()));
        if (!shared_cb) { set_error(s, "UHH_SHARED callback '" + p->shared_export + "' is not exported by the agent DLL"); return false; }
        p->callback = shared_cb;
        p->shared_export.clear();
    }
    return true;
}

static bool read_file_exports(const std::wstring &path, std::unordered_set<std::string> &out);

// Reattach must map the very same file as the retained target image: this both
// validates export RVAs and reconnects the image's UHH_SHARED section.
bool reuse_target_agent(probe_session *s) {
    bool needed = false;
    for (const auto &p : s->probes) if ((p->flags & PROBE_INLINE) || !p->shared_export.empty()) needed = true;
    if (!needed) return true;
    auto unknown = [&](const char *why) {
        set_error(s, std::string("retained inline agent unknown-image: ") + why +
                     "; restart the target before attaching");
        return false;
    };
#if defined(UHH_TEST_HOOKS)
    const bool reuse_trace = std::getenv("UHH_TEST_REUSE_TRACE") != nullptr;
#else
    const bool reuse_trace = false;
#endif
    // Identify UHH from mapped PE exports, never from the loader list or filename.
    // Unreadable/unrelated images are not evidence of a retained agent.
    struct Retained { uintptr_t base; IMAGE_NT_HEADERS nt; const char *how; };
    std::vector<Retained> agents;
    for (uintptr_t at = 0; ; ) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQueryEx(s->pi.hProcess, reinterpret_cast<void *>(at), &mbi, sizeof(mbi))) {
            if (reuse_trace) std::fprintf(stderr, "probe: test: reuse scan end at=0x%llx error=%lu\n",
                                         (unsigned long long)at, GetLastError());
            break;
        }
        const uintptr_t next = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
        if (mbi.Type == MEM_IMAGE && mbi.BaseAddress == mbi.AllocationBase) {
            const uintptr_t base = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
            IMAGE_NT_HEADERS nt{};
            const char *how = "headers";
            DWORD export_names = 0;
            char dll_name[64] = {};
            auto identify = [&]() {
                uint64_t limit = 1u << 20; // bound header reads before SizeOfImage is known
                auto read = [&](uint64_t rva, void *dst, size_t n) {
                    SIZE_T got = 0;
                    const bool ok = rva <= limit && n <= limit - rva && rva <= UINTPTR_MAX - base &&
                        n <= UINTPTR_MAX - base - rva &&
                        ReadProcessMemory(s->pi.hProcess, reinterpret_cast<void *>(base + (uintptr_t)rva),
                                          dst, n, &got) && got == n;
                    if (!ok && reuse_trace) std::fprintf(stderr,
                        "probe: test: reuse read failed base=0x%llx rva=0x%llx bytes=%zu got=%zu error=%lu\n",
                        (unsigned long long)base, (unsigned long long)rva, n, (size_t)got, GetLastError());
                    return ok;
                };
                IMAGE_DOS_HEADER dos{};
                if (!read(0, &dos, sizeof(dos)) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 ||
                    !read(dos.e_lfanew, &nt, sizeof(nt)) || nt.Signature != IMAGE_NT_SIGNATURE ||
                    nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) return false;
#if defined(UHH_TEST_HOOKS)
                if (!(nt.FileHeader.Characteristics & IMAGE_FILE_DLL)) {
                    if (std::getenv("UHH_TEST_REUSE_UNKNOWN")) {
                        // No filename is available for this non-agent. Discovery
                        // must use memory alone, so no name lookup is needed.
                        std::fprintf(stderr, "probe: test: unrelated image unidentified\n");
                    }
                    if (std::getenv("UHH_TEST_REUSE_UNREADABLE_NON_AGENT")) {
                        // Simulate failure of its remaining PE/export reads.
                        std::fprintf(stderr, "probe: test: unrelated image headers unreadable\n"); return false;
                    }
                }
#endif
                how = "export directory";
                limit = nt.OptionalHeader.SizeOfImage;
                if (!limit || limit > (256u << 20) ||
                    nt.OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return false;
                const auto &dir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
                IMAGE_EXPORT_DIRECTORY exp{};
                if (!dir.VirtualAddress || !read(dir.VirtualAddress, &exp, sizeof(exp))) return false;
                export_names = exp.NumberOfNames;
                if (reuse_trace && exp.Name) {
                    read(exp.Name, dll_name, sizeof(dll_name) - 1);
                    dll_name[sizeof(dll_name) - 1] = 0;
                }
                auto named = [&](DWORD rva, const char *want) {
                    char name[64] = {};
                    const size_t n = strlen(want) + 1;
                    return n <= sizeof(name) && read(rva, name, n) && !memcmp(name, want, n);
                };
#if defined(UHH_TEST_HOOKS)
                const bool no_dll_name = std::getenv("UHH_TEST_REUSE_NO_EXPORT_DLL_NAME") != nullptr;
#else
                const bool no_dll_name = false;
#endif
                if (!no_dll_name && exp.Name && named(exp.Name, "probe_api_agent.dll")) {
                    how = "DLL name"; return true;
                }
                how = "control exports";
                // Export names are sorted. The agent includes all callback exports
                // (far more than 64), so search instead of capping the name count.
                if (exp.NumberOfNames > limit / sizeof(DWORD)) return false;
                auto exported = [&](const char *want) {
                    DWORD lo = 0, hi = exp.NumberOfNames;
                    while (lo < hi) {
                        const DWORD mid = lo + (hi - lo) / 2;
                        DWORD rva = 0;
                        if (!read((uint64_t)exp.AddressOfNames + (uint64_t)mid * sizeof(DWORD), &rva, sizeof(rva))) return false;
                        // One remote read per probe (inside the image: read() bounds it by
                        // SizeOfImage); names longer than the buffer compare by their prefix,
                        // which decides against our short names exactly as a full compare would.
                        unsigned char name[40] = {};       // longer than every name we look for
                        if (rva >= limit) return false;
                        const size_t len = (size_t)std::min<uint64_t>(sizeof(name), limit - rva);
                        const bool bulk = read(rva, name, len);
                        int cmp = 0;
                        for (size_t k = 0; ; ++k) {        // want's NUL ends it in time
                            unsigned char ch = 0;
                            if (bulk && k < len) ch = name[k];
                            else if (!read((uint64_t)rva + k, &ch, 1)) return false;
                            cmp = (int)ch - (unsigned char)want[k];
                            if (cmp || !want[k]) break;
                        }
                        if (!cmp) return true;
                        if (cmp < 0) lo = mid + 1;
                        else hi = mid;
                    }
                    return false;
                };
                const bool init = exported("probe_agent_init"), stop = exported("probe_agent_stop"),
                           bind = exported("probe_agent_bind_controller");
                if (reuse_trace) std::fprintf(stderr,
                    "probe: test: reuse controls base=0x%llx init=%d stop=%d bind=%d\n",
                    (unsigned long long)base, (int)init, (int)stop, (int)bind);
                return init && stop && bind;
            };
            const bool identified = identify();
            if (reuse_trace) std::fprintf(stderr,
                "probe: test: reuse image base=0x%llx %s via=%s magic=0x%x machine=0x%x names=%lu DLL=%s\n",
                (unsigned long long)base, identified ? "identified" : "skip", how,
                nt.OptionalHeader.Magic, nt.FileHeader.Machine, export_names, dll_name);
            if (identified) agents.push_back({base, nt, how});
        }
        if (next <= at) break;
        at = next;
    }
    if (agents.size() > 1) return unknown("multiple retained agents");
    for (const auto &agent : agents) {
#if defined(UHH_TEST_HOOKS)
        if (std::getenv("UHH_TEST_REUSE_AGENT_UNREADABLE")) return unknown("test: agent identity unreadable");
#endif
        if (!ensure_local_agent(s)) return false;
        // The same PE build fields/checksum used for warm-copy identity, read
        // from the loaded image before consulting its backing file.
        const auto *local_dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(s->local_agent);
        const auto *local_nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(
            reinterpret_cast<const unsigned char *>(s->local_agent) + local_dos->e_lfanew);
        const auto &have_nt = agent.nt;
        if (reuse_trace) {
            auto headers = [&](const char *which, uintptr_t base, const IMAGE_NT_HEADERS &nt) {
                std::fprintf(stderr, "probe: test: reuse %s base=0x%llx via=%s magic=0x%x machine=0x%x "
                             "stamp=0x%lx sections=%u size=0x%lx entry=0x%lx version=%u.%u checksum=0x%lx\n",
                             which, (unsigned long long)base, agent.how, nt.OptionalHeader.Magic,
                             nt.FileHeader.Machine, nt.FileHeader.TimeDateStamp, nt.FileHeader.NumberOfSections,
                             nt.OptionalHeader.SizeOfImage, nt.OptionalHeader.AddressOfEntryPoint,
                             nt.OptionalHeader.MajorImageVersion, nt.OptionalHeader.MinorImageVersion, nt.OptionalHeader.CheckSum);
            };
            headers("target", agent.base, have_nt);
            headers("controller", reinterpret_cast<uintptr_t>(s->local_agent), *local_nt);
        }
        const bool same = have_nt.FileHeader.TimeDateStamp == local_nt->FileHeader.TimeDateStamp &&
            have_nt.FileHeader.Machine == local_nt->FileHeader.Machine &&
            have_nt.FileHeader.NumberOfSections == local_nt->FileHeader.NumberOfSections &&
            have_nt.OptionalHeader.SizeOfImage == local_nt->OptionalHeader.SizeOfImage &&
            have_nt.OptionalHeader.AddressOfEntryPoint == local_nt->OptionalHeader.AddressOfEntryPoint &&
            have_nt.OptionalHeader.MajorImageVersion == local_nt->OptionalHeader.MajorImageVersion &&
            have_nt.OptionalHeader.MinorImageVersion == local_nt->OptionalHeader.MinorImageVersion &&
            have_nt.OptionalHeader.CheckSum == local_nt->OptionalHeader.CheckSum;
        if (reuse_trace) std::fprintf(stderr, "probe: test: reuse headers %s\n", same ? "match" : "differ");
        if (!same) {
            set_error(s, "retained inline agent differs from this build; restart the target before attaching"); return false;
        }
        wchar_t path[32768];
        DWORD n = K32GetModuleFileNameExW(s->pi.hProcess, reinterpret_cast<HMODULE>(agent.base),
                                        path, (DWORD)(sizeof(path) / sizeof(path[0])));
#if defined(UHH_TEST_HOOKS)
        if (std::getenv("UHH_TEST_REUSE_NO_MODULE_NAME")) n = 0;
#endif
        std::wstring file;
        if (n && n < sizeof(path) / sizeof(path[0])) file.assign(path, n);
        else {
            n = K32GetMappedFileNameW(s->pi.hProcess, reinterpret_cast<void *>(agent.base), path,
                                     (DWORD)(sizeof(path) / sizeof(path[0])));
            if (!n || n >= sizeof(path) / sizeof(path[0])) return unknown(win_error("mapped agent filename").c_str());
            if (reuse_trace) std::fprintf(stderr, "probe: test: reuse mapped path=%ls\n", path);
            file = L"\\\\?\\GLOBALROOT" + std::wstring(path, n);
            // Prefer the DOS spelling for the retained file (also used by the
            // loader). Keep GLOBALROOT only for volumes with no drive alias.
            wchar_t drives[512];
            const DWORD count = GetLogicalDriveStringsW(_countof(drives), drives);
            if (count && count < _countof(drives)) {
                for (const wchar_t *drive = drives; *drive; drive += wcslen(drive) + 1) {
                    wchar_t letter[3] = {drive[0], L':', 0}, device[512];
                    if (!QueryDosDeviceW(letter, device, _countof(device))) continue;
                    const size_t len = wcslen(device);
                    if (len < n && path[len] == L'\\' && !_wcsnicmp(path, device, len)) {
                        file = std::wstring(letter) + (path + len); break;
                    }
                }
            }
        }
#if defined(UHH_TEST_HOOKS)
        if (std::getenv("UHH_TEST_REUSE_STALE_MAPPED_NAME")) file += L".missing";
#endif
        auto read = [](const std::wstring &file, std::vector<unsigned char> &bytes) {
            HANDLE f = CreateFileW(file.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE,
                                   nullptr, OPEN_EXISTING, 0, nullptr);
            if (f == INVALID_HANDLE_VALUE) return false;
            const bool ok = read_whole_file(f, bytes);
            const DWORD error = GetLastError(); CloseHandle(f);
            if (!ok) SetLastError(error);
            if (ok) trim_agent_image(bytes);
            return ok;
        };
        std::vector<unsigned char> want, have;
        if (!read(s->agent_path, want)) return unknown(win_error("read controller agent file").c_str());
        if (reuse_trace) std::fprintf(stderr, "probe: test: reuse files controller=%ls target=%ls\n",
                                     s->agent_path.c_str(), file.c_str());
        if (!read(file, have)) {
            DWORD error = GetLastError();
            if (reuse_trace) std::fprintf(stderr, "probe: test: reuse retained file read failed error=%lu\n", error);
            // A warmed image section can retain its pre-rename filename. Find
            // the current loader path for this exact, memory-identified base;
            // this lookup cannot authorize fresh injection or select another DLL.
            HANDLE snap = INVALID_HANDLE_VALUE;
            for (int attempt = 0; attempt < 3; ++attempt) {
                snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetProcessId(s->pi.hProcess));
                if (snap != INVALID_HANDLE_VALUE || GetLastError() != ERROR_BAD_LENGTH) break;
            }
            bool recovered = false;
            if (snap != INVALID_HANDLE_VALUE) {
                MODULEENTRY32W entry{}; entry.dwSize = sizeof(entry);
                if (Module32FirstW(snap, &entry)) do {
                    if (reinterpret_cast<uintptr_t>(entry.modBaseAddr) != agent.base) continue;
                    file = entry.szExePath;
                    if (reuse_trace) std::fprintf(stderr, "probe: test: reuse snapshot path=%ls\n", file.c_str());
                    recovered = read(file, have);
                    if (!recovered) error = GetLastError();
                    break;
                } while (Module32NextW(snap, &entry));
                CloseHandle(snap);
            }
            if (!recovered) {
                SetLastError(error); return unknown(win_error("read retained agent file").c_str());
            }
        }
        if (reuse_trace) std::fprintf(stderr, "probe: test: reuse normalized files %s controller=%ls target=%ls\n",
                                     want == have ? "match" : "differ", s->agent_path.c_str(), file.c_str());
        if (want != have) {
            set_error(s, "retained inline agent differs from this build; restart the target before attaching"); return false;
        }
        // ensure_local_agent may already have bound pending callbacks to the new copy.
        for (auto &p : s->probes) {
            HMODULE owner{};
            if (!(p->flags & PROBE_INLINE) && module_of(reinterpret_cast<const void *>(p->callback), owner) &&
                owner == s->local_agent && !callback_export_name(p->callback, p->shared_export)) {
                set_error(s, "cannot rebind retained agent callback"); return false;
            }
        }
        FreeLibrary(s->local_agent); s->local_agent = nullptr; s->agent_prep_module = nullptr;
        s->agent_path = file; s->agent_prep_error = 0;
        return ensure_local_agent(s);
    }
    return true;
}

// The export names of the agent DLL FILE (the per-session copy is the same bytes), read from the
// file's export directory -- so a probe_add can refuse a UHH_SHARED callback the agent does not
// export without waiting for the agent to load.
static bool read_file_exports(const std::wstring &path, std::unordered_set<std::string> &out) {
    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (f == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER size{};
    std::vector<unsigned char> img;
    bool ok = GetFileSizeEx(f, &size) && size.QuadPart > 0 && size.QuadPart < (256ll << 20);
    if (ok) {
        img.resize((size_t)size.QuadPart);
        DWORD got = 0;
        ok = ReadFile(f, img.data(), (DWORD)img.size(), &got, nullptr) && got == img.size();
    }
    CloseHandle(f);
    if (!ok || img.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    auto in = [&](uint64_t off, uint64_t n) { return off <= img.size() && n <= img.size() - off; };
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER *>(img.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0 || !in((uint64_t)dos->e_lfanew, sizeof(IMAGE_NT_HEADERS))) return false;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS *>(img.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.NumberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_EXPORT) return false;
    auto sec = IMAGE_FIRST_SECTION(nt);
    const WORD nsec = nt->FileHeader.NumberOfSections;
    if (!in((uint64_t)((const unsigned char *)sec - img.data()), (uint64_t)nsec * sizeof(IMAGE_SECTION_HEADER))) return false;
    auto offset_of = [&](uint64_t rva, uint64_t &off) {
        for (WORD i = 0; i < nsec; ++i)
            if (rva >= sec[i].VirtualAddress && rva < (uint64_t)sec[i].VirtualAddress + sec[i].SizeOfRawData) {
                off = rva - sec[i].VirtualAddress + sec[i].PointerToRawData; return true;
            }
        return false;
    };
    const auto &dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    uint64_t eoff = 0;
    if (!dir.VirtualAddress) return true;                       // no exports
    if (!offset_of(dir.VirtualAddress, eoff) || !in(eoff, sizeof(IMAGE_EXPORT_DIRECTORY))) return false;
    auto ed = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY *>(img.data() + eoff);
    uint64_t noff = 0;
    if (ed->NumberOfNames && (!offset_of(ed->AddressOfNames, noff) || !in(noff, (uint64_t)ed->NumberOfNames * 4))) return false;
    for (DWORD i = 0; i < ed->NumberOfNames; ++i) {
        DWORD rva; std::memcpy(&rva, img.data() + noff + 4ull * i, 4);
        uint64_t off = 0;
        if (!offset_of(rva, off) || !in(off, 1)) return false;
        const char *name = reinterpret_cast<const char *>(img.data() + off);
        const size_t len = strnlen(name, img.size() - off);
        out.emplace(name, len);
    }
    return true;
}

// A breakpoint/hw callback whose module uses UHH_SHARED runs from the controller's copy of
// the agent DLL (found by export name), so it shares those globals with inline callbacks.
bool bind_shared_callback(probe_session *s, probe_callback &cb, uint32_t flags, std::string &pending_export) {
    if (flags & PROBE_INLINE) return true;                   // runs in the target's copy anyway
    HMODULE m{};
    if (!module_of(reinterpret_cast<const void *>(cb), m) || m == s->local_agent ||
        !image_has_section(reinterpret_cast<const unsigned char *>(m), "uhhshr")) return true;
    std::string name;
    if (!callback_export_name(cb, name)) {
        set_error(s, "callback uses UHH_SHARED state but is not a named export (the controller runs it from the agent DLL)");
        return false;
    }
    if (!s->local_agent && !s->launched) {
        // Before the launch/attach: checked against the agent file's exports now, bound once the
        // agent is loaded (ensure_local_agent; the load runs meanwhile, start_agent_prep).
        start_agent_prep(s);                     // first: the export check below reads the file too
        if (!s->agent_file_exports_read) {
            s->agent_file_exports_read = true;
            if (!read_file_exports(sibling_agent_path(), s->agent_file_exports)) s->agent_file_exports.clear();
        }
        if (!s->agent_file_exports.empty()) {
            if (!s->agent_file_exports.count(name)) {
                set_error(s, "UHH_SHARED callback '" + name + "' is not exported by the agent DLL"); return false;
            }
            pending_export = name;
            return true;
        }
    }
    if (!ensure_local_agent(s)) return false;
    auto shared_cb = reinterpret_cast<probe_callback>(GetProcAddress(s->local_agent, name.c_str()));
    if (!shared_cb) { set_error(s, "UHH_SHARED callback '" + name + "' is not exported by the agent DLL"); return false; }
    cb = shared_cb;
    return true;
}

bool resolve_inline(probe_session *s, Probe &p, uint64_t base) {
    if (p.rva > UINT64_MAX - base) { set_error(s, "probe address overflow"); return false; }
    if (!s->shared || p.agent_index >= s->shared->request_count) {
        set_error(s, "inline shared request is unavailable"); return false;
    }
    p.base = base; p.address = base + p.rva;
    auto &request = s->shared->requests[p.agent_index];
    request.site = p.address; MemoryBarrier();
    // A probe re-armed after its module was unloaded and loaded again: a new install.
    if (request.status != PROBE_AGENT_PENDING) InterlockedExchange(&request.status, PROBE_AGENT_PENDING);
    std::fprintf(stderr, "probe: resolved %s -> base=0x%llx addr=0x%llx (awaiting agent)\n",
                 p.location.c_str(), (unsigned long long)base, (unsigned long long)p.address);
    return true;
}

static bool open_agent_section(probe_session *s, uint32_t count) {
    if (count && int3_armed(s) > PROBE_AGENT_INT3_CAP) { // the agent's INT3 copy could not hold them all
        set_error(s, "too many software breakpoints armed alongside inline probes (max " +
                     std::to_string(PROBE_AGENT_INT3_CAP) + ")");
        return false;
    }
    wchar_t name[64]; probe_agent_mapping_name(s->pi.dwProcessId, name);
    s->mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
                                    (DWORD)sizeof(probe_agent_shared), name);
    const bool existing = s->mapping && GetLastError() == ERROR_ALREADY_EXISTS;
    if (!s->mapping || (existing && !s->attached)) {
        set_error(s, win_error("create inline shared section")); return false;
    }
    s->shared = static_cast<probe_agent_shared *>(MapViewOfFile(
        s->mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(probe_agent_shared)));
    if (!s->shared) { set_error(s, win_error("map inline shared section")); return false; }
    if (existing && (s->shared->magic != PROBE_AGENT_MAGIC || s->shared->version != PROBE_AGENT_VERSION)) {
        set_error(s, "incompatible existing inline shared section"); return false;
    }
    // Usually the detached agent is quiescent: reuse BOTH its section and target view/handle.
    // A suspended (or otherwise possibly surviving) callback still owns the old storage;
    // only that exceptional case retains it and uses an unnamed channel instead.
    if (existing && !probe_agent_running(s->shared)) {
        s->agent_mapping = (HANDLE)(uintptr_t)s->shared->agent_mapping;
    } else if (existing) {
        UnmapViewOfFile(s->shared); CloseHandle(s->mapping);
        s->mapping = CreateFileMappingW(INVALID_HANDLE_VALUE, nullptr, PAGE_READWRITE, 0,
                                        (DWORD)sizeof(probe_agent_shared), nullptr);
        s->shared = s->mapping ? static_cast<probe_agent_shared *>(MapViewOfFile(
            s->mapping, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(probe_agent_shared))) : nullptr;
        if (!s->shared) { set_error(s, win_error("map replacement inline shared section")); return false; }
    }
    if (!s->agent_mapping) {
        if (!DuplicateHandle(GetCurrentProcess(), s->mapping, s->pi.hProcess,
                             &s->agent_mapping, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            set_error(s, win_error("duplicate inline shared section")); return false;
        }
        s->agent_mapping_duplicated = true;
    }
    // Invalidate old per-hit snapshots before resetting counters; never clear the epoch itself.
    InterlockedIncrement(&s->shared->session_epoch);
    constexpr size_t epoch_end = offsetof(probe_agent_shared, session_epoch) + sizeof(LONG);
    std::memset(s->shared, 0, offsetof(probe_agent_shared, session_epoch));
    std::memset((char *)s->shared + epoch_end, 0, sizeof(*s->shared) - epoch_end);
    s->shared->agent_mapping = (uint64_t)(uintptr_t)s->agent_mapping;
    s->shared->magic = PROBE_AGENT_MAGIC; s->shared->version = PROBE_AGENT_VERSION;
    s->shared->request_count = count;
    bench_phase("section_mapped");
    for (uint32_t i = 0; i < PROBE_AGENT_LOG_CAP; ++i) s->shared->logs[i].seq = i;   // ring: all free
    bench_phase("section_ring");
    sync_int3_table(s);                                 // breakpoints armed before the channel existed
    s->shared->controller_pid = GetCurrentProcessId();
    s->shared->log_ipc = 1;                     // this debugger services PROBE_IPC_LOG (cleared before it leaves)
    // Benchmark-only knob (not API): compare inline extended-state handling strategies.
    if (const char *m = std::getenv("UHH_BENCH_XSTATE"))
        s->shared->xstate_mode = !std::strcmp(m, "none") ? 1 : !std::strcmp(m, "full") ? 2 :
                                 !std::strcmp(m, "noxsave") ? 3 : !std::strcmp(m, "fx") ? 4 :
                                 !std::strcmp(m, "fnsave") ? 5 : 0;   // 3: regress, a CPU without OSXSAVE; 4/5: x86 bench
    if (s->attached) {          // the agent's guard waits on this handle (closes it itself)
        HANDLE dup = nullptr;
        if (DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), s->pi.hProcess, &dup, SYNCHRONIZE, FALSE, 0))
            s->shared->guard.controller_process = (LONG64)(uintptr_t)dup;
        s->guard_since = GetTickCount64();
    }
    if (!s->drain_event) {
        wchar_t dn[64]; probe_agent_drain_name(s->pi.dwProcessId, dn);
        s->drain_event = CreateEventW(nullptr, FALSE, FALSE, dn);   // auto-reset; none: the drainer polls
    }
    start_drainer(s);
    wchar_t svc[64]; probe_agent_service_name(s->pi.dwProcessId, svc);
    s->svc_event = CreateEventW(nullptr, FALSE, FALSE, svc);
    bench_phase("section_drainer");
    const bool la = ensure_local_agent(s);
    bench_phase("local_agent");
    return la;
}

// Before dropping the debug port: a 0 ms detach may never have started agent init.
// Its unused duplicate must not keep a multi-MB section alive in a target with no agent.
// Borrowed handles, and any handle an init could already be using, remain the agent's.
void release_unclaimed_agent_mapping(probe_session *s) {
    if (!s->agent_mapping_duplicated || s->agent_init_started || !s->agent_mapping) return;
    if (s->shared) s->shared->agent_mapping = 0;
    DuplicateHandle(s->pi.hProcess, s->agent_mapping, nullptr, nullptr, 0, FALSE, DUPLICATE_CLOSE_SOURCE);
    s->agent_mapping = nullptr;
    s->agent_mapping_duplicated = false;
}

// A config larger than the request's inline buffer goes to a block allocated in the target
// (freed at close unless a callback may still read it), so an inline probe takes the same configs as a breakpoint/hw probe. If
// that block cannot be made, config_remote stays 0 and the agent refuses the request.
static void fill_request(probe_session *s, const Probe &p) {
    auto &request = s->shared->requests[p.agent_index]; request.flags = p.flags;
    request.config_len = (uint32_t)p.config.size();
    std::memcpy(request.callback, p.callback_export.c_str(), p.callback_export.size() + 1);   // '\n'-separated aliases
    if (p.config.size() <= PROBE_AGENT_CONFIG_CAP) {
        if (!p.config.empty()) std::memcpy(request.config, p.config.data(), p.config.size());
        return;
    }
    void *mem = VirtualAllocEx(s->pi.hProcess, nullptr, p.config.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    size_t wrote = 0;
    if (!mem) return;
    if (!remote_write(s->pi.hProcess, (uint64_t)(uintptr_t)mem, p.config.data(), p.config.size(), &wrote) ||
        wrote != p.config.size()) { VirtualFreeEx(s->pi.hProcess, mem, 0, MEM_RELEASE); return; }
    s->config_blocks.push_back((uint64_t)(uintptr_t)mem);
    request.config_remote = (uint64_t)(uintptr_t)mem;
}

bool create_agent_channel(probe_session *s) {
    uint32_t count = 0;
    {
        std::lock_guard<std::mutex> lock(s->agent_mu);
        for (auto &m : s->agent_map) m = UINT32_MAX;
        for (size_t i = 0; i < s->probes.size(); ++i)
            if (s->probes[i]->flags & PROBE_INLINE) {
                if (count < PROBE_AGENT_MAX_PROBES) s->agent_map[count] = (uint32_t)i;
                s->probes[i]->agent_index = count++;
            }
    }
    if (!count) return true;          // no inline probe (yet): no agent, no channel (see guard_pending)
    if (count > PROBE_AGENT_MAX_PROBES) { set_error(s, "too many inline probes"); return false; }
    if (!open_agent_section(s, count)) return false;
    for (const auto &p : s->probes) if (p->flags & PROBE_INLINE) fill_request(s, *p);
    return true;
}
// An inline probe added while the target runs (from a callback). It gets the next free
// request slot -- creating the channel on first use -- and is installed by the agent on
// a FRESH remote thread, never inside the calling callback: the installer freezes other
// threads, and the caller may hold locks (heap, loader) a frozen thread is waiting on.
// confirm_runtime_inline holds the caller while a mapped installation confirms.
bool register_runtime_inline(probe_session *s, Probe &p) {
    if (!s->shared && !open_agent_section(s, 0)) return false;
    uint32_t idx = s->shared->request_count;
    if (idx >= PROBE_AGENT_MAX_PROBES) { set_error(s, "too many inline probes"); return false; }
    p.agent_index = idx; p.runtime = true;
    {
        std::lock_guard<std::mutex> lock(s->agent_mu);
        if (idx == 0) for (auto &m : s->agent_map) m = UINT32_MAX;
        s->agent_map[idx] = probe_index(s, &p);
    }
    fill_request(s, p);
    MemoryBarrier();
    s->shared->request_count = idx + 1;
    // The add waits in confirm_runtime_inline before returning to its callback. Do not
    // queue another post-callback hold: confirmation may already have released the others.
    return true;
}

// ---- Synchronous inline install -----------------------------------------------------
// An inline hook installed asynchronously races the target's first calls unless the
// target happens to wait. So threads that could reach an uninstalled site are HELD
// (suspended) until the agent confirms the install round: the main thread at the image
// entry point (the loader lock is free there, so the agent can still be loaded), and a
// thread that is loading a DLL with inline sites (it holds the loader lock, so the
// install is done by the agent's already-running service thread, never a new thread).
static bool inline_unconfirmed(const probe_session *s) {
    for (const auto &p : s->probes)
        if ((p->flags & PROBE_INLINE) && p->address && !p->active && !p->retired) return true;
    return false;
}

// Hold the main thread at the entry point while an inline install is outstanding OR
// while inline probes exist but the agent's service thread is not up yet: a module
// with an inline site may load at any moment after entry, and the thread loading it
// holds the loader lock -- only an already-running service thread can install then.
bool inline_hold_needed(const probe_session *s) {
    if (inline_unconfirmed(s)) return true;
    return has_inline(s) && !(s->shared && s->shared->service_ready && s->svc_event);
}

// A thread of OUR agent (its service thread, started from the agent image): never hold it
// -- it may own the agent's install lock or be the one that must do the install.
bool agent_thread(const probe_session *s, DWORD tid) {
    if (!s->remote_agent) return false;
    using QueryFn = LONG(NTAPI *)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static auto query = reinterpret_cast<QueryFn>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationThread"));
    HANDLE t = OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
    if (!t || !query) { if (t) CloseHandle(t); return false; }
    PVOID start = nullptr;
    LONG st = query(t, 9 /*ThreadQuerySetWin32StartAddress*/, &start, sizeof(start), nullptr);
    CloseHandle(t);
    if (st < 0) return false;
    IMAGE_DOS_HEADER dos{}; IMAGE_NT_HEADERS nt{}; size_t got = 0;
    if (!remote_read(s->pi.hProcess, s->remote_agent, &dos, sizeof(dos), &got) || got != sizeof(dos) ||
        !remote_read(s->pi.hProcess, s->remote_agent + (uint32_t)dos.e_lfanew, &nt, sizeof(nt), &got) || got != sizeof(nt))
        return false;
    const uint64_t a = (uint64_t)(uintptr_t)start;
    return a >= s->remote_agent && a < s->remote_agent + nt.OptionalHeader.SizeOfImage;
}

void hold_thread(probe_session *s, DWORD tid) {
    // While detaching, the drain dispatches queued events (CREATE_THREADs, gate hits) that
    // would otherwise place an install hold -- and its release (the agent confirming) may
    // never come before we let go: the target would be left with suspended threads after
    // the detach. No hooks are being installed any more anyway.
    if (s->detaching) return;
    // (QUERY_LIMITED: the controller-death guard mirrors held threads by id, GetThreadId.)
    HANDLE t = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, tid);
    if (!t) return;
    guard_note_hold(s, tid);
    DWORD prev = SuspendThread(t);
    if (prev == (DWORD)-1) { CloseHandle(t); return; }
    if (trace_enabled()) std::fprintf(stderr, "  hold tid=%lu prev_suspend=%lu\n", (unsigned long)tid, (unsigned long)prev);
    if (s->held.empty()) s->held_since = GetTickCount64();
    s->held.push_back(t);
    std::fprintf(stderr, "probe: holding thread %lu until inline installs confirm\n", (unsigned long)tid);
    if (trace_enabled()) std::fprintf(stderr, "  hold t=%llu\n", (unsigned long long)GetTickCount64());
}

// ---- Inline-install gates ------------------------------------------------------------
// A module with inline sites that loads while the target runs: rather than park the
// LOADING thread at its LOAD_DLL event (it is the loader's load owner; parking it is safe
// only because the agent's service thread never needs the loader once it runs -- it reports
// ready from its own code, after its loader thread-init), put a hardware execute breakpoint
// on each pending site.
// Whoever reaches a site before its hook is confirmed is held THERE (no loader locks),
// and resumes straight into the hook once it is in. No call is missed, nothing waits on
// the loader. Falls back to the old hold when the debug registers are all taken.
bool arm_gates_for_pending(probe_session *s) {
    if (s->detaching) return true;                 // no new gates (nor holds) while letting go
    std::vector<uint64_t> sites;
    for (auto &p : s->probes)
        if ((p->flags & PROBE_INLINE) && p->address && !p->active && !p->retired) {
            bool gated = false;
            for (auto &g : s->gates) if (g.first == p->address) gated = true;
            if (!gated) sites.push_back(p->address);
        }
    for (const auto &e : s->extra_gates) {
        const uint64_t x = e.site;
        bool gated = std::find(sites.begin(), sites.end(), x) != sites.end();
        for (auto &g : s->gates) if (g.first == x) gated = true;
        if (!gated) sites.push_back(x);
    }
    std::vector<int> slots;
    const uint8_t foreign = sites.empty() ? 0 : target_slots_any(s);
    for (int slot = 0; slot < 4 && slots.size() < sites.size(); ++slot)
        if (!(s->dr_used & (1u << slot)) && !(foreign & (1u << slot))) slots.push_back(slot);
    if (slots.size() < sites.size()) return false;           // not enough DRs: caller holds instead
    size_t new_guard_sites = 0;
    for (uint64_t site : sites) if (!s->hw_armed_ever.count(site)) ++new_guard_sites;
    if (s->attached && s->shared &&
        s->hw_armed_ever.size() + new_guard_sites > PROBE_AGENT_GUARD_DR_SITES) return false;
    for (size_t i = 0; i < sites.size(); ++i) {
        const int slot = slots[i];
        s->hw_armed_ever.insert(sites[i]);
        for (DWORD tid : s->threads) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
            GuardTouch touch(s, tid);
            if (t) { keep_queued_dr6(s, tid, t); set_dr_on_thread(t, slot, sites[i], true, 0, 0, s, tid); CloseHandle(t); }
        }
        s->dr_used |= (uint8_t)(1u << slot); s->dr_ever |= (uint8_t)(1u << slot);
        s->gates.push_back({sites[i], slot});
        // A thread still in its loader initialisation, or inside exception dispatch / an APC,
        // resumes through NtContinue with the debug registers it had before -- without this
        // gate -- and could run the site uncaught before its hook is in (seen: hunt-dll-work-
        // backend-inline, x86 under load, 1-5 of 240 calls missed). The thread-start and
        // context-restore fixups put gates back as they do hardware probes (after this event).
        s->thread_start_due = true;
        if (trace_enabled()) std::fprintf(stderr, "  gate 0x%llx DR%d\n", (unsigned long long)sites[i], slot);
    }
    return true;
}

static void clear_gates(probe_session *s) {
    // A gate on another instance's copy of an ACTIVE probe's site stays until a thread hits it
    // (the probe moves there) or the probe leaves that instance; the rest go.
    std::vector<probe_session::ExtraGate> keep;
    for (const auto &e : s->extra_gates)
        if (e.probe && e.probe->active && !e.probe->retired && e.probe->address != e.site && !s->detaching) keep.push_back(e);
    s->extra_gates = keep;
    std::vector<std::pair<uint64_t, int>> kept;
    for (auto &g : s->gates) {
        if (std::any_of(keep.begin(), keep.end(), [&](const auto &e) { return e.site == g.first; })) { kept.push_back(g); continue; }
        for (DWORD tid : s->threads) {
            HANDLE t = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, tid);
            GuardTouch touch(s, tid);
            if (t) { keep_queued_dr6(s, tid, t); clear_dr_on_thread(t, g.second, g.first); CloseHandle(t); }
        }
        s->dr_used &= (uint8_t)~(1u << g.second);
        retire_hw_address(s, g.first);                       // a #DB already in flight is stale
    }
    s->gates = kept;
}

// A gate fired: hold this thread at the site until the hook is confirmed.
bool handle_gate(probe_session *s, const DEBUG_EVENT &event, bool &handled, bool *failed) {
    if (failed) *failed = false;
    handled = false;
    if (s->gates.empty()) return false;
    HANDLE thread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, event.dwThreadId);
    if (!thread) return false;
    CONTEXT c{}; c.ContextFlags = CONTEXT_CONTROL | CONTEXT_DEBUG_REGISTERS;
    bool hit = false;
    DWORD64 consumed = 0;
    if (GetThreadContext(thread, &c)) {
        c.Dr6 |= dr6_carried(s, event.dwThreadId);
        for (auto &g : s->gates)
            if ((c.Dr6 & (1u << g.second)) && dr_address(c, g.second) == g.first &&
                ((c.Dr7 >> (g.second * 2)) & 3) && (uint64_t)EMU_IP(c) == g.first) { hit = true; consumed |= (DWORD64)1 << g.second; c.Dr6 &= ~(DWORD64)(1u << g.second); }
        if (hit) { handled = !(c.Dr6 & 0xE00Fu); c.EFlags |= 0x10000u; SetThreadContext(thread, &c); }   // RF: run the site once resumed
    }
    CloseHandle(thread);
    if (hit) {
        if (!handled && event.u.Exception.dwFirstChance &&
            !queue_debug_delivery(s, event.dwThreadId, (uint64_t)EMU_IP(c), consumed, c.Dr6 & 0xE00Fu)) {
            if (failed) *failed = true;
            return false;
        }
        hold_thread(s, event.dwThreadId);
#if defined(_WIN64)
        const uint64_t pc = c.Rip;
#else
        const uint64_t pc = c.Eip;
#endif
        // Another instance's copy of a probe's site, now running: that instance is the live
        // one. The probe moves there (the old instance keeps its hook until it is unmapped;
        // its calls still count), and this thread waits for the new hook like any gated one.
        for (auto it = s->extra_gates.begin(); it != s->extra_gates.end(); ++it) {
            if (it->site != pc || !it->probe) continue;
            Probe &p = *it->probe;
            const uint64_t base = it->base;
            s->extra_gates.erase(it);
            if (p.address == pc || p.retired) break;
            if (trace_enabled()) std::fprintf(stderr, "  gate: %s moves to the live instance at 0x%llx\n", p.location.c_str(),
                                              (unsigned long long)base);
            p.active = false; p.vetted = false; p.base = p.address = 0;
            arm_quietly(s, p.module, base);
            if (agent_has_pending(s)) kick_agent(s);
            break;
        }
    }
    return hit;
}

void release_held(probe_session *s, const char *why) {
    clear_gates(s);                                          // hooks confirmed (or giving up): gates go first
    if (s->held.empty()) return;
    for (HANDLE t : s->held) {
        DWORD prev = ResumeThread(t);
        if (trace_enabled()) std::fprintf(stderr, "  release tid=%lu prev_suspend=%lu\n", (unsigned long)GetThreadId(t), (unsigned long)prev);
        CloseHandle(t);
    }
    std::fprintf(stderr, "probe: released %zu held thread(s) (%s)\n", s->held.size(), why);
    bench_phase("released_held", why);
    s->held.clear();
    guard_resync(s);                                         // our suspensions are over: off the list
}

static bool vet_pending_inline(probe_session *s);

// Start (or queue) agent work for pending inline requests.
bool kick_agent(probe_session *s) {
    if (s->detaching) return true;                 // the session is letting go: install nothing more
    if (s->shared && s->shared->service_ready && s->svc_event) {     // persistent service thread
        if (trace_enabled()) std::fprintf(stderr, "  vet start t=%llu\n", (unsigned long long)GetTickCount64());
        if (!vet_pending_inline(s)) return false;
        if (trace_enabled()) std::fprintf(stderr, "  vet end t=%llu\n", (unsigned long long)GetTickCount64());
        if (trace_enabled()) std::fprintf(stderr, "  kick service t=%llu\n", (unsigned long long)GetTickCount64());
        SetEvent(s->svc_event); return true;
    }
    if (s->remote_work != probe_session::REMOTE_NONE) return true;   // picked up when it finishes
    if (!s->remote_agent) return start_agent_load(s);
    return start_agent_init(s);
}
// A mapped runtime add waits for the installation result; deferred safety refusals retain
// accepted-submission semantics (diagnosed, retired, no hook), as before.
// Continue its event with the calling thread suspended, as call_func does, so the service
// thread can install while this callback's stack and IPC request remain live.
bool confirm_runtime_inline(probe_session *s, Probe &p) {
    if (p.deferred_site_refused) return true; // submission accepted; refusal was diagnosed by vet_pending_inline
    if (!(p.flags & PROBE_INLINE) || !p.address || !s->cb_tid || GetCurrentThreadId() != s->debug_tid) return true;
    EventFiber *const f = s->cur_fiber;
    if (!f || !s->shared) { set_error(s, "cannot wait for runtime inline installation"); return false; }
    if (!f->resume_after) {
        HANDLE t = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_LIMITED_INFORMATION, FALSE, s->cb_tid);
        guard_note_hold(s, s->cb_tid);
        if (!t || SuspendThread(t) == (DWORD)-1) {
            if (t) CloseHandle(t);
            set_error(s, win_error("hold runtime inline caller")); return false;
        }
        f->resume_after = t; f->stop_suspended = true;
        if (!ContinueDebugEvent(f->ev.dwProcessId, f->ev.dwThreadId, DBG_CONTINUE)) {
            const std::string why = win_error("continue runtime inline add");
            ResumeThread(t); CloseHandle(t); f->resume_after = nullptr; f->stop_suspended = false;
            set_error(s, why); return false;
        }
    }
    struct WaitScope {
        probe_session *s; DWORD prev;
        ~WaitScope() { s->inline_add_wait_tid = prev; }
    } wait{s, s->inline_add_wait_tid};
    s->inline_add_wait_tid = s->cb_tid;
    const ULONGLONG until = GetTickCount64() + 5000;
    while (!s->exited && !s->stop_requested && GetTickCount64() < until) {
        MemoryBarrier();
        if (p.deferred_site_refused) return true;
        if (!(p.flags & PROBE_INLINE)) return p.active; // deferred vetting selected hardware fallback
        const LONG status = s->shared->requests[p.agent_index].status;
        if (status == PROBE_AGENT_INSTALLED) return true;
        if (p.retired || (status != PROBE_AGENT_PENDING && status != PROBE_AGENT_INSTALLING)) {
            set_error(s, "runtime inline installation failed (status=" + std::to_string(status) + ")");
            return false;
        }
        drain_agent_logs(s);
        if (!poll_calls(s)) return false;
        DEBUG_EVENT event{};
        if (WaitForDebugEvent(&event, 20) && !continue_foreign_event(s, event) && !service_event(s, event)) return false;
        if (s->rekick_at && GetTickCount64() >= s->rekick_at) {
            s->rekick_at = 0;
            if (agent_has_pending(s) && !kick_agent(s)) return false;
        }
    }
    set_error(s, "runtime inline installation not confirmed within 5 s");
    return false;
}
// UHH_SHARED callbacks still waiting for the agent (a session without inline probes opens no
// channel, which is where the agent is otherwise loaded): load it and bind them now.
bool bind_pending_shared(probe_session *s) {
    for (const auto &p : s->probes) if (!p->shared_export.empty()) return ensure_local_agent(s);
    return true;
}
static bool site_executable(HANDLE h, uint64_t a) {
    MEMORY_BASIC_INFORMATION m{};
    return a && VirtualQueryEx(h, (void *)(uintptr_t)a, &m, sizeof(m)) && m.State == MEM_COMMIT && !(m.Protect & PAGE_GUARD) &&
           (m.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
}
// An install round made no progress: a pending inline probe whose site is not installable (not
// executable code -- an instance still relocating, or a mapping the loader discards) while
// another instance of its module has that site as code: move the probe there (newest first).
void retarget_pending(probe_session *s) {
    bool moved = false;
    std::vector<std::pair<std::string, uint64_t>> arm;           // armed after the scan (arming may add probes)
    for (auto &p : s->probes) {
        if (!(p->flags & PROBE_INLINE) || !p->address || !p->base || p->active || p->retired) continue;
        if (site_executable(s->pi.hProcess, p->address)) continue;
        const uint64_t off = p->address - p->base;
        for (auto it = s->module_instances.rbegin(); it != s->module_instances.rend(); ++it) {
            if (it->second == p->base || !iequals(it->first, p->module)) continue;
            if (!site_executable(s->pi.hProcess, it->second + off)) continue;
            if (trace_enabled()) std::fprintf(stderr, "  retarget %s 0x%llx -> 0x%llx\n", p->location.c_str(),
                                              (unsigned long long)p->address, (unsigned long long)(it->second + off));
            p->base = p->address = 0; p->vetted = false;
            arm.emplace_back(it->first, it->second);
            moved = true;
            break;
        }
    }
    for (const auto &a : arm) arm_quietly(s, a.first, a.second);
    if (moved) arm_gates_for_pending(s);
}

// ---- Frozen hook writes (agent FREEZE / THAW) ------------------------------------------
// The agent writes inline hooks only while every other target thread is suspended here, so
// no thread can execute bytes mid-write and the page never has to be made non-executable
// (which faulted on ntdll's own syscall stubs and raised exceptions the target could see).
void ipc_thaw(probe_session *s) {
    const bool any = !s->ipc_frozen.empty();
    for (HANDLE t : s->ipc_frozen) { ResumeThread(t); CloseHandle(t); }
    s->ipc_frozen.clear();
    s->ipc_freezer = 0;
    if (any) guard_resync(s);                                // our suspensions are over: off the list
}

bool ipc_freeze_thread(probe_session *s, DWORD tid) {
    HANDLE t = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION,
                          FALSE, tid);                     // (QUERY_LIMITED: GetThreadId, guard_sync)
#if defined(UHH_TEST_HOOKS)
    if (t && std::getenv("UHH_TEST_FREEZE_FAIL")) {
        CloseHandle(t); std::fprintf(stderr, "probe: test: freeze denied\n"); return false;
    }
#endif
    if (!t) {
        // An EXIT_THREAD event can still be queued behind the agent's FREEZE.
        const auto it = s->thread_handle.find(tid);
        if (it != s->thread_handle.end() && thread_terminating(it->second)) return true;
        std::fprintf(stderr, "probe: freeze: open thread %lu failed (%lu)\n",
                     (unsigned long)tid, (unsigned long)GetLastError());
        return false;
    }
    if (thread_terminating(t)) { CloseHandle(t); return true; }
    guard_note_hold(s, tid);
    if (SuspendThread(t) == (DWORD)-1) {
        const DWORD error = GetLastError();
        const bool gone = thread_terminating(t);
        CloseHandle(t);
        if (!gone) std::fprintf(stderr, "probe: freeze: suspend thread %lu failed (%lu)\n",
                                (unsigned long)tid, (unsigned long)error);
        return gone;
    }
    try { s->ipc_frozen.push_back(t); }
    catch (...) { ResumeThread(t); CloseHandle(t); return false; }
    return true;
}

// A frozen thread stopped strictly inside a range the agent is about to overwrite would
// resume on torn bytes. Move it to the same instruction in that hook's trampoline, which
// holds relocated copies of exactly those instructions (one-to-one, in order) and then
// jumps back to site + patch_len.
static bool move_into_trampoline(probe_session *s, HANDLE t) {
    CONTEXT c{}; c.ContextFlags = CONTEXT_CONTROL;
    GuardTouch touch(s, GetThreadId(t));
#if defined(UHH_TEST_HOOKS)
    if (std::getenv("UHH_TEST_FREEZE_CONTEXT_FAIL")) {
        std::fprintf(stderr, "probe: test: freeze context denied\n"); return false;
    }
#endif
    if (!GetThreadContext(t, &c)) return thread_terminating(t);
#if defined(_WIN64)
    uint64_t ip = c.Rip;
#else
    uint64_t ip = c.Eip;
#endif
    for (uint32_t i = 0; i < PROBE_AGENT_MAX_PROBES; ++i) {
        const auto &r = s->shared->requests[i];
        if (!r.enabling) continue;                    // only ranges about to be overwritten
        const uint64_t site = r.site, tramp = r.trampoline; const uint32_t len = r.patch_len;
        if (!site || !tramp || !len || len > 32 || ip <= site || ip >= site + len) continue;
        unsigned char ob[48] = {}, tb[128] = {}; size_t on = 0, tn = 0;
        remote_read(s->pi.hProcess, site, ob, sizeof(ob), &on);
        remote_read(s->pi.hProcess, tramp, tb, sizeof(tb), &tn);
        ZydisDecoder dec;
#if defined(_WIN64)
        ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
        ZydisDecoderInit(&dec, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
#endif
        size_t o = 0, q = 0;
        while (o < len && o < on && q < tn) {
            if (site + o == ip) {
#if defined(_WIN64)
                c.Rip = tramp + q;
#else
                c.Eip = (DWORD)(tramp + q);
#endif
                return SetThreadContext(t, &c) != FALSE;
            }
            ZydisDecodedInstruction a{}, b{};
            if (!ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&dec, nullptr, ob + o, on - o, &a)) ||
                !ZYAN_SUCCESS(ZydisDecoderDecodeInstruction(&dec, nullptr, tb + q, tn - q, &b))) break;
            o += a.length; q += b.length;
        }
        std::fprintf(stderr, "probe: freeze: thread at 0x%llx inside hook range 0x%llx+%u not mapped\n",
                     (unsigned long long)ip, (unsigned long long)site, len);
        return false;
    }
    return true;
}

static int32_t ipc_freeze(probe_session *s, DWORD self, uint64_t mask) {
    ipc_thaw(s);                                  // a stale freeze (agent thread died) never stacks
    for (DWORD tid : s->threads) {
        if (tid == self) continue;
        if (!ipc_freeze_thread(s, tid)) {
            ipc_thaw(s); return 0;
        }
    }
    std::vector<CONTEXT> before;
    try { if (mask) before.resize(s->ipc_frozen.size()); }
    catch (...) { ipc_thaw(s); return 0; }
    if (mask) {
        for (size_t i = 0; i < before.size(); ++i) {
            before[i].ContextFlags = CONTEXT_CONTROL;
            if (!GetThreadContext(s->ipc_frozen[i], &before[i])) {
                if (thread_terminating(s->ipc_frozen[i])) continue;
                std::fprintf(stderr, "probe: freeze: get context thread %lu failed (%lu)\n",
                             (unsigned long)GetThreadId(s->ipc_frozen[i]), (unsigned long)GetLastError());
                ipc_thaw(s); return 0;
            }
        }
        for (size_t i = 0; i < before.size(); ++i) if (!move_into_trampoline(s, s->ipc_frozen[i])) {
            for (size_t j = 0; j < i; ++j) SetThreadContext(s->ipc_frozen[j], &before[j]);
            ipc_thaw(s); return 0;
        }
    }
    s->ipc_freezer = self;
    return 1;
}

// Agent -> controller control-plane call (an inline callback used get_session(c)).
// The raising thread is stopped; service the request and write the result back.
// Trust boundary: the target is untrusted. A request is honoured only when an inline
// agent exists and it names a real inline probe as its origin, and the callback is
// resolved ONLY among the exports of that probe's controller-side callback module (so
// keep that module's exports to callbacks). Anything else is not ours: pass it through.
bool handle_ipc(probe_session *s, const DEBUG_EVENT &event) {
    auto &ex = event.u.Exception.ExceptionRecord;
    if (!s->shared || ex.NumberParameters < 1) return false;
    // Every request the agent raises is a whole probe_ipc_request: one read for all of it (a
    // read per field was a ReadProcessMemory each); the head alone only if that fails.
    probe_ipc_request whole{}; size_t whole_n = 0;
    const bool have_whole = remote_read(s->pi.hProcess, (uint64_t)ex.ExceptionInformation[0], &whole, sizeof(whole), &whole_n) &&
                            whole_n == sizeof(whole);
    {
        probe_ipc_request head = whole; size_t n = have_whole ? offsetof(probe_ipc_request, address) : 0;
        if (!have_whole) remote_read(s->pi.hProcess, (uint64_t)ex.ExceptionInformation[0], &head, offsetof(probe_ipc_request, address), &n);
        if (n == offsetof(probe_ipc_request, address) && (head.op == PROBE_IPC_FREEZE || head.op == PROBE_IPC_THAW)) {
            if (trace_enabled()) std::fprintf(stderr, "  ipc op=%u tid=%lu (freeze/thaw) t=%llu\n", head.op, (unsigned long)event.dwThreadId, (unsigned long long)GetTickCount64());
            uint64_t mask = whole.address; size_t m = have_whole ? sizeof(mask) : 0;
            if (!have_whole)
                remote_read(s->pi.hProcess, (uint64_t)ex.ExceptionInformation[0] + offsetof(probe_ipc_request, address), &mask, sizeof(mask), &m);
            if (head.op == PROBE_IPC_THAW) { if (s->ipc_freezer == event.dwThreadId) ipc_thaw(s); return true; }
            int32_t result = ipc_freeze(s, event.dwThreadId, m == sizeof(mask) ? mask : 0);
            // Test hook (regress lifecycle-killed-in-freeze): stall with an install's FREEZE taken
            // (every other thread suspended) but not yet answered, so the test can kill the
            // controller exactly there.
            static const unsigned long stall_ms = [] { const char *v = std::getenv("UHH_TEST_FREEZE_STALL_MS"); return v ? std::strtoul(v, nullptr, 10) : 0ul; }();
            if (stall_ms && mask) { std::fprintf(stderr, "probe: test: install freeze stalled\n"); std::fflush(stderr); Sleep(stall_ms); }
            size_t wrote = 0;
            remote_write(s->pi.hProcess, (uint64_t)ex.ExceptionInformation[0] + offsetof(probe_ipc_request, result), &result, sizeof(result), &wrote);
            return true;
        }
        if (trace_enabled() && n == offsetof(probe_ipc_request, address))
            std::fprintf(stderr, "  ipc op=%u tid=%lu t=%llu\n", head.op, (unsigned long)event.dwThreadId, (unsigned long long)GetTickCount64());
        if (n == offsetof(probe_ipc_request, address) && head.op == PROBE_IPC_LOG) {
            // A producer could not get a ring slot (the ring is stalled behind a suspended
            // producer): the record comes over synchronously. Untrusted like the ring itself;
            // enqueue_agent_record bounds every field.
            uint64_t at = (uint64_t)ex.ExceptionInformation[0], where = 0;
            size_t m = 0, got = 0;
            auto rec = std::make_unique<probe_agent_log>();
            int32_t result = 0;
            if (remote_read(s->pi.hProcess, at + offsetof(probe_ipc_request, address), &where, sizeof(where), &m) &&
                m == sizeof(where) && remote_read(s->pi.hProcess, where, rec.get(), sizeof(*rec), &got) && got == sizeof(*rec)) {
                drain_agent_logs(s);                 // whatever the ring can still give goes first
                deliver_past_stall(s);
                enqueue_agent_record(s, *rec);
                result = 1;
            }
            size_t wrote = 0;
            remote_write(s->pi.hProcess, at + offsetof(probe_ipc_request, result), &result, sizeof(result), &wrote);
            return true;
        }
        if (n == offsetof(probe_ipc_request, address) && head.op == PROBE_IPC_INSTALL_DONE) {
            // Harmless if forged: acceptance re-checks every request status itself.
            const bool accepted = accept_agent_install(s); // prints each failure once
            // This thread runs: the guard is up (see arm_module) -- breakpoint/hw probes go
            // active with the inline ones, not when the init thread returns.
            if (accepted && guard_pending(s) && s->shared->service_ready && !guard_set_ready(s, nullptr))
                std::fprintf(stderr, "probe: %s\n", s->error.c_str());
            // Still pending after a round: its site is not installable YET (a relocated DLL's
            // code is not executable until the loader has finished relocating it). Asking again
            // at once made the agent spin round after round, each an event that freezes the
            // target -- the loading thread starved and the install timed out after 5 s (calls
            // missed: hunt-dll-work-backend-inline under load). Ask again in 5 ms instead.
            if (agent_has_pending(s)) s->rekick_at = GetTickCount64() + 5;
            else if (!inline_hold_needed(s)) release_held(s, "inline installs confirmed");
            return true;
        }
    }
    uint64_t at = (uint64_t)ex.ExceptionInformation[0];
    if (!have_whole) return false;
    const probe_ipc_request req = whole;
    const Probe *origin = nullptr;
    for (const auto &p : s->probes)
        if ((p->flags & PROBE_INLINE) && p->agent_index == req.origin_site && p->callback) { origin = p.get(); break; }
    if (!origin) return false; // reject forged origins before allocating target-supplied lengths
    // The name, symbol and config are read from the (stopped) calling thread's memory.
    auto fetch = [&](uint64_t from, uint64_t len, uint64_t cap, void *to) {
        size_t n = 0;
        return len <= cap && (!len || (remote_read(s->pi.hProcess, from, to, (size_t)len, &n) && n == len));
    };
    std::string name, symbol; std::vector<unsigned char> config;
    // The config limit is the API's, the same on every backend (probe_api.h: 4 GB); it used to
    // be 64 MiB here only, so a dynamic add accepted by breakpoint/hw was refused inline.
    const bool cfg_too_big = req.config_len > PROBE_IPC_CONFIG_MAX;
    bool fetched = req.callback_len <= PROBE_IPC_TEXT_MAX && req.symbol_len <= PROBE_IPC_TEXT_MAX && !cfg_too_big &&
                   req.config_len <= config.max_size();
    if (fetched) {
        try {
#if defined(UHH_TEST_HOOKS)
            if (std::getenv("UHH_TEST_IPC_CONFIG_LENGTH_ERROR")) throw std::length_error("test config capacity");
#endif
            name.resize((size_t)req.callback_len); symbol.resize((size_t)req.symbol_len); config.resize((size_t)req.config_len);
        } catch (const std::bad_alloc &) { fetched = false; }
          catch (const std::length_error &) { fetched = false; }
        fetched = fetched && fetch(req.callback, req.callback_len, PROBE_IPC_TEXT_MAX, name.data()) &&
                  fetch(req.symbol, req.symbol_len, PROBE_IPC_TEXT_MAX, symbol.data()) &&
                  fetch(req.config, req.config_len, PROBE_IPC_CONFIG_MAX, config.data());
    }
    // The callback is named; find the controller's copy of the same source. Prefer the
    // module that holds the originating inline probe's callback, then the executable.
    probe_callback cb = nullptr;
    for (auto &p : s->probes)
        if ((p->flags & PROBE_INLINE) && p->agent_index == req.origin_site && p->callback) {
            HMODULE m{};
            if (fetched && GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                                              reinterpret_cast<LPCSTR>(p->callback), &m))
                for (size_t at0 = 0; !cb && at0 < name.size(); ) {          // '\n'-separated: any that resolves
                    size_t nl = name.find('\n', at0);
                    if (nl == std::string::npos) nl = name.size();
                    cb = reinterpret_cast<probe_callback>(GetProcAddress(m, name.substr(at0, nl - at0).c_str()));
                    at0 = nl + 1;
                }
            break;
        }
    int32_t result = 0;
    struct CbTid { probe_session *s; const Probe *prev; ~CbTid() { s->cb_tid = 0; s->cb_probe = prev; } } cb_tid_scope{s, s->cb_probe};
    s->cb_tid = event.dwThreadId; s->cb_probe = origin;
    if (cfg_too_big) {
        std::fprintf(stderr, "probe: error: probe config is larger than 4 GB\n");   // as probe_add_symbol_cfg says it
    } else if (!fetched) {
        std::fprintf(stderr, "probe: dynamic add from inline callback: cannot read its arguments from the target\n");
    } else if (!cb) {                                // as callback_ok_from_callback says it on breakpoint/hw
        std::fprintf(stderr, "probe: dynamic add failed: %s ('%s' is not exported there)\n", kAddForeignCallback, name.c_str());
    } else if (req.op == PROBE_IPC_ADD_ADDRESS) result = probe_add_address(s, req.address, cb, req.flags);
    else if (req.op == PROBE_IPC_WATCH)       result = probe_watch(s, req.address, cb, req.flags);
    else if (req.op == PROBE_IPC_ADD_SYMBOL)
        result = probe_add_symbol_cfg(s, req.symbol ? symbol.c_str() : nullptr, cb, req.flags,
                                      config.empty() ? nullptr : config.data(), config.size());
    // Failures only (or traced): the added probe's own "probe: active"/"pending" line says the
    // rest, and a line per successful add was a console write per dynamic add.
    if (result != 1 || trace_enabled())
        std::fprintf(stderr, "probe: ipc op=%u from inline site %u cb=%s -> %d\n", req.op, req.origin_site, name.c_str(), result);
    size_t wrote = 0;
    remote_write(s->pi.hProcess, at + offsetof(probe_ipc_request, result), &result, sizeof(result), &wrote);
    return true;
}

// Our threads in the target (agent load / init / stop) run above normal priority. The target
// may keep every CPU busy: a new normal-priority thread then waits behind its threads for a
// whole scheduling quantum (Windows Server: ~190 ms) at every start and wake-up -- measured on
// 2-vCPU CI runners with 4 spinning target threads, an attach armed its breakpoint/hw probes
// (which, beside inline probes, wait for the agent's controller-death guard) only 0.3-1.5 s
// after the attach, and a detach took as long. The agent's work is short and never spins, so the boost costs the
// program nothing but those milliseconds. (CREATE_SUSPENDED: the priority is in place before
// the thread's first instruction.)
HANDLE create_remote_thread_boosted(HANDLE process, LPTHREAD_START_ROUTINE entry, void *argument, DWORD *tid) {
    HANDLE t = CreateRemoteThread(process, nullptr, 0, entry, argument, CREATE_SUSPENDED, tid);
    if (!t) return t;
    SetThreadPriority(t, THREAD_PRIORITY_HIGHEST);
    ResumeThread(t);
    return t;
}

static bool start_remote(probe_session *s, LPTHREAD_START_ROUTINE entry,
                         void *argument, probe_session::RemoteWork work) {
    s->remote_fault.clear();
    if (s->shared) s->init_returns_at = s->shared->init_returns;
    s->remote_thread = create_remote_thread_boosted(s->pi.hProcess, entry, argument, &s->remote_tid);
    if (!s->remote_thread) { set_error(s, win_error("create agent thread")); return false; }
    if (trace_enabled()) std::fprintf(stderr, "  remote work=%d tid=%lu\n", (int)work, (unsigned long)s->remote_tid);
    s->remote_work = work; return true;
}

// Why a remote LoadLibraryW of the agent fails by design: the process admits only
// Microsoft-signed images (Code Integrity Guard -- every Chromium/Edge renderer and most of its
// utility processes). Empty when no such policy is set.
static std::string agent_load_policy_hint(HANDLE process) {
    using GetPolicyFn = BOOL(WINAPI *)(HANDLE, PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
    auto get = reinterpret_cast<GetPolicyFn>(GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "GetProcessMitigationPolicy"));
    PROCESS_MITIGATION_BINARY_SIGNATURE_POLICY sig{};
    if (get && get(process, ProcessSignaturePolicy, &sig, sizeof(sig)) && (sig.MicrosoftSignedOnly || sig.StoreSignedOnly))
        return " (the target admits only Microsoft-signed DLLs -- ProcessSignaturePolicy, e.g. a Chromium/Edge "
               "renderer -- so the agent cannot load there: no inline probes; breakpoint and hw probes work)";
    return {};
}

// kernel32!LoadLibraryW in the target (0 = its module not loaded there yet) and a copy of the
// agent DLL's path in its memory (s->remote_path).
static uint64_t remote_load_library(probe_session *s) {
    HMODULE local_kernel = GetModuleHandleW(L"kernel32.dll");
    auto local_load = reinterpret_cast<uintptr_t>(GetProcAddress(local_kernel, "LoadLibraryW"));
    if (!local_kernel || !local_load) { set_error(s, win_error("resolve LoadLibraryW")); return 0; }
    HMODULE load_owner{};
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCSTR>(local_load), &load_owner)) {
        set_error(s, win_error("resolve LoadLibraryW owner")); return 0;
    }
    std::string owner_name = module_name_from_module(load_owner); uint64_t remote_owner = 0;
    for (const auto &module : s->module_bases)
        if (iequals(module.first, owner_name)) { remote_owner = module.second; break; }
    if (!remote_owner) {
        set_error(s, "target module owning LoadLibraryW was not observed"); return 0;
    }
    size_t bytes = (s->agent_path.size() + 1) * sizeof(wchar_t);
    if (s->remote_path) VirtualFreeEx(s->pi.hProcess, s->remote_path, 0, MEM_RELEASE);
    s->remote_path = VirtualAllocEx(s->pi.hProcess, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!s->remote_path) { set_error(s, win_error("allocate remote agent path")); return 0; }
    SIZE_T written{};
    if (!WriteProcessMemory(s->pi.hProcess, s->remote_path, s->agent_path.c_str(), bytes, &written) ||
        written != bytes) {
        set_error(s, win_error("write remote agent path")); return 0;
    }
    return remote_owner + local_load - reinterpret_cast<uintptr_t>(load_owner);
}
bool start_agent_load(probe_session *s) {
    if (s->detaching) return true;                 // never inject into a target we are leaving
    if (s->remote_work != probe_session::REMOTE_NONE || s->remote_agent) return true;
    const uint64_t remote_load = remote_load_library(s);
    if (!remote_load) return false;
    return start_remote(s, reinterpret_cast<LPTHREAD_START_ROUTINE>((uintptr_t)remote_load),
                        s->remote_path, probe_session::REMOTE_LOAD_AGENT);
}

static bool vet_pending_inline(probe_session *s) {
    // Vet every inline site about to be installed: the bytes may have changed since the
    // site was resolved (a TLS callback or another tool can patch during loader init).
    for (size_t i = 0; i < s->probes.size(); ++i) {
        Probe &p = *s->probes[i];
        if (!(p.flags & PROBE_INLINE) || !p.address || p.active || p.retired || p.vetted) continue;
        // (Re-judged here even if judged at resolve time: a foreign hook may have been
        //  placed in between, e.g. by a TLS callback during loader initialisation.)
        auto &request = s->shared->requests[p.agent_index];
        if (request.status != PROBE_AGENT_PENDING) continue;
        p.vetted = true;
        bool moved = false;
        if (!vet_site(s, p, moved)) {
            p.deferred_site_refused = p.runtime;
            if (p.runtime) { std::fprintf(stderr, "probe: %s\n", s->error.c_str()); s->error.clear(); }
            InterlockedExchange(&request.status, PROBE_AGENT_BAD_REQUEST); p.retired = true;
            if (!p.runtime) return false;
            continue;
        }
        if (moved) {
            InterlockedExchange(&request.status, PROBE_AGENT_BAD_REQUEST);   // agent must not install it
            uint64_t base = p.base; p.address = 0;
            if (!arm_hw(s, p, base)) return false;
        }
    }
    return true;
}

bool start_agent_init(probe_session *s) {
    if (s->detaching) return true;                 // an init now would hook a target we are leaving
    if (s->remote_work != probe_session::REMOTE_NONE || !s->remote_agent || !s->local_agent) {
        set_error(s, "inline agent is not ready for initialization"); return false;
    }
    if (!vet_pending_inline(s)) return false;
    s->agent_init_started = true;
    // Nothing to install yet: still run init once if the agent's service thread is not up --
    // it is what installs hooks in modules that load later (whose loading thread holds the
    // loader lock, so no new thread could do it then). Not after an early init: it made the
    // service thread, which reports itself; a second init thread only repeated that while the
    // program already ran (hunt-early-inline, hunt-exit-terminate-inline).
    if (!agent_has_pending(s) && s->shared && (s->shared->service_ready || s->early_inited)) return accept_agent_install(s);
    auto local_init = reinterpret_cast<uintptr_t>(GetProcAddress(s->local_agent, "probe_agent_init"));
    uint64_t remote_init = s->remote_agent + local_init - reinterpret_cast<uintptr_t>(s->local_agent);
    return start_remote(s, reinterpret_cast<LPTHREAD_START_ROUTINE>((uintptr_t)remote_init), s->agent_mapping,
                        probe_session::REMOTE_INIT_AGENT);
}

// Early agent (ROADMAP A6). The usual agent load runs on a new thread -- which cannot start
// before process initialisation ends, so inline hooks went in at the entry point: every call
// made before it (TLS callbacks, static DLLs' DllMain) was missed. A launched target is instead
// stopped at its loader breakpoint (static imports mapped, no initialiser run yet), and there
// its MAIN thread itself loads the agent and runs its init (call_in_target, as call_func does):
// the hooks are in before the first initialiser runs. The service thread init starts reports
// ready once process initialisation lets it run (the entry hold waits for it, as before).
// Returns true if it took over; false: nothing was done (no kernel32 yet, the call failed
// before loading) -- the caller loads the agent the usual way. CET shadow stacks are no
// reason any more: call_in_target enters the callee through a real CALL (runfix2).
bool early_agent(probe_session *s, const DEBUG_EVENT &event, bool &ok) {
    if (s->attached || s->remote_agent || s->remote_work != probe_session::REMOTE_NONE || !has_inline(s) || !s->shared ||
        s->in_call_tid || s->detaching || !s->local_agent)
        return false;
    const std::string saved_error = s->error;
    const uint64_t load = remote_load_library(s);
    if (!load) { s->error = saved_error; return false; }
    CallbackState st{s, nullptr, event.dwProcessId, event.dwThreadId};
    s->remote_work = probe_session::REMOTE_EARLY; s->quiet_tid = event.dwThreadId;
    uint64_t module = 0; const uint64_t path = (uint64_t)(uintptr_t)s->remote_path;
    const ULONGLONG t0 = GetTickCount64();
    bench_phase("early_load_begin");
    const int loaded = call_in_target(s, &st, load, &module, 1, &path, 60000);
    bench_phase("early_load_end");
    if (trace_enabled())
        std::fprintf(stderr, "  early agent load ok=%d module=0x%llx agent=0x%llx ms=%llu\n", loaded, (unsigned long long)module,
                     (unsigned long long)s->remote_agent, (unsigned long long)(GetTickCount64() - t0));
    // The call timed out (or the thread is gone): the thread is held or released, no second call.
    const bool continued = !loaded && (st.released || (s->cur_fiber && s->cur_fiber->resume_after));
    VirtualFreeEx(s->pi.hProcess, s->remote_path, 0, MEM_RELEASE); s->remote_path = nullptr;
    auto done = [&] { s->quiet_tid = 0; s->remote_work = probe_session::REMOTE_NONE; };
    if (!loaded || !module || !s->remote_agent) {
        done();
        if (s->remote_agent) { ok = start_agent_init(s); return true; }
        if (continued) { ok = start_agent_load(s); return true; }
        return false;
    }
    if (continued) { done(); ok = start_agent_init(s); return true; }
    if (!vet_pending_inline(s)) { done(); ok = false; return true; }
    s->agent_init_started = true;
    auto local_init = reinterpret_cast<uintptr_t>(GetProcAddress(s->local_agent, "probe_agent_init"));
    const uint64_t init = s->remote_agent + local_init - reinterpret_cast<uintptr_t>(s->local_agent), channel = (uint64_t)(uintptr_t)s->agent_mapping;
    uint64_t code = 1;
    InterlockedExchange(&s->shared->early_init, 1);
    const int inited = local_init ? call_in_target(s, &st, init, &code, 1, &channel, 60000) : 0;
    InterlockedExchange(&s->shared->early_init, 0);
    bench_phase("early_init_end");
    if (trace_enabled())
        std::fprintf(stderr, "  early agent init ok=%d code=%llu ms=%llu\n", inited, (unsigned long long)code,
                     (unsigned long long)(GetTickCount64() - t0));
    done();
    s->early_inited = inited && (uint32_t)code == 0;
    if (!inited || (uint32_t)code != 0) {
        // Not initialised here: the usual init thread (it repeats init safely).
        ok = start_agent_init(s); return true;
    }
    ok = accept_agent_install(s) && guard_set_ready(s, nullptr);
    if (ok && agent_has_pending(s)) ok = kick_agent(s);
    return true;
}

bool agent_has_pending(const probe_session *s) {
    if (!s->shared) return false;
    for (const auto &p : s->probes) if ((p->flags & PROBE_INLINE) && p->address &&
        s->shared->requests[p->agent_index].status == PROBE_AGENT_PENDING) return true;
    return false;
}

bool accept_agent_install(probe_session *s, bool completed_round) {
    MemoryBarrier();
    if (!s->shared) return true;
    std::string first_failure;      // every probe is accepted or retired, THEN a boot-time failure is reported
    for (auto &p : s->probes) if ((p->flags & PROBE_INLINE) && p->address && !p->active && !p->retired) {
        LONG status = s->shared->requests[p->agent_index].status;
        if (status == PROBE_AGENT_PENDING || status == PROBE_AGENT_INSTALLING) continue;   // next round
        if (status != PROBE_AGENT_INSTALLED) {
            const auto &request = s->shared->requests[p->agent_index];
            const char *reason = status == PROBE_AGENT_BAD_REQUEST ? "bad request" :
                status == PROBE_AGENT_CALLBACK_MISSING ? "callback missing" : "unexpected install status";
            if (status == PROBE_AGENT_HOOK_FAILED) {
                switch (request.install_failure) {
                case PROBE_INSTALL_BUILD: reason = "trampoline build"; break;
                case PROBE_INSTALL_FREEZE: reason = "freeze"; break;
                case PROBE_INSTALL_SITE: reason = "site check"; break;
                case PROBE_INSTALL_WRITE: reason = "patch write"; break;
                case PROBE_INSTALL_VERIFY: reason = "verification"; break;
                case PROBE_INSTALL_CONTROLLER_GONE: reason = "controller gone"; break;
                default: reason = "hook failure (stage unavailable)"; break;
                }
            }
            std::string why = "inline agent failed to install " + p->location +
                              " (status=" + std::to_string(status) + "): " + reason;
            std::fprintf(stderr, "probe: %s\n", why.c_str());
            p->retired = true;
            if (!p->runtime && first_failure.empty()) first_failure = why;
            continue;
        }
        // INSTALLED is published inside the frozen write, before THAW/INSTALL_DONE.
        // Polling may consume failures, but must not announce readiness or let callers
        // run the target before the install round has released its holds.
        if (!completed_round) continue;
        p->active = true;
        std::fprintf(stderr, "probe: active %s -> addr=0x%llx (inline)\n",
                     p->location.c_str(), (unsigned long long)p->address);
    }
    if (!first_failure.empty()) { set_error(s, first_failure); return false; }
    if (completed_round) s->inline_ready = true;
    return true;
}

bool complete_remote_thread(probe_session *s, DWORD result) {
    // The exit code comes from EXIT_THREAD_DEBUG_EVENT, not GetExitCodeThread: at
    // the instant that event is delivered the thread handle can still report
    // STILL_ACTIVE, which is the race that made agent init look like it failed.
    CloseHandle(s->remote_thread); s->remote_thread = nullptr;
    auto work = s->remote_work; s->remote_work = probe_session::REMOTE_NONE; s->remote_tid = 0;
    if (work == probe_session::REMOTE_LOAD_AGENT) {
        if (s->remote_path) {
            VirtualFreeEx(s->pi.hProcess, s->remote_path, 0, MEM_RELEASE); s->remote_path = nullptr;
        }
        if (result == 0 || !s->remote_agent) {
            const std::string why = "LoadLibraryW failed for probe_api_agent.dll" + (s->remote_fault.empty() ? std::string() : ": " + s->remote_fault) +
                                    agent_load_policy_hint(s->pi.hProcess);
            set_error(s, why);
            return false;
        }
        return start_agent_init(s);
    }
    if (work == probe_session::REMOTE_INIT_AGENT) {
        // Killed before it returned (the target is ending: ExitProcess / TerminateProcess while it
        // ran -- its exit code is then the program's): no init failure, the target's end is the
        // outcome. 1 and 2 are init's own codes from before its channel was usable.
        if (s->shared && result != 1 && result != 2 && s->shared->init_returns == s->init_returns_at) {
            std::fprintf(stderr, "probe: agent init thread ended by the target before it returned (exit code 0x%lx)\n",
                         (unsigned long)result);
            return true;
        }
        if (result != 0) {
            char code[16]; std::snprintf(code, sizeof(code), "0x%lx", (unsigned long)result);
            const std::string why = std::string("probe_agent_init failed (code=") + code + ")" +
                                    (s->remote_fault.empty() ? std::string() : ": " + s->remote_fault);
            set_error(s, why);
            return false;
        }
        if (!accept_agent_install(s)) return false;
        if (!guard_set_ready(s, nullptr)) return false;
        // Requests registered while that round ran (runtime inline adds) go next.
        if (agent_has_pending(s)) return kick_agent(s);
        // Release only once the service thread runs too (it reports itself with an
        // INSTALL_DONE): a module with inline sites may load the moment the threads go.
        if (!inline_hold_needed(s)) release_held(s, "inline installs confirmed");
        return true;
    }
    return true;
}

} // namespace uhh_session

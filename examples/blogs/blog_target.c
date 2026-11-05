/* blog_target -- small, contrived but realistic programs that do what the subjects of
   well-known instrumentation write-ups do, so the blog-replica drivers can instrument
   them. Every scenario prints ONE {"kind":"target",...} JSON line whose deterministic
   fields must be identical with and without instrumentation (the baseline).

     blog_target crypto   [--threads T] [--files F]     ransomware-style file encryption
     blog_target registry [--threads T] [--values V]    Run-key persistence (test key, removed)
     blog_target net      [--clients N]                 DNS + loopback TCP client/server
     blog_target spawn    [--threads T] [--children C]  many child processes
     blog_target com      [--threads T] [--objects M]   CLSID_ShellLink (.lnk written, removed)
     blog_target game     [--frames F]                  1 kHz update loop, frame jitter
     blog_target child <n>                              (spawn's child: exits with n+1)

   Everything is local: files under %TEMP%, a registry key under HKCU\Software that is
   deleted at the end, sockets on 127.0.0.1 only, DNS with DNS_QUERY_NO_WIRE_QUERY. */
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <windns.h>
#include <objbase.h>
#include <shlobj.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "uuid.lib")

#if defined(_MSC_VER) && defined(_M_IX86)
#pragma comment(linker, "/EXPORT:blog_frame=_blog_frame")
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)
#endif

static uint32_t arg_u32(int argc, char **argv, const char *name, uint32_t def) {
    for (int i = 2; i + 1 < argc; ++i)
        if (!strcmp(argv[i], name)) return (uint32_t)strtoul(argv[i + 1], NULL, 0);
    return def;
}

static uint64_t fnv(uint64_t h, const void *p, size_t n) {
    const uint8_t *b = (const uint8_t *)p;
    for (size_t i = 0; i < n; ++i) { h ^= b[i]; h *= 0x100000001b3ULL; }
    return h;
}
#define FNV0 0xcbf29ce484222325ULL

typedef DWORD (WINAPI *worker_fn)(void *);
static int run_threads(uint32_t n, worker_fn fn, void *ctx_array, size_t ctx_size) {
    HANDLE th[64];
    if (n > 64) n = 64;
    for (uint32_t i = 0; i < n; ++i)
        th[i] = CreateThread(NULL, 0, fn, (char *)ctx_array + i * ctx_size, 0, NULL);
    for (uint32_t i = 0; i < n; ++i) { WaitForSingleObject(th[i], INFINITE); CloseHandle(th[i]); }
    return 1;
}

/* ===================================================================== crypto ===== */
#define CRYPTO_PT 4096u
#define CRYPTO_RNG 48u            /* 32-byte key + 16-byte IV: the size the monitor keys on */
#define CAPI_PT 256u

typedef struct { uint32_t t, files; wchar_t dir[MAX_PATH];
                 uint32_t enc, gen, capi, roundtrip, written; uint64_t pt_sum, rng_sum; } crypto_ctx;

static void make_plain(uint8_t *p, size_t n, const char *tag, uint32_t t, uint32_t f) {
    for (size_t i = 0; i < n; ++i) p[i] = (uint8_t)(t * 31u + f * 7u + i * 13u);
    char hdr[48]; int k = snprintf(hdr, sizeof hdr, "%s t=%02u f=%03u ", tag, t, f);
    memcpy(p, hdr, (size_t)k);
}

/* The 48 random bytes come back from BCryptGenRandom: the monitor captures them at the
   return (a probe on this function's return site, added from the entry callback). */
static __declspec(noinline) NTSTATUS crypto_random(uint8_t *out) {
    return BCryptGenRandom(NULL, out, CRYPTO_RNG, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
}

static DWORD WINAPI crypto_worker(void *p) {
    crypto_ctx *c = (crypto_ctx *)p;
    BCRYPT_ALG_HANDLE alg = NULL;
    HCRYPTPROV prov = 0; HCRYPTKEY ckey = 0;
    if (!NT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_AES_ALGORITHM, NULL, 0))) return 1;
    BCryptSetProperty(alg, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!CryptAcquireContextW(&prov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) ||
        !CryptGenKey(prov, CALG_AES_128, 0, &ckey)) return 2;
    static uint8_t pt_s[64][CRYPTO_PT], ct_s[64][CRYPTO_PT + 16], back_s[64][CRYPTO_PT + 16];
    uint8_t *pt = pt_s[c->t], *ct = ct_s[c->t], *back = back_s[c->t];
    for (uint32_t f = 0; f < c->files; ++f) {
        uint8_t rnd[CRYPTO_RNG], iv[16];
        make_plain(pt, CRYPTO_PT, "UHHFILE", c->t, f);
        c->pt_sum = fnv(c->pt_sum, pt, CRYPTO_PT);
        if (!NT_SUCCESS(crypto_random(rnd))) continue;
        c->gen++;
        uint64_t first; memcpy(&first, rnd, 8); c->rng_sum += first;
        BCRYPT_KEY_HANDLE key = NULL; ULONG cb = 0;
        if (!NT_SUCCESS(BCryptGenerateSymmetricKey(alg, &key, NULL, 0, rnd, 32, 0))) continue;
        memcpy(iv, rnd + 32, 16);
        NTSTATUS st = BCryptEncrypt(key, pt, CRYPTO_PT, NULL, iv, 16, ct, CRYPTO_PT + 16, &cb, BCRYPT_BLOCK_PADDING);
        c->enc++;
        if (NT_SUCCESS(st)) {
            wchar_t path[MAX_PATH]; DWORD wr = 0;
            swprintf(path, MAX_PATH, L"%s\\t%02u_f%03u.enc", c->dir, c->t, f);
            HANDLE h = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (h != INVALID_HANDLE_VALUE) {
                if (WriteFile(h, ct, cb, &wr, NULL) && wr == cb) c->written++;
                CloseHandle(h);
                DeleteFileW(path);
            }
            ULONG cb2 = 0; memcpy(iv, rnd + 32, 16);
            if (NT_SUCCESS(BCryptDecrypt(key, ct, cb, NULL, iv, 16, back, CRYPTO_PT + 16, &cb2, BCRYPT_BLOCK_PADDING)) &&
                cb2 == CRYPTO_PT && !memcmp(back, pt, CRYPTO_PT)) c->roundtrip++;
        }
        BCryptDestroyKey(key);
        if (f % 4 == 0) {                                  /* the legacy CryptoAPI path too */
            uint8_t buf[CAPI_PT + 16]; DWORD len = CAPI_PT;
            make_plain(buf, CAPI_PT, "UHHCAPI", c->t, f);
            c->capi++;
            if (CryptEncrypt(ckey, 0, TRUE, 0, buf, &len, sizeof buf)) {
                DWORD len2 = len;
                uint8_t ref[CAPI_PT]; make_plain(ref, CAPI_PT, "UHHCAPI", c->t, f);
                if (CryptDecrypt(ckey, 0, TRUE, 0, buf, &len2) && len2 == CAPI_PT && !memcmp(buf, ref, CAPI_PT))
                    c->roundtrip++;
            }
        }
    }
    CryptDestroyKey(ckey); CryptReleaseContext(prov, 0);
    BCryptCloseAlgorithmProvider(alg, 0);
    return 0;
}

static int scenario_crypto(int argc, char **argv) {
    uint32_t T = arg_u32(argc, argv, "--threads", 6), F = arg_u32(argc, argv, "--files", 20);
    if (T > 64) T = 64;
    wchar_t dir[MAX_PATH]; GetTempPathW(MAX_PATH, dir);
    wchar_t sub[MAX_PATH]; swprintf(sub, MAX_PATH, L"%suhhblog_crypto_%lu", dir, GetCurrentProcessId());
    CreateDirectoryW(sub, NULL);
    crypto_ctx *ctx = (crypto_ctx *)calloc(T, sizeof(crypto_ctx));
    for (uint32_t i = 0; i < T; ++i) { ctx[i].t = i; ctx[i].files = F; ctx[i].pt_sum = FNV0; wcscpy(ctx[i].dir, sub); }
    run_threads(T, crypto_worker, ctx, sizeof(crypto_ctx));
    uint32_t enc = 0, gen = 0, capi = 0, rt = 0, wr = 0; uint64_t pts = 0, rng = 0;
    for (uint32_t i = 0; i < T; ++i) {
        enc += ctx[i].enc; gen += ctx[i].gen; capi += ctx[i].capi; rt += ctx[i].roundtrip; wr += ctx[i].written;
        pts ^= ctx[i].pt_sum * (i + 1); rng += ctx[i].rng_sum;
    }
    BOOL removed = RemoveDirectoryW(sub);
    printf("{\"kind\":\"target\",\"scenario\":\"crypto\",\"threads\":%u,\"files\":%u,\"bcrypt_encrypt\":%u,"
           "\"genrandom\":%u,\"capi_encrypt\":%u,\"roundtrip_ok\":%u,\"written\":%u,\"pt_checksum\":\"%016llx\","
           "\"rng_first8_sum\":\"%016llx\",\"dir_removed\":%s}\n",
           T, F, enc, gen, capi, rt, wr, (unsigned long long)pts, (unsigned long long)rng, removed ? "true" : "false");
    free(ctx);
    return 0;
}

/* =================================================================== registry ===== */
typedef struct { uint32_t t, values; wchar_t root[128]; uint32_t created, set, readback; } reg_ctx;

static DWORD WINAPI reg_worker(void *p) {
    reg_ctx *c = (reg_ctx *)p;
    wchar_t path[256]; HKEY k = NULL; DWORD disp = 0;
    swprintf(path, 256, L"%s\\T%u\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", c->root, c->t);
    if (RegCreateKeyExW(HKEY_CURRENT_USER, path, 0, NULL, 0, KEY_ALL_ACCESS, NULL, &k, &disp) != ERROR_SUCCESS) return 1;
    c->created++;
    for (uint32_t v = 0; v < c->values; ++v) {
        wchar_t name[64], data[128];
        swprintf(name, 64, L"Updater_%u_%u", c->t, v);
        swprintf(data, 128, L"C:\\Users\\Public\\uhh_%u_%u.exe /silent", c->t, v);
        if (RegSetValueExW(k, name, 0, REG_SZ, (const BYTE *)data, (DWORD)((wcslen(data) + 1) * 2)) == ERROR_SUCCESS)
            c->set++;
        wchar_t back[128]; DWORD cb = sizeof back, type = 0;
        if (RegQueryValueExW(k, name, NULL, &type, (BYTE *)back, &cb) == ERROR_SUCCESS && type == REG_SZ && !wcscmp(back, data))
            c->readback++;
    }
    RegCloseKey(k);
    return 0;
}

static int scenario_registry(int argc, char **argv) {
    uint32_t T = arg_u32(argc, argv, "--threads", 4), V = arg_u32(argc, argv, "--values", 25);
    if (T > 64) T = 64;
    wchar_t root[128]; swprintf(root, 128, L"Software\\UHHBlogTest_%lu", GetCurrentProcessId());
    reg_ctx *ctx = (reg_ctx *)calloc(T, sizeof(reg_ctx));
    for (uint32_t i = 0; i < T; ++i) { ctx[i].t = i; ctx[i].values = V; wcscpy(ctx[i].root, root); }
    run_threads(T, reg_worker, ctx, sizeof(reg_ctx));
    uint32_t cr = 0, set = 0, rb = 0;
    for (uint32_t i = 0; i < T; ++i) { cr += ctx[i].created; set += ctx[i].set; rb += ctx[i].readback; }
    LSTATUS del = RegDeleteTreeW(HKEY_CURRENT_USER, root);
    if (del == ERROR_SUCCESS) del = RegDeleteKeyW(HKEY_CURRENT_USER, root);
    HKEY probe = NULL;
    BOOL gone = RegOpenKeyExW(HKEY_CURRENT_USER, root, 0, KEY_READ, &probe) == ERROR_FILE_NOT_FOUND;
    if (probe) RegCloseKey(probe);
    printf("{\"kind\":\"target\",\"scenario\":\"registry\",\"threads\":%u,\"values\":%u,\"created\":%u,\"set\":%u,"
           "\"readback_ok\":%u,\"cleaned\":%s,\"pid\":%lu}\n",
           T, V, cr, set, rb, gone ? "true" : "false", GetCurrentProcessId());
    free(ctx);
    return 0;
}

/* ======================================================================== net ===== */
#define NET_MSG 64
static volatile LONG g_net_send, g_net_recv, g_net_ok, g_dns_calls, g_dns_ok;
static SOCKET g_listen;
static uint32_t g_clients;

static int recv_all(SOCKET s, char *buf, int n) {
    int got = 0;
    while (got < n) {
        InterlockedIncrement(&g_net_recv);
        int r = recv(s, buf + got, n - got, 0);
        if (r <= 0) return 0;
        got += r;
    }
    return 1;
}
static int send_all(SOCKET s, const char *buf, int n) {
    int put = 0;
    while (put < n) {
        InterlockedIncrement(&g_net_send);
        int r = send(s, buf + put, n - put, 0);
        if (r <= 0) return 0;
        put += r;
    }
    return 1;
}

static DWORD WINAPI net_server(void *unused) {
    (void)unused;
    for (uint32_t i = 0; i < g_clients; ++i) {
        SOCKET s = accept(g_listen, NULL, NULL);
        if (s == INVALID_SOCKET) return 1;
        char buf[NET_MSG];
        if (recv_all(s, buf, NET_MSG)) {
            memcpy(buf, "UHHRSP", 6);
            send_all(s, buf, NET_MSG);
        }
        closesocket(s);
    }
    return 0;
}

typedef struct { uint32_t t, per; uint16_t port; } net_ctx;
static DWORD WINAPI net_client(void *p) {
    net_ctx *c = (net_ctx *)p;
    PDNS_RECORD rec = NULL;
    InterlockedIncrement(&g_dns_calls);
    if (DnsQuery_W(L"localhost", DNS_TYPE_A, DNS_QUERY_NO_WIRE_QUERY, NULL, &rec, NULL) == 0) InterlockedIncrement(&g_dns_ok);
    if (rec) DnsRecordListFree(rec, DnsFreeRecordList);
    for (uint32_t k = 0; k < c->per; ++k) {
        uint32_t id = c->t * c->per + k;
        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        struct sockaddr_in a; memset(&a, 0, sizeof a);
        a.sin_family = AF_INET; a.sin_port = htons(c->port); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        int r = (id & 1) ? WSAConnect(s, (struct sockaddr *)&a, sizeof a, NULL, NULL, NULL, NULL)
                         : connect(s, (struct sockaddr *)&a, sizeof a);
        char msg[NET_MSG], back[NET_MSG];
        memset(msg, '.', sizeof msg);
        snprintf(msg, sizeof msg, "UHHREQ id=%03u GET /beacon", id);
        if (r == 0 && send_all(s, msg, NET_MSG) && recv_all(s, back, NET_MSG) &&
            !memcmp(back, "UHHRSP", 6) && !memcmp(back + 6, msg + 6, NET_MSG - 6))
            InterlockedIncrement(&g_net_ok);
        closesocket(s);
    }
    return 0;
}

static int scenario_net(int argc, char **argv) {
    uint32_t threads = arg_u32(argc, argv, "--threads", 4), per = arg_u32(argc, argv, "--per", 4);
    if (threads > 64) threads = 64;
    WSADATA w; WSAStartup(MAKEWORD(2, 2), &w);
    g_clients = threads * per;
    g_listen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int alen = sizeof a;
    if (bind(g_listen, (struct sockaddr *)&a, sizeof a) || listen(g_listen, 64) ||
        getsockname(g_listen, (struct sockaddr *)&a, &alen)) { printf("{\"kind\":\"target\",\"error\":\"listen\"}\n"); return 1; }
    HANDLE srv = CreateThread(NULL, 0, net_server, NULL, 0, NULL);
    net_ctx *ctx = (net_ctx *)calloc(threads, sizeof(net_ctx));
    for (uint32_t i = 0; i < threads; ++i) { ctx[i].t = i; ctx[i].per = per; ctx[i].port = ntohs(a.sin_port); }
    run_threads(threads, net_client, ctx, sizeof(net_ctx));
    WaitForSingleObject(srv, 30000); CloseHandle(srv);
    closesocket(g_listen);
    printf("{\"kind\":\"target\",\"scenario\":\"net\",\"clients\":%u,\"port\":%u,\"exchanges_ok\":%ld,\"send_calls\":%ld,"
           "\"recv_calls\":%ld,\"dns_calls\":%ld,\"dns_ok\":%ld,\"connect_calls\":%u,\"wsaconnect_calls\":%u}\n",
           g_clients, (unsigned)ntohs(a.sin_port), g_net_ok, g_net_send, g_net_recv, g_dns_calls, g_dns_ok,
           (g_clients + 1) / 2, g_clients / 2);
    WSACleanup();
    free(ctx);
    return 0;
}

/* ====================================================================== spawn ===== */
typedef struct { uint32_t t, children; uint32_t started, exit_ok; } spawn_ctx;
static wchar_t g_self[MAX_PATH];

static DWORD WINAPI spawn_worker(void *p) {
    spawn_ctx *c = (spawn_ctx *)p;
    for (uint32_t k = 0; k < c->children; ++k) {
        uint32_t n = c->t * c->children + k;
        wchar_t cmd[MAX_PATH + 64];
        swprintf(cmd, MAX_PATH + 64, L"\"%s\" child %u", g_self, n);
        STARTUPINFOW si; PROCESS_INFORMATION pi;
        memset(&si, 0, sizeof si); si.cb = sizeof si;
        if (!CreateProcessW(g_self, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) continue;
        c->started++;
        WaitForSingleObject(pi.hProcess, 30000);
        DWORD code = 0;
        if (GetExitCodeProcess(pi.hProcess, &code) && code == n + 1) c->exit_ok++;
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    }
    return 0;
}

static int scenario_spawn(int argc, char **argv) {
    uint32_t T = arg_u32(argc, argv, "--threads", 4), C = arg_u32(argc, argv, "--children", 6);
    if (T > 64) T = 64;
    GetModuleFileNameW(NULL, g_self, MAX_PATH);
    spawn_ctx *ctx = (spawn_ctx *)calloc(T, sizeof(spawn_ctx));
    for (uint32_t i = 0; i < T; ++i) { ctx[i].t = i; ctx[i].children = C; }
    run_threads(T, spawn_worker, ctx, sizeof(spawn_ctx));
    uint32_t st = 0, ok = 0;
    for (uint32_t i = 0; i < T; ++i) { st += ctx[i].started; ok += ctx[i].exit_ok; }
    printf("{\"kind\":\"target\",\"scenario\":\"spawn\",\"threads\":%u,\"children\":%u,\"started\":%u,\"exit_ok\":%u}\n",
           T, T * C, st, ok);
    free(ctx);
    return 0;
}

/* ======================================================================== com ===== */
typedef struct { uint32_t t, objects; wchar_t dir[MAX_PATH]; uint32_t created, saved, removed; } com_ctx;

static DWORD WINAPI com_worker(void *p) {
    com_ctx *c = (com_ctx *)p;
    if (FAILED(CoInitializeEx(NULL, COINIT_APARTMENTTHREADED))) return 1;
    for (uint32_t m = 0; m < c->objects; ++m) {
        IShellLinkW *link = NULL; IPersistFile *pf = NULL;
        if (FAILED(CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER, &IID_IShellLinkW, (void **)&link))) continue;
        c->created++;
        wchar_t args[64], path[MAX_PATH];
        swprintf(args, 64, L"--uhh %u %u", c->t, m);
        link->lpVtbl->SetPath(link, L"C:\\Windows\\System32\\notepad.exe");
        link->lpVtbl->SetArguments(link, args);
        swprintf(path, MAX_PATH, L"%suhhblog_%lu_%u_%u.lnk", c->dir, GetCurrentProcessId(), c->t, m);
        if (SUCCEEDED(link->lpVtbl->QueryInterface(link, &IID_IPersistFile, (void **)&pf))) {
            if (SUCCEEDED(pf->lpVtbl->Save(pf, path, TRUE)) && GetFileAttributesW(path) != INVALID_FILE_ATTRIBUTES) c->saved++;
            pf->lpVtbl->Release(pf);
        }
        link->lpVtbl->Release(link);
        if (DeleteFileW(path)) c->removed++;
    }
    CoUninitialize();
    return 0;
}

static int scenario_com(int argc, char **argv) {
    uint32_t T = arg_u32(argc, argv, "--threads", 3), M = arg_u32(argc, argv, "--objects", 8);
    if (T > 64) T = 64;
    wchar_t dir[MAX_PATH]; GetTempPathW(MAX_PATH, dir);
    com_ctx *ctx = (com_ctx *)calloc(T, sizeof(com_ctx));
    for (uint32_t i = 0; i < T; ++i) { ctx[i].t = i; ctx[i].objects = M; wcscpy(ctx[i].dir, dir); }
    run_threads(T, com_worker, ctx, sizeof(com_ctx));
    uint32_t cr = 0, sv = 0, rm = 0;
    for (uint32_t i = 0; i < T; ++i) { cr += ctx[i].created; sv += ctx[i].saved; rm += ctx[i].removed; }
    printf("{\"kind\":\"target\",\"scenario\":\"com\",\"threads\":%u,\"objects\":%u,\"created\":%u,\"saved\":%u,\"removed\":%u}\n",
           T, T * M, cr, sv, rm);
    free(ctx);
    return 0;
}

/* ======================================================================= game ===== */
/* The per-frame function a game-hacking write-up would hook (an "Update/Present" stand-in). */
__declspec(dllexport) __declspec(noinline) uint64_t blog_frame(uint32_t frame, uint64_t *state) {
    uint64_t s = *state;
    for (uint32_t i = 0; i < 64; ++i) s = s * 6364136223846793005ULL + frame + i;
    *state = s;
    return s >> 7;
}

static int cmp_i64(const void *a, const void *b) {
    int64_t x = *(const int64_t *)a, y = *(const int64_t *)b;
    return x < y ? -1 : x > y;
}

static int scenario_game(int argc, char **argv) {
    uint32_t F = arg_u32(argc, argv, "--frames", 2000);
    LARGE_INTEGER fq, t0, now; QueryPerformanceFrequency(&fq);
    int64_t period = fq.QuadPart / 1000;                     /* 1 kHz */
    int64_t *late = (int64_t *)calloc(F, sizeof(int64_t)), *cost = (int64_t *)calloc(F, sizeof(int64_t));
    uint64_t state = 0x1234, sum = FNV0; uint32_t missed = 0;
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_HIGHEST);
    QueryPerformanceCounter(&t0);
    int64_t deadline = t0.QuadPart;
    for (uint32_t f = 0; f < F; ++f) {
        deadline += period;
        do QueryPerformanceCounter(&now); while (now.QuadPart < deadline);   /* spin to the frame boundary */
        int64_t start = now.QuadPart;
        uint64_t out = blog_frame(f, &state);
        QueryPerformanceCounter(&now);
        sum = fnv(sum, &out, sizeof out);
        cost[f] = (now.QuadPart - start) * 1000000 / fq.QuadPart;
        late[f] = (start - deadline) * 1000000 / fq.QuadPart;
        if (now.QuadPart > deadline + period) missed++;           /* frame overran its 1 ms budget */
    }
    qsort(late, F, sizeof(int64_t), cmp_i64); qsort(cost, F, sizeof(int64_t), cmp_i64);
    printf("{\"kind\":\"target\",\"scenario\":\"game\",\"frames\":%u,\"checksum\":\"%016llx\",\"missed\":%u,"
           "\"cost_us_p50\":%lld,\"cost_us_p99\":%lld,\"cost_us_max\":%lld,\"late_us_p50\":%lld,\"late_us_p99\":%lld,\"late_us_max\":%lld}\n",
           F, (unsigned long long)sum, missed, (long long)cost[F / 2], (long long)cost[F * 99 / 100], (long long)cost[F - 1],
           (long long)late[F / 2], (long long)late[F * 99 / 100], (long long)late[F - 1]);
    free(late); free(cost);
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc < 2) { fprintf(stderr, "usage: blog_target crypto|registry|net|spawn|com|game [opts]\n"); return 2; }
    const char *s = argv[1];
    if (!strcmp(s, "child")) return argc > 2 ? (int)strtoul(argv[2], NULL, 0) + 1 : 1;
    if (!strcmp(s, "crypto")) return scenario_crypto(argc, argv);
    if (!strcmp(s, "registry")) return scenario_registry(argc, argv);
    if (!strcmp(s, "net")) return scenario_net(argc, argv);
    if (!strcmp(s, "spawn")) return scenario_spawn(argc, argv);
    if (!strcmp(s, "com")) return scenario_com(argc, argv);
    if (!strcmp(s, "game")) return scenario_game(argc, argv);
    fprintf(stderr, "blog_target: unknown scenario %s\n", s);
    return 2;
}

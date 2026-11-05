// flagflip_target -- fixture for flagflip. Late-loads flagfeature.dll, creates the features
// "alpha" and "beta" (both ship disabled), and from several threads asks each one
// IsEnabled() through its vtable; only an enabled feature runs its gated path. Prints its
// own ground truth, one line per feature:
//   {"kind":"ff_feature","name":"beta","this":"0x1f2a3b40","calls":800,"enabled":800,"gated_ran":800}
// usage: flagflip_target [--threads T] [--calls N]
#include "flagfeature.h"
#include <windows.h>
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

namespace {
struct Stats { std::atomic<long> calls{0}, enabled{0}, gated{0}; };

// The code path that ships off: it only runs when the feature says it is enabled.
void gated_path(Stats &s) { s.gated.fetch_add(1); }
}  // namespace

int main(int argc, char **argv) {
    int threads = 4, calls = 200;
    for (int i = 1; i + 1 < argc; i += 2) {
        if (!std::strcmp(argv[i], "--threads")) threads = std::atoi(argv[i + 1]);
        else if (!std::strcmp(argv[i], "--calls")) calls = std::atoi(argv[i + 1]);
    }
    HMODULE dll = LoadLibraryW(L"flagfeature.dll");
    auto create = dll ? (Feature *(*)(const char *))GetProcAddress(dll, "CreateFeature") : nullptr;
    if (!create) { std::fprintf(stderr, "flagflip_target: flagfeature.dll!CreateFeature not found\n"); return 2; }
    const char *names[] = {"alpha", "beta"};
    Feature *features[2] = {create(names[0]), create(names[1])};
    Stats stats[2];
    std::vector<std::thread> pool;
    for (int t = 0; t < threads; ++t)
        pool.emplace_back([&] {
            for (int n = 0; n < calls; ++n)
                for (int k = 0; k < 2; ++k) {
                    stats[k].calls.fetch_add(1);
                    if (features[k]->IsEnabled()) { stats[k].enabled.fetch_add(1); gated_path(stats[k]); }
                }
        });
    for (auto &th : pool) th.join();
    for (int k = 0; k < 2; ++k)
        std::printf("{\"kind\":\"ff_feature\",\"name\":\"%s\",\"this\":\"0x%llx\",\"calls\":%ld,\"enabled\":%ld,"
                    "\"gated_ran\":%ld}\n", features[k]->name(), (unsigned long long)(uintptr_t)features[k],
                    stats[k].calls.load(), stats[k].enabled.load(), stats[k].gated.load());
    return 0;
}

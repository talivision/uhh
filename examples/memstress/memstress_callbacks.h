#pragma once

#include "probe_api.h"
#include <stdint.h>

#define MEMSTRESS_EXPORT __declspec(dllexport)
#define MEMSTRESS_CONFIG_VERSION 1u
#define MEMSTRESS_CONFIG_THROUGHPUT 1u
#define MEMSTRESS_THROUGHPUT_REPEATS 1u

struct memstress_config {
    uint32_t version;
    uint32_t flags;
    uint32_t throughput_repeats;
    uint32_t reserved;
    uint64_t expected_calls;
};

extern "C" MEMSTRESS_EXPORT void ms_on_site(probe_context *c);

#pragma once
// Blog-replica callbacks. ONE source, compiled into blog_driver (breakpoint / hw: the
// callbacks run in the controller) and into probe_api_agent.dll (inline: they run inside
// the target, found by export name).
#include "probe_api.h"
#include <stdint.h>

#define BLOG_EXPORT extern "C" __declspec(dllexport)

#define BLOG_COOKIE 0x626c6f67u        /* "blog" */
#define BLOG_RNG_LEN 48u               /* the BCryptGenRandom size whose OUTPUT is captured */

struct blog_config {
    uint32_t cookie;    /* BLOG_COOKIE */
    uint32_t backend;   /* PROBE_* of the entry probe: dynamic return probes use the same */
    uint32_t log;       /* 0 = count only (game: measure the bare per-hit cost) */
    uint32_t flags;     /* BLOG_NAIVE */
};
#define BLOG_NAIVE 1u   /* crypto: capture nested BCryptGenRandom calls too (needs a 5th hw slot) */

// crypto (ransomware-detection write-ups)
BLOG_EXPORT void blog_on_bcrypt_encrypt(probe_context *c);
BLOG_EXPORT void blog_on_genrandom(probe_context *c);
BLOG_EXPORT void blog_on_genrandom_ret(probe_context *c);
BLOG_EXPORT void blog_on_capi_encrypt(probe_context *c);
// registry persistence
BLOG_EXPORT void blog_on_ntcreatekey(probe_context *c);
BLOG_EXPORT void blog_on_ntsetvaluekey(probe_context *c);
// network / DNS
BLOG_EXPORT void blog_on_dnsquery(probe_context *c);
BLOG_EXPORT void blog_on_connect(probe_context *c);
BLOG_EXPORT void blog_on_send(probe_context *c);
BLOG_EXPORT void blog_on_recv(probe_context *c);
// process creation
BLOG_EXPORT void blog_on_create_process_internal(probe_context *c);
BLOG_EXPORT void blog_on_nt_create_user_process(probe_context *c);
// COM
BLOG_EXPORT void blog_on_cocreateinstance(probe_context *c);
// game loop
BLOG_EXPORT void blog_on_frame(probe_context *c);

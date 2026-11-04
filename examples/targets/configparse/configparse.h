#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct parsed_config { uint32_t reads_enabled, reserved; } parsed_config;
/* configparse.dll!ParseConfig: returns 1 and fills *out, or 0 on invalid text. */
typedef int (*parse_config_fn)(const char *text, parsed_config *out);
#ifdef __cplusplus
}
#endif

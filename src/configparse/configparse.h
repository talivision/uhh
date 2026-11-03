#pragma once
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct parsed_config { uint32_t reads_enabled, reserved; } parsed_config;
typedef int (*parse_config_fn)(const char *text, parsed_config *out);
#ifdef __cplusplus
}
#endif

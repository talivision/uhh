/* Stand-in for a third-party configuration library that the application loads
   only after user input. Never a static dependency of probe_app. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "configparse.h"

/* Assembly helper: the parsed value is in EAX at ParsedFlagSite, immediately
   before it is stored. See flag.asm. */
uint32_t StoreParsedFlag(parsed_config *out, uint32_t value);

static int key_is(const char *line, size_t len, const char *key) {
    size_t k = strlen(key);
    return len > k && !strncmp(line, key, k) && line[k] == '=';
}

__declspec(dllexport) int ParseConfig(const char *text, parsed_config *out) {
    if (!text || !out) return 0;
    memset(out, 0, sizeof(*out));
    int saw_flag = 0;
    while (*text) {
        const char *end = strchr(text, '\n');
        size_t len = end ? (size_t)(end - text) : strlen(text);
        if (key_is(text, len, "reads_enabled")) {
            char *stop = NULL;
            unsigned long v = strtoul(text + sizeof("reads_enabled"), &stop, 10);
            if (stop == text + sizeof("reads_enabled") || v > 1) return 0;
            StoreParsedFlag(out, (uint32_t)v);
            saw_flag = 1;
        }
        text += len + (end ? 1 : 0);
    }
    return saw_flag;
}

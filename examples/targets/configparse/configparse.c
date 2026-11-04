/* Stand-in for a third-party configuration library that the application loads only
   after user input. Never a static dependency of probe_app.

   The exported entry point ParseConfig is written in assembly (parse_x64.asm /
   parse_x86.asm) so that the instruction storing the parsed flag sits at a FIXED
   offset from the export on both architectures: configparse.dll!ParseConfig+0x16.
   This file only does the text parsing. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "configparse.h"

static int key_is(const char *line, size_t len, const char *key) {
    size_t k = strlen(key);
    return len > k && !strncmp(line, key, k) && line[k] == '=';
}

/* Returns the parsed reads_enabled value (0 or 1), or -1 when the text is invalid or
   has no reads_enabled line. ParseConfig stores the value into *out. */
int32_t ParseReadsEnabled(const char *text, parsed_config *out) {
    int32_t value = -1;
    if (!text || !out) return -1;
    memset(out, 0, sizeof(*out));
    while (*text) {
        const char *end = strchr(text, '\n');
        size_t len = end ? (size_t)(end - text) : strlen(text);
        if (key_is(text, len, "reads_enabled")) {
            char *stop = NULL;
            unsigned long v = strtoul(text + sizeof("reads_enabled"), &stop, 10);
            if (stop == text + sizeof("reads_enabled") || v > 1) return -1;
            value = (int32_t)v;
        }
        text += len + (end ? 1 : 0);
    }
    return value;
}

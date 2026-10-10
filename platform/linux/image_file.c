/**
 * @file platform/linux/image_file.c
 * @brief Shared file reader for the desktop image decoders.
 */

#include "image_file.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

uint8_t* image_read_file(const char* path, size_t* out_len, size_t max_len) {
    if (!path || !out_len) return NULL;

    FILE* f = fopen(path, "rb");
    if (!f) return NULL;

    uint8_t* buf = NULL;
    size_t   len = 0, cap = 0;
    bool     ok = true;

    for (;;) {
        if (len == cap) {
            if (cap >= max_len) { /* refuse to slurp an absurd file */
                ok = false;
                break;
            }
            size_t   ncap = cap ? cap * 2 : 65536;
            uint8_t* nbuf = realloc(buf, ncap);
            if (!nbuf) {
                ok = false;
                break;
            }
            buf = nbuf;
            cap = ncap;
        }

        size_t n = fread(buf + len, 1, cap - len, f);
        if (n == 0) {
            ok = !ferror(f); /* short read or end of file */
            break;
        }
        len += n;
    }

    fclose(f);
    if (!ok) {
        free(buf);
        return NULL;
    }

    *out_len = len;
    return buf;
}

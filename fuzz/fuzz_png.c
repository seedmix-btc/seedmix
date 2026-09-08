/**
 * @file fuzz/fuzz_png.c
 * @brief libFuzzer target for the desktop PNG decoder.
 */

#include "png_gray.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* The decoder API takes a path, so each input is written to a file first. */
#define FUZZ_PATH "/tmp/seedmix_fuzz_png.tmp"

/* Sink for the image reads, so the compiler cannot drop the loop. */
static volatile uint8_t g_sink;

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FILE* f = fopen(FUZZ_PATH, "wb");
    if (!f) return 0;
    if (size && fwrite(data, 1, size, f) != size) {
        fclose(f);
        return 0;
    }
    fclose(f);

    uint32_t w = 0, h = 0;
    uint8_t* gray = png_decode_gray_file(FUZZ_PATH, &w, &h);
    if (!gray) return 0;

    /* A decoded image has a size, and the decoder caps the total pixel count
     * (PNG_MAX_PIXELS) before it allocates anything. */
    if (!w || !h) abort();
    if ((uint64_t)w * h > 64u * 1024u * 1024u) abort();

    for (size_t i = 0; i < (size_t)w * h; i++) g_sink ^= gray[i];

    free(gray);
    return 0;
}

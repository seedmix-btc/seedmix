/**
 * @file fuzz/fuzz_gif.c
 * @brief libFuzzer target for the desktop GIF decoder.
 */

#include "gif_gray.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* The decoder API takes a path, so each input is written to a file first. */
#define FUZZ_PATH "/tmp/seedmix_fuzz_gif.tmp"

/* Sink for the frame reads, so the compiler cannot drop the loop. */
static volatile uint8_t g_sink;

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FILE* f = fopen(FUZZ_PATH, "wb");
    if (!f) return 0;
    if (size && fwrite(data, 1, size, f) != size) {
        fclose(f);
        return 0;
    }
    fclose(f);

    uint32_t    w = 0, h = 0;
    gif_gray_t* g = gif_gray_open(FUZZ_PATH, &w, &h);
    if (!g) return 0;

    /* The screen size comes from two 16-bit header fields and is capped at
     * 4 Mpx of canvas, so a decoder that opened the file has to report a sane
     * size. */
    if (!w || !h || w > 0xFFFFu || h > 0xFFFFu) abort();
    if ((uint64_t)w * h > 4u * 1024u * 1024u) abort();

    /* Two passes: the second one replays the animation from a rewound decoder,
     * which is what a looping animation does. */
    for (int pass = 0; pass < 2; pass++) {
        uint8_t* gray     = NULL;
        uint32_t delay_ms = 0;

        while (gif_gray_next(g, &gray, &delay_ms)) {
            if (!gray) abort();         /* a frame is always a buffer */
            if (delay_ms == 0) abort(); /* frames without a delay get 100 ms */

            for (size_t i = 0; i < (size_t)w * h; i++) g_sink ^= gray[i];

            free(gray);
            gray = NULL;
        }
        free(gray);

        gif_gray_rewind(g);
    }

    gif_gray_close(g);
    return 0;
}

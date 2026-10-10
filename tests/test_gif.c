/**
 * @file tests/test_gif.c
 * @brief Unity tests for the desktop GIF decoder (platform/linux/gif_gray.c).
 *
 * The animated GIFs under tests/vectors/psbt/qr-gif/ are the real-world case:
 * one QR code per frame, holding the parts of a fountain-encoded PSBT UR.  The
 * test decodes every frame, feeds the payloads the QR decoder gets out of them
 * to the multi-part UR decoder, and checks the reassembled PSBT against the
 * raw bytes the vector was generated from.
 */

#include "gif_gray.h"
#include "image_file.h"
#include "qr.h"
#include "ur_psbt.h"
#include "util/utils.h"
#include "vectors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <unity.h>

#define PAYLOAD_MAX 4096

void setUp(void) {}
void tearDown(void) {}

/* Decode every frame of a GIF; returns the frame count (0 when it never
 * opened).  Frames are handed to `per_frame` when given. */
typedef void (*frame_cb_t)(const uint8_t* gray, uint32_t w, uint32_t h, unsigned index, void* ctx);

static unsigned decode_all_frames(const char* path, frame_cb_t per_frame, void* ctx,
                                  bool* out_failed) {
    uint32_t    w = 0, h = 0;
    gif_gray_t* g = gif_gray_open(path, &w, &h);
    if (!g) return 0;

    TEST_ASSERT_GREATER_THAN_UINT32(0, w);
    TEST_ASSERT_GREATER_THAN_UINT32(0, h);

    unsigned frames = 0;
    for (unsigned guard = 0; guard < 4096; guard++) {
        uint8_t* gray     = NULL;
        uint32_t delay_ms = 0;
        if (!gif_gray_next(g, &gray, &delay_ms)) break;

        TEST_ASSERT_NOT_NULL(gray);
        TEST_ASSERT_EQUAL_UINT32(w, w);
        TEST_ASSERT_GREATER_THAN_UINT32(0, delay_ms);
        if (per_frame) per_frame(gray, w, h, frames, ctx);
        free(gray);
        frames++;
    }

    if (out_failed) *out_failed = gif_gray_failed(g);
    gif_gray_close(g);
    return frames;
}

/* -- Vector GIFs ------------------------------------------------------- */

typedef struct {
    ur_psbt_decoder_t* decoder;
    unsigned           qr_frames; /* frames a QR code was read out of */
    int                done;      /* 1 once the UR assembled */
    uint8_t*           psbt;
    size_t             psbt_len;
} reassemble_t;

static void feed_part(const uint8_t* gray, uint32_t w, uint32_t h, unsigned index, void* ctx) {
    (void)index;
    reassemble_t* r = ctx;

    uint8_t payload[PAYLOAD_MAX];
    size_t  plen = 0;
    if (!qr_decode(gray, w, h, payload, sizeof(payload), &plen)) return; /* not a QR frame */

    r->qr_frames++;

    uint8_t* psbt = NULL;
    size_t   len  = 0;
    int      got  = ur_psbt_decoder_receive(r->decoder, (const char*)payload, plen, &psbt, &len);
    TEST_ASSERT_TRUE(got >= 0); /* every frame is a UR part */
    if (got == 1) {
        r->done     = 1;
        r->psbt     = psbt;
        r->psbt_len = len;
    }
}

/* Every part of an animated PSBT GIF must come out of the frames, in order. */
static void test_gif_frames_reassemble_psbt(void) {
    char** slugs   = NULL;
    size_t n_slugs = 0;
    TEST_ASSERT_TRUE(vectors_list_slugs("psbt/qr-gif", ".multipart.gif", &slugs, &n_slugs));
    TEST_ASSERT_TRUE(n_slugs > 0);

    for (size_t s = 0; s < n_slugs; s++) {
        const char* slug = slugs[s];
        char        path[512];

        /* Expected raw PSBT. */
        snprintf(path, sizeof(path), "psbt/raw/%s.hex", slug);
        char* hex = (char*)vectors_read_file(path, NULL);
        TEST_ASSERT_NOT_NULL(hex);
        vectors_trim(hex);
        size_t   expect_len = strlen(hex) / 2;
        uint8_t* expect     = malloc(expect_len);
        TEST_ASSERT_NOT_NULL(expect);
        TEST_ASSERT_TRUE(hex_to_bytes(hex, strlen(hex), expect, expect_len));
        free(hex);

        reassemble_t r;
        memset(&r, 0, sizeof(r));
        r.decoder = ur_psbt_decoder_new();
        TEST_ASSERT_NOT_NULL(r.decoder);

        snprintf(path, sizeof(path), "psbt/qr-gif/%s.multipart.gif", slug);
        char full[640];
        vector_path(full, sizeof(full), path);
        bool     failed = true;
        unsigned frames = decode_all_frames(full, feed_part, &r, &failed);

        TEST_ASSERT_GREATER_THAN_UINT(1, frames);    /* an animated GIF */
        TEST_ASSERT_FALSE(failed);                   /* the trailer was reached */
        TEST_ASSERT_EQUAL_UINT(frames, r.qr_frames); /* one QR code per frame */

        TEST_ASSERT_EQUAL_INT(1, r.done); /* the parts add up to the PSBT */
        TEST_ASSERT_EQUAL_UINT(expect_len, (unsigned)r.psbt_len);
        TEST_ASSERT_EQUAL_MEMORY(expect, r.psbt, expect_len);

        free(r.psbt);
        free(expect);
        ur_psbt_decoder_free(r.decoder);
    }

    vectors_free_slugs(slugs, n_slugs);
}

/* Playing the animation again must start from the same first frame: the canvas
 * has to be reset, not carried over from the last frame. */
static void test_gif_rewind_repeats_the_animation(void) {
    char** slugs   = NULL;
    size_t n_slugs = 0;
    TEST_ASSERT_TRUE(vectors_list_slugs("psbt/qr-gif", ".multipart.gif", &slugs, &n_slugs));
    TEST_ASSERT_TRUE(n_slugs > 0);

    for (size_t s = 0; s < n_slugs; s++) {
        char path[512];
        snprintf(path, sizeof(path), "psbt/qr-gif/%s.multipart.gif", slugs[s]);

        char full[640];
        vector_path(full, sizeof(full), path);

        uint32_t    w = 0, h = 0;
        gif_gray_t* g = gif_gray_open(full, &w, &h);
        TEST_ASSERT_NOT_NULL(g);

        uint8_t* first       = NULL;
        uint8_t* first_again = NULL;
        size_t   frame_bytes = (size_t)w * h;
        uint32_t delay       = 0;

        TEST_ASSERT_TRUE(gif_gray_next(g, &first, &delay));
        TEST_ASSERT_NOT_NULL(first);

        /* Play to the end of the animation. */
        unsigned guard = 0;
        uint8_t* gray  = NULL;
        while (gif_gray_next(g, &gray, &delay)) {
            free(gray);
            gray = NULL;
            TEST_ASSERT_TRUE(++guard < 4096);
        }
        TEST_ASSERT_FALSE(gif_gray_failed(g));
        TEST_ASSERT_GREATER_THAN_UINT(0, guard);

        gif_gray_rewind(g);
        TEST_ASSERT_TRUE(gif_gray_next(g, &first_again, &delay));
        TEST_ASSERT_EQUAL_MEMORY(first, first_again, frame_bytes);

        free(first_again);
        free(first);
        gif_gray_close(g);
    }

    vectors_free_slugs(slugs, n_slugs);
}

/* -- Bad input --------------------------------------------------------- */

static void test_gif_rejects_non_gif(void) {
    uint32_t    w = 0, h = 0;
    gif_gray_t* g = gif_gray_open(NULL, &w, &h);
    TEST_ASSERT_NULL(g);

    g = gif_gray_open("/nonexistent/seedmix.gif", &w, &h);
    TEST_ASSERT_NULL(g);

    /* A PNG next to the GIFs: recognised as "not a GIF" without decoding. */
    char** slugs   = NULL;
    size_t n_slugs = 0;
    TEST_ASSERT_TRUE(vectors_list_slugs("psbt/qr-png", ".v2.png", &slugs, &n_slugs));
    TEST_ASSERT_TRUE(n_slugs > 0);

    char path[512];
    snprintf(path, sizeof(path), "psbt/qr-png/%s.v2.png", slugs[0]);

    char full[640];
    vector_path(full, sizeof(full), path);
    g = gif_gray_open(full, &w, &h);
    TEST_ASSERT_NULL(g);
    vectors_free_slugs(slugs, n_slugs);
}

/* Truncated and mutated files must fail cleanly - no crash, no leak (the
 * sanitizer CI job runs this suite too). */
static void test_gif_broken_files_fail_cleanly(void) {
    char** slugs   = NULL;
    size_t n_slugs = 0;
    TEST_ASSERT_TRUE(vectors_list_slugs("psbt/qr-gif", ".multipart.gif", &slugs, &n_slugs));
    TEST_ASSERT_TRUE(n_slugs > 0);

    char src[512];
    snprintf(src, sizeof(src), "psbt/qr-gif/%s.multipart.gif", slugs[0]);

    size_t   len  = 0;
    uint8_t* data = vectors_read_file(src, &len);
    TEST_ASSERT_NOT_NULL(data);
    TEST_ASSERT_GREATER_THAN_UINT(0, (unsigned)len);

    char tmp[] = "/tmp/seedmix_gifXXXXXX";
    int  fd    = mkstemp(tmp);
    TEST_ASSERT_TRUE(fd >= 0);
    TEST_ASSERT_EQUAL_INT(0, close(fd));

    /* Truncations: everything from a bare header to nearly the whole file. */
    size_t cuts[] = {13, len / 4, len / 2, len - 1};
    for (size_t c = 0; c < sizeof(cuts) / sizeof(cuts[0]); c++) {
        size_t n = cuts[c] < len ? cuts[c] : len;
        FILE*  f = fopen(tmp, "wb");
        TEST_ASSERT_NOT_NULL(f);
        TEST_ASSERT_EQUAL_UINT(n, fwrite(data, 1, n, f));
        TEST_ASSERT_EQUAL_INT(0, fclose(f));

        uint32_t    w = 0, h = 0;
        gif_gray_t* g = gif_gray_open(tmp, &w, &h);
        if (!g) continue; /* too short to be a GIF at all: fine */

        uint8_t* gray  = NULL;
        uint32_t delay = 0;
        for (unsigned guard = 0; guard < 4096; guard++) {
            if (!gif_gray_next(g, &gray, &delay)) break;
            free(gray);
            gray = NULL;
        }
        TEST_ASSERT_TRUE(gif_gray_failed(g)); /* it ran out of file */
        gif_gray_close(g);
    }

    /* Bit flips all over the stream. */
    for (size_t i = 0; i < 64; i++) {
        size_t at = 8 + (i * 7919) % (len - 8);
        data[at] ^= (uint8_t)(1u << (i % 8));

        FILE* f = fopen(tmp, "wb");
        TEST_ASSERT_NOT_NULL(f);
        TEST_ASSERT_EQUAL_UINT(len, fwrite(data, 1, len, f));
        TEST_ASSERT_EQUAL_INT(0, fclose(f));
        data[at] ^= (uint8_t)(1u << (i % 8)); /* undo */

        uint32_t    w = 0, h = 0;
        gif_gray_t* g = gif_gray_open(tmp, &w, &h);
        if (!g) continue;

        uint8_t* gray  = NULL;
        uint32_t delay = 0;
        for (unsigned guard = 0; guard < 4096; guard++) {
            if (!gif_gray_next(g, &gray, &delay)) break;
            free(gray);
            gray = NULL;
        }
        gif_gray_close(g);
    }

    unlink(tmp);
    free(data);
    vectors_free_slugs(slugs, n_slugs);
}

/* -- Decoder fixtures (tests/vectors/gif/) ------------------------------ */

/* Decode a fixture and check every frame against the expected pixels: one
 * pointer into `expected` per frame, each w*h bytes. */
static void expect_frames_at(const char* path, const char* label, uint32_t w, uint32_t h,
                             const uint8_t* const* expected, size_t n_expected, bool want_failed) {
    uint32_t    gw = 0, gh = 0;
    gif_gray_t* g = gif_gray_open(path, &gw, &gh);
    TEST_ASSERT_NOT_NULL_MESSAGE(g, label);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(w, gw, label);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(h, gh, label);

    size_t frames = 0;
    for (unsigned guard = 0; guard < 64; guard++) {
        uint8_t* gray     = NULL;
        uint32_t delay_ms = 0;
        if (!gif_gray_next(g, &gray, &delay_ms)) break;

        TEST_ASSERT_LESS_THAN_UINT_MESSAGE((unsigned)n_expected, (unsigned)frames, label);
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expected[frames], gray, (size_t)w * h, label);
        free(gray);
        frames++;
    }

    TEST_ASSERT_EQUAL_UINT_MESSAGE((unsigned)n_expected, (unsigned)frames, label);
    TEST_ASSERT_EQUAL_MESSAGE(want_failed, gif_gray_failed(g), label);
    gif_gray_close(g);
}

/* The same for a named file under tests/vectors/gif/. */
static void expect_frames(const char* name, uint32_t w, uint32_t h, const uint8_t* const* expected,
                          size_t n_expected, bool want_failed) {
    char rel[128];
    snprintf(rel, sizeof(rel), "gif/%s", name);

    char path[640];
    vector_path(path, sizeof(path), rel);
    expect_frames_at(path, name, w, h, expected, n_expected, want_failed);
}

/* Copy bytes to a fresh temp file and hand back its path. */
static bool tmp_file(const void* data, size_t len, char* path, size_t path_len) {
    static const char tmpl[] = "/tmp/seedmix_gifXXXXXX";
    if (path_len < sizeof(tmpl)) return false;
    memcpy(path, tmpl, sizeof(tmpl));

    int fd = mkstemp(path);
    if (fd < 0) return false;
    close(fd);

    FILE* f = fopen(path, "wb");
    if (!f) return false;
    return fwrite(data, 1, len, f) == len && fclose(f) == 0;
}

/*
 * Frame disposal: the first frame paints the canvas white, the second paints the
 * right half black and then asks for the canvas to be put back - to the
 * background (disposal 2, the grey palette entry the file names as its
 * background) or to what the first frame left behind (disposal 3, all white).
 * The third frame is fully transparent, so it shows exactly that: ignoring the
 * disposal would leave the black right half in place.
 */
static void test_gif_disposal_restores_the_canvas(void) {
    static const uint8_t white[16]      = {255, 255, 255, 255, 255, 255, 255, 255,
                                      255, 255, 255, 255, 255, 255, 255, 255};
    static const uint8_t half[16]       = {255, 255, 0, 0, 255, 255, 0, 0,
                                     255, 255, 0, 0, 255, 255, 0, 0};
    static const uint8_t background[16] = {255, 255, 100, 100, 255, 255, 100, 100,
                                           255, 255, 100, 100, 255, 255, 100, 100};

    const uint8_t* disposal2[3] = {white, half, background};
    const uint8_t* disposal3[3] = {white, half, white};

    expect_frames("disposal2.gif", 4, 4, disposal2, 3, false);
    expect_frames("disposal3.gif", 4, 4, disposal3, 3, false);
}

/*
 * Interlaced frame: the fixture's four rows (grey 0, 100, 255, 200) are stored
 * in natural order with the interlace flag set, so the decoder has to place
 * them where GIF puts an interlaced stream: stored row 0 stays at y=0, row 1
 * goes to y=2, row 2 to y=1 and row 3 stays.  Pillow reads the same file the
 * same way, which is how these expectations were checked.
 */
static void test_gif_interlaced_frame(void) {
    static const uint8_t f1[16] = {0,   0,   0,   0,   100, 100, 100, 100,
                                   255, 255, 255, 255, 200, 200, 200, 200};

    const uint8_t* frames[1] = {f1};
    expect_frames("interlaced.gif", 4, 4, frames, 1, false);
}

/* A plain two-frame animation, plus the same file with a stray padding byte in
 * it: padding is not worth failing a file over. */
static void test_gif_plain_animation(void) {
    static const uint8_t f1[4] = {255, 255, 255, 255};
    static const uint8_t f2[4] = {0, 0, 0, 0};

    const uint8_t* frames[2] = {f1, f2};
    expect_frames("plain.gif", 2, 2, frames, 2, false);
    expect_frames("broken-padding.gif", 2, 2, frames, 2, false);
}

/*
 * A background index outside the palette leaves the decoder with no background
 * color at all, and then it starts from white: a light canvas is what a QR code
 * needs, so guessing white beats throwing the file away.
 *
 * The disposal fixture shows it, because its disposal restores the background:
 * pointing the background index past the end of the palette turns the grey the
 * third frame shows into white.
 */
static void test_gif_background_falls_back_to_white(void) {
    static const uint8_t white[16] = {255, 255, 255, 255, 255, 255, 255, 255,
                                      255, 255, 255, 255, 255, 255, 255, 255};
    static const uint8_t half[16]  = {255, 255, 0, 0, 255, 255, 0, 0,
                                     255, 255, 0, 0, 255, 255, 0, 0};

    size_t   len  = 0;
    uint8_t* data = vectors_read_file("gif/disposal2.gif", &len);
    TEST_ASSERT_NOT_NULL(data);
    TEST_ASSERT_GREATER_THAN_UINT(0, (unsigned)len);

    data[11] = 0xFF; /* background index, past the end of the 4-color table */

    char tmp[64];
    TEST_ASSERT_TRUE(tmp_file(data, len, tmp, sizeof(tmp)));
    free(data);

    const uint8_t* frames[3] = {white, half, white};
    expect_frames_at(tmp, "disposal2.gif with a bad background index", 4, 4, frames, 3, false);
    unlink(tmp);
}

/* Every way a GIF file can be broken: the ones that never open, the ones whose
 * decoding stops part way, and the ones that must still decode. */
static void test_gif_broken_fixtures(void) {
    const char* const no_open[] = {"broken-short-header.gif", "broken-truncated-palette.gif"};
    for (size_t i = 0; i < sizeof(no_open) / sizeof(no_open[0]); i++) {
        char rel[128];
        snprintf(rel, sizeof(rel), "gif/%s", no_open[i]);
        char path[640];
        vector_path(path, sizeof(path), rel);

        uint32_t w = 0, h = 0;
        TEST_ASSERT_NULL_MESSAGE(gif_gray_open(path, &w, &h), no_open[i]);
    }

    /* A screen size of zero, which is not an image: refused up front. */
    {
        size_t   len  = 0;
        uint8_t* data = vectors_read_file("gif/plain.gif", &len);
        TEST_ASSERT_NOT_NULL(data);
        TEST_ASSERT_GREATER_THAN_UINT(13, (unsigned)len);

        data[6] = 0; /* width, little endian */
        data[7] = 0;

        char tmp[64];
        TEST_ASSERT_TRUE(tmp_file(data, len, tmp, sizeof(tmp)));
        free(data);

        uint32_t w = 0, h = 0;
        TEST_ASSERT_NULL(gif_gray_open(tmp, &w, &h));
        unlink(tmp);
    }

    /* These open but stop decoding: `frames` is how far each one gets first. */
    struct {
        const char* name;
        unsigned    frames;
    } const cases[] = {
        {"broken-no-trailer.gif", 2},        /* both frames, then no end marker */
        {"broken-bad-block.gif", 0},         /* neither extension nor frame */
        {"broken-comment-subblocks.gif", 0}, /* sub-block longer than the file */
        {"broken-gce-size.gif", 0},          /* control extension of the wrong size */
        {"broken-truncated-data.gif", 1},    /* first frame fits, the file ends there */
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char rel[128];
        snprintf(rel, sizeof(rel), "gif/%s", cases[i].name);
        char path[640];
        vector_path(path, sizeof(path), rel);

        uint32_t    w = 0, h = 0;
        gif_gray_t* g = gif_gray_open(path, &w, &h);
        TEST_ASSERT_NOT_NULL_MESSAGE(g, cases[i].name);

        unsigned frames = 0;
        for (unsigned guard = 0; guard < 64; guard++) {
            uint8_t* gray     = NULL;
            uint32_t delay_ms = 0;
            if (!gif_gray_next(g, &gray, &delay_ms)) break;
            free(gray);
            frames++;
        }

        TEST_ASSERT_EQUAL_UINT_MESSAGE(cases[i].frames, frames, cases[i].name);
        TEST_ASSERT_TRUE_MESSAGE(gif_gray_failed(g), cases[i].name);
        gif_gray_close(g);
    }
}

/* -- Shared file reader ------------------------------------------------ */

/* Reading a whole file, which the decoders do before parsing it. */
static void test_image_read_file_limits(void) {
    const size_t big = 200 * 1024; /* more than the reader's first buffer */

    char tmp[] = "/tmp/seedmix_imgfileXXXXXX";
    int  fd    = mkstemp(tmp);
    TEST_ASSERT_TRUE(fd >= 0);
    TEST_ASSERT_EQUAL_INT(0, close(fd));

    FILE* f = fopen(tmp, "wb");
    TEST_ASSERT_NOT_NULL(f);
    for (size_t i = 0; i < big; i++) {
        TEST_ASSERT_NOT_EQUAL_MESSAGE(EOF, fputc((int)(i & 0xFFu), f), "write");
    }
    TEST_ASSERT_EQUAL_INT(0, fclose(f));

    size_t   len = 0;
    uint8_t* buf = image_read_file(tmp, &len, big * 2);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_EQUAL_UINT(big, (unsigned)len);
    TEST_ASSERT_EQUAL_UINT8(0x00, buf[0]);
    TEST_ASSERT_EQUAL_UINT8((uint8_t)((big - 1) & 0xFFu), buf[big - 1]);
    free(buf);

    /* A cap below the file size is refused instead of being read. */
    TEST_ASSERT_NULL(image_read_file(tmp, &len, 1024));

    /* Nothing to read. */
    TEST_ASSERT_NULL(image_read_file("/nonexistent/seedmix.bin", &len, 4096));
    TEST_ASSERT_NULL(image_read_file(tmp, NULL, 4096));
    TEST_ASSERT_NULL(image_read_file(NULL, &len, 4096));

    unlink(tmp);
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_gif_frames_reassemble_psbt);
    RUN_TEST(test_gif_rewind_repeats_the_animation);
    RUN_TEST(test_gif_rejects_non_gif);
    RUN_TEST(test_gif_broken_files_fail_cleanly);
    RUN_TEST(test_gif_disposal_restores_the_canvas);
    RUN_TEST(test_gif_interlaced_frame);
    RUN_TEST(test_gif_plain_animation);
    RUN_TEST(test_gif_background_falls_back_to_white);
    RUN_TEST(test_gif_broken_fixtures);
    RUN_TEST(test_image_read_file_limits);

    return UNITY_END();
}

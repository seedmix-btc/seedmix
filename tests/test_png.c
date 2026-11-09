/**
 * @file tests/test_png.c
 * @brief Unity tests for the desktop PNG decoder (platform/linux/png_gray.c).
 *
 * PNG is what a screenshot or a wallet's "save this QR" button produces, so the
 * desktop HAL hands every picked PNG to this decoder.  The fixtures under
 * tests/vectors/png/ are packed byte by byte by scripts/gen_vectors.py - one per
 * colour type and bit depth, one per row filter, Adam7, and a batch of broken
 * files - and each one's grayscale output is checked against a hand-written
 * expectation.  The fixtures use greys (the luminance of a grey (v, v, v) is
 * exactly v) and alpha levels 0/128/255, which composite over white to 255, 127
 * and the colour itself, so the expected bytes can be written down by hand.
 *
 * The vector PNGs of the real QR codes are checked too: they are the same
 * payloads the other suites decode from text, which is what the file scan needs.
 */

#include "png_gray.h"
#include "qr.h"
#include "util/utils.h"
#include "vectors.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unity.h>

#define PAYLOAD_MAX 4096

void setUp(void) {}
void tearDown(void) {}

/* -- Fixtures ---------------------------------------------------------- */

/* The four grey levels the fixtures cycle through, so most of them share one of
 * a handful of expected 4x4 patterns. */
static const uint8_t pattern4x4[16] = {0,   85,  170, 255, 85,  170, 255, 0,
                                       170, 255, 0,   85,  255, 0,   85,  170};
static const uint8_t pattern4x5[20] = {0, 85, 170, 255, 85, 170, 255, 0,  170, 255,
                                       0, 85, 255, 0,   85, 170, 0,   85, 170, 255};
static const uint8_t checker4x4[16] = {0, 255, 0, 255, 255, 0, 255, 0,
                                       0, 255, 0, 255, 255, 0, 255, 0};
static const uint8_t alpha4x4[16]   = {0, 127, 255, 255, 0, 127, 255, 255,
                                     0, 127, 255, 255, 0, 127, 255, 255};
/* 1/2/4-bit levels scale to exact 8-bit values: 4-bit sample 7 is 7*255/15. */
static const uint8_t scaled4bit[16]       = {0,  85,  170, 255, 17, 102, 187, 0,
                                       34, 119, 204, 17,  51, 136, 221, 34};
static const uint8_t palette4bit[16]      = {0,   51,  119, 255, 51,  119, 255, 0,
                                        119, 255, 0,   51,  255, 0,   51,  119};
static const uint8_t palette_alpha4x4[16] = {0, 127, 0, 127, 127, 0, 127, 0,
                                             0, 127, 0, 127, 127, 0, 127, 0};
static const uint8_t wide16x1[16]         = {0, 255, 0, 255, 0, 255, 0, 255,
                                     0, 255, 0, 255, 0, 255, 0, 255};

static void expect_png(const char* name, uint32_t w, uint32_t h, const uint8_t* expected) {
    char rel[128];
    snprintf(rel, sizeof(rel), "png/%s", name);

    char path[640];
    vector_path(path, sizeof(path), rel);

    uint32_t w_got = 0, h_got = 0;
    uint8_t* gray = png_decode_gray_file(path, &w_got, &h_got);
    TEST_ASSERT_NOT_NULL_MESSAGE(gray, name);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(w, w_got, name);
    TEST_ASSERT_EQUAL_UINT32_MESSAGE(h, h_got, name);
    TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(expected, gray, w * h, name);
    free(gray);
}

/* Every colour type and bit depth, and every filter type. */
static void test_png_fixture_pixels(void) {
    struct {
        const char*    name;
        uint32_t       w, h;
        const uint8_t* expected;
    } const cases[] = {
        /* Grayscale: 1-bit levels are 0/255, 2-bit 0/85/170/255, and the 4-bit
         * rows step by 5 samples, so the scaling is checked too. */
        {"gray-1bit.png", 4, 4, checker4x4},
        {"gray-2bit.png", 4, 4, pattern4x4},
        {"gray-4bit.png", 4, 4, scaled4bit},
        {"gray-8bit.png", 4, 4, pattern4x4},
        {"gray-16bit.png", 4, 4, pattern4x4}, /* the high byte of each sample */

        {"rgb-8bit.png", 4, 4, pattern4x4},
        {"rgb-16bit.png", 4, 4, pattern4x4},
        {"rgba-8bit.png", 4, 4, pattern4x4},
        {"rgba-16bit.png", 4, 4, pattern4x4},

        /* Alpha composited over white: black at alpha 0 stays white, and
         * (0 * 128 + 255 * 127) / 255 = 127. */
        {"gray-alpha-8bit.png", 4, 4, alpha4x4},
        {"gray-alpha-16bit.png", 4, 4, alpha4x4},
        {"rgba-alpha-8bit.png", 4, 4, alpha4x4},
        {"rgba-alpha-16bit.png", 4, 4, alpha4x4},

        {"palette-1bit.png", 4, 4, checker4x4},
        {"palette-2bit.png", 4, 4, pattern4x4},
        {"palette-4bit.png", 4, 4, palette4bit},
        {"palette-8bit.png", 4, 4, pattern4x4},
        {"palette-alpha.png", 4, 4, palette_alpha4x4},

        /* Row filters 0..4, one row each: unfiltering is what is being tested,
         * so all five rows have to come out as the stripes that went in. */
        {"filters.png", 4, 5, pattern4x5},

        /* Adam7, plus the sizes where most passes stay empty. */
        {"adam7-gray-8bit.png", 4, 4, pattern4x4},
        {"adam7-rgba-16bit.png", 4, 4, pattern4x4},
        {"adam7-1x1.png", 1, 1, (const uint8_t[]){255}},

        /* A row that is not a whole number of bytes, and the smallest image. */
        {"wide-16x1-1bit.png", 16, 1, wide16x1},
        {"tiny-1x1.png", 1, 1, (const uint8_t[]){0}},
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        expect_png(cases[i].name, cases[i].w, cases[i].h, cases[i].expected);
    }
}

/* A palette index past the end of the table is not worth failing a whole image
 * over, but it must not read past the table either: those pixels come out black,
 * and the ones that are in range keep their colour. */
static void test_png_palette_index_past_the_end(void) {
    static const uint8_t expected[16] = {0, 0, 0, 0, 0, 0, 0, 255, 0, 0, 255, 0, 0, 255, 0, 0};
    expect_png("broken-palette-index.png", 4, 4, expected);
}

/* Every way a PNG file can be broken: all of them have to fail cleanly (the
 * sanitizer CI job runs this suite, so a read past the end of a buffer is a
 * failure here too). */
static void test_png_broken_fixtures(void) {
    const char* const cases[] = {
        "broken-signature.png",    /* first byte flipped */
        "broken-crc.png",          /* chunk data does not match its CRC */
        "broken-truncated.png",    /* cut in half */
        "broken-depth.png",        /* RGB at a 4-bit depth */
        "broken-colour-type.png",  /* colour type 5 */
        "broken-interlace.png",    /* an interlace method that does not exist */
        "broken-zero-size.png",    /* zero width */
        "broken-huge.png",         /* 262144 x 262144 pixels */
        "broken-no-ihdr.png",      /* first chunk is not IHDR */
        "broken-ihdr-size.png",    /* IHDR that is not 13 bytes long */
        "broken-no-idat.png",      /* header only */
        "broken-no-palette.png",   /* palette image without a PLTE chunk */
        "broken-palette-size.png", /* PLTE that is not whole RGB triples */
        "broken-chunk-length.png", /* chunk length running past the file */
        "broken-short-raw.png",    /* scanlines short of the declared height */
        "broken-long-raw.png",     /* and more of them than declared */
        "broken-bad-filter.png",   /* filter type 5 */
    };

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char rel[128];
        snprintf(rel, sizeof(rel), "png/%s", cases[i]);

        char path[640];
        vector_path(path, sizeof(path), rel);

        uint32_t w = 0, h = 0;
        TEST_ASSERT_NULL_MESSAGE(png_decode_gray_file(path, &w, &h), cases[i]);
    }
}

/* Missing files and missing arguments. */
static void test_png_rejects_odd_input(void) {
    uint32_t w = 0, h = 0;

    TEST_ASSERT_NULL(png_decode_gray_file(NULL, &w, &h));
    TEST_ASSERT_NULL(png_decode_gray_file("/nonexistent/seedmix.png", &w, &h));

    char path[640];
    vector_path(path, sizeof(path), "png/gray-8bit.png");
    TEST_ASSERT_NULL(png_decode_gray_file(path, NULL, &h));
    TEST_ASSERT_NULL(png_decode_gray_file(path, &w, NULL));

    /* A GIF is not a PNG: the caller falls back to the other decoders. */
    vector_path(path, sizeof(path), "gif/plain.gif");
    TEST_ASSERT_NULL(png_decode_gray_file(path, &w, &h));
}

/* -- Vector files ------------------------------------------------------ */

/* Decode a PNG vector and read the QR payload out of it. */
static bool png_payload(const char* rel, uint8_t* payload, size_t cap, size_t* out_len) {
    char path[640];
    vector_path(path, sizeof(path), rel);

    uint32_t w = 0, h = 0;
    uint8_t* gray = png_decode_gray_file(path, &w, &h);
    if (!gray) {
        TEST_FAIL_MESSAGE(rel);
        return false;
    }

    bool ok = qr_decode(gray, w, h, payload, cap, out_len);
    free(gray);
    return ok;
}

/*
 * The single-part PSBT QR codes have to decode to the very UR string the other
 * suites decode from text.  One vector is denser than quirc can read (version
 * 30, more alignment patterns than QUIRC_MAX_CAPSTONES): its PNG still has to
 * decode, and the payload is then simply not readable - which is what makes the
 * animated multi-part form necessary.  Both cases are required, so neither a
 * broken decoder nor a silently unreadable QR code passes unnoticed.
 */
static void test_png_psbt_vector_files(void) {
    char** slugs   = NULL;
    size_t n_slugs = 0;
    TEST_ASSERT_TRUE(vectors_list_slugs("psbt/qr-png", ".v2.png", &slugs, &n_slugs));
    TEST_ASSERT_TRUE(n_slugs > 0);

    unsigned readable = 0, dense = 0;

    for (size_t s = 0; s < n_slugs; s++) {
        char rel[256];
        snprintf(rel, sizeof(rel), "psbt/qr-png/%s.v2.png", slugs[s]);

        uint8_t payload[PAYLOAD_MAX];
        size_t  payload_len = 0;

        if (!png_payload(rel, payload, sizeof(payload), &payload_len)) {
            dense++;
            continue;
        }
        readable++;

        char ur_rel[256];
        snprintf(ur_rel, sizeof(ur_rel), "psbt/ur/%s.v2.ur", slugs[s]);
        char* ur = (char*)vectors_read_file(ur_rel, NULL);
        TEST_ASSERT_NOT_NULL(ur);
        vectors_trim(ur);

        TEST_ASSERT_EQUAL_UINT_MESSAGE((unsigned)strlen(ur), (unsigned)payload_len, rel);
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(ur, payload, payload_len, rel);
        free(ur);
    }

    TEST_ASSERT_GREATER_THAN_UINT(0, readable);
    TEST_ASSERT_GREATER_THAN_UINT(0, dense);
    vectors_free_slugs(slugs, n_slugs);
}

/* The SeedQR PNGs: a compact SeedQR holds the raw entropy, a standard one the
 * BIP-39 word indices as digits - both exactly as the text vectors hold them. */
static void test_png_seedqr_vector_files(void) {
    struct {
        const char* suffix;
        const char* raw_dir;
        const char* raw_suffix;
        bool        text;
    } const variants[] = {
        {".compact.png", "raw/", ".compact.bin", false},
        {".standard.png", "raw/", ".standard.txt", true},
    };

    for (size_t v = 0; v < sizeof(variants) / sizeof(variants[0]); v++) {
        char** slugs   = NULL;
        size_t n_slugs = 0;
        TEST_ASSERT_TRUE(vectors_list_slugs("seedqr/qr-png", variants[v].suffix, &slugs, &n_slugs));
        TEST_ASSERT_TRUE(n_slugs > 0);

        for (size_t s = 0; s < n_slugs; s++) {
            char rel[256];
            snprintf(rel, sizeof(rel), "seedqr/qr-png/%s%s", slugs[s], variants[v].suffix);

            uint8_t payload[PAYLOAD_MAX];
            size_t  payload_len = 0;
            TEST_ASSERT_TRUE_MESSAGE(png_payload(rel, payload, sizeof(payload), &payload_len), rel);

            char expect_rel[256];
            snprintf(expect_rel, sizeof(expect_rel), "seedqr/%s%s%s", variants[v].raw_dir, slugs[s],
                     variants[v].raw_suffix);

            size_t   expect_len = 0;
            uint8_t* expect     = vectors_read_file(expect_rel, &expect_len);
            TEST_ASSERT_NOT_NULL_MESSAGE(expect, expect_rel);
            if (variants[v].text) { /* the digit stream, without the newline */
                vectors_trim((char*)expect);
                expect_len = strlen((char*)expect);
            }

            TEST_ASSERT_EQUAL_UINT_MESSAGE((unsigned)expect_len, (unsigned)payload_len, rel);
            TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expect, payload, payload_len, rel);
            free(expect);
        }
        vectors_free_slugs(slugs, n_slugs);
    }
}

int main(void) {
    UNITY_BEGIN();

    RUN_TEST(test_png_fixture_pixels);
    RUN_TEST(test_png_palette_index_past_the_end);
    RUN_TEST(test_png_broken_fixtures);
    RUN_TEST(test_png_rejects_odd_input);
    RUN_TEST(test_png_psbt_vector_files);
    RUN_TEST(test_png_seedqr_vector_files);

    return UNITY_END();
}

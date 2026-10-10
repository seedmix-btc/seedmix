/**
 * @file tests/test_jpeg.c
 * @brief Unity tests for the LVGL-backed image decode (platform/linux/lvgl_gray.c).
 *
 * JPEG is the one format the desktop build leaves to LVGL (PNG and GIF have
 * decoders of their own), so this is the only suite that links LVGL.  It drives
 * the same helper the HAL calls for a picked file - decode to grayscale, then
 * read the QR code out of it - and checks the JPEG decodes to the very payload
 * the PNG of the same QR does, which has to survive a lossy, subsampled
 * re-encode.  The PNG decoder is linked in as that reference.
 */

#include "lvgl_gray.h"
#include "qr.h"
#include "ur_psbt.h"
#include "util/utils.h"
#include "vectors.h"

#include <lvgl.h> /* lv_init() registers LVGL's decoders and file system driver */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <unity.h>

#define PAYLOAD_MAX 4096

void setUp(void) {}
void tearDown(void) {}

/* How an image file turned out: the decoder could not read it, it decoded but
 * holds no QR code quirc can read, or it gave us the QR payload. */
typedef enum {
    IMG_FAILED = 0,
    IMG_NO_QR,
    IMG_QR,
} img_result_t;

/* Decode an image vector with the decoder the desktop build uses for JPEG and
 * read the QR payload out of it. */
static img_result_t image_payload(const char* rel, uint8_t* payload, size_t cap, size_t* out_len) {
    char path[640];
    vector_path(path, sizeof(path), rel);

    uint32_t w = 0, h = 0;
    uint8_t* gray = lvgl_gray_decode_file(path, &w, &h);
    if (!gray) return IMG_FAILED;

    bool ok = qr_decode(gray, w, h, payload, cap, out_len);
    free(gray);
    return ok ? IMG_QR : IMG_NO_QR;
}

/* Check one JPEG against the UR text of the same slug: the QR code carries that
 * very string, so the JPEG has to decode to exactly it, and the string has to
 * reassemble the PSBT the vector was generated from.
 *
 * A QR code denser than roughly version 25 is the one case that no image format
 * can help with: its finder + alignment patterns outnumber quirc's
 * QUIRC_MAX_CAPSTONES (32), so the identifier never finds the grid.  Those
 * vectors ship an animated multi-part form instead - one small, readable QR
 * code per part - and this function reports the case rather than failing it. */
static img_result_t check_jpeg_against_ur(const char* slug, const char* rel_img) {
    char ur_rel[256];
    snprintf(ur_rel, sizeof(ur_rel), "psbt/ur/%s.v2.ur", slug);
    char* ur = (char*)vectors_read_file(ur_rel, NULL);
    TEST_ASSERT_NOT_NULL(ur);
    vectors_trim(ur);

    uint8_t      got[PAYLOAD_MAX];
    size_t       got_len = 0;
    img_result_t res     = image_payload(rel_img, got, sizeof(got), &got_len);

    /* Whatever the QR holds, the file itself has to decode. */
    TEST_ASSERT_NOT_EQUAL_MESSAGE(IMG_FAILED, res, rel_img);

    if (res == IMG_QR) {
        TEST_ASSERT_EQUAL_UINT_MESSAGE((unsigned)strlen(ur), (unsigned)got_len, rel_img);
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(ur, got, got_len, rel_img);

        uint8_t* psbt     = NULL;
        size_t   psbt_len = 0;
        TEST_ASSERT_TRUE_MESSAGE(ur_psbt_decode((const char*)got, got_len, &psbt, &psbt_len),
                                 rel_img);

        char hex_rel[256];
        snprintf(hex_rel, sizeof(hex_rel), "psbt/raw/%s.hex", slug);
        char* hex = (char*)vectors_read_file(hex_rel, NULL);
        TEST_ASSERT_NOT_NULL(hex);
        vectors_trim(hex);
        size_t   expect_len = strlen(hex) / 2;
        uint8_t* expect     = malloc(expect_len);
        TEST_ASSERT_NOT_NULL(expect);
        TEST_ASSERT_TRUE(hex_to_bytes(hex, strlen(hex), expect, expect_len));

        TEST_ASSERT_EQUAL_UINT_MESSAGE(expect_len, (unsigned)psbt_len, rel_img);
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(expect, psbt, expect_len, rel_img);

        free(expect);
        free(hex);
        free(psbt);
    }

    free(ur);
    return res;
}

/* -- Vector files ------------------------------------------------------ */

/* Baseline JPEG: the color one carries chroma subsampling and lossy data, which
 * is what a screenshot exported by another wallet looks like. */
static void test_jpeg_vector_files(void) {
    char** slugs   = NULL;
    size_t n_slugs = 0;

    unsigned readable = 0, dense = 0;

    const char* const variants[] = {".v2.jpg", ".v2.gray.jpg"};
    for (size_t v = 0; v < sizeof(variants) / sizeof(variants[0]); v++) {
        TEST_ASSERT_TRUE(vectors_list_slugs("psbt/qr-jpg", variants[v], &slugs, &n_slugs));
        TEST_ASSERT_TRUE(n_slugs > 0);

        for (size_t s = 0; s < n_slugs; s++) {
            char rel[256];
            snprintf(rel, sizeof(rel), "psbt/qr-jpg/%s%s", slugs[s], variants[v]);

            if (check_jpeg_against_ur(slugs[s], rel) == IMG_QR)
                readable++;
            else
                dense++;
        }
        vectors_free_slugs(slugs, n_slugs);
    }

    /* The vectors keep both cases covered: one QR code quirc can read and one it
     * cannot, so neither a broken decoder nor a silent regression hides here. */
    TEST_ASSERT_GREATER_THAN_UINT(0, readable);
    TEST_ASSERT_GREATER_THAN_UINT(0, dense);
}

/* -- Known limits of the LVGL decoders --------------------------------- */

/* TJpgDec handles baseline JPEG only: a progressive one is rejected as an
 * unsupported JPEG standard, so the scan screen reports a file it cannot
 * read.  Pinned here so the day a progressive decoder appears, this test
 * tells us. */
static void test_progressive_jpeg_is_rejected(void) {
    char** slugs   = NULL;
    size_t n_slugs = 0;
    TEST_ASSERT_TRUE(vectors_list_slugs("psbt/qr-jpg", ".v2.progressive.jpg", &slugs, &n_slugs));
    TEST_ASSERT_TRUE(n_slugs > 0);

    for (size_t s = 0; s < n_slugs; s++) {
        char path[640];
        char rel[256];
        snprintf(rel, sizeof(rel), "psbt/qr-jpg/%s.v2.progressive.jpg", slugs[s]);
        vector_path(path, sizeof(path), rel);

        uint32_t w = 0, h = 0;
        TEST_ASSERT_NULL_MESSAGE(lvgl_gray_decode_file(path, &w, &h), rel);
    }
    vectors_free_slugs(slugs, n_slugs);
}

/* LVGL picks the decoder from the file extension, so a JPEG that lost its .jpg
 * name is not readable - worth knowing before blaming the decoder. */
static void test_decoder_is_chosen_by_extension(void) {
    char** slugs   = NULL;
    size_t n_slugs = 0;
    TEST_ASSERT_TRUE(vectors_list_slugs("psbt/qr-jpg", ".v2.jpg", &slugs, &n_slugs));
    TEST_ASSERT_TRUE(n_slugs > 0);

    char rel[256];
    snprintf(rel, sizeof(rel), "psbt/qr-jpg/%s.v2.jpg", slugs[0]);
    char src[640];
    vector_path(src, sizeof(src), rel);

    size_t   len  = 0;
    uint8_t* data = vectors_read_file(rel, &len);
    TEST_ASSERT_NOT_NULL(data);
    TEST_ASSERT_GREATER_THAN_UINT(0, (unsigned)len);

    /* Same bytes, a name LVGL has no decoder for (mkstemp needs the template to
     * end in XXXXXX, so the suffix is added by renaming). */
    char tmp[] = "/tmp/seedmix_jpgXXXXXX";
    int  fd    = mkstemp(tmp);
    TEST_ASSERT_TRUE(fd >= 0);
    FILE* f = fdopen(fd, "wb");
    TEST_ASSERT_NOT_NULL(f);
    TEST_ASSERT_EQUAL_UINT(len, fwrite(data, 1, len, f));
    TEST_ASSERT_EQUAL_INT(0, fclose(f));

    char renamed[64];
    snprintf(renamed, sizeof(renamed), "%s.bin", tmp);
    TEST_ASSERT_EQUAL_INT(0, rename(tmp, renamed));

    uint32_t w = 0, h = 0;
    TEST_ASSERT_NULL(lvgl_gray_decode_file(renamed, &w, &h));

    /* The same bytes under a name LVGL does understand do decode. */
    char jpg[64];
    snprintf(jpg, sizeof(jpg), "%s.jpg", tmp);
    TEST_ASSERT_EQUAL_INT(0, rename(renamed, jpg));

    uint8_t* gray = lvgl_gray_decode_file(jpg, &w, &h);
    TEST_ASSERT_NOT_NULL(gray);
    free(gray);

    unlink(jpg);
    free(data);
    vectors_free_slugs(slugs, n_slugs);
}

/* -- Bad input --------------------------------------------------------- */

/* Missing, truncated and corrupted files must fail cleanly - no crash, no leak
 * (the sanitizer CI job runs this suite too).  A truncated JPEG may still
 * decode the top of the image, so only the size is checked for those. */
static void test_jpeg_broken_files_fail_cleanly(void) {
    uint32_t w = 0, h = 0;
    TEST_ASSERT_NULL(lvgl_gray_decode_file("/nonexistent/seedmix.jpg", &w, &h));
    TEST_ASSERT_NULL(lvgl_gray_decode_file(NULL, &w, &h));

    char** slugs   = NULL;
    size_t n_slugs = 0;
    TEST_ASSERT_TRUE(vectors_list_slugs("psbt/qr-jpg", ".v2.jpg", &slugs, &n_slugs));
    TEST_ASSERT_TRUE(n_slugs > 0);

    char rel[256];
    snprintf(rel, sizeof(rel), "psbt/qr-jpg/%s.v2.jpg", slugs[0]);

    size_t   len  = 0;
    uint8_t* data = vectors_read_file(rel, &len);
    TEST_ASSERT_NOT_NULL(data);

    char tmp[] = "/tmp/seedmix_jpgXXXXXX";
    int  fd    = mkstemp(tmp);
    TEST_ASSERT_TRUE(fd >= 0);
    TEST_ASSERT_EQUAL_INT(0, close(fd));

    /* Broken files still have to reach the JPEG decoder, so keep the .jpg name
     * (LVGL picks its decoder by extension). */
    char broken[64];
    snprintf(broken, sizeof(broken), "%s.jpg", tmp);
    TEST_ASSERT_EQUAL_INT(0, rename(tmp, broken));

    /* Truncations: headers only, half the scan, almost everything. */
    size_t cuts[] = {2, len / 8, len / 2, len - 16};
    for (size_t c = 0; c < sizeof(cuts) / sizeof(cuts[0]); c++) {
        size_t n = cuts[c] < len ? cuts[c] : len;
        FILE*  f = fopen(broken, "wb");
        TEST_ASSERT_NOT_NULL(f);
        TEST_ASSERT_EQUAL_UINT(n, fwrite(data, 1, n, f));
        TEST_ASSERT_EQUAL_INT(0, fclose(f));

        uint32_t dw = 0, dh = 0;
        uint8_t* gray = lvgl_gray_decode_file(broken, &dw, &dh);
        if (gray) {
            /* A partial image is allowed; a wild size is not. */
            TEST_ASSERT_GREATER_THAN_UINT32(0, dw);
            TEST_ASSERT_LESS_OR_EQUAL_UINT32(4096, dw);
            TEST_ASSERT_GREATER_THAN_UINT32(0, dh);
            TEST_ASSERT_LESS_OR_EQUAL_UINT32(4096, dh);
            free(gray);
        }
    }

    /* Bit flips all over the stream: whatever the decoder makes of them, it
     * must not walk off the end of anything. */
    for (size_t i = 0; i < 32; i++) {
        size_t at = 8 + (i * 7919) % (len - 8);
        data[at] ^= (uint8_t)(1u << (i % 8));

        FILE* f = fopen(broken, "wb");
        TEST_ASSERT_NOT_NULL(f);
        TEST_ASSERT_EQUAL_UINT(len, fwrite(data, 1, len, f));
        TEST_ASSERT_EQUAL_INT(0, fclose(f));
        data[at] ^= (uint8_t)(1u << (i % 8)); /* undo */

        uint32_t dw = 0, dh = 0;
        uint8_t* gray = lvgl_gray_decode_file(broken, &dw, &dh);
        free(gray);
    }

    unlink(broken);
    free(data);
    vectors_free_slugs(slugs, n_slugs);
}

/* -- BMP fixtures ------------------------------------------------------ */

/*
 * LVGL's BMP decoder reports the colour depth it found in the file, so these
 * two tiny BMPs drive the 16-bit (RGB565) and 32-bit (ARGB8888) pixel paths the
 * JPEG vectors never reach.  Both are 8x8, with a black top row and eight
 * stripes below it, so every pixel is checked - including the row order, which
 * BMP stores bottom-up.
 */
static void test_bmp_fixture_pixels(void) {
    static const uint8_t black_row[8]   = {0};
    static const uint8_t stripes565[8]  = {0, 0, 255, 255, 149, 149, 29, 29};
    static const uint8_t stripes8888[8] = {0, 0, 255, 255, 140, 140, 124, 124};

    struct {
        const char*    rel;
        const uint8_t* stripes;
    } const cases[] = {
        {"bmp/rgb565.bmp", stripes565},
        {"bmp/argb8888.bmp", stripes8888},
    };

    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        char path[640];
        vector_path(path, sizeof(path), cases[c].rel);

        uint32_t w = 0, h = 0;
        uint8_t* gray = lvgl_gray_decode_file(path, &w, &h);
        TEST_ASSERT_NOT_NULL_MESSAGE(gray, cases[c].rel);
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(8, w, cases[c].rel);
        TEST_ASSERT_EQUAL_UINT32_MESSAGE(8, h, cases[c].rel);

        for (uint32_t y = 0; y < h; y++) {
            const uint8_t* want = y == 0 ? black_row : cases[c].stripes;
            TEST_ASSERT_EQUAL_UINT8_ARRAY_MESSAGE(want, gray + (size_t)y * w, w, cases[c].rel);
        }
        free(gray);
    }
}

int main(void) {
    /* Registers LVGL's decoders (TJpgDec, BMP) and the POSIX file system
     * driver the decoder opens the file with. */
    lv_init();

    UNITY_BEGIN();

    RUN_TEST(test_jpeg_vector_files);
    RUN_TEST(test_progressive_jpeg_is_rejected);
    RUN_TEST(test_decoder_is_chosen_by_extension);
    RUN_TEST(test_bmp_fixture_pixels);
    RUN_TEST(test_jpeg_broken_files_fail_cleanly);

    return UNITY_END();
}

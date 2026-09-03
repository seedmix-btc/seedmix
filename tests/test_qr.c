/**
 * @file tests/test_qr.c
 * @brief Round-trip tests for main/qr/qr.c (libqrencode encode -> quirc decode).
 */

#include "qr/qr.h"
#include "unity.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* Render a grid onto a grayscale image with a white quiet zone. */
static uint8_t* grid_to_gray(const qr_grid_t* g, uint32_t scale, uint32_t border, uint32_t* out_w,
                             uint32_t* out_h) {
    uint32_t dim = (g->size + 2 * border) * scale;
    uint8_t* img = (uint8_t*)malloc((size_t)dim * dim);
    memset(img, 0xFF, (size_t)dim * dim); /* white */

    for (uint32_t y = 0; y < g->size; y++) {
        for (uint32_t x = 0; x < g->size; x++) {
            uint8_t  v  = g->cells[(size_t)y * g->size + x] ? 0x00 : 0xFF;
            uint32_t py = (y + border) * scale;
            uint32_t px = (x + border) * scale;
            for (uint32_t dy = 0; dy < scale; dy++) {
                memset(img + (size_t)(py + dy) * dim + px, v, scale);
            }
        }
    }

    *out_w = dim;
    *out_h = dim;
    return img;
}

static void roundtrip(const uint8_t* data, size_t len, qr_mode_t mode, uint32_t expect_size) {
    qr_grid_t g = {0};
    TEST_ASSERT_TRUE(qr_encode(data, len, mode, &g));
    TEST_ASSERT_EQUAL_UINT(expect_size, g.size);

    uint32_t w = 0, h = 0;
    uint8_t* img = grid_to_gray(&g, 4, 4, &w, &h);

    uint8_t payload[256];
    size_t  out_len = 0;
    TEST_ASSERT_TRUE(qr_decode(img, w, h, payload, sizeof(payload), &out_len));
    TEST_ASSERT_EQUAL_UINT((unsigned)len, (unsigned)out_len);
    TEST_ASSERT_EQUAL_MEMORY(data, payload, len);

    free(img);
    qr_grid_free(&g);
}

static void test_compact_12(void) {
    // 16 entropy bytes -> 21x21 (CompactSeedQR).
    const uint8_t e[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    roundtrip(e, sizeof(e), QR_MODE_BYTE, 21);
}

static void test_compact_24(void) {
    // 32 entropy bytes -> 25x25 (CompactSeedQR).
    const uint8_t e[32] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
                           16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    roundtrip(e, sizeof(e), QR_MODE_BYTE, 25);
}

static void test_standard_12(void) {
    // 48 numeric digits -> 25x25 (Standard SeedQR).
    const char digits[49] = "073318950739065415961602009907670428187212261116";
    roundtrip((const uint8_t*)digits, 48, QR_MODE_NUMERIC, 25);
}

static void test_standard_24(void) {
    // 96 numeric digits -> 29x29 (Standard SeedQR).
    const char digits[97] = "0115132511540127119007710415074212891906200808700266134314202016179206"
                            "14089619290300152408010643";
    roundtrip((const uint8_t*)digits, 96, QR_MODE_NUMERIC, 29);
}

static void test_rejects_oversized_frame(void) {
    uint8_t img[1]      = {0};
    uint8_t payload[32] = {0};
    size_t  out_len     = 0;

    TEST_ASSERT_FALSE(qr_decode(img, 513, 1, payload, sizeof(payload), &out_len));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)out_len);
    TEST_ASSERT_FALSE(qr_decode(img, 1, 513, payload, sizeof(payload), &out_len));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)out_len);
    TEST_ASSERT_FALSE(qr_decode(img, 513, 513, payload, sizeof(payload), &out_len));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)out_len);
}

static void test_rejects_empty_payload(void) {
    // Version-1 QR (21x21 modules, ECC L) encoding an empty byte payload
    static const char* const modules = "111111101101001111111"
                                       "100000100001101000001"
                                       "101110100101001011101"
                                       "101110101100101011101"
                                       "101110100011001011101"
                                       "100000100111101000001"
                                       "111111101010101111111"
                                       "000000000101000000000"
                                       "001011101011010001001"
                                       "110101010010011000110"
                                       "110110101111110010001"
                                       "000000010101111000110"
                                       "000000101000011010101"
                                       "000000001101001101010"
                                       "111111100011100101101"
                                       "100000101000000111010"
                                       "101110101110110101101"
                                       "101110100011011000110"
                                       "101110101010100010001"
                                       "100000100001110000110"
                                       "111111100100100010111";

    qr_grid_t g = {0};
    g.size      = 21;
    g.cells     = (uint8_t*)malloc(21u * 21u);
    TEST_ASSERT_NOT_NULL(g.cells);
    for (uint32_t i = 0; i < 21u * 21u; i++) {
        g.cells[i] = (modules[i] == '1') ? 1u : 0u;
    }

    uint32_t w = 0, h = 0;
    uint8_t* img = grid_to_gray(&g, 4, 4, &w, &h);

    uint8_t payload[256] = {0};
    size_t  out_len      = 0;
    TEST_ASSERT_FALSE(qr_decode(img, w, h, payload, sizeof(payload), &out_len));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)out_len);

    free(img);
    free(g.cells);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_compact_12);
    RUN_TEST(test_compact_24);
    RUN_TEST(test_standard_12);
    RUN_TEST(test_standard_24);
    RUN_TEST(test_rejects_oversized_frame);
    RUN_TEST(test_rejects_empty_payload);
    return UNITY_END();
}

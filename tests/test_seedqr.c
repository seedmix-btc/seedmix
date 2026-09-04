/**
 * @file tests/test_seedqr.c
 * @brief Unity tests for main/crypto/seedqr.c
 */

#include "crypto/bip39_wordlist.h"
#include "crypto/mnemonic.h"
#include "crypto/seedqr.h"
#include "unity.h"

#include <stdint.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static void test_compact_roundtrip_12(void) {
    const uint8_t e[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    mnemonic_t*   m     = mnemonic_from_entropy(e, sizeof(e));
    TEST_ASSERT_NOT_NULL(m);

    uint8_t out[16];
    TEST_ASSERT_EQUAL_UINT(16, (unsigned)seedqr_compact_encode(m, out, sizeof(out)));
    TEST_ASSERT_EQUAL_MEMORY(e, out, sizeof(e));

    mnemonic_t* d = seedqr_compact_decode(out, sizeof(out));
    TEST_ASSERT_NOT_NULL(d);
    TEST_ASSERT_EQUAL_STRING(mnemonic_words(m), mnemonic_words(d));

    mnemonic_discard(d);
    mnemonic_discard(m);
}

static void test_compact_roundtrip_24(void) {
    const uint8_t e[32] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
                           16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    mnemonic_t*   m     = mnemonic_from_entropy(e, sizeof(e));
    TEST_ASSERT_NOT_NULL(m);

    uint8_t out[32];
    TEST_ASSERT_EQUAL_UINT(32, (unsigned)seedqr_compact_encode(m, out, sizeof(out)));
    TEST_ASSERT_EQUAL_MEMORY(e, out, sizeof(e));

    mnemonic_t* d = seedqr_compact_decode(out, sizeof(out));
    TEST_ASSERT_NOT_NULL(d);
    TEST_ASSERT_EQUAL_STRING(mnemonic_words(m), mnemonic_words(d));

    mnemonic_discard(d);
    mnemonic_discard(m);
}

static void test_standard_roundtrip_12(void) {
    const uint8_t e[16] = {42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57};
    mnemonic_t*   m     = mnemonic_from_entropy(e, sizeof(e));
    TEST_ASSERT_NOT_NULL(m);

    char digits[SEEDQR_STANDARD_12_DIGITS + 1];
    TEST_ASSERT_EQUAL_UINT(SEEDQR_STANDARD_12_DIGITS,
                           (unsigned)seedqr_standard_encode(m, digits, sizeof(digits)));

    mnemonic_t* d = seedqr_standard_decode(digits);
    TEST_ASSERT_NOT_NULL(d);
    TEST_ASSERT_EQUAL_STRING(mnemonic_words(m), mnemonic_words(d));

    mnemonic_discard(d);
    mnemonic_discard(m);
}

static void test_standard_roundtrip_24(void) {
    const uint8_t e[32] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
                           16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    mnemonic_t*   m     = mnemonic_from_entropy(e, sizeof(e));
    TEST_ASSERT_NOT_NULL(m);

    char digits[SEEDQR_STANDARD_24_DIGITS + 1];
    TEST_ASSERT_EQUAL_UINT(SEEDQR_STANDARD_24_DIGITS,
                           (unsigned)seedqr_standard_encode(m, digits, sizeof(digits)));

    mnemonic_t* d = seedqr_standard_decode(digits);
    TEST_ASSERT_NOT_NULL(d);
    TEST_ASSERT_EQUAL_STRING(mnemonic_words(m), mnemonic_words(d));

    mnemonic_discard(d);
    mnemonic_discard(m);
}

static void test_standard_zeros_12(void) {
    // all-zero entropy -> "abandon" x11 + "about" -> indices 0 x11 + 3
    const uint8_t e[16] = {0};
    mnemonic_t*   m     = mnemonic_from_entropy(e, sizeof(e));
    TEST_ASSERT_NOT_NULL(m);

    char digits[SEEDQR_STANDARD_12_DIGITS + 1];
    TEST_ASSERT_EQUAL_UINT(SEEDQR_STANDARD_12_DIGITS,
                           (unsigned)seedqr_standard_encode(m, digits, sizeof(digits)));

    char expected[SEEDQR_STANDARD_12_DIGITS + 1];
    for (int i = 0; i < 11; i++) strcpy(expected + i * 4, "0000");
    strcpy(expected + 44, "0003");
    expected[48] = '\0';

    TEST_ASSERT_EQUAL_STRING(expected, digits);
    mnemonic_discard(m);
}

static void test_vector4_spec(void) {
    // SeedSigner docs/seed_qr/README.md, Test Vector 4 (12 words)
    const uint8_t e[16] = {0x5b, 0xbd, 0x9d, 0x71, 0xa8, 0xec, 0x79, 0x90,
                           0x83, 0x1a, 0xff, 0x35, 0x9d, 0x42, 0x65, 0x45};
    mnemonic_t*   m     = mnemonic_from_entropy(e, sizeof(e));
    TEST_ASSERT_NOT_NULL(m);
    TEST_ASSERT_EQUAL_STRING(
        "forum undo fragile fade shy sign arrest garment culture tube off merit",
        mnemonic_words(m));

    char digits[SEEDQR_STANDARD_12_DIGITS + 1];
    TEST_ASSERT_EQUAL_UINT(SEEDQR_STANDARD_12_DIGITS,
                           (unsigned)seedqr_standard_encode(m, digits, sizeof(digits)));
    TEST_ASSERT_EQUAL_STRING("073318950739065415961602009907670428187212261116", digits);

    uint8_t out[16];
    TEST_ASSERT_EQUAL_UINT(16, (unsigned)seedqr_compact_encode(m, out, sizeof(out)));
    TEST_ASSERT_EQUAL_MEMORY(e, out, sizeof(e));

    mnemonic_discard(m);
}

/* -- Error / boundary paths -------------------------------------------- */

static void test_compact_decode_invalid_len(void) {
    uint8_t buf[33] = {0};
    TEST_ASSERT_NULL(seedqr_compact_decode(NULL, 16));
    TEST_ASSERT_NULL(seedqr_compact_decode(buf, 0));
    TEST_ASSERT_NULL(seedqr_compact_decode(buf, 15));
    TEST_ASSERT_NULL(seedqr_compact_decode(buf, 17));
    TEST_ASSERT_NULL(seedqr_compact_decode(buf, 31));
    TEST_ASSERT_NULL(seedqr_compact_decode(buf, 33));
}

static void test_compact_encode_short_buffer(void) {
    const uint8_t e[16] = {0};
    mnemonic_t*   m     = mnemonic_from_entropy(e, sizeof(e));
    TEST_ASSERT_NOT_NULL(m);

    uint8_t out[15];
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)seedqr_compact_encode(m, out, sizeof(out)));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)seedqr_compact_encode(m, NULL, 16));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)seedqr_compact_encode(NULL, out, sizeof(out)));

    mnemonic_discard(m);
}

static void test_standard_decode_null_and_bad_length(void) {
    TEST_ASSERT_NULL(seedqr_standard_decode(NULL));
    TEST_ASSERT_NULL(seedqr_standard_decode(""));
    TEST_ASSERT_NULL(seedqr_standard_decode("0733189507390654")); // 16 chars
    char s47[48] = {0};
    char s49[50] = {0};
    memset(s47, '0', 47);
    memset(s49, '0', 49);
    TEST_ASSERT_NULL(seedqr_standard_decode(s47));
    TEST_ASSERT_NULL(seedqr_standard_decode(s49));
}

static void test_standard_decode_rejects_non_digit(void) {
    char s[SEEDQR_STANDARD_12_DIGITS + 1];
    memset(s, '0', SEEDQR_STANDARD_12_DIGITS);
    s[SEEDQR_STANDARD_12_DIGITS] = '\0';
    s[0]                         = 'a'; // strtoul consumes nothing -> rejected
    TEST_ASSERT_NULL(seedqr_standard_decode(s));

    memset(s, '0', SEEDQR_STANDARD_12_DIGITS);
    s[4] = '-';
    TEST_ASSERT_NULL(seedqr_standard_decode(s));
}

static void test_standard_decode_rejects_bad_index(void) {
    char s[SEEDQR_STANDARD_12_DIGITS + 1];
    memset(s, '0', SEEDQR_STANDARD_12_DIGITS);
    s[SEEDQR_STANDARD_12_DIGITS] = '\0';
    // First index 2048 == BIP39_WORD_COUNT (out of range)
    memcpy(s, "2048", 4);
    TEST_ASSERT_NULL(seedqr_standard_decode(s));
}

static void test_standard_decode_rejects_bad_checksum(void) {
    // 12 x index 0 -> "abandon" x12, an invalid BIP39 checksum.
    char s[SEEDQR_STANDARD_12_DIGITS + 1];
    memset(s, '0', SEEDQR_STANDARD_12_DIGITS);
    s[SEEDQR_STANDARD_12_DIGITS] = '\0';
    TEST_ASSERT_NULL(seedqr_standard_decode(s));
}

static void test_standard_encode_error_paths(void) {
    const uint8_t e[16] = {0};
    mnemonic_t*   m     = mnemonic_from_entropy(e, sizeof(e));
    TEST_ASSERT_NOT_NULL(m);

    char out[SEEDQR_STANDARD_12_DIGITS + 1];
    // NULL input mnemonic
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)seedqr_standard_encode(NULL, out, sizeof(out)));
    // NULL output buffer
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)seedqr_standard_encode(m, NULL, sizeof(out)));
    // Output buffer too small
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)seedqr_standard_encode(m, out, SEEDQR_STANDARD_12_DIGITS));

    mnemonic_discard(m);
}

int main(void) {
    UNITY_BEGIN();
    mnemonic_init();
    RUN_TEST(test_compact_roundtrip_12);
    RUN_TEST(test_compact_roundtrip_24);
    RUN_TEST(test_standard_roundtrip_12);
    RUN_TEST(test_standard_roundtrip_24);
    RUN_TEST(test_standard_zeros_12);
    RUN_TEST(test_vector4_spec);
    RUN_TEST(test_compact_decode_invalid_len);
    RUN_TEST(test_compact_encode_short_buffer);
    RUN_TEST(test_standard_decode_null_and_bad_length);
    RUN_TEST(test_standard_decode_rejects_non_digit);
    RUN_TEST(test_standard_decode_rejects_bad_index);
    RUN_TEST(test_standard_decode_rejects_bad_checksum);
    RUN_TEST(test_standard_encode_error_paths);
    return UNITY_END();
}

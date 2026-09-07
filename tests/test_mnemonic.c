/**
 * @file tests/test_mnemonic.c
 * @brief Unity tests for main/crypto/mnemonic.c (uses the HAL random stub).
 */

#include "crypto/mnemonic.h"
#include "unity.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wally_bip39.h>

void setUp(void) {}
void tearDown(void) {}

static void noop_process_cb(const char* process) { (void)process; }

static unsigned count_words(const char* s) {
    if (!s || !*s) return 0;
    unsigned n = 1;
    for (const char* p = s; *p; p++) {
        if (*p == ' ') n++;
    }
    return n;
}

static void test_generate_12_words(void) {
    mnemonic_t* m = mnemonic_generate(12, noop_process_cb);
    TEST_ASSERT_NOT_NULL(m);
    TEST_ASSERT_EQUAL_UINT(12, count_words(mnemonic_words(m)));
    TEST_ASSERT_EQUAL_UINT(16, (unsigned)mnemonic_entropy_size(m));
    mnemonic_discard(m);
}

static void test_generate_24_words(void) {
    mnemonic_t* m = mnemonic_generate(24, noop_process_cb);
    TEST_ASSERT_NOT_NULL(m);
    TEST_ASSERT_EQUAL_UINT(24, count_words(mnemonic_words(m)));
    TEST_ASSERT_EQUAL_UINT(32, (unsigned)mnemonic_entropy_size(m));
    mnemonic_discard(m);
}

static void test_from_entropy_roundtrip(void) {
    const uint8_t entropy[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    mnemonic_t*   m           = mnemonic_from_entropy(entropy, sizeof(entropy));
    TEST_ASSERT_NOT_NULL(m);

    uint8_t out[16] = {0};
    TEST_ASSERT_EQUAL_UINT(16, (unsigned)mnemonic_to_entropy(m, out));
    TEST_ASSERT_EQUAL_MEMORY(entropy, out, sizeof(entropy));

    mnemonic_discard(m);
}

static void test_combine_xor(void) {
    const uint8_t a_bytes[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    const uint8_t b_bytes[16] = {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};

    mnemonic_t* a = mnemonic_from_entropy(a_bytes, sizeof(a_bytes));
    mnemonic_t* b = mnemonic_from_entropy(b_bytes, sizeof(b_bytes));
    mnemonic_t* c = mnemonic_combine(a, b);
    TEST_ASSERT_NOT_NULL(c);

    uint8_t expected[16];
    for (size_t i = 0; i < sizeof(expected); i++) expected[i] = a_bytes[i] ^ b_bytes[i];

    uint8_t out[16] = {0};
    TEST_ASSERT_EQUAL_UINT(16, (unsigned)mnemonic_to_entropy(c, out));
    TEST_ASSERT_EQUAL_MEMORY(expected, out, sizeof(expected));

    mnemonic_discard(c);
}

static void test_to_entropy_24_roundtrip(void) {
    const uint8_t entropy[32] = {0,  1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15,
                                 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31};
    mnemonic_t*   m           = mnemonic_from_entropy(entropy, sizeof(entropy));
    TEST_ASSERT_NOT_NULL(m);

    uint8_t out[32] = {0};
    TEST_ASSERT_EQUAL_UINT(32, (unsigned)mnemonic_to_entropy(m, out));
    TEST_ASSERT_EQUAL_MEMORY(entropy, out, sizeof(entropy));

    mnemonic_discard(m);
}

static void test_combine_xor_24(void) {
    const uint8_t a_bytes[32] = {1,  2,  3,  4,  5,  6,  7,  8,  9,  10, 11, 12, 13, 14, 15, 16,
                                 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
    const uint8_t b_bytes[32] = {32, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17,
                                 16, 15, 14, 13, 12, 11, 10, 9,  8,  7,  6,  5,  4,  3,  2,  1};

    mnemonic_t* a = mnemonic_from_entropy(a_bytes, sizeof(a_bytes));
    mnemonic_t* b = mnemonic_from_entropy(b_bytes, sizeof(b_bytes));
    mnemonic_t* c = mnemonic_combine(a, b);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_UINT(32, (unsigned)mnemonic_entropy_size(c));

    uint8_t expected[32];
    for (size_t i = 0; i < sizeof(expected); i++) expected[i] = a_bytes[i] ^ b_bytes[i];

    uint8_t out[32] = {0};
    TEST_ASSERT_EQUAL_UINT(32, (unsigned)mnemonic_to_entropy(c, out));
    TEST_ASSERT_EQUAL_MEMORY(expected, out, sizeof(expected));

    mnemonic_discard(c);
}

static void test_from_string_roundtrip(void) {
    const uint8_t entropy[16] = {42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57};
    mnemonic_t*   m           = mnemonic_from_entropy(entropy, sizeof(entropy));
    TEST_ASSERT_NOT_NULL(m);

    const char* words  = mnemonic_words(m);
    mnemonic_t* parsed = mnemonic_from_string(words);
    TEST_ASSERT_NOT_NULL(parsed);
    TEST_ASSERT_EQUAL_STRING(words, mnemonic_words(parsed));

    mnemonic_discard(parsed);
    mnemonic_discard(m);
}

static void test_from_string_invalid_word(void) {
    TEST_ASSERT_NULL(mnemonic_from_string("zzzzzz this is not a real mnemonic"));
}

static void test_from_string_too_long(void) {
    char words[MNEMONIC_MAX_INPUT_LEN + 1];
    memset(words, 'a', sizeof(words) - 1);
    words[sizeof(words) - 1] = '\0';
    TEST_ASSERT_NULL(mnemonic_from_string(words));
}

static void test_from_string_invalid_checksum(void) {
    // 12 x "abandon" is not a checksum-valid mnemonic
    TEST_ASSERT_NULL(mnemonic_from_string("abandon abandon abandon abandon abandon abandon abandon "
                                          "abandon abandon abandon abandon abandon"));
}

static void test_from_string_unsupported_word_count(void) {
    // 15 words -> 20 bytes of entropy: valid BIP39, but unsupported here
    uint8_t entropy[20] = {0};
    char*   words       = NULL;
    TEST_ASSERT_EQUAL_INT(WALLY_OK,
                          bip39_mnemonic_from_bytes(NULL, entropy, sizeof(entropy), &words));
    TEST_ASSERT_NOT_NULL(words);
    TEST_ASSERT_NULL(mnemonic_from_string(words));
    wally_free_string(words);
}

static void test_from_string_24_words(void) {
    const uint8_t e[32] = {0};
    mnemonic_t*   m     = mnemonic_from_entropy(e, sizeof(e));
    TEST_ASSERT_NOT_NULL(m);

    mnemonic_t* parsed = mnemonic_from_string(mnemonic_words(m));
    TEST_ASSERT_NOT_NULL(parsed);
    TEST_ASSERT_EQUAL_UINT(32, (unsigned)mnemonic_entropy_size(parsed));

    mnemonic_discard(parsed);
    mnemonic_discard(m);
}

static void test_null_safety(void) {
    TEST_ASSERT_NULL(mnemonic_words(NULL));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)mnemonic_entropy_size(NULL));
}

static void test_from_string_empty_null(void) {
    TEST_ASSERT_NULL(mnemonic_from_string(NULL));
    TEST_ASSERT_NULL(mnemonic_from_string(""));
}

static bool candidate_forms_valid_mnemonic(const char* prefix, const char* last) {
    char full[MNEMONIC_MAX_INPUT_LEN];
    int  r = snprintf(full, sizeof(full), "%s %s", prefix, last);
    if (r <= 0 || (size_t)r >= sizeof(full)) return false;
    mnemonic_t* m = mnemonic_from_string(full);
    if (!m) return false;
    mnemonic_discard(m);
    return true;
}

static void test_last_word_candidates_12(void) {
    const char* input = "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                        "abandon abandon abandon";
    const char* prefix =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

    const char* out[128];
    size_t      n = mnemonic_last_word_candidates(input, out, 128);
    TEST_ASSERT_EQUAL_UINT(128, (unsigned)n);
    for (size_t i = 0; i < n; i++) {
        TEST_ASSERT_NOT_NULL(out[i]);
        TEST_ASSERT(candidate_forms_valid_mnemonic(prefix, out[i]));
    }
}

static void test_last_word_candidates_24(void) {
    const char* input = "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                        "abandon abandon abandon "
                        "abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                        "abandon abandon abandon";
    const char* prefix =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon "
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon";

    const char* out[128];
    size_t      n = mnemonic_last_word_candidates(input, out, 128);
    TEST_ASSERT_EQUAL_UINT(8, (unsigned)n);
    for (size_t i = 0; i < n; i++) {
        TEST_ASSERT_NOT_NULL(out[i]);
        TEST_ASSERT(candidate_forms_valid_mnemonic(prefix, out[i]));
    }
}

static void test_last_word_candidates_invalid(void) {
    const char* out[128];
    // A non-word in the prefix cannot produce candidates.
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)mnemonic_last_word_candidates(
                                  "zzzzzz abandon abandon abandon abandon abandon abandon abandon "
                                  "abandon abandon abandon abandon",
                                  out, 128));
    // Unsupported word counts and empty input.
    TEST_ASSERT_EQUAL_UINT(
        0, (unsigned)mnemonic_last_word_candidates("abandon abandon abandon", out, 128));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)mnemonic_last_word_candidates("", out, 128));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)mnemonic_last_word_candidates(NULL, out, 128));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)mnemonic_last_word_candidates(
                                  "abandon abandon abandon abandon abandon abandon abandon abandon "
                                  "abandon abandon abandon abandon",
                                  NULL, 0));
    // More than 24 words must be rejected without overflowing the tokenizer.
    TEST_ASSERT_EQUAL_UINT(
        0, (unsigned)mnemonic_last_word_candidates(
               "abandon abandon abandon abandon abandon abandon abandon abandon "
               "abandon abandon abandon abandon abandon abandon abandon abandon "
               "abandon abandon abandon abandon abandon abandon abandon abandon abandon",
               out, 128));
}

int main(void) {
    UNITY_BEGIN();
    mnemonic_init();
    RUN_TEST(test_generate_12_words);
    RUN_TEST(test_generate_24_words);
    RUN_TEST(test_from_entropy_roundtrip);
    RUN_TEST(test_combine_xor);
    RUN_TEST(test_to_entropy_24_roundtrip);
    RUN_TEST(test_combine_xor_24);
    RUN_TEST(test_from_string_roundtrip);
    RUN_TEST(test_from_string_invalid_word);
    RUN_TEST(test_from_string_too_long);
    RUN_TEST(test_from_string_invalid_checksum);
    RUN_TEST(test_from_string_unsupported_word_count);
    RUN_TEST(test_from_string_24_words);
    RUN_TEST(test_null_safety);
    RUN_TEST(test_from_string_empty_null);
    RUN_TEST(test_last_word_candidates_12);
    RUN_TEST(test_last_word_candidates_24);
    RUN_TEST(test_last_word_candidates_invalid);
    return UNITY_END();
}

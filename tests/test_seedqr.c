/**
 * @file tests/test_seedqr.c
 * @brief Unity tests for main/crypto/seedqr.c
 */

#include "crypto/bip39_wordlist.h"
#include "crypto/mnemonic.h"
#include "crypto/seedqr.h"
#include "unity.h"
#include "util/utils.h"
#include "vectors.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

/* -- SeedSigner's published test vectors ------------------------------- */
/* tests/vectors/seedqr/spec/seedsigner.txt is copied from SeedSigner's SeedQR
 * specification by scripts/check_seedqr_vectors.py, which also verifies that
 * the copy still matches upstream. Each vector is the same seed in all three
 * forms, so both encoders and both decoders are checked against the reference
 * rather than against each other. Several compact payloads deliberately
 * contain 0x00, 0x0a, 0x0d or 0x0d 0x0a: the bytes QR readers commonly stop at
 * or split on. */
#define SEEDQR_SPEC_MAX_VECTORS 16

typedef struct {
    const char* seeds; // points into the file buffer
    const char* standard;
    uint8_t     compact[32];
    size_t      compact_len;
} seedqr_spec_vector_t;

/* Read the vectors out of the spec file; *text_out owns the strings in @p out. */
static size_t seedqr_spec_load(seedqr_spec_vector_t* out, size_t cap, uint8_t** text_out) {
    uint8_t* text = vectors_read_file("seedqr/spec/seedsigner.txt", NULL);
    if (!text) return 0;
    *text_out = text;

    size_t count   = 0;
    char*  saveptr = NULL;
    for (char* line = strtok_r((char*)text, "\n", &saveptr); line;
         line       = strtok_r(NULL, "\n", &saveptr)) {
        vectors_trim(line);
        if (line[0] == '\0' || line[0] == '#') continue;
        if (count >= cap) break;

        if (strncmp(line, "seeds: ", 7) == 0) {
            memset(&out[count], 0, sizeof(out[count]));
            out[count].seeds = line + 7;
        } else if (strncmp(line, "standard: ", 10) == 0) {
            out[count].standard = line + 10;
        } else if (strncmp(line, "compact: ", 9) == 0) {
            if (!hex_to_bytes(line + 9, strlen(line + 9), out[count].compact,
                              sizeof(out[count].compact))) {
                continue;
            }
            out[count].compact_len = strlen(line + 9) / 2;
            if (out[count].seeds && out[count].standard && out[count].compact_len >= 16 &&
                out[count].compact_len <= 32) {
                count++;
            }
        }
    }
    return count;
}

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

/* Encode each published vector and read both forms back. */
static void test_seedsigner_spec_vectors(void) {
    seedqr_spec_vector_t vectors[SEEDQR_SPEC_MAX_VECTORS];
    uint8_t*             text = NULL;
    const size_t         n    = seedqr_spec_load(vectors, SEEDQR_SPEC_MAX_VECTORS, &text);

    TEST_ASSERT_TRUE_MESSAGE(n >= 9, "the specification's test vectors are all present");

    for (size_t i = 0; i < n; i++) {
        const seedqr_spec_vector_t* v = &vectors[i];
        char                        msg[32];
        snprintf(msg, sizeof(msg), "SeedSigner vector %u", (unsigned)i + 1);

        mnemonic_t* m = mnemonic_from_string(v->seeds);
        TEST_ASSERT_NOT_NULL_MESSAGE(m, msg);

        char   digits[SEEDQR_STANDARD_24_DIGITS + 1];
        size_t len = seedqr_standard_encode(m, digits, sizeof(digits));
        TEST_ASSERT_EQUAL_UINT_MESSAGE((unsigned)strlen(v->standard), (unsigned)len, msg);
        TEST_ASSERT_EQUAL_STRING_MESSAGE(v->standard, digits, msg);

        uint8_t compact[32];
        len = seedqr_compact_encode(m, compact, sizeof(compact));
        TEST_ASSERT_EQUAL_UINT_MESSAGE((unsigned)v->compact_len, (unsigned)len, msg);
        TEST_ASSERT_EQUAL_MEMORY_MESSAGE(v->compact, compact, v->compact_len, msg);
        mnemonic_discard(m);

        mnemonic_t* from_std = seedqr_standard_decode(v->standard);
        TEST_ASSERT_NOT_NULL_MESSAGE(from_std, msg);
        TEST_ASSERT_EQUAL_STRING_MESSAGE(v->seeds, mnemonic_words(from_std), msg);
        mnemonic_discard(from_std);

        mnemonic_t* from_compact = seedqr_compact_decode(v->compact, v->compact_len);
        TEST_ASSERT_NOT_NULL_MESSAGE(from_compact, msg);
        TEST_ASSERT_EQUAL_STRING_MESSAGE(v->seeds, mnemonic_words(from_compact), msg);
        mnemonic_discard(from_compact);
    }

    free(text);
}

/* -- Generated SeedQR vectors (tests/vectors/seedqr/) ------------------- */
static void test_seedqr_vector_files(void) {
    char** slugs   = NULL;
    size_t n_slugs = 0;
    TEST_ASSERT_TRUE(vectors_list_slugs("seedqr/raw", ".compact.bin", &slugs, &n_slugs));
    TEST_ASSERT_TRUE(n_slugs > 0);

    for (size_t s = 0; s < n_slugs; s++) {
        const char* slug = slugs[s];
        char        path[256];

        snprintf(path, sizeof(path), "seedqr/raw/%s.compact.bin", slug);
        size_t   ent_len = 0;
        uint8_t* entropy = vectors_read_file(path, &ent_len);
        TEST_ASSERT_NOT_NULL(entropy);
        TEST_ASSERT_TRUE(ent_len == 16 || ent_len == 32);

        snprintf(path, sizeof(path), "seedqr/raw/%s.standard.txt", slug);
        char* digits = (char*)vectors_read_file(path, NULL);
        TEST_ASSERT_NOT_NULL(digits);
        vectors_trim(digits);

        snprintf(path, sizeof(path), "seedqr/raw/%s.mnemonic.txt", slug);
        char* words = (char*)vectors_read_file(path, NULL);
        TEST_ASSERT_NOT_NULL(words);
        vectors_trim(words);

        /* entropy -> mnemonic must match the reference words */
        mnemonic_t* m = mnemonic_from_entropy(entropy, ent_len);
        TEST_ASSERT_NOT_NULL(m);
        TEST_ASSERT_EQUAL_STRING(words, mnemonic_words(m));

        /* CompactSeedQR roundtrip */
        uint8_t compact[32];
        size_t  clen = seedqr_compact_encode(m, compact, sizeof(compact));
        TEST_ASSERT_EQUAL_UINT(ent_len, (unsigned)clen);
        TEST_ASSERT_EQUAL_MEMORY(entropy, compact, ent_len);

        mnemonic_t* dc = seedqr_compact_decode(entropy, ent_len);
        TEST_ASSERT_NOT_NULL(dc);
        TEST_ASSERT_EQUAL_STRING(words, mnemonic_words(dc));
        mnemonic_discard(dc);

        /* Standard SeedQR roundtrip */
        char   enc[SEEDQR_STANDARD_24_DIGITS + 1];
        size_t elen = seedqr_standard_encode(m, enc, sizeof(enc));
        TEST_ASSERT_EQUAL_UINT(strlen(digits), (unsigned)elen);
        TEST_ASSERT_EQUAL_STRING(digits, enc);

        mnemonic_t* ds = seedqr_standard_decode(digits);
        TEST_ASSERT_NOT_NULL(ds);
        TEST_ASSERT_EQUAL_STRING(words, mnemonic_words(ds));
        mnemonic_discard(ds);

        mnemonic_discard(m);
        free(words);
        free(digits);
        free(entropy);
    }

    vectors_free_slugs(slugs, n_slugs);
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
    s[0]                         = 'a'; // not a digit -> rejected
    TEST_ASSERT_NULL(seedqr_standard_decode(s));

    memset(s, '0', SEEDQR_STANDARD_12_DIGITS);
    s[4] = '-';
    TEST_ASSERT_NULL(seedqr_standard_decode(s));
}

/* A payload that is not four digits per word must be rejected by the parser itself. */
static void test_standard_decode_rejects_space_and_sign(void) {
    char s[SEEDQR_STANDARD_12_DIGITS + 1];
    memset(s, '0', SEEDQR_STANDARD_12_DIGITS);
    memcpy(s + SEEDQR_STANDARD_12_DIGITS - 4, "0003", 4); // ... abandon, about
    s[SEEDQR_STANDARD_12_DIGITS] = '\0';

    mnemonic_t* ok = seedqr_standard_decode(s);
    TEST_ASSERT_NOT_NULL(ok); // the unmodified digits are a valid SeedQR
    mnemonic_discard(ok);

    s[0] = ' '; // leading space is invalid
    TEST_ASSERT_NULL(seedqr_standard_decode(s));

    s[0] = '+'; // leading plus sign is invalid
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
    RUN_TEST(test_seedsigner_spec_vectors);
    RUN_TEST(test_seedqr_vector_files);
    RUN_TEST(test_compact_decode_invalid_len);
    RUN_TEST(test_compact_encode_short_buffer);
    RUN_TEST(test_standard_decode_null_and_bad_length);
    RUN_TEST(test_standard_decode_rejects_non_digit);
    RUN_TEST(test_standard_decode_rejects_space_and_sign);
    RUN_TEST(test_standard_decode_rejects_bad_index);
    RUN_TEST(test_standard_decode_rejects_bad_checksum);
    RUN_TEST(test_standard_encode_error_paths);
    return UNITY_END();
}

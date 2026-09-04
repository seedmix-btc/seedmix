/**
 * @file tests/test_bip39_wordlist.c
 * @brief Unity tests for main/crypto/bip39_wordlist.c
 */

#include "crypto/bip39_wordlist.h"
#include "unity.h"

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static bool has_match(const char** matches, size_t n, const char* word) {
    for (size_t i = 0; i < n; i++) {
        if (strcmp(matches[i], word) == 0) return true;
    }
    return false;
}

static void test_lookup_aba(void) {
    const char* matches[BIP39_MAX_MATCHES] = {0};
    size_t      n                          = bip39_wordlist_lookup("aba", matches);
    TEST_ASSERT_TRUE(n > 0);
    TEST_ASSERT_TRUE(has_match(matches, n, "abandon"));
}

static void test_lookup_case_insensitive(void) {
    const char* lower[BIP39_MAX_MATCHES] = {0};
    const char* upper[BIP39_MAX_MATCHES] = {0};
    size_t      nl                       = bip39_wordlist_lookup("aba", lower);
    size_t      nu                       = bip39_wordlist_lookup("ABA", upper);
    TEST_ASSERT_TRUE(nl > 0);
    TEST_ASSERT_EQUAL_UINT((unsigned)nl, (unsigned)nu);
}

static void test_lookup_empty_prefix(void) {
    const char* matches[BIP39_MAX_MATCHES] = {0};
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)bip39_wordlist_lookup("", matches));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)bip39_wordlist_lookup(NULL, matches));
}

static void test_lookup_exact_word(void) {
    const char* matches[BIP39_MAX_MATCHES] = {0};
    size_t      n                          = bip39_wordlist_lookup("zoo", matches);
    TEST_ASSERT_TRUE(n > 0);
    TEST_ASSERT_TRUE(has_match(matches, n, "zoo"));
}

static void test_lookup_caps_at_max_matches(void) {
    static const char sentinel[]                     = "sentinel";
    const char*       matches[BIP39_MAX_MATCHES + 1] = {0};
    matches[BIP39_MAX_MATCHES]                       = sentinel;

    /* "a" matches far more than BIP39_MAX_MATCHES words. */
    size_t n = bip39_wordlist_lookup("a", matches);

    TEST_ASSERT_EQUAL_UINT(BIP39_MAX_MATCHES, (unsigned)n);
    TEST_ASSERT_EQUAL_PTR(sentinel, matches[BIP39_MAX_MATCHES]);
}

static void test_word_at_index(void) {
    TEST_ASSERT_EQUAL_STRING("abandon", bip39_wordlist_word(0));
    TEST_ASSERT_EQUAL_STRING("zoo", bip39_wordlist_word(BIP39_WORD_COUNT - 1));
    TEST_ASSERT_NULL(bip39_wordlist_word(BIP39_WORD_COUNT));
}

static void test_index_of_word(void) {
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)bip39_wordlist_index("abandon"));
    TEST_ASSERT_EQUAL_UINT(BIP39_WORD_COUNT - 1, (unsigned)bip39_wordlist_index("zoo"));
    TEST_ASSERT_TRUE(bip39_wordlist_index("notaword") == SIZE_MAX);
    TEST_ASSERT_TRUE(bip39_wordlist_index("") == SIZE_MAX);
    TEST_ASSERT_TRUE(bip39_wordlist_index(NULL) == SIZE_MAX);
}

static void test_word_index_roundtrip(void) {
    static const char* const words[] = {"abandon", "ability", "zoo", "legal", "about"};
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++) {
        size_t idx = bip39_wordlist_index(words[i]);
        TEST_ASSERT_TRUE(idx != SIZE_MAX);
        TEST_ASSERT_EQUAL_STRING(words[i], bip39_wordlist_word(idx));
    }
}

int main(void) {
    UNITY_BEGIN();
    bip39_wordlist_init();
    RUN_TEST(test_lookup_aba);
    RUN_TEST(test_lookup_case_insensitive);
    RUN_TEST(test_lookup_empty_prefix);
    RUN_TEST(test_lookup_exact_word);
    RUN_TEST(test_lookup_caps_at_max_matches);
    RUN_TEST(test_word_at_index);
    RUN_TEST(test_index_of_word);
    RUN_TEST(test_word_index_roundtrip);
    return UNITY_END();
}

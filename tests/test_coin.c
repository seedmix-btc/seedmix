/**
 * @file tests/test_coin.c
 * @brief Unity tests for main/crypto/coin.c
 */

#include "crypto/coin.h"
#include "unity.h"

#include <stdint.h>

void setUp(void) {}
void tearDown(void) {}

static void test_begin_defaults(void) {
    coin_entropy_t* c = coin_entropy_begin(12);
    TEST_ASSERT_NOT_NULL(c);
    TEST_ASSERT_EQUAL_UINT(128, coin_entropy_needed(c));
    TEST_ASSERT_EQUAL_UINT(0, coin_entropy_bits(c));
    TEST_ASSERT_EQUAL_UINT(0, coin_entropy_flips(c));
    TEST_ASSERT_FALSE(coin_entropy_ready(c));
    coin_entropy_discard(c);
}

static void test_one_bit_per_flip(void) {
    coin_entropy_t* c = coin_entropy_begin(12);
    coin_entropy_add_flip(c, 1);
    coin_entropy_add_flip(c, 0);
    TEST_ASSERT_EQUAL_UINT(2, coin_entropy_bits(c));
    TEST_ASSERT_EQUAL_UINT(2, coin_entropy_flips(c));
    TEST_ASSERT_EQUAL_UINT8(0x80, coin_entropy_bytes(c)[0]); // tails=1, heads=0, ...
    coin_entropy_discard(c);
}

static void test_derive_is_the_flip_bits(void) {
    uint8_t out[32] = {0};

    coin_entropy_t* heads = coin_entropy_begin(12);
    for (unsigned i = 0; i < 128; i++) coin_entropy_add_flip(heads, 0);
    TEST_ASSERT_EQUAL_UINT(16, (unsigned)coin_entropy_derive(heads, out, sizeof(out)));
    for (unsigned i = 0; i < 16; i++) TEST_ASSERT_EQUAL_UINT8(0x00, out[i]);
    coin_entropy_discard(heads);

    coin_entropy_t* tails = coin_entropy_begin(12);
    for (unsigned i = 0; i < 128; i++) coin_entropy_add_flip(tails, 1);
    TEST_ASSERT_EQUAL_UINT(16, (unsigned)coin_entropy_derive(tails, out, sizeof(out)));
    for (unsigned i = 0; i < 16; i++) TEST_ASSERT_EQUAL_UINT8(0xFF, out[i]);
    coin_entropy_discard(tails);
}

static void test_ready_after_128_flips(void) {
    coin_entropy_t* c = coin_entropy_begin(12);
    for (unsigned i = 0; i < 127; i++) coin_entropy_add_flip(c, i & 1);
    TEST_ASSERT_FALSE(coin_entropy_ready(c));

    coin_entropy_add_flip(c, 1);
    TEST_ASSERT_TRUE(coin_entropy_ready(c));
    TEST_ASSERT_EQUAL_UINT(128, coin_entropy_flips(c));
    coin_entropy_discard(c);
}

static void test_derive_lengths(void) {
    uint8_t out[32] = {0};

    coin_entropy_t* c12 = coin_entropy_begin(12);
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)coin_entropy_derive(c12, out, sizeof(out)));
    for (unsigned i = 0; i < 128; i++) coin_entropy_add_flip(c12, i & 1);
    TEST_ASSERT_EQUAL_UINT(16, (unsigned)coin_entropy_derive(c12, out, sizeof(out)));
    coin_entropy_discard(c12);

    coin_entropy_t* c24 = coin_entropy_begin(24);
    for (unsigned i = 0; i < 256; i++) coin_entropy_add_flip(c24, i & 1);
    TEST_ASSERT_TRUE(coin_entropy_ready(c24));
    TEST_ASSERT_EQUAL_UINT(32, (unsigned)coin_entropy_derive(c24, out, sizeof(out)));
    coin_entropy_discard(c24);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_begin_defaults);
    RUN_TEST(test_one_bit_per_flip);
    RUN_TEST(test_ready_after_128_flips);
    RUN_TEST(test_derive_is_the_flip_bits);
    RUN_TEST(test_derive_lengths);
    return UNITY_END();
}

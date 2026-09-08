/**
 * @file tests/test_fatal.c
 * @brief Death tests: assert that invalid inputs hit ASSERT_OR_DIE / FATAL.
 */

#include "fatal_test.h"
#include "unity.h"

#include "crypto/coin.h"
#include "crypto/dice.h"
#include "crypto/mnemonic.h"
#include "crypto/secure_stack.h"
#include "crypto/touch.h"
#include "util/utils.h"

#include <stdint.h>

void setUp(void) {}
void tearDown(void) {}

/* -- dice ---------------------------------------------------------------- */
static void test_dice_begin_invalid_word_count(void) {
    TEST_ASSERT_FATAL(dice_entropy_begin(11, 6));
    TEST_ASSERT_FATAL(dice_entropy_begin(0, 6));
}

static void test_dice_begin_invalid_sides(void) {
    TEST_ASSERT_FATAL(dice_entropy_begin(12, 1));
    TEST_ASSERT_FATAL(dice_entropy_begin(12, 256));
}

static void test_dice_roll_above_range(void) {
    dice_entropy_t* d = dice_entropy_begin(12, 6);
    TEST_ASSERT_FATAL(dice_entropy_add_roll(d, 7));
}

static void test_dice_roll_below_range(void) {
    dice_entropy_t* d = dice_entropy_begin(12, 6);
    TEST_ASSERT_FATAL(dice_entropy_add_roll(d, 0));
}

/* -- coin ---------------------------------------------------------------- */
static void test_coin_flip_out_of_range(void) {
    coin_entropy_t* c = coin_entropy_begin(12);
    TEST_ASSERT_FATAL(coin_entropy_add_flip(c, 2));
}

/* -- secure_stack -------------------------------------------------------- */
static void test_stack_pop_empty(void) {
    secure_stack_t* s = secure_stack_create(1);
    uint8_t         x = 0;
    TEST_ASSERT_FATAL(secure_stack_pop(s, &x));
}

static void test_stack_pop_mismatch(void) {
    secure_stack_t* s = secure_stack_create(1);
    uint8_t         a = 1, b = 2;
    secure_stack_push(s, &a, 1);
    TEST_ASSERT_FATAL(secure_stack_pop(s, &b));
}

static void test_stack_destroy_unpopped(void) {
    secure_stack_t* s = secure_stack_create(1);
    uint8_t         a = 1;
    secure_stack_push(s, &a, 1);
    TEST_ASSERT_FATAL(secure_stack_destroy(s));
}

/* -- mnemonic ------------------------------------------------------------ */
static void test_mnemonic_generate_null_callback(void) {
    TEST_ASSERT_FATAL(mnemonic_generate(12, NULL));
}

static void test_mnemonic_combine_identical(void) {
    const uint8_t e[16] = {0};
    mnemonic_t*   a     = mnemonic_from_entropy(e, sizeof(e));
    mnemonic_t*   b     = mnemonic_from_entropy(e, sizeof(e));
    TEST_ASSERT_FATAL(mnemonic_combine(a, b));
}

static void test_mnemonic_combine_word_count_mismatch(void) {
    const uint8_t e16[16] = {0};
    const uint8_t e32[32] = {0};
    mnemonic_t*   a       = mnemonic_from_entropy(e16, sizeof(e16));
    mnemonic_t*   b       = mnemonic_from_entropy(e32, sizeof(e32));
    TEST_ASSERT_FATAL(mnemonic_combine(a, b));
}

/* -- utils --------------------------------------------------------------- */
static void test_word_count_bits_invalid(void) { TEST_ASSERT_FATAL(utils_word_count_bits(11)); }

/* -- overflow / buffer-size / null guards -------------------------------- */
static void test_dice_accumulator_overflow(void) {
    dice_entropy_t* d = dice_entropy_begin(12, 2); /* cap = 128 rolls */
    for (unsigned i = 0; i < 128; i++) dice_entropy_add_roll(d, (i % 2) + 1);
    TEST_ASSERT_FATAL(dice_entropy_add_roll(d, 1));
}

static void test_dice_derive_buffer_too_small(void) {
    dice_entropy_t* d = dice_entropy_begin(12, 6);
    for (unsigned i = 0; i < 64; i++) dice_entropy_add_roll(d, (i % 6) + 1);
    uint8_t out[8] = {0};
    TEST_ASSERT_FATAL(dice_entropy_derive(d, out, sizeof(out)));
}

static void test_touch_accumulator_overflow(void) {
    touch_entropy_t* t = touch_entropy_begin(12, 480, 320); /* cap = 32 taps */
    for (unsigned i = 0; i < 32; i++) touch_entropy_add_tap(t, (int32_t)i, (int32_t)i);
    TEST_ASSERT_FATAL(touch_entropy_add_tap(t, 1, 1));
}

static void test_touch_derive_buffer_too_small(void) {
    touch_entropy_t* t = touch_entropy_begin(12, 480, 320);
    for (unsigned i = 0; i < 32; i++) touch_entropy_add_tap(t, (int32_t)i, (int32_t)i);
    uint8_t out[8] = {0};
    TEST_ASSERT_FATAL(touch_entropy_derive(t, out, sizeof(out)));
}

static void test_mnemonic_from_entropy_invalid_length(void) {
    uint8_t bytes[20] = {0};
    TEST_ASSERT_FATAL(mnemonic_from_entropy(bytes, sizeof(bytes)));
}

static void test_mnemonic_combine_self(void) {
    const uint8_t e[16] = {0};
    mnemonic_t*   a     = mnemonic_from_entropy(e, sizeof(e));
    TEST_ASSERT_FATAL(mnemonic_combine(a, a));
}

static void test_mnemonic_to_entropy_null(void) {
    uint8_t out[16] = {0};
    TEST_ASSERT_FATAL(mnemonic_to_entropy(NULL, out));
}

static void test_mnemonic_discard_null(void) { TEST_ASSERT_FATAL(mnemonic_discard(NULL)); }

static void test_sha256_expand_invalid_input(void) {
    uint8_t out[32] = {0};
    TEST_ASSERT_FATAL(sha256_expand(NULL, 1, out, sizeof(out)));
    TEST_ASSERT_FATAL(sha256_expand(out, 0, out, sizeof(out)));
}

static void test_floor_log2_zero(void) { TEST_ASSERT_FATAL(utils_floor_log2(0)); }

int main(void) {
    UNITY_BEGIN();
    mnemonic_init();
    RUN_TEST(test_dice_begin_invalid_word_count);
    RUN_TEST(test_dice_begin_invalid_sides);
    RUN_TEST(test_dice_roll_above_range);
    RUN_TEST(test_dice_roll_below_range);
    RUN_TEST(test_coin_flip_out_of_range);
    RUN_TEST(test_stack_pop_empty);
    RUN_TEST(test_stack_pop_mismatch);
    RUN_TEST(test_stack_destroy_unpopped);
    RUN_TEST(test_mnemonic_generate_null_callback);
    RUN_TEST(test_mnemonic_combine_identical);
    RUN_TEST(test_mnemonic_combine_word_count_mismatch);
    RUN_TEST(test_word_count_bits_invalid);
    RUN_TEST(test_dice_accumulator_overflow);
    RUN_TEST(test_dice_derive_buffer_too_small);
    RUN_TEST(test_touch_accumulator_overflow);
    RUN_TEST(test_touch_derive_buffer_too_small);
    RUN_TEST(test_mnemonic_from_entropy_invalid_length);
    RUN_TEST(test_mnemonic_combine_self);
    RUN_TEST(test_mnemonic_to_entropy_null);
    RUN_TEST(test_mnemonic_discard_null);
    RUN_TEST(test_sha256_expand_invalid_input);
    RUN_TEST(test_floor_log2_zero);
    return UNITY_END();
}

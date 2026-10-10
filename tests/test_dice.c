/**
 * @file tests/test_dice.c
 * @brief Unity tests for main/crypto/dice.c
 */

#include "crypto/dice.h"
#include "unity.h"

#include <stdint.h>

void setUp(void) {}
void tearDown(void) {}

static void test_begin_defaults(void) {
    dice_entropy_t* d = dice_entropy_begin(12, 4);
    TEST_ASSERT_NOT_NULL(d);
    TEST_ASSERT_EQUAL_UINT(4, dice_entropy_sides(d));
    TEST_ASSERT_EQUAL_UINT(128, dice_entropy_needed(d));
    TEST_ASSERT_EQUAL_UINT(0, dice_entropy_bits(d));
    TEST_ASSERT_EQUAL_UINT(0, dice_entropy_rolls(d));
    TEST_ASSERT_FALSE(dice_entropy_ready(d));
    dice_entropy_discard(d);
}

static void test_accumulate_until_ready(void) {
    // 4 sides -> 2 bits per roll; 64 rolls -> 128 bits
    dice_entropy_t* d = dice_entropy_begin(12, 4);
    for (unsigned i = 0; i < 63; i++) dice_entropy_add_roll(d, (i % 4) + 1);
    TEST_ASSERT_FALSE(dice_entropy_ready(d));
    TEST_ASSERT_EQUAL_UINT(126, dice_entropy_bits(d));

    dice_entropy_add_roll(d, 1);
    TEST_ASSERT_TRUE(dice_entropy_ready(d));
    TEST_ASSERT_EQUAL_UINT(128, dice_entropy_bits(d));
    TEST_ASSERT_EQUAL_UINT(64, dice_entropy_rolls(d));
    dice_entropy_discard(d);
}

static void test_bits_are_the_roll_values(void) {
    // d4 roll v carries (v - 1) in 2 bits, most significant first.
    dice_entropy_t* d        = dice_entropy_begin(12, 4);
    const unsigned  rolls[4] = {1, 2, 3, 4}; // 00 01 10 11
    for (unsigned i = 0; i < 4; i++) dice_entropy_add_roll(d, rolls[i]);
    TEST_ASSERT_EQUAL_UINT(8, dice_entropy_bits(d));
    TEST_ASSERT_EQUAL_UINT8(0x1B, dice_entropy_bytes(d)[0]);
    dice_entropy_discard(d);
}

static void test_partial_last_roll_is_dropped(void) {
    // 8 sides -> 3 bits per roll; 43 rolls would be 129 bits, only 128 kept.
    dice_entropy_t* d = dice_entropy_begin(12, 8);
    for (unsigned i = 0; i < 43; i++) dice_entropy_add_roll(d, (i % 8) + 1);
    TEST_ASSERT_TRUE(dice_entropy_ready(d));
    TEST_ASSERT_EQUAL_UINT(128, dice_entropy_bits(d));
    dice_entropy_discard(d);
}

static void test_d6_splits_into_a_d4_and_a_coin(void) {
    // Faces are taken in power-of-two parts, largest first: a d6 is a d4 plus a
    // coin.  Faces 1..4 are therefore worth 2 bits (v - 1, exactly like a d4)
    // and 5, 6 are worth 1 bit each.
    dice_entropy_t* d      = dice_entropy_begin(12, 6);
    const unsigned  low[4] = {1, 2, 3, 4}; // 00 01 10 11
    for (unsigned i = 0; i < 4; i++) {
        dice_entropy_add_roll(d, low[i]);
        TEST_ASSERT_EQUAL_UINT(2, dice_entropy_last_bits(d));
    }
    TEST_ASSERT_EQUAL_UINT(8, dice_entropy_bits(d));
    TEST_ASSERT_EQUAL_UINT8(0x1B, dice_entropy_bytes(d)[0]);

    dice_entropy_add_roll(d, 5); // the coin part: one bit, 0
    TEST_ASSERT_EQUAL_UINT(1, dice_entropy_last_bits(d));
    dice_entropy_add_roll(d, 6); // the coin part: one bit, 1
    TEST_ASSERT_EQUAL_UINT(1, dice_entropy_last_bits(d));
    TEST_ASSERT_EQUAL_UINT(10, dice_entropy_bits(d));
    TEST_ASSERT_EQUAL_UINT8(0x40, dice_entropy_bytes(d)[1]); // 0 1
    TEST_ASSERT_EQUAL_UINT(6, dice_entropy_last_roll(d));
    dice_entropy_discard(d);
}

static void test_d12_splits_into_a_d8_and_a_d4(void) {
    // 12 = 8 + 4, so faces 1..8 are worth 3 bits and 9..12 are worth 2.
    dice_entropy_t* d = dice_entropy_begin(12, 12);
    dice_entropy_add_roll(d, 8);
    TEST_ASSERT_EQUAL_UINT(3, dice_entropy_bits(d));
    dice_entropy_add_roll(d, 10); // second face of the d4 part: v = 1 -> 01
    TEST_ASSERT_EQUAL_UINT(2, dice_entropy_last_bits(d));
    TEST_ASSERT_EQUAL_UINT(5, dice_entropy_bits(d));
    TEST_ASSERT_EQUAL_UINT8(0xE8, dice_entropy_bytes(d)[0]); // 111 01
    dice_entropy_discard(d);
}

static void test_odd_die_leftover_face_gives_nothing(void) {
    // 3 = 2 + 1: faces 1 and 2 are a coin and face 3 has no part of its own, so
    // it adds no bits at all.  Every odd die has such a face; the offered dice
    // (6, 10, 12, 20) do not, because each remainder is itself a power of two.
    dice_entropy_t* d = dice_entropy_begin(12, 3);
    dice_entropy_add_roll(d, 1);
    TEST_ASSERT_EQUAL_UINT(1, dice_entropy_last_bits(d));
    dice_entropy_add_roll(d, 3);
    TEST_ASSERT_EQUAL_UINT(0, dice_entropy_last_bits(d));
    TEST_ASSERT_EQUAL_UINT(1, dice_entropy_bits(d));
    dice_entropy_discard(d);
}

static void test_roll_bits_is_what_a_roll_adds(void) {
    // The rule the help text and the dice screen quote is also the rule the
    // collector runs: dice_entropy_roll_bits() must equal last_bits() for every
    // face of every offered die.
    const unsigned sides[4] = {6, 10, 12, 20};
    for (unsigned k = 0; k < 4; k++) {
        dice_entropy_t* d = dice_entropy_begin(12, sides[k]);
        for (unsigned v = 1; v <= sides[k]; v++) {
            dice_entropy_add_roll(d, v);
            TEST_ASSERT_EQUAL_UINT(dice_entropy_roll_bits(sides[k], v), dice_entropy_last_bits(d));
        }
        dice_entropy_discard(d);
    }
    TEST_ASSERT_EQUAL_UINT(1, dice_entropy_roll_bits(3, 2));
    TEST_ASSERT_EQUAL_UINT(0, dice_entropy_roll_bits(3, 3));
    TEST_ASSERT_EQUAL_UINT(2, dice_entropy_roll_bits(7, 4));
    TEST_ASSERT_EQUAL_UINT(1, dice_entropy_roll_bits(7, 6));
    TEST_ASSERT_EQUAL_UINT(0, dice_entropy_roll_bits(7, 7)); // the leftover face
}

static void test_split_rates_match_the_rule(void) {
    // Whole bits per roll, but fewer of them than log2(sides): that is the price
    // of never carrying a fraction.  Pooled over 20 seeds per die, since one
    // seed is only ~70-160 rolls and the per-roll count varies.
    const unsigned sides[4]  = {6, 10, 12, 20};
    const double   expect[4] = {1.6667, 2.6000, 2.6667, 3.6000};
    for (unsigned k = 0; k < 4; k++) {
        unsigned long bits = 0, rolls = 0;
        for (unsigned run = 0; run < 20; run++) {
            dice_entropy_t* d = dice_entropy_begin(12, sides[k]);
            unsigned        s = 11u + k + run;
            while (!dice_entropy_ready(d)) {
                s = s * 1103515245u + 12345u;
                dice_entropy_add_roll(d, ((s >> 16) % sides[k]) + 1u);
                rolls++;
            }
            bits += dice_entropy_bits(d);
            dice_entropy_discard(d);
        }
        const double rate = (double)bits / (double)rolls;
        TEST_ASSERT_FLOAT_WITHIN(0.08f, (float)expect[k], (float)rate);
    }
}

static void test_help_screen_example(void) {
    // The worked example in the dice help screen: a d6 showing 3, then 6, then 5
    // releases 2, then 1, then 1 bits (the seed starts 1010).  If this changes
    // the help text and its diagrams need updating too.
    dice_entropy_t* d = dice_entropy_begin(24, 6);

    dice_entropy_add_roll(d, 3); // the d4 part: 10
    TEST_ASSERT_EQUAL_UINT(2, dice_entropy_last_bits(d));
    TEST_ASSERT_EQUAL_UINT8(0x80, dice_entropy_bytes(d)[0]);

    dice_entropy_add_roll(d, 6); // the coin part: 1
    TEST_ASSERT_EQUAL_UINT(1, dice_entropy_last_bits(d));
    TEST_ASSERT_EQUAL_UINT(3, dice_entropy_bits(d));
    TEST_ASSERT_EQUAL_UINT8(0xA0, dice_entropy_bytes(d)[0]); // 101 in the seed

    dice_entropy_add_roll(d, 5); // the coin part: 0
    TEST_ASSERT_EQUAL_UINT(1, dice_entropy_last_bits(d));
    TEST_ASSERT_EQUAL_UINT(4, dice_entropy_bits(d));
    TEST_ASSERT_EQUAL_UINT8(0xA0, dice_entropy_bytes(d)[0]); // 1010
    dice_entropy_discard(d);
}

static void test_batched_dice_reach_ready(void) {
    // A d6 pays 1.67 bits a roll, so 128 bits takes ~77 rolls - it would be ~50
    // if the fraction were carried.  The split must not be worse than its rate.
    dice_entropy_t* d = dice_entropy_begin(12, 6);
    uint32_t        s = 12345u;
    unsigned        i = 0;
    while (!dice_entropy_ready(d) && i < 200) {
        s = s * 1103515245u + 12345u;
        dice_entropy_add_roll(d, ((s >> 16) % 6u) + 1u);
        i++;
    }
    TEST_ASSERT_TRUE(dice_entropy_ready(d));
    TEST_ASSERT_EQUAL_UINT(128, dice_entropy_bits(d));
    TEST_ASSERT_LESS_THAN_UINT(90, i);
    dice_entropy_discard(d);
}

static void test_other_dice_work(void) {
    const unsigned sides[2] = {12, 20};
    for (unsigned k = 0; k < 2; k++) {
        dice_entropy_t* d = dice_entropy_begin(12, sides[k]);
        unsigned        i = 0;
        while (!dice_entropy_ready(d) && i < 200) dice_entropy_add_roll(d, (i++ % sides[k]) + 1);
        TEST_ASSERT_TRUE(dice_entropy_ready(d));
        TEST_ASSERT_EQUAL_UINT(128, dice_entropy_bits(d));
        dice_entropy_discard(d);
    }
}

static void test_derive_not_ready_returns_zero(void) {
    dice_entropy_t* d       = dice_entropy_begin(12, 4);
    uint8_t         out[32] = {0};
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)dice_entropy_derive(d, out, sizeof(out)));
    dice_entropy_discard(d);
}

static void test_derive_length_16(void) {
    dice_entropy_t* d = dice_entropy_begin(12, 4);
    for (unsigned i = 0; i < 64; i++) dice_entropy_add_roll(d, (i % 4) + 1);
    uint8_t out[32] = {0};
    TEST_ASSERT_EQUAL_UINT(16, (unsigned)dice_entropy_derive(d, out, sizeof(out)));
    // The seed IS the collected bits: derive() copies them unchanged.
    TEST_ASSERT_EQUAL_MEMORY(dice_entropy_bytes(d), out, 16);
    dice_entropy_discard(d);
}

static void test_derive_length_32(void) {
    dice_entropy_t* d = dice_entropy_begin(24, 4);
    for (unsigned i = 0; i < 128; i++) dice_entropy_add_roll(d, (i % 4) + 1);
    uint8_t out[32] = {0};
    TEST_ASSERT_EQUAL_UINT(32, (unsigned)dice_entropy_derive(d, out, sizeof(out)));
    dice_entropy_discard(d);
}

static void test_derive_deterministic(void) {
    dice_entropy_t* a = dice_entropy_begin(12, 8);
    dice_entropy_t* b = dice_entropy_begin(12, 8);
    for (unsigned i = 0; i < 43; i++) {
        unsigned v = (i % 8) + 1;
        dice_entropy_add_roll(a, v);
        dice_entropy_add_roll(b, v);
    }
    uint8_t outa[16] = {0}, outb[16] = {0};
    TEST_ASSERT_EQUAL_UINT(16, (unsigned)dice_entropy_derive(a, outa, sizeof(outa)));
    TEST_ASSERT_EQUAL_UINT(16, (unsigned)dice_entropy_derive(b, outb, sizeof(outb)));
    TEST_ASSERT_EQUAL_MEMORY(outa, outb, sizeof(outa));
    dice_entropy_discard(a);
    dice_entropy_discard(b);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_begin_defaults);
    RUN_TEST(test_accumulate_until_ready);
    RUN_TEST(test_bits_are_the_roll_values);
    RUN_TEST(test_partial_last_roll_is_dropped);
    RUN_TEST(test_d6_splits_into_a_d4_and_a_coin);
    RUN_TEST(test_d12_splits_into_a_d8_and_a_d4);
    RUN_TEST(test_odd_die_leftover_face_gives_nothing);
    RUN_TEST(test_roll_bits_is_what_a_roll_adds);
    RUN_TEST(test_split_rates_match_the_rule);
    RUN_TEST(test_help_screen_example);
    RUN_TEST(test_batched_dice_reach_ready);
    RUN_TEST(test_other_dice_work);
    RUN_TEST(test_derive_not_ready_returns_zero);
    RUN_TEST(test_derive_length_16);
    RUN_TEST(test_derive_length_32);
    RUN_TEST(test_derive_deterministic);
    return UNITY_END();
}

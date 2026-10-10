/**
 * @file main/crypto/coin.c
 * @brief Coin-flip entropy collection.
 *
 * Implemented as a 2-sided die (heads = 1, tails = 2) reusing the dice
 * entropy collector.
 */

#include "coin.h"
#include "util/error.h"

#define COIN_SIDES 2

coin_entropy_t* coin_entropy_begin(unsigned word_count) {
    return dice_entropy_begin(word_count, COIN_SIDES);
}

void coin_entropy_add_flip(coin_entropy_t* c, unsigned value) {
    ASSERT_OR_DIE(value == 0 || value == 1, "coin value must be 0 or 1");
    dice_entropy_add_roll(c, value + 1); // heads -> 1, tails -> 2
}

bool coin_entropy_ready(const coin_entropy_t* c) { return dice_entropy_ready(c); }

uint32_t coin_entropy_bits(const coin_entropy_t* c) { return dice_entropy_bits(c); }

uint32_t coin_entropy_needed(const coin_entropy_t* c) { return dice_entropy_needed(c); }

unsigned coin_entropy_flips(const coin_entropy_t* c) { return dice_entropy_rolls(c); }

const uint8_t* coin_entropy_bytes(const coin_entropy_t* c) { return dice_entropy_bytes(c); }

unsigned coin_entropy_last_flip(const coin_entropy_t* c) { return dice_entropy_last_roll(c); }

uint32_t coin_entropy_last_bits(const coin_entropy_t* c) { return dice_entropy_last_bits(c); }

size_t coin_entropy_derive(coin_entropy_t* c, uint8_t* out, size_t out_len) {
    return dice_entropy_derive(c, out, out_len);
}

void coin_entropy_discard(coin_entropy_t* c) { dice_entropy_discard(c); }

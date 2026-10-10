/**
 * @file main/crypto/coin.h
 * @brief Coin-flip entropy collection.
 *
 * A coin flip is a 2-sided die (heads = 1, tails = 2); this is a thin wrapper
 * over the dice entropy collector.  Each flip contributes 1 bit of entropy.
 */

#ifndef COIN_H
#define COIN_H

#include "dice.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Coin flips are modeled as a 2-sided die. */
typedef dice_entropy_t coin_entropy_t;

/**
 * @brief Start collecting coin-flip entropy.
 *
 * @param word_count 12 or 24.
 *
 * Each flip contributes exactly 1 bit of entropy.
 *
 * @return New collector (caller owns it; discard with coin_entropy_discard()).
 */
coin_entropy_t* coin_entropy_begin(unsigned word_count);

/** Add one coin flip (0 = heads, 1 = tails) to the accumulator. */
void coin_entropy_add_flip(coin_entropy_t* c, unsigned value);

/** True once the estimated entropy meets the target. */
bool coin_entropy_ready(const coin_entropy_t* c);

/** Estimated bits collected so far. */
uint32_t coin_entropy_bits(const coin_entropy_t* c);

/** Estimated bits required (128 or 256). */
uint32_t coin_entropy_needed(const coin_entropy_t* c);

/** Number of flips collected so far. */
unsigned coin_entropy_flips(const coin_entropy_t* c);

/** Raw entropy bits collected so far (see dice_entropy_bytes()). */
const uint8_t* coin_entropy_bytes(const coin_entropy_t* c);

/** Value of the most recent flip (1 = heads, 2 = tails). */
unsigned coin_entropy_last_flip(const coin_entropy_t* c);

/** Bits the most recent flip contributed. */
uint32_t coin_entropy_last_bits(const coin_entropy_t* c);

/**
 * @brief Derive the mnemonic entropy from the collected flips.
 *
 * @param c       Collector (must be ready).
 * @param out     Buffer of at least 32 bytes.
 * @param out_len Capacity of @p out.
 * @return        Bytes written (16 or 32), or 0 if not ready.
 */
size_t coin_entropy_derive(coin_entropy_t* c, uint8_t* out, size_t out_len);

/** Discard (zero + free). */
void coin_entropy_discard(coin_entropy_t* c);

#ifdef __cplusplus
}
#endif

#endif /* COIN_H */

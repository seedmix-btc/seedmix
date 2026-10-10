/**
 * @file main/crypto/dice.h
 * @brief Dice-roll entropy collection.
 *
 * Turns die rolls (1..sides) into raw entropy bits until a 12-word (128-bit)
 * or 24-word (256-bit) mnemonic's worth is collected. Nothing is hashed: the
 * bits ARE the mnemonic entropy.
 */

#ifndef DICE_H
#define DICE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dice_entropy_t dice_entropy_t;

/**
 * @brief Start collecting dice-roll entropy.
 *
 * @param word_count 12 or 24.
 * @param sides      Number of die faces (2..256).
 *
 * A die is read as a sum of power-of-two dice: faces are taken in
 * power-of-two parts, largest first, and a part of 2^k faces is worth k bits.
 * A power-of-two die is one part, so it contributes exactly log2(sides) bits per
 * roll: `v - 1` written most-significant-bit first, so a roll reads like its
 * binary form. Any other die splits - a d6 is a d4 plus a coin (2 bits for
 * faces 1..4, 1 bit for 5 and 6), a d12 is a d8 plus a d4, a d20 is a d16 plus
 * a d4 - and averages less than log2(sides) bits per roll (1.67 for a d6 rather
 * than 2.58) in exchange for whole bits per roll and no held-back state.
 *
 * Every bit is uniform and independent whatever the die, so a seed has exactly
 * as much entropy as it has bits. A single leftover face (a d3, a d5, the last
 * face of an odd die) is worth nothing, which is the only way a roll can add no
 * bits at all.
 *
 * @return New collector (caller owns it; discard with dice_entropy_discard()).
 */
dice_entropy_t* dice_entropy_begin(unsigned word_count, unsigned sides);

/** Add one die roll (value 1..sides) to the collector. */
void dice_entropy_add_roll(dice_entropy_t* d, unsigned value);

/**
 * @brief Bits a single roll of a @p sides die is worth: @p value's part width.
 *
 * Exposed so a screen can say what a die yields without reimplementing the
 * split. Returns 0..floor(log2(sides)).
 */
unsigned dice_entropy_roll_bits(unsigned sides, unsigned value);

/** Number of die faces. */
unsigned dice_entropy_sides(const dice_entropy_t* d);

/** True once the collected bits meet the target. */
bool dice_entropy_ready(const dice_entropy_t* d);

/** Bits collected so far. */
uint32_t dice_entropy_bits(const dice_entropy_t* d);

/** Bits required (128 or 256). */
uint32_t dice_entropy_needed(const dice_entropy_t* d);

/** Number of rolls collected so far. */
unsigned dice_entropy_rolls(const dice_entropy_t* d);

/** Value of the most recent roll (1..sides). */
unsigned dice_entropy_last_roll(const dice_entropy_t* d);

/** Bits the most recent roll contributed (can be 0 for an odd-sided die). */
uint32_t dice_entropy_last_bits(const dice_entropy_t* d);

/**
 * Raw entropy bits collected so far, most-significant-bit first. The last
 * byte is only complete once dice_entropy_bits() is a multiple of 8.
 */
const uint8_t* dice_entropy_bytes(const dice_entropy_t* d);

/**
 * @brief Copy out the mnemonic entropy: the collected bits, 16 or 32 bytes.
 *
 * @param d       Collector (must be ready).
 * @param out     Buffer of at least 32 bytes.
 * @param out_len Capacity of @p out.
 * @return        Bytes written (16 or 32), or 0 if not ready.
 */
size_t dice_entropy_derive(dice_entropy_t* d, uint8_t* out, size_t out_len);

/** Discard (zero + free). */
void dice_entropy_discard(dice_entropy_t* d);

#ifdef __cplusplus
}
#endif

#endif /* DICE_H */

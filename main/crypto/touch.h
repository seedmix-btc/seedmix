/**
 * @file main/crypto/touch.h
 * @brief Touch-screen entropy collection.
 *
 * The screen is read as a grid of tiles, so a tap is worth whole bits: the tile
 * the finger lands in is written as its index in TOUCH_BITS_PER_TAP bits, most
 * significant first, and those bits accumulate into a plain bit string.
 *
 * The bits are the raw material, not the seed. Taps are neither uniform over the
 * screen nor independent of each other, so the bits are hashed when the entropy
 * is derived, and only half of them are assumed to carry anything - the target
 * is twice the seed size.
 */

#ifndef TOUCH_H
#define TOUCH_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Tiles per axis: an 8x8 grid, i.e. 6 bits a tap. */
#define TOUCH_TILES_PER_AXIS 8u
#define TOUCH_BITS_PER_TAP 6u

typedef struct touch_entropy_t touch_entropy_t;

/**
 * @brief Start collecting touch entropy.
 *
 * @param word_count 12 or 24.
 * @param res_x      Display width in pixels.
 * @param res_y      Display height in pixels.
 *
 * @return New collector (caller owns it; discard with touch_entropy_discard()).
 */
touch_entropy_t* touch_entropy_begin(unsigned word_count, uint32_t res_x, uint32_t res_y);

/** Add one tap: its tile's index becomes TOUCH_BITS_PER_TAP bits. */
void touch_entropy_add_tap(touch_entropy_t* t, int32_t x, int32_t y);

/** True once the tapped bits reach the target. */
bool touch_entropy_ready(const touch_entropy_t* t);

/** Tapped bits collected so far, most-significant first (what the grid shows). */
uint32_t touch_entropy_bits(const touch_entropy_t* t);

/** Tapped bits needed: twice the seed size, since half are assumed to be noise. */
uint32_t touch_entropy_target_bits(const touch_entropy_t* t);

/** Number of taps collected so far. */
unsigned touch_entropy_taps(const touch_entropy_t* t);

/** Tile index (0..TOUCH_TILES_PER_AXIS^2-1) of the most recent tap. */
unsigned touch_entropy_last_tile(const touch_entropy_t* t);

/** The tapped bits as bytes, for a bit view. The last byte is partial. */
const uint8_t* touch_entropy_bytes(const touch_entropy_t* t);

/**
 * @brief Hash the tapped bits into the mnemonic entropy.
 *
 * @param t       Collector (must be ready).
 * @param out     Buffer of at least 32 bytes.
 * @param out_len Capacity of @p out.
 * @return        Bytes written (16 or 32), or 0 if not ready.
 */
size_t touch_entropy_derive(touch_entropy_t* t, uint8_t* out, size_t out_len);

/** Discard (zero + free). */
void touch_entropy_discard(touch_entropy_t* t);

#ifdef __cplusplus
}
#endif

#endif /* TOUCH_H */

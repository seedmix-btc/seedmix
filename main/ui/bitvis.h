/**
 * @file main/ui/bitvis.h
 * @brief Bit-level visualisations: an animated XOR scan, an animated single
 * value, a static grid the caller fills, and a one-roll readout.
 */

#ifndef BITVIS_H
#define BITVIS_H

#include "lvgl.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Add an animated bit-level XOR view to @p parent.
 *
 * Draws three grids of byte blocks - A, B and A ^ B - from three hex strings
 * (lowercase, no prefix, all the same length) and animates a bit-by-bit scan:
 * a highlight walks one bit per tick and the merged row fills in as each bit
 * is XORed. A label below the grids shows the current `a ^ b = r`. Each bit
 * is re-derived from A and B when the scan reaches it and checked against the
 * merged bit, so a wrong result errors out instead of being drawn.
 *
 * The grids are hand-rendered RGB565 buffers shown with lv_image widgets and a
 * timer drives the animation. The buffers hold entropy bits, so they are
 * wiped and freed when @p screen is deleted; @p screen must be the screen that
 * owns @p parent.
 *
 * Errors out (fatal error screen) when a hex string is null, differs in
 * length, or is not valid hex, and when the buffers can't be allocated - these
 * only happen on a programming error or an exhausted heap.
 */
void bitvis_add_xor(lv_obj_t* parent, lv_obj_t* screen, const char* a_hex, const char* b_hex,
                    const char* r_hex);

/**
 * @brief Add an animated bit-level view of a single value to @p parent.
 *
 * Same layout and scan as bitvis_add_xor(), but one grid: its bits fill in
 * from the left as the scan passes them. Used to show a working seed as raw
 * entropy. Errors out under the same conditions as bitvis_add_xor().
 */
void bitvis_add_entropy(lv_obj_t* parent, lv_obj_t* screen, const char* hex);

/**
 * A bit grid whose contents the caller sets (no animation). Use it for streams
 * that grow from user input rather than a timer, e.g. dice/coin collection.
 */
typedef struct {
    void* priv; // internal; cleared when the owning screen is deleted
} bitvis_grid_t;

/**
 * @brief Draw a static grid of @p total_bits bits inside @p parent.
 *
 * The same byte blocks as the animated views; every bit starts unknown.  @p g
 * must outlive @p screen: its widgets are released when @p screen is deleted,
 * after which bitvis_grid_set() does nothing.
 */
void bitvis_grid_create(bitvis_grid_t* g, lv_obj_t* parent, lv_obj_t* screen, uint32_t total_bits);

/**
 * @brief Show a caller-filled grid: known bits, with the newest ones highlighted.
 *
 * @p bytes holds the stream MSB-first with @p filled_bits of them known. Bits
 * from @p highlight_from up are drawn highlighted (e.g. the bits the latest roll
 * produced); everything past @p filled_bits stays unknown.
 */
void bitvis_grid_set(bitvis_grid_t* g, const uint8_t* bytes, uint32_t filled_bits,
                     uint32_t highlight_from);

/**
 * The newest roll's readout: a label where a byte block shows its hex, and the
 * bits that roll produced below it.
 */
typedef struct {
    void* priv; // internal; cleared when the owning screen is deleted
} bitvis_roll_t;

/**
 * @brief Draw a roll readout of @p cells bit cells inside @p parent.
 *
 * @p cells should be as wide as the die's longest part, i.e. the most bits one
 * roll can contribute; a roll worth fewer shows just those bits. Drawn with
 * the same cells, colours and font as the grid, so build it against the same
 * @p screen and it lines up with it.  @p r must outlive @p screen: its widgets
 * are released when @p screen is deleted, after which bitvis_roll_set() does
 * nothing.
 */
void bitvis_roll_create(bitvis_roll_t* r, lv_obj_t* parent, lv_obj_t* screen, unsigned cells);

/**
 * @brief Show @p label above the newest @p nbits bits of the stream.
 *
 * @p bytes holds the stream MSB-first with @p filled_bits of them known; the
 * last @p nbits of those are shown (a roll's contribution, which is what the
 * grid highlights).  @p nbits == 0 leaves every cell unknown.
 */
void bitvis_roll_set(bitvis_roll_t* r, const char* label, const uint8_t* bytes,
                     uint32_t filled_bits, uint32_t nbits);

#ifdef __cplusplus
}
#endif

#endif /* BITVIS_H */

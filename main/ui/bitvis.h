/**
 * @file main/ui/bitvis.h
 * @brief Animated bit-level XOR view drawn into a parent object.
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
 * is XORed.  A label below the grids shows the current `a ^ b = r`. Each bit
 * is re-derived from A and B when the scan reaches it and checked against the
 * merged bit, so a wrong result errors out instead of being drawn.
 *
 * The grids are hand-rendered RGB565 buffers shown with lv_image widgets and a
 * timer drives the animation.  The buffers hold entropy bits, so they are
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
 * from the left as the scan passes them.  Used to show a working seed as raw
 * entropy.  Errors out under the same conditions as bitvis_add_xor().
 */
void bitvis_add_entropy(lv_obj_t* parent, lv_obj_t* screen, const char* hex);

#ifdef __cplusplus
}
#endif

#endif /* BITVIS_H */

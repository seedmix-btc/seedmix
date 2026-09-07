/**
 * @file main/ui/ui_internal.h
 * @brief Internal helpers shared between ui.c and log.c.
 */

#ifndef UI_INTERNAL_H
#define UI_INTERNAL_H

#include "lvgl.h"
#include "ui.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    UI_BTN_SIZE_SMALL, // 80 x 30  corner/utility buttons
    UI_BTN_SIZE_MED,   // 160 x 44 confirm/back buttons
    UI_BTN_SIZE_LARGE, // 200 x 44 primary navigation buttons
    UI_BTN_SIZE_WIDE,  // 180 x 44 side-by-side action buttons
    UI_BTN_SIZE_HERO,  // 240 x 56 hero call-to-action
} ui_btn_size_t;

lv_obj_t* ui_make_screen(void);
lv_obj_t* ui_add_title(lv_obj_t* parent, const char* text);
void      ui_btn_invoke(lv_event_t* e);
void      ui_swap_screen(lv_obj_t* new_scr);

/**
 * Scale a pixel value laid out against the 480x320 reference resolution to
 * the active display.  The scale is uniform (limited by the shorter axis) so
 * screens keep their proportions and fit on any panel.
 */
lv_coord_t ui_scale(lv_coord_t n);

/**
 * Pick the best bundled Montserrat font for a reference pixel size on the
 * active display (never smaller than 10 px).
 */
const lv_font_t* ui_font(uint8_t px);

/**
 * True when the active display is a small (embedded) panel, e.g. the TTGO
 * T-Display's 240x135.  Used to switch layouts (fewer columns, arrow
 * controls) that only make sense when space is tight.
 */
bool ui_small_screen(void);

/**
 * Create an up/down arrow button pair that scrolls @p target vertically by
 * @p step pixels per press.  Returns the container holding both buttons; the
 * caller positions it (typically lv_obj_align_to(... LV_ALIGN_OUT_RIGHT_MID
 * ...)).  @p target must have vertical scrolling enabled.
 */
lv_obj_t* ui_add_scroll_arrows(lv_obj_t* parent, lv_obj_t* target, lv_coord_t step);

/**
 * Rebuild the shared navigation group from the focusable widgets on @p scr
 * and focus the first one.  No-op when no navigation input device has been
 * attached (e.g. on desktop builds).
 */
void ui_nav_build(lv_obj_t* scr);

/**
 * Add a focusable widget to the shared navigation group without rebuilding
 * the whole screen.  No-op when no navigation input
 * device has been attached.
 */
void ui_nav_add_obj(lv_obj_t* obj);

/** Create a button with a plain void(void) callback. */
lv_obj_t* ui_add_btn(lv_obj_t* parent, const char* text, ui_cb_t cb, ui_btn_size_t size,
                     lv_align_t align, lv_coord_t x_ofs, lv_coord_t y_ofs);

/** Create a button with an LVGL event callback (and optional user_data). */
lv_obj_t* ui_add_btn_evt(lv_obj_t* parent, const char* text, lv_event_cb_t evt_cb, void* user_data,
                         ui_btn_size_t size, lv_align_t align, lv_coord_t x_ofs, lv_coord_t y_ofs);

#ifdef __cplusplus
}
#endif

#endif /* UI_INTERNAL_H */

/**
 * @file main/ui/ui.h
 * @brief UI screens for the mnemonic wallet tool.
 */

#ifndef UI_H
#define UI_H

#include "lvgl.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void (*ui_cb_t)(void);
typedef void (*ui_tap_cb_t)(lv_coord_t x, lv_coord_t y);
typedef void (*ui_uint_cb_t)(uint8_t value);
typedef void (*ui_word_cb_t)(const char* word);

#define UI_COLOR_SEED_GREEN 0xA6CF5E // light green
#define UI_COLOR_MIX_GREEN 0x305C2B  // dark green

typedef enum {
    MNEMONIC_TYPE_GENERATED,
    MNEMONIC_TYPE_ENTERED,
    MNEMONIC_TYPE_MERGED,
    MNEMONIC_TYPE_FINAL,
} mnemonic_type_t;

void ui_show_main(lv_event_cb_t on_new_wallet, lv_event_cb_t on_test_error);
void ui_show_word_count(ui_cb_t on_12, ui_cb_t on_24);
void ui_show_source(ui_cb_t on_generate, ui_cb_t on_enter, ui_cb_t on_other_source,
                    ui_cb_t on_state, ui_cb_t on_finish, bool is_additional);
void ui_show_other_source(ui_cb_t on_camera, ui_cb_t on_scan_qr, ui_cb_t on_dice, ui_cb_t on_coins,
                          ui_cb_t on_touch, ui_cb_t on_back);
void ui_show_camera_feed(ui_cb_t on_use, ui_cb_t on_cancel);
void ui_camera_feed_update(const uint8_t* rgb565, uint32_t w, uint32_t h);
void ui_show_seedqr(const uint8_t* cells, uint32_t size, ui_cb_t on_done);
void ui_seedqr_cleanup(void);
void ui_show_qr_scan(ui_cb_t on_scan, ui_cb_t on_cancel);
void ui_show_touch_screen(ui_tap_cb_t on_tap, ui_cb_t on_cancel);
void ui_touch_screen_set_status(const char* text);
void ui_show_dice_sides(ui_uint_cb_t on_sides, ui_cb_t on_back);
void ui_show_dice(unsigned sides, ui_uint_cb_t on_roll, ui_cb_t on_cancel);
void ui_dice_set_status(const char* text);
void ui_show_coin(ui_uint_cb_t on_flip, ui_cb_t on_cancel);
void ui_coin_set_status(const char* text);

/** @deprecated Use ui_word_entry_begin from word_entry.h instead. */
void        ui_show_enter_words(ui_cb_t on_ok);
const char* ui_get_entered_words(void);

void ui_show_mnemonic(const char* words, mnemonic_type_t type, ui_cb_t on_ok, ui_cb_t on_export);
void ui_show_merge_process(const char* current_words, const char* current_entropy_hex,
                           const char* new_entropy_hex, const char* merged_entropy_hex,
                           const char* merged_words, ui_cb_t on_ok);
void ui_show_msg(const char* msg);
void ui_show_mnemonic_error(ui_cb_t on_cancel, ui_cb_t on_retry, ui_cb_t on_choose);
void ui_show_word_picker(const char* title, const char* const* words, size_t count,
                         ui_word_cb_t on_select, ui_cb_t on_back);
void ui_delay_ms(uint32_t ms);
void ui_go_main(void);

/**
 * @brief Attach a keypad/encoder input device for button navigation.
 *
 * Creates the shared navigation group and routes the input device to it.
 * Call once after lv_init() and before the first screen is shown.  The group
 * is rebuilt automatically every time a screen is swapped in, collecting the
 * screen's focusable widgets (buttons, textareas, keyboards and clickable
 * labels).
 */
void ui_nav_set_indev(lv_indev_t* indev);

/**
 * @brief Show a brief startup splash screen, then call @p on_done.
 *
 * The splash is shown for a fixed delay and then automatically transitions
 * to @p on_done (typically the main screen).
 */
void ui_show_splash(ui_cb_t on_done);

/**
 * @brief Zero all label text on @p scr (recursively) without deleting it.
 *
 * lv_label_set_text() copies strings into LVGL heap memory.  Call this on a
 * screen that displayed secrets (mnemonic words, entropy hex) as soon as it
 * is no longer shown, so the copies don't linger until deferred deletion.
 */
void ui_scrub_screen(lv_obj_t* scr);

#ifdef __cplusplus
}
#endif

#endif /* UI_H */

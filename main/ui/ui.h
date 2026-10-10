/**
 * @file main/ui/ui.h
 * @brief UI screens for the mnemonic wallet tool.
 */

#ifndef UI_H
#define UI_H

#include "lvgl.h"
#include "mnemonic_view.h"

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

void ui_show_main(lv_event_cb_t on_new_wallet, lv_event_cb_t on_inspect_tx,
                  lv_event_cb_t on_test_error);
void ui_show_word_count(ui_cb_t on_12, ui_cb_t on_24);
void ui_show_source(ui_cb_t on_generate, ui_cb_t on_enter, ui_cb_t on_other_source,
                    ui_cb_t on_state, ui_cb_t on_finish, bool is_additional);
void ui_show_other_source(ui_cb_t on_camera, ui_cb_t on_scan_qr, ui_cb_t on_dice, ui_cb_t on_coins,
                          ui_cb_t on_touch, ui_cb_t on_back);
/**
 * @brief Show the live camera feed screen.
 *
 * The frame is shown on the left and, on the right, how far each pixel stands out
 * from the ones beside and below it - the grain and detail the seed is made of -
 * with the frame count, the bytes seen and the share of the frame carrying that
 * detail below it.
 * @p on_help may be NULL, which leaves the Help button out.
 */
void ui_show_camera_feed(ui_cb_t on_use, ui_cb_t on_cancel, ui_cb_t on_help);
void ui_camera_feed_update(const uint8_t* rgb565, uint32_t w, uint32_t h);
/** @brief Feed the frame count and byte total into the feed screen's stats line. */
void ui_camera_feed_stats(unsigned frames, uint64_t bytes);
/** @brief Show how the camera's frames become the seed (help screen). */
void ui_show_camera_help(ui_cb_t on_close);
void ui_show_seedqr(const uint8_t* cells, uint32_t size, ui_cb_t on_done);
void ui_seedqr_cleanup(void);
void ui_show_qr_scan_auto(ui_cb_t on_cancel, const char* title, ui_cb_t on_open_file);
void ui_qr_scan_progress(size_t received, size_t expected);
void ui_show_tx_inspect(const char* title, const char* body, const char* warning, ui_cb_t on_done);

/**
 * @brief Show a scrollable overview of a scanned wallet descriptor.
 *
 * Shown between scanning the descriptor and using it, so a wrong wallet can be
 * spotted while scanning another one is still cheap. The body is one long
 * scrollable text block (see descriptor_overview()), so a descriptor that does
 * not fit on screen can still be read in full.  @p on_continue accepts the
 * descriptor, @p on_cancel discards it.
 */
void ui_show_descriptor_overview(const char* title, const char* body, ui_cb_t on_continue,
                                 ui_cb_t on_cancel);
/**
 * @brief Show the touch collection screen.
 *
 * The screen is read as an 8x8 grid of tiles and each tap writes its tile's
 * number as whole bits, so the screen shows real bits rather than an estimate.
 * They are hashed into the seed when @p target_bits are reached, and the seed is
 * then shown beside them until @p on_continue is pressed.  @p on_help may be
 * NULL to leave the Help button off.
 */
void ui_show_touch_screen(ui_tap_cb_t on_tap, ui_cb_t on_cancel, ui_cb_t on_help,
                          ui_cb_t on_continue, uint32_t target_bits);

/**
 * @brief Show how far the taps have got.
 *
 * @p bytes holds the tapped bits (MSB-first) of which @p bits are collected,
 * @p target_bits is the target, @p taps the count and @p last_tile the tile the
 * newest tap landed in (0..63).
 */
void ui_touch_screen_set_progress(const uint8_t* bytes, uint32_t bits, uint32_t target_bits,
                                  unsigned taps, unsigned last_tile);

/** @brief Show the finished seed beside the tapped bits, and a Continue button. */
void ui_touch_screen_show_seed(const uint8_t* seed, size_t seed_len);

/** @brief Show the "taps to bits" help screen. */
void ui_show_touch_help(ui_cb_t on_close);
void ui_show_dice_sides(ui_uint_cb_t on_sides, ui_cb_t on_back);
/**
 * @brief Show the dice collection screen.
 *
 * @p total_bits is the target (128 or 256); the bit grid is sized to it and
 * fills in as rolls arrive. The screen also shows what a roll of @p sides is
 * worth on average and how many rolls are roughly left.
 */
void ui_show_dice(unsigned sides, uint32_t total_bits, ui_uint_cb_t on_roll, ui_cb_t on_help,
                  ui_cb_t on_cancel);

/**
 * @brief Update the dice collection: bit grid, counts and readout.
 *
 * @p bytes holds the collected entropy (MSB-first), of which @p filled_bits are
 * known; @p last_roll / @p last_bits describe the newest roll, whose bits are
 * highlighted in the grid. Bits are never held back: what a roll is worth is in
 * the seed straight away.
 */
void ui_dice_set_progress(const uint8_t* bytes, unsigned count, uint32_t filled_bits,
                          uint32_t needed, unsigned last_roll, uint32_t last_bits);

/** @brief Coin flavour of ui_show_dice(). */
void ui_show_coin(uint32_t total_bits, ui_uint_cb_t on_flip, ui_cb_t on_help, ui_cb_t on_cancel);

/**
 * @brief Show how a roll becomes bits, with diagrams.
 *
 * Reached from the dice/coin screens' Help button.  @p on_close returns to the
 * screen that opened it - the caller re-renders its progress, since this screen
 * owns the widgets in between.
 */
void ui_show_roll_help(ui_cb_t on_close);

/** @brief Coin flavour of ui_dice_set_progress(). */
void ui_coin_set_progress(const uint8_t* bytes, unsigned count, uint32_t filled_bits,
                          uint32_t needed, unsigned last_roll, uint32_t last_bits);

/** @deprecated Use ui_word_entry_begin from word_entry.h instead. */
void        ui_show_enter_words(ui_cb_t on_ok);
const char* ui_get_entered_words(void);

void ui_show_mnemonic(const char* words, mnemonic_type_t type, ui_cb_t on_ok, ui_cb_t on_export,
                      ui_cb_t on_help, const mnemonic_bits_t* bits);
/**
 * @brief Explain how the words are cut out of the entropy, eleven bits at a time.
 *
 * An example and the rule, not the mnemonic's own bits: the word boxes already
 * show those.
 */
void ui_show_words_help(ui_cb_t on_close);

/**
 * @brief Show the entropy merge in progress: the two input entropies, the XOR
 *        result and the animated bit view. The mnemonic words are only shown
 *        on the screen that follows Ok (the final stage).
 */
void ui_show_merge_process(const char* current_entropy_hex, const char* new_entropy_hex,
                           const char* merged_entropy_hex, ui_cb_t on_ok);

/**
 * @brief Show a working seed as raw entropy: the hex value and the animated
 *        bit view. Used for the generated / entered / merged stages; the
 *        mnemonic words are only shown on the final stage.
 */
void ui_show_entropy(const char* entropy_hex, mnemonic_type_t type, ui_cb_t on_ok);
void ui_show_msg(const char* msg);

/**
 * @brief Show a two-button confirmation screen.
 *
 * @p on_yes / @p on_no are called when the corresponding button is pressed.
 * This is used for the "scan a wallet descriptor first?" prompt that precedes
 * transaction/PSBT scanning.
 */
void ui_show_confirm(const char* title, const char* msg, const char* yes_label,
                     const char* no_label, ui_cb_t on_yes, ui_cb_t on_no);

/**
 * @brief Show a vertical list of mutually exclusive choices.
 *
 * @p options holds @p count NUL-terminated button labels.  @p on_choice is
 * called with the index of the selected option and @p on_cancel (optional)
 * when Cancel is pressed. The list scrolls when the options don't fit.
 */
void ui_show_choice(const char* title, const char* msg, const char* const* options, size_t count,
                    ui_uint_cb_t on_choice, ui_cb_t on_cancel);
void ui_show_mnemonic_error(ui_cb_t on_cancel, ui_cb_t on_retry, ui_cb_t on_choose);
void ui_show_word_picker(const char* title, const char* const* words, size_t count,
                         ui_word_cb_t on_select, ui_cb_t on_back);
void ui_delay_ms(uint32_t ms);
void ui_go_main(void);

/**
 * @brief Attach a keypad/encoder input device for button navigation.
 *
 * Creates the shared navigation group and routes the input device to it.
 * Call once after lv_init() and before the first screen is shown. The group
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
 * lv_label_set_text() copies strings into LVGL heap memory. Call this on a
 * screen that displayed secrets (mnemonic words, entropy hex) as soon as it
 * is no longer shown, so the copies don't linger until deferred deletion.
 */
void ui_scrub_screen(lv_obj_t* scr);

#ifdef __cplusplus
}
#endif

#endif /* UI_H */

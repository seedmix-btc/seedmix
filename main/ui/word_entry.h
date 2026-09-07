/**
 * @file main/ui/word_entry.h
 * @brief Guided BIP39 word entry with autocomplete keyboard.
 */

#ifndef WORD_ENTRY_H
#define WORD_ENTRY_H

#include "lvgl.h"
#include "ui.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque handle returned by ui_word_entry_begin. */
typedef void* word_entry_handle_t;

/** Begin guided multi-word entry. `on_done` called when all words entered, `on_cancel` when back pressed on first word. */
word_entry_handle_t ui_word_entry_begin(unsigned total_words, ui_cb_t on_done, ui_cb_t on_cancel);

/**
 * Resume entry with `words_done` words already entered (stored in
 * `result_so_far`, space-separated, no trailing space).  Entry continues at
 * word `words_done + 1`.
 */
word_entry_handle_t ui_word_entry_resume(unsigned total_words, unsigned words_done,
                                         const char* result_so_far, ui_cb_t on_done,
                                         ui_cb_t on_cancel);

/**
 * Like ui_word_entry_resume, but restrict autocomplete to `filter_words`
 * (the full BIP39 word list is ignored while the filter is active).
 */
word_entry_handle_t ui_word_entry_resume_filtered(unsigned total_words, unsigned words_done,
                                                  const char*        result_so_far,
                                                  const char* const* filter_words,
                                                  size_t filter_count, ui_cb_t on_done,
                                                  ui_cb_t on_cancel);

/** Advance to next word. Returns true if all words entered. */
bool ui_word_entry_next(word_entry_handle_t handle);

/** Get the completed mnemonic string after all words are entered. */
const char* ui_word_entry_result(word_entry_handle_t handle);

/** Discard the word entry and free all resources (user cancelled/backed out). */
void ui_word_entry_discard(word_entry_handle_t handle);

#ifdef __cplusplus
}
#endif

#endif /* WORD_ENTRY_H */

/**
 * @file main/ui/word_entry.c
 * @brief Guided BIP39 word entry with autocomplete keyboard.
 */

#include "word_entry.h"
#include "crypto/bip39_wordlist.h"
#include "ui_internal.h"
#include "util/error.h"
#include "util/utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* -- State ------------------------------------------------------------ */
typedef struct {
    unsigned  total;
    unsigned  current;
    char      result[512];
    char      prefix[32];
    lv_obj_t* match_container;
    lv_obj_t* status;
    lv_obj_t* ta;           // display-only textarea (keyboard target)
    lv_obj_t* key_btns[27]; // 26 letter keys + backspace
    lv_obj_t* entry_screen; // word entry screen (for returning from confirm)
    ui_cb_t   on_done;
    ui_cb_t   on_cancel;
    char      selected[32];

    /* Optional restricted word set for autocomplete (NULL = full BIP39 list). */
    const char* const* filter;
    size_t             filter_count;
} we_ctx_t;

static void we_update_status(we_ctx_t* c) {
    char buf[32];
    int  res = snprintf(buf, sizeof(buf), "Word %u of %u", c->current + 1, c->total);
    ASSERT_OR_DIE(res > 0 && (size_t)res < sizeof(buf), "status string too long");
    if (c->status) lv_label_set_text(c->status, buf);
}

/* -- Forward declarations --------------------------------------------- */
static void we_go_back(lv_event_t* e);
static void we_select_word(lv_event_t* e);
static void we_key_cb(lv_event_t* e);
static void we_confirm(lv_event_t* e);
static void we_cancel_confirm(lv_event_t* e);

/* QWERTY keyboard layout (index i in key_btns[] maps to this letter). */
static const char* KEY_LAYOUT = "qwertyuiopasdfghjklzxcvbnm";

/* -- Refresh match list ----------------------------------------------- */
/* Look up words matching `prefix`, restricted to the candidate filter when
 * one is active.  An empty prefix lists the first candidates up to the limit. */
static size_t we_lookup(const we_ctx_t* c, const char* prefix, const char** matches) {
    if (!c->filter) return bip39_wordlist_lookup(prefix, matches);

    size_t plen  = strlen(prefix);
    size_t count = 0;
    for (size_t i = 0; i < c->filter_count && count < BIP39_MAX_MATCHES; i++) {
        if (plen == 0 || strncasecmp(c->filter[i], prefix, plen) == 0) {
            matches[count++] = c->filter[i];
        }
    }
    return count;
}

static void we_refresh_matches(we_ctx_t* c) {
    if (!c->match_container) return;
    lv_obj_clean(c->match_container);
    c->selected[0] = '\0';

    const char* match_buf[2048];
    size_t      n = we_lookup(c, c->prefix, match_buf);
    for (size_t i = 0; i < n; i++) {
        lv_obj_t* lbl = lv_label_create(c->match_container);
        lv_label_set_text(lbl, match_buf[i]);
        lv_obj_set_style_text_color(lbl, lv_color_white(), 0);
        lv_obj_set_style_text_font(lbl, ui_font(14), 0);
        lv_obj_set_style_bg_color(lbl, lv_color_hex(0x333333), 0);
        lv_obj_set_style_bg_opa(lbl, LV_OPA_COVER, 0);
        lv_obj_set_style_radius(lbl, 4, 0);
        lv_obj_set_style_pad_hor(lbl, 8, 0);
        lv_obj_set_style_pad_ver(lbl, 4, 0);
        lv_obj_set_style_bg_color(lbl, lv_color_hex(0x1E88E5), LV_STATE_FOCUSED);
        lv_obj_add_flag(lbl, LV_OBJ_FLAG_CLICKABLE);
        lv_obj_add_flag(lbl, LV_OBJ_FLAG_SCROLL_ON_FOCUS);
        lv_obj_remove_flag(lbl, LV_OBJ_FLAG_SCROLLABLE);
        lv_obj_add_event_cb(lbl, we_select_word, LV_EVENT_CLICKED, c);
        ui_nav_add_obj(lbl);
    }

    if (!c->key_btns[0]) return;
    char test[sizeof(c->prefix) + 2]; // prefix + 1 char + null
    for (int i = 0; i < 26; i++) {
        int res = snprintf(test, sizeof(test), "%s%c", c->prefix, KEY_LAYOUT[i]);
        ASSERT_OR_DIE(res > 0 && (size_t)res < sizeof(test), "test string too long");
        if (we_lookup(c, test, match_buf) > 0) {
            lv_obj_clear_state(c->key_btns[i], LV_STATE_DISABLED);
        } else {
            lv_obj_add_state(c->key_btns[i], LV_STATE_DISABLED);
        }
    }
}

/* -- Event handlers --------------------------------------------------- */
static void we_key_cb(lv_event_t* e) {
    we_ctx_t* c = lv_event_get_user_data(e);
    ASSERT_OR_DIE(c, "null context");

    lv_obj_t*   lbl  = lv_obj_get_child(lv_event_get_target(e), 0);
    const char* text = lbl ? lv_label_get_text(lbl) : NULL;
    if (!text || !*text) return;

    if (strcmp(text, LV_SYMBOL_BACKSPACE) == 0) {
        size_t len = strlen(c->prefix);
        if (len > 0) c->prefix[len - 1] = '\0';
    } else {
        size_t len = strlen(c->prefix);
        if (len + 1 < sizeof(c->prefix)) {
            c->prefix[len]     = text[0];
            c->prefix[len + 1] = '\0';
        }
    }
    c->selected[0] = '\0';

    if (c->ta) lv_textarea_set_text(c->ta, c->prefix);
    we_refresh_matches(c);
}

static void we_select_word(lv_event_t* e) {
    we_ctx_t* c = lv_event_get_user_data(e);
    ASSERT_OR_DIE(c, "null context");
    const char* word = lv_label_get_text(lv_event_get_target(e));
    if (word && *word) {
        strncpy(c->selected, word, sizeof(c->selected) - 1);
        // show confirm screen
        lv_obj_t* s     = ui_make_screen();
        lv_obj_t* title = lv_label_create(s);
        lv_label_set_text(title, "Confirm Word");
        lv_obj_set_style_text_color(title, lv_color_white(), 0);
        lv_obj_set_style_text_font(title, ui_font(28), 0);
        lv_obj_align(title, LV_ALIGN_TOP_MID, 0, ui_scale(15));

        lv_obj_t* w = lv_label_create(s);
        lv_label_set_text(w, word);
        lv_obj_set_style_text_color(w, lv_color_white(), 0);
        lv_obj_set_style_text_font(w, ui_font(48), 0);
        lv_obj_align(w, LV_ALIGN_CENTER, 0, ui_scale(-10));

        ui_add_btn_evt(s, "Yes", we_confirm, c, UI_BTN_SIZE_MED, LV_ALIGN_CENTER, -90, 60);

        ui_add_btn_evt(s, "No", we_cancel_confirm, c, UI_BTN_SIZE_MED, LV_ALIGN_CENTER, 90, 60);

        ui_nav_build(s);
        lv_scr_load(s);
    }
}

static void we_confirm(lv_event_t* e) {
    we_ctx_t* c = lv_event_get_user_data(e);
    ASSERT_OR_DIE(c, "null context");
    lv_obj_t* confirm_screen = lv_obj_get_parent(lv_event_get_target(e));
    if (!c->selected[0]) return;
    strncpy(c->prefix, c->selected, sizeof(c->prefix) - 1);
    c->selected[0] = '\0';
    ui_word_entry_next(c); // loads entry_screen first
    lv_obj_delete(confirm_screen);
}

static void we_cancel_confirm(lv_event_t* e) {
    we_ctx_t* c = lv_event_get_user_data(e);
    ASSERT_OR_DIE(c, "null context");
    lv_obj_t* confirm_screen = lv_obj_get_parent(lv_event_get_target(e));
    c->selected[0]           = '\0';
    if (c->entry_screen) {
        ui_nav_build(c->entry_screen);
        lv_scr_load(c->entry_screen); // load first
    }
    lv_obj_delete(confirm_screen); // then delete old
}

/* -- Public API ------------------------------------------------------- */
static word_entry_handle_t we_begin(unsigned total_words, unsigned words_done,
                                    const char* result_so_far, const char* const* filter_words,
                                    size_t filter_count, ui_cb_t on_done, ui_cb_t on_cancel) {
    ASSERT_OR_DIE(total_words > 0 && total_words <= 24, "total_words must be between 1 and 24");
    ASSERT_OR_DIE(words_done < total_words, "words_done must be less than total_words");
    ASSERT_OR_DIE(result_so_far, "result_so_far is required");
    ASSERT_OR_DIE(on_done, "on_done callback is required");
    ASSERT_OR_DIE(on_cancel, "on_cancel callback is required");

    bip39_wordlist_init();
    we_ctx_t* c = calloc(1, sizeof(*c));
    ASSERT_OR_DIE(c, "out of memory");
    c->total        = total_words;
    c->current      = words_done;
    c->filter       = filter_words;
    c->filter_count = filter_count;
    c->on_done      = on_done;
    c->on_cancel    = on_cancel;
    strncpy(c->result, result_so_far, sizeof(c->result) - 1);
    c->result[sizeof(c->result) - 1] = '\0';

    lv_obj_t* s     = ui_make_screen();
    c->entry_screen = s;

    c->status = lv_label_create(s);
    lv_obj_set_style_text_color(c->status, lv_color_white(), 0);
    lv_obj_set_style_text_font(c->status, ui_font(20), 0);
    lv_obj_align(c->status, LV_ALIGN_TOP_MID, 0, ui_scale(5));

    lv_obj_t* ta = lv_textarea_create(s);
    lv_obj_set_size(ta, ui_scale(300), ui_scale(60));
    lv_obj_align(ta, LV_ALIGN_TOP_MID, 0, ui_scale(30));
    lv_obj_set_style_text_font(ta, ui_font(24), 0);
    if (ui_small_screen()) {
        lv_obj_set_style_text_font(ta, ui_font(14), 0);
    }
    lv_obj_set_style_bg_color(ta, lv_color_hex(0x222222), 0);
    lv_obj_set_style_text_color(ta, lv_color_white(), 0);
    lv_textarea_set_placeholder_text(ta, "Type to filter...");
    if (ui_small_screen()) {
        lv_obj_set_style_pad_all(ta, 4, 0);
    }
    // The textarea is only a display target for the on-screen keyboard, keep
    // it out of the keypad navigation group so ENTER doesn't trap focus in
    // textarea edit mode.  The keyboard becomes the initial focus
    lv_obj_clear_flag(ta, LV_OBJ_FLAG_CLICK_FOCUSABLE);
    c->ta = ta;
    we_update_status(c);

    c->match_container = lv_obj_create(s);
    lv_obj_set_size(c->match_container, ui_scale(460), ui_scale(50));
    lv_obj_align(c->match_container, LV_ALIGN_TOP_MID, 0, ui_scale(98));
    lv_obj_set_style_bg_color(c->match_container, lv_color_hex(0x111111), 0);
    lv_obj_set_style_border_width(c->match_container, 0, 0);
    lv_obj_set_flex_flow(c->match_container, LV_FLEX_FLOW_ROW);
    lv_obj_set_flex_align(c->match_container, LV_FLEX_ALIGN_START, LV_FLEX_ALIGN_CENTER,
                          LV_FLEX_ALIGN_CENTER);
    lv_obj_set_scroll_dir(c->match_container, LV_DIR_HOR);
    if (ui_small_screen()) {
        lv_obj_set_style_pad_all(c->match_container, 2, 0);
    }

    // On-screen keyboard made of individual keys, so each key is a focusable
    // object in the navigation group and can be selected directly with the
    // two-button input (no separate edit mode).
    lv_obj_t* kb = lv_obj_create(s);
    lv_obj_set_size(kb, ui_scale(460), ui_scale(152));
    lv_obj_align(kb, LV_ALIGN_BOTTOM_MID, 0, 0);
    lv_obj_set_style_bg_color(kb, lv_color_black(), 0);
    lv_obj_set_style_border_width(kb, 0, 0);
    lv_obj_set_style_pad_all(kb, 0, 0);
    lv_obj_set_flex_flow(kb, LV_FLEX_FLOW_COLUMN);
    lv_obj_set_flex_align(kb, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER);
    lv_obj_set_style_pad_row(kb, 0, 0);

    // Three QWERTY rows: q-p, a-l, then z-m with the backspace key at the end
    static const struct {
        int start;
        int count;
    } rows[] = {
        {0, 10}, // q w e r t y u i o p
        {10, 9}, // a s d f g h j k l
        {19, 7}, // z x c v b n m
    };

    for (int r = 0; r < 3; r++) {
        lv_obj_t* row = lv_obj_create(kb);
        lv_obj_set_size(row, LV_SIZE_CONTENT, LV_SIZE_CONTENT);
        lv_obj_set_style_bg_color(row, lv_color_black(), 0);
        lv_obj_set_style_border_width(row, 0, 0);
        lv_obj_set_style_pad_all(row, 0, 0);
        lv_obj_set_style_pad_hor(row, ui_scale(6), 0);
        lv_obj_set_style_pad_ver(row, ui_scale(6), 0);
        lv_obj_set_flex_flow(row, LV_FLEX_FLOW_ROW);
        lv_obj_set_flex_align(row, LV_FLEX_ALIGN_CENTER, LV_FLEX_ALIGN_CENTER,
                              LV_FLEX_ALIGN_CENTER);
        lv_obj_set_style_pad_column(row, ui_scale(6), 0);

        for (int j = 0; j < rows[r].count; j++) {
            int       i         = rows[r].start + j;
            char      letter[2] = {KEY_LAYOUT[i], '\0'};
            lv_obj_t* b         = lv_button_create(row);
            lv_obj_set_size(b, ui_scale(36), ui_scale(36));
            lv_obj_add_event_cb(b, we_key_cb, LV_EVENT_CLICKED, c);
            lv_obj_t* l = lv_label_create(b);
            lv_label_set_text(l, letter);
            lv_obj_set_style_text_font(l, ui_font(16), 0);
            lv_obj_center(l);
            c->key_btns[i] = b;
        }

        if (r == 2) {
            // Backspace key at the end of the last row
            lv_obj_t* bs = lv_button_create(row);
            lv_obj_set_size(bs, ui_scale(36), ui_scale(36));
            lv_obj_add_event_cb(bs, we_key_cb, LV_EVENT_CLICKED, c);
            lv_obj_t* bsl = lv_label_create(bs);
            lv_label_set_text(bsl, LV_SYMBOL_BACKSPACE);
            lv_obj_set_style_text_font(bsl, ui_font(16), 0);
            lv_obj_center(bsl);
            c->key_btns[26] = bs;
        }
    }

    ui_add_btn_evt(s, "Back", we_go_back, c, UI_BTN_SIZE_SMALL, LV_ALIGN_TOP_RIGHT, -10, 5);

    we_refresh_matches(c);

    ui_nav_build(s);
    lv_scr_load(s);
    return c;
}

word_entry_handle_t ui_word_entry_begin(unsigned total_words, ui_cb_t on_done, ui_cb_t on_cancel) {
    return we_begin(total_words, 0, "", NULL, 0, on_done, on_cancel);
}

word_entry_handle_t ui_word_entry_resume(unsigned total_words, unsigned words_done,
                                         const char* result_so_far, ui_cb_t on_done,
                                         ui_cb_t on_cancel) {
    return we_begin(total_words, words_done, result_so_far, NULL, 0, on_done, on_cancel);
}

word_entry_handle_t ui_word_entry_resume_filtered(unsigned total_words, unsigned words_done,
                                                  const char*        result_so_far,
                                                  const char* const* filter_words,
                                                  size_t filter_count, ui_cb_t on_done,
                                                  ui_cb_t on_cancel) {
    return we_begin(total_words, words_done, result_so_far, filter_words, filter_count, on_done,
                    on_cancel);
}

bool ui_word_entry_next(word_entry_handle_t handle) {
    we_ctx_t* c = (we_ctx_t*)handle;
    ASSERT_OR_DIE(c, "null context");
    const char* matches[2048];
    size_t      n    = we_lookup(c, c->prefix, matches);
    const char* word = (n > 0) ? matches[0] : c->prefix;
    if (!word[0]) return false;

    if (c->current > 0) strcat(c->result, " ");
    strcat(c->result, word);
    c->current++;
    c->prefix[0]   = '\0';
    c->selected[0] = '\0';

    if (c->ta) lv_textarea_set_text(c->ta, "");

    if (c->current >= c->total) {
        c->on_done();
        return true;
    }

    we_update_status(c);
    we_refresh_matches(c);
    if (c->entry_screen) {
        ui_nav_build(c->entry_screen);
        lv_scr_load(c->entry_screen);
    }
    return false;
}

static void we_go_back(lv_event_t* e) {
    we_ctx_t* c = lv_event_get_user_data(e);
    ASSERT_OR_DIE(c, "null context");
    if (c->current == 0) {
        c->on_cancel();
        return;
    }
    char* last = strrchr(c->result, ' ');
    if (last) {
        secure_memzero(last, strlen(last) + 1);
    } else {
        secure_memzero(c->result, strlen(c->result) + 1);
    }
    c->current--;
    c->prefix[0] = '\0';

    if (c->ta) lv_textarea_set_text(c->ta, "");

    we_update_status(c);
    we_refresh_matches(c);
    if (c->entry_screen) ui_nav_build(c->entry_screen);
}

const char* ui_word_entry_result(word_entry_handle_t handle) {
    we_ctx_t* c = (we_ctx_t*)handle;
    ASSERT_OR_DIE(c, "null context");
    return c->result;
}

static void delete_screen_async(void* ptr) { lv_obj_delete((lv_obj_t*)ptr); }

void ui_word_entry_discard(word_entry_handle_t handle) {
    we_ctx_t* c = (we_ctx_t*)handle;
    ASSERT_OR_DIE(c, "null context");
    if (c->entry_screen) lv_async_call(delete_screen_async, c->entry_screen);
    secure_memzero(c, sizeof(*c));
    free(c);
}

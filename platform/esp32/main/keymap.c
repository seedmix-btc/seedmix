/**
 * @file keymap.c
 * @brief Translation layer: physical buttons -> logical LVGL keys.
 *
 * The hardware layer (buttons.c) only reports raw button state.  This layer
 * debounces each button, then debounces the button combination so a slightly
 * staggered two-button press still registers as ENTER, and maps combinations
 * to logical LVGL navigation keys:
 *
 *   button 0 alone       -> LV_KEY_LEFT  (previous focusable item)
 *   button 1 alone       -> LV_KEY_RIGHT (next focusable item)
 *   button 0 + button 1  -> LV_KEY_ENTER (confirm / activate)
 */

#include "keymap.h"

#include "buttons.h"
#include "lvgl.h"
#include "sdkconfig.h"

#if CONFIG_SEEDMIX_BUTTONS_ENABLE

static lv_indev_t* s_indev    = NULL;
static lv_key_t    s_last_key = 0;

typedef struct {
    uint32_t last_raw;
    uint32_t stable_since;
    bool     state;
} debounce_t;

static debounce_t s_dbnc[CONFIG_SEEDMIX_BUTTONS_COUNT];

static bool debounced_pressed(int idx) {
    if (idx < 0 || idx >= CONFIG_SEEDMIX_BUTTONS_COUNT) {
        return false;
    }
    debounce_t* d   = &s_dbnc[idx];
    bool        raw = button_is_pressed(idx);
    uint32_t    now = lv_tick_get();

    if ((uint32_t)raw != d->last_raw) {
        d->last_raw     = (uint32_t)raw;
        d->stable_since = now;
    }
    if ((now - d->stable_since) >= (uint32_t)CONFIG_SEEDMIX_BUTTONS_DEBOUNCE_MS) {
        d->state = raw;
    }
    return d->state;
}

/* -- Two-stage debounce ------------------------------------------------
 * Each button is debounced individually (debounced_pressed), then the button
 * combination is debounced again so a slightly staggered two-button press is
 * recognised as ENTER instead of firing a stray PREV/NEXT first.
 *
 *   IDLE    -> ARMING  when one button goes down (start the combo window)
 *   ARMING  -> ENTER   when the second button joins within the window
 *   ARMING  -> SINGLE  when the window elapses with still one button
 *   SINGLE  -> ENTER   when the second button joins later
 *   ENTER   -> IDLE    only when every button is released (latched)
 */
typedef enum {
    KEYMAP_STATE_IDLE = 0,
    KEYMAP_STATE_ARMING,
    KEYMAP_STATE_SINGLE,
    KEYMAP_STATE_ENTER,
} keymap_state_t;

static keymap_state_t s_state     = KEYMAP_STATE_IDLE;
static lv_key_t       s_arm_key   = 0;
static uint32_t       s_arm_since = 0;

/* Map the current button combination to a single logical key (0 = none). */
static lv_key_t translate(void) {
    bool     b0  = debounced_pressed(0);
    bool     b1  = debounced_pressed(1);
    uint32_t now = lv_tick_get();

    switch (s_state) {
    case KEYMAP_STATE_IDLE:
        if (b0 && b1) {
            s_state = KEYMAP_STATE_ENTER;
            return LV_KEY_ENTER;
        }
        if (b0 || b1) {
            s_state     = KEYMAP_STATE_ARMING;
            s_arm_key   = b0 ? LV_KEY_LEFT : LV_KEY_RIGHT;
            s_arm_since = now;
        }
        return 0;

    case KEYMAP_STATE_ARMING:
        if (b0 && b1) {
            s_state = KEYMAP_STATE_ENTER;
            return LV_KEY_ENTER;
        }
        if (!b0 && !b1) {
            s_state = KEYMAP_STATE_IDLE;
            return 0;
        }
        {
            lv_key_t key = b0 ? LV_KEY_LEFT : LV_KEY_RIGHT;
            if (key != s_arm_key) {
                /* A different single button went down - re-arm. */
                s_arm_key   = key;
                s_arm_since = now;
                return 0;
            }
            if ((now - s_arm_since) >= (uint32_t)CONFIG_SEEDMIX_BUTTONS_COMBO_MS) {
                s_state = KEYMAP_STATE_SINGLE;
                return s_arm_key;
            }
        }
        return 0;

    case KEYMAP_STATE_SINGLE:
        if (b0 && b1) {
            s_state = KEYMAP_STATE_ENTER;
            return LV_KEY_ENTER;
        }
        if (!b0 && !b1) {
            s_state = KEYMAP_STATE_IDLE;
            return 0;
        }
        return (b0 ? LV_KEY_LEFT : LV_KEY_RIGHT);

    case KEYMAP_STATE_ENTER:
        /* Latch ENTER until all buttons are released so an early release of
         * one button cannot produce a stray LEFT/RIGHT afterwards. */
        if (!b0 && !b1) {
            s_state = KEYMAP_STATE_IDLE;
            return 0;
        }
        return LV_KEY_ENTER;

    default:
        s_state = KEYMAP_STATE_IDLE;
        return 0;
    }
}

static void keymap_read_cb(lv_indev_t* indev, lv_indev_data_t* data) {
    (void)indev;

    lv_key_t cur = translate();
    if (cur != 0) {
        s_last_key  = cur;
        data->state = LV_INDEV_STATE_PRESSED;
    } else {
        data->state = LV_INDEV_STATE_RELEASED;
    }
    data->key = s_last_key;
}

#endif /* CONFIG_SEEDMIX_BUTTONS_ENABLE */

void keymap_init(void) {
#if CONFIG_SEEDMIX_BUTTONS_ENABLE
    s_indev = lv_indev_create();
    lv_indev_set_type(s_indev, LV_INDEV_TYPE_ENCODER);
    lv_indev_set_read_cb(s_indev, keymap_read_cb);
#endif
}

lv_indev_t* keymap_get_indev(void) {
#if CONFIG_SEEDMIX_BUTTONS_ENABLE
    return s_indev;
#else
    return NULL;
#endif
}

lv_key_t keymap_current_key(void) {
#if CONFIG_SEEDMIX_BUTTONS_ENABLE
    return translate();
#else
    return 0;
#endif
}

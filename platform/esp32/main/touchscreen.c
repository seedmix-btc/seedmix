/**
 * @file touchscreen.c
 * @brief Capacitive touchscreen bring-up (see touchscreen.h).
 *
 * Coordinate handling deliberately delegates to esp_lcd_touch: the framework
 * applies `flags.swap_xy` / `flags.mirror_x` / `flags.mirror_y` in software
 * (the FT5x06 driver registers no hardware versions), mirroring around
 * `x_max` / `y_max` before swapping.  `x_max` / `y_max` must therefore be the
 * *controller-native* extents, which for an axis-aligned panel is always
 * min()/max() of the display dimensions - that holds for both the portrait
 * and the rotated (landscape) configuration.
 */

#include "touchscreen.h"

#include "display.h"
#include "driver/gpio.h"
#include "esp_check.h"
#include "esp_lcd_panel_io.h"
#if CONFIG_SEEDMIX_TOUCHSCREEN_ENABLE
#include "esp_lcd_touch.h"
#include "esp_lcd_touch_ft5x06.h"
#endif
#include "esp_log.h"
#include "i2c_bus.h"
#include "sdkconfig.h"

static const char* TAG = "touchscreen";

/* FT5x06/FT6x36 register for the touch detection threshold (G_THGROUP) */
#define TOUCH_REG_THGROUP 0x80

/* Kept outside the feature guard: the accessors below always reference them. */
static lv_indev_t* s_indev   = NULL;
static bool        s_present = false;

#if CONFIG_SEEDMIX_TOUCHSCREEN_ENABLE

static esp_lcd_touch_handle_t    s_touch    = NULL;
static esp_lcd_panel_io_handle_t s_touch_io = NULL;
static uint16_t                  s_last_x   = 0;
static uint16_t                  s_last_y   = 0;
static bool                      s_pressed  = false;

/* Coordinates as the controller reported them, captured before
 * esp_lcd_touch applies swap/mirror.  Read and written from the LVGL task
 * (the read callback and the debug screen timer), so no locking is needed. */
static uint16_t s_raw_x      = 0;
static uint16_t s_raw_y      = 0;
static uint8_t  s_raw_points = 0;

/* process_coordinates() hook: runs on every read, before the software
 * swap/mirror adjustment, which makes it the only place the untransformed
 * controller values are still visible. */
static void capture_raw_coordinates(esp_lcd_touch_handle_t tp, uint16_t* x, uint16_t* y,
                                    uint16_t* strength, uint8_t* point_num, uint8_t max_point_num) {
    (void)tp;
    (void)strength;
    (void)max_point_num;

    s_raw_points = *point_num;
    s_raw_x      = (*point_num > 0) ? x[0] : 0;
    s_raw_y      = (*point_num > 0) ? y[0] : 0;
}

/* -- LVGL pointer input ------------------------------------------------- */
static void touchscreen_read_cb(lv_indev_t* indev, lv_indev_data_t* data) {
    (void)indev;

    esp_lcd_touch_point_data_t point = {0};
    uint8_t                    count = 0;

    if (esp_lcd_touch_read_data(s_touch) == ESP_OK &&
        esp_lcd_touch_get_data(s_touch, &point, &count, 1) == ESP_OK && count > 0) {
        s_last_x  = point.x;
        s_last_y  = point.y;
        s_pressed = true;
    } else {
        s_pressed = false;
    }

    data->point.x = s_last_x;
    data->point.y = s_last_y;
    data->state   = s_pressed ? LV_INDEV_STATE_PRESSED : LV_INDEV_STATE_RELEASED;
}

#endif /* CONFIG_SEEDMIX_TOUCHSCREEN_ENABLE */

/* -- Init --------------------------------------------------------------- */
esp_err_t touchscreen_init(void) {
#if !CONFIG_SEEDMIX_TOUCHSCREEN_ENABLE
    ESP_LOGI(TAG, "touchscreen disabled in Kconfig");
    return ESP_OK;
#elif !defined(CONFIG_SEEDMIX_TOUCHSCREEN_DRIVER_FT5X06)
    ESP_LOGW(TAG, "touchscreen enabled but the selected controller has no driver");
    return ESP_ERR_NOT_SUPPORTED;
#else
    ESP_RETURN_ON_FALSE(CONFIG_SEEDMIX_I2C_ENABLE, ESP_ERR_INVALID_STATE, TAG,
                        "touchscreen requires the shared I2C bus (SEEDMIX_I2C_ENABLE)");

    i2c_master_bus_handle_t bus = i2c_bus_get();
    ESP_RETURN_ON_FALSE(bus, ESP_ERR_INVALID_STATE, TAG, "shared I2C bus not initialized");

    /* Panel IO over I2C: register address in the control phase, no D/C bit */
    esp_lcd_panel_io_i2c_config_t io_config = ESP_LCD_TOUCH_IO_I2C_FT5x06_CONFIG();
    io_config.dev_addr                      = CONFIG_SEEDMIX_TOUCHSCREEN_I2C_ADDR;
    io_config.scl_speed_hz                  = CONFIG_SEEDMIX_I2C_FREQ_HZ;
    ESP_RETURN_ON_ERROR(esp_lcd_new_panel_io_i2c(bus, &io_config, &s_touch_io), TAG,
                        "create touch panel IO failed");

    const uint16_t native_w =
        (DISPLAY_WIDTH < DISPLAY_HEIGHT) ? (uint16_t)DISPLAY_WIDTH : (uint16_t)DISPLAY_HEIGHT;
    const uint16_t native_h =
        (DISPLAY_WIDTH < DISPLAY_HEIGHT) ? (uint16_t)DISPLAY_HEIGHT : (uint16_t)DISPLAY_WIDTH;

    esp_lcd_touch_config_t tp_cfg = {
        .x_max = native_w,
        .y_max = native_h,
        /* Both pins are not routed to a GPIO on the Waveshare board */
        .rst_gpio_num = (gpio_num_t)CONFIG_SEEDMIX_TOUCHSCREEN_RST_GPIO,
        .int_gpio_num = (gpio_num_t)CONFIG_SEEDMIX_TOUCHSCREEN_IRQ_GPIO,
        .levels       = {.reset = 0, .interrupt = 0},
        .flags =
            {
                .swap_xy  = false,
                .mirror_x = false,
                .mirror_y = false,
            },
        .process_coordinates = capture_raw_coordinates,
    };
#if CONFIG_SEEDMIX_TOUCHSCREEN_SWAP_XY
    tp_cfg.flags.swap_xy  = true;
#endif
#if CONFIG_SEEDMIX_TOUCHSCREEN_INVERT_X
    tp_cfg.flags.mirror_x = true;
#endif
#if CONFIG_SEEDMIX_TOUCHSCREEN_INVERT_Y
    tp_cfg.flags.mirror_y = true;
#endif

    const esp_err_t err = esp_lcd_touch_new_i2c_ft5x06(s_touch_io, &tp_cfg, &s_touch);
    if (err != ESP_OK) {
        /* Keep the board usable through its buttons instead of aborting */
        ESP_LOGW(TAG, "touch controller not found (%s) - continuing without touch",
                 esp_err_to_name(err));
        s_touch = NULL;
        return ESP_ERR_NOT_FOUND;
    }

#if CONFIG_SEEDMIX_TOUCHSCREEN_THRESHOLD > 0
    /* Applied after the driver's init, which is where the 70 above is written */
    const uint8_t   threshold = (uint8_t)CONFIG_SEEDMIX_TOUCHSCREEN_THRESHOLD;
    const esp_err_t th_err =
        esp_lcd_panel_io_tx_param(s_touch_io, TOUCH_REG_THGROUP, &threshold, 1);
    if (th_err != ESP_OK) {
        ESP_LOGW(TAG, "could not set the touch threshold to %u: %s", (unsigned)threshold,
                 esp_err_to_name(th_err));
    }
#endif

    s_indev = lv_indev_create();
    ESP_RETURN_ON_FALSE(s_indev, ESP_ERR_NO_MEM, TAG, "lv_indev_create failed");
    lv_indev_set_type(s_indev, LV_INDEV_TYPE_POINTER);
    lv_indev_set_read_cb(s_indev, touchscreen_read_cb);
    lv_indev_set_display(s_indev, lv_display_get_default());

    lv_timer_t* read_timer = lv_indev_get_read_timer(s_indev);
    if (read_timer) {
        lv_timer_set_period(read_timer, CONFIG_SEEDMIX_TOUCHSCREEN_POLL_MS);
    }

    s_present = true;
    ESP_LOGI(TAG, "touch ready: %ux%u native, display %dx%d, swap_xy=%d mirror_x=%d mirror_y=%d",
             native_w, native_h, DISPLAY_WIDTH, DISPLAY_HEIGHT, tp_cfg.flags.swap_xy ? 1 : 0,
             tp_cfg.flags.mirror_x ? 1 : 0, tp_cfg.flags.mirror_y ? 1 : 0);
    ESP_LOGI(TAG, "polling every %d ms, threshold %d", CONFIG_SEEDMIX_TOUCHSCREEN_POLL_MS,
             CONFIG_SEEDMIX_TOUCHSCREEN_THRESHOLD);
    return ESP_OK;
#endif
}

lv_indev_t* touchscreen_get_indev(void) { return s_indev; }

bool touchscreen_is_present(void) { return s_present; }

void touchscreen_debug_get(touchscreen_debug_t* out) {
    if (!out) {
        return;
    }
#if CONFIG_SEEDMIX_TOUCHSCREEN_ENABLE
    out->present = s_present;
    out->pressed = s_pressed;
    out->points  = s_raw_points;
    out->raw_x   = s_raw_x;
    out->raw_y   = s_raw_y;
    out->x       = s_last_x;
    out->y       = s_last_y;
#else
    *out = (touchscreen_debug_t){.present = false};
#endif
}

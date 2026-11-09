/**
 * @file main_esp32.c
 * @brief ESP-IDF entry point for seedmix.
 *
 * Brings up LVGL with the configured display, touchscreen and physical
 * buttons, then runs the LVGL loop.  Holding a button during boot shows the
 * hardware debug screen; otherwise the shared application (app_init) runs.
 */

#include "app.h"
#include "buttons.h"
#include "debug_screen.h"
#include "display.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "i2c_bus.h"
#include "keymap.h"
#include "lvgl.h"
#include "sdkconfig.h"
#include "touchscreen.h"
#include "ui.h"

/* -- Hardening: no radio ---------------------------------------------- */
/* APP_NO_BLOBS removes the WiFi/Bluetooth/RF-PHY binary blobs, so the device
 * has no radio capability. */
#if !CONFIG_APP_NO_BLOBS
#error                                                                                             \
    "seedmix hardening (no radio): CONFIG_APP_NO_BLOBS must be enabled (no WiFi/Bluetooth/RF-PHY binary blobs)"
#endif

/* -- Hardening: no flash storage -------------------------------------- */
#if CONFIG_ESP_PHY_CALIBRATION_AND_DATA_STORAGE
#error                                                                                             \
    "seedmix hardening (no flash storage): CONFIG_ESP_PHY_CALIBRATION_AND_DATA_STORAGE must be disabled"
#endif
#if !CONFIG_PARTITION_TABLE_CUSTOM
#error                                                                                             \
    "seedmix hardening (no flash storage): CONFIG_PARTITION_TABLE_CUSTOM must be enabled (partitions_hardened.csv has no data partitions)"
#endif

static const char* TAG = "seedmix";

/* -- LVGL tick source (milliseconds) ---------------------------------- */
static uint32_t lvgl_tick_cb(void) { return (uint32_t)(esp_timer_get_time() / 1000); }

/* -- Entry point ------------------------------------------------------- */
void app_main(void) {
    ESP_LOGI(TAG, "seedmix ESP32 boot");

    lv_init();
    lv_tick_set_cb(lvgl_tick_cb);

    // Shared I2C bus first: the touchscreen and the IO expander (panel reset)
    // hang off it.
    const esp_err_t i2c_err = i2c_bus_init();
    if (i2c_err != ESP_OK) {
        ESP_LOGE(TAG, "I2C bus init failed: %s", esp_err_to_name(i2c_err));
    }

    display_init();

    // Touch is optional: keep the UI usable through the buttons if it fails.
    const esp_err_t touch_err = touchscreen_init();
    if (touch_err != ESP_OK && touch_err != ESP_ERR_NOT_FOUND) {
        ESP_LOGW(TAG, "touchscreen init failed: %s", esp_err_to_name(touch_err));
    }

    buttons_init();
    keymap_init();
    ui_nav_set_indev(keymap_get_indev());

    // Hold any physical button during boot to enter the hardware debug
    // screen otherwise launch the normal application
    if (buttons_any_pressed()) {
        ESP_LOGI(TAG, "button held at boot - showing debug screen");
        debug_screen_init();
    } else {
        ESP_LOGI(TAG, "starting main app");
        app_init();
    }

    uint32_t last_busy_log = 0;
    while (1) {
        // lv_timer_handler() returns how long until the next timer is due
        const uint32_t busy_start = lv_tick_get();
        uint32_t       wait_ms    = lv_timer_handler();
        const uint32_t busy_ms    = lv_tick_get() - busy_start;
        const uint32_t flushed    = display_flush_pixels_take();

        // A slow pass means LVGL spent it rendering the live preview; the pixel
        // count says whether it was render- or transfer-bound. One line/second.
        if (busy_ms >= 30 && (busy_start - last_busy_log) >= 1000) {
            last_busy_log = busy_start;
            ESP_LOGI(TAG, "lvgl pass took %u ms, flushed %u px", (unsigned)busy_ms,
                     (unsigned)flushed);
        }

        if (wait_ms == 0 || wait_ms > 10) {
            wait_ms = 10;
        }
        // vTaskDelay(0) only yields, starving the idle task and tripping the
        // watchdog, so always give up at least one tick.
        const TickType_t ticks = pdMS_TO_TICKS(wait_ms);
        vTaskDelay(ticks ? ticks : 1);
    }
}

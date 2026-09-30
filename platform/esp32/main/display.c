/**
 * @file display.c
 * @brief ESP-IDF LVGL display driver using esp_lcd over SPI
 */

#include "display.h"

#include <stdlib.h>

#include "driver/gpio.h"
#include "driver/ledc.h"
#include "driver/spi_master.h"
#include "esp_err.h"
#include "esp_heap_caps.h"
#if CONFIG_SEEDMIX_IO_EXPANDER_ENABLE && (CONFIG_SEEDMIX_IO_EXPANDER_LCD_RESET_PIN >= 0)
#include "expander.h"
#endif
#include "esp_lcd_panel_io.h"
#include "esp_lcd_panel_ops.h"
#include "esp_lcd_panel_st7789.h"
#include "esp_lcd_panel_vendor.h"
#if CONFIG_SEEDMIX_DISPLAY_DRIVER_ST7796
#include "esp_lcd_st7796.h"
#endif
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "i2c_bus.h"
#include "lvgl.h"
/* lv_draw_sw_rgb565_swap(): for panels that expect big-endian RGB565 */
#include "src/draw/sw/lv_draw_sw_utils.h"

static const char* TAG = "display";

/* Render buffer sizes to try, tallest first. Taller strips mean fewer flushes,
 * but the buffer has to fit internal RAM, so the tallest that fits is picked at
 * boot. */
static const uint16_t s_draw_buf_ladder[] = {96, 64, 40, 24, 16};

// Internal DMA-capable memory avoids a bounce copy, but the pool is small, so
// fall back to plain internal memory.
static void* draw_buf_alloc(size_t size) {
    void* p = heap_caps_malloc(size, MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
    if (!p) {
        p = heap_caps_malloc(size, MALLOC_CAP_INTERNAL);
    }
    return p;
}

/* LEDC settings used when the backlight supports PWM dimming. */
#define BACKLIGHT_LEDC_MODE LEDC_LOW_SPEED_MODE
#define BACKLIGHT_LEDC_TIMER LEDC_TIMER_1
#define BACKLIGHT_LEDC_CHANNEL LEDC_CHANNEL_0
#define BACKLIGHT_LEDC_DUTY_RES LEDC_TIMER_10_BIT
#define BACKLIGHT_LEDC_MAX_DUTY ((1u << 10) - 1)

static esp_lcd_panel_handle_t s_panel        = NULL;
static lv_display_t*          s_display      = NULL;
static uint8_t*               s_draw_buf[2]  = {NULL, NULL};
static uint32_t               s_flush_pixels = 0;

// Pixels handed to the panel since the last query. Logged next to the LVGL pass
// time to say whether a slow pass was render-bound or transfer-bound.
uint32_t display_flush_pixels_take(void) {
    const uint32_t px = s_flush_pixels;
    s_flush_pixels    = 0;
    return px;
}

// LVGL renders RGB565 little-endian. Panels without a hardware byte-order
// command (e.g. the ST7796) need every pixel's bytes swapped on the way out.
static bool s_swap_bytes = false;

/* -- LVGL flush callback ---------------------------------------------- */
static void lvgl_flush_cb(lv_display_t* disp, const lv_area_t* area, uint8_t* px_map) {
    const uint32_t px_count =
        (uint32_t)(area->x2 - area->x1 + 1) * (uint32_t)(area->y2 - area->y1 + 1);
    s_flush_pixels += px_count;

    if (s_swap_bytes) {
        lv_draw_sw_rgb565_swap(px_map, px_count);
    }

    const esp_err_t err = esp_lcd_panel_draw_bitmap(s_panel, area->x1, area->y1, area->x2 + 1,
                                                    area->y2 + 1, (const void*)px_map);
    if (err != ESP_OK) {
        /* The transfer never queued, so on_color_trans_done() will not fire and
         * LVGL would wait forever: release it here instead. */
        ESP_LOGE(TAG, "draw_bitmap failed: %s", esp_err_to_name(err));
        lv_display_flush_ready(disp);
    }
}

/* draw_bitmap() only queues the transfer, so flush_ready() must wait for the
 * DMA to really finish. */
static bool on_color_trans_done(esp_lcd_panel_io_handle_t io, esp_lcd_panel_io_event_data_t* edata,
                                void* user_ctx) {
    (void)io;
    (void)edata;
    lv_display_flush_ready((lv_display_t*)user_ctx);
    return false;
}

/* -- Backlight --------------------------------------------------------- */
// Configure the backlight dark; backlight_enable() applies the brightness once
// the panel is initialized, so no bright glitch is shown while it comes up.
static void backlight_init(void) {
#if CONFIG_SEEDMIX_DISPLAY_BACKLIGHT_GPIO >= 0
#if CONFIG_SEEDMIX_DISPLAY_BACKLIGHT_PWM
    const ledc_timer_config_t timer = {
        .speed_mode      = BACKLIGHT_LEDC_MODE,
        .duty_resolution = BACKLIGHT_LEDC_DUTY_RES,
        .timer_num       = BACKLIGHT_LEDC_TIMER,
        .freq_hz         = CONFIG_SEEDMIX_DISPLAY_BACKLIGHT_FREQ_HZ,
        .clk_cfg         = LEDC_AUTO_CLK,
    };
    ESP_ERROR_CHECK(ledc_timer_config(&timer));

    const ledc_channel_config_t channel = {
        .gpio_num   = CONFIG_SEEDMIX_DISPLAY_BACKLIGHT_GPIO,
        .speed_mode = BACKLIGHT_LEDC_MODE,
        .channel    = BACKLIGHT_LEDC_CHANNEL,
        .timer_sel  = BACKLIGHT_LEDC_TIMER,
        .intr_type  = LEDC_INTR_DISABLE,
        .duty       = 0,
        .hpoint     = 0,
    };
    ESP_ERROR_CHECK(ledc_channel_config(&channel));

    ESP_LOGI(TAG, "backlight PWM on GPIO %d (%d Hz)", CONFIG_SEEDMIX_DISPLAY_BACKLIGHT_GPIO,
             CONFIG_SEEDMIX_DISPLAY_BACKLIGHT_FREQ_HZ);
#else
    const gpio_config_t bl = {
        .pin_bit_mask = 1ULL << CONFIG_SEEDMIX_DISPLAY_BACKLIGHT_GPIO,
        .mode         = GPIO_MODE_OUTPUT,
        .intr_type    = GPIO_INTR_DISABLE,
    };
    ESP_ERROR_CHECK(gpio_config(&bl));
    ESP_ERROR_CHECK(gpio_set_level(CONFIG_SEEDMIX_DISPLAY_BACKLIGHT_GPIO, 0));
    ESP_LOGI(TAG, "backlight on GPIO %d", CONFIG_SEEDMIX_DISPLAY_BACKLIGHT_GPIO);
#endif
#else
    ESP_LOGD(TAG, "no backlight pin configured");
#endif
}

static void backlight_enable(void) {
#if CONFIG_SEEDMIX_DISPLAY_BACKLIGHT_GPIO >= 0
#if CONFIG_SEEDMIX_DISPLAY_BACKLIGHT_PWM
    const uint32_t duty =
        (uint32_t)CONFIG_SEEDMIX_DISPLAY_BACKLIGHT_DUTY_PCT * BACKLIGHT_LEDC_MAX_DUTY / 100u;
    ESP_ERROR_CHECK(ledc_set_duty(BACKLIGHT_LEDC_MODE, BACKLIGHT_LEDC_CHANNEL, duty));
    ESP_ERROR_CHECK(ledc_update_duty(BACKLIGHT_LEDC_MODE, BACKLIGHT_LEDC_CHANNEL));
    ESP_LOGI(TAG, "backlight at %d%%", CONFIG_SEEDMIX_DISPLAY_BACKLIGHT_DUTY_PCT);
#else
    ESP_ERROR_CHECK(gpio_set_level(CONFIG_SEEDMIX_DISPLAY_BACKLIGHT_GPIO, 1));
#endif
#endif
}

/* -- Panel reset through the board's IO expander ----------------------- */
// Some boards wire the panel RST to a TCA9554 output instead of a GPIO. Such a
// panel needs the pulse before it accepts the init sequence.
static void panel_reset_via_expander(void) {
#if CONFIG_SEEDMIX_IO_EXPANDER_ENABLE && (CONFIG_SEEDMIX_IO_EXPANDER_LCD_RESET_PIN >= 0)
    const int pin = CONFIG_SEEDMIX_IO_EXPANDER_LCD_RESET_PIN;
    if (!expander_available()) {
        ESP_LOGW(TAG, "no IO expander - skipping the panel reset");
        return;
    }

    // Pulse it low and back high. The handle stays alive: the PWR button on
    // the same chip is polled for the whole run.
    esp_err_t pulse = expander_set_output(pin, false);
    if (pulse == ESP_OK) {
        vTaskDelay(pdMS_TO_TICKS(100));
        pulse = expander_set_output(pin, true);
    }
    if (pulse == ESP_OK) {
        vTaskDelay(pdMS_TO_TICKS(100));
        ESP_LOGI(TAG, "panel reset pulsed via TCA9554 pin %d", pin);
    } else {
        ESP_LOGW(TAG, "panel reset via TCA9554 failed: %s", esp_err_to_name(pulse));
    }
#else
    // Either the panel RST is on a GPIO or this board needs no expander reset.
#endif
}

/* -- Init -------------------------------------------------------------- */
void display_init(void) {
#if CONFIG_SEEDMIX_DISPLAY_DRIVER_NONE
    ESP_LOGW(TAG, "display driver is 'None'; no display initialized");
    return;
#endif

#if defined(CONFIG_SEEDMIX_DISPLAY_DRIVER_ILI9341) || defined(CONFIG_SEEDMIX_DISPLAY_DRIVER_ST7735)
#error                                                                                             \
    "ILI9341/ST7735 are not in-tree. Add espressif/esp_lcd_ili9341 or espressif/esp_lcd_st7735 to idf_component.yml and extend this file."
#endif

    const char* driver_name = "ST7789";
#if CONFIG_SEEDMIX_DISPLAY_DRIVER_ST7796
    driver_name = "ST7796";
#endif

#if CONFIG_SEEDMIX_DISPLAY_SWAP_BYTES
    s_swap_bytes = true;
#endif

    bool bgr = false;
#if CONFIG_SEEDMIX_DISPLAY_BGR
    bgr = true;
#endif

    ESP_LOGI(TAG, "init %dx%d %s (%s colour, byte_swap=%d)", DISPLAY_WIDTH, DISPLAY_HEIGHT,
             driver_name, bgr ? "BGR" : "RGB", s_swap_bytes ? 1 : 0);

    // Reset the panel first: on some boards that reset is an expander output.
    panel_reset_via_expander();

    backlight_init();

    // LVGL display + double partial-render buffers: draw_bitmap() is async
    // (DMA), so one strip can be sent while LVGL renders into the other.
    s_display = lv_display_create(DISPLAY_WIDTH, DISPLAY_HEIGHT);
    lv_display_set_color_format(s_display, LV_COLOR_FORMAT_RGB565);

    size_t draw_buf_size  = 0;
    int    draw_buf_lines = 0;
    for (size_t rung = 0; rung < sizeof(s_draw_buf_ladder) / sizeof(s_draw_buf_ladder[0]); rung++) {
        const int    lines = s_draw_buf_ladder[rung];
        const size_t size  = (size_t)DISPLAY_WIDTH * (size_t)lines * sizeof(uint16_t);
        s_draw_buf[0]      = draw_buf_alloc(size);
        s_draw_buf[1]      = draw_buf_alloc(size);
        if (s_draw_buf[0] && s_draw_buf[1]) {
            draw_buf_size  = size;
            draw_buf_lines = lines;
            break;
        }
        free(s_draw_buf[0]);
        free(s_draw_buf[1]);
        s_draw_buf[0] = NULL;
        s_draw_buf[1] = NULL;
    }
    /* A zero size must never reach LVGL: it divides by the buffer size and
     * loops forever. ESP_ERROR_CHECK only prints here (NDEBUG build). */
    if (draw_buf_size == 0) {
        ESP_LOGE(TAG, "no internal memory for the display render buffer");
        abort();
    }
    ESP_LOGI(TAG, "render buffer: 2 x %d lines, %u bytes each", draw_buf_lines,
             (unsigned)draw_buf_size);

    lv_display_set_buffers(s_display, s_draw_buf[0], s_draw_buf[1], draw_buf_size,
                           LV_DISPLAY_RENDER_MODE_PARTIAL);
    lv_display_set_flush_cb(s_display, lvgl_flush_cb);

    // SPI bus
    spi_bus_config_t bus_cfg = {
        .sclk_io_num     = CONFIG_SEEDMIX_DISPLAY_SPI_CLK_GPIO,
        .mosi_io_num     = CONFIG_SEEDMIX_DISPLAY_SPI_MOSI_GPIO,
        .miso_io_num     = -1,
        .quadwp_io_num   = -1,
        .quadhd_io_num   = -1,
        .max_transfer_sz = DISPLAY_WIDTH * DISPLAY_HEIGHT * sizeof(uint16_t) + 16,
    };
    ESP_ERROR_CHECK(spi_bus_initialize(CONFIG_SEEDMIX_DISPLAY_SPI_HOST, &bus_cfg, SPI_DMA_CH_AUTO));

    // Panel IO (SPI). A negative CS means "no chip-select line": the panel is
    // the only device on the bus and stays selected (Waveshare wiring).
    esp_lcd_panel_io_handle_t     io     = NULL;
    esp_lcd_panel_io_spi_config_t io_cfg = {
        .cs_gpio_num       = CONFIG_SEEDMIX_DISPLAY_SPI_CS_GPIO,
        .dc_gpio_num       = CONFIG_SEEDMIX_DISPLAY_SPI_DC_GPIO,
        .spi_mode          = 0,
        .pclk_hz           = CONFIG_SEEDMIX_DISPLAY_SPI_FREQ_HZ,
        .trans_queue_depth = 10,
        .lcd_cmd_bits      = 8,
        .lcd_param_bits    = 8,
        // Signal LVGL only once the pixels really reached the panel
        .on_color_trans_done = on_color_trans_done,
        .user_ctx            = s_display,
    };
    ESP_ERROR_CHECK(esp_lcd_new_panel_io_spi(
        (esp_lcd_spi_bus_handle_t)CONFIG_SEEDMIX_DISPLAY_SPI_HOST, &io_cfg, &io));

    // Panel. `data_endian` only affects controllers with a RAMCTL command
    // (ST7789); the ST7796 is handled by s_swap_bytes.
    esp_lcd_panel_dev_config_t panel_cfg = {
        .reset_gpio_num = CONFIG_SEEDMIX_DISPLAY_RST_GPIO,
        .bits_per_pixel = 16,
        .data_endian    = LCD_RGB_DATA_ENDIAN_LITTLE,
    };
#if CONFIG_SEEDMIX_DISPLAY_BGR
    panel_cfg.rgb_ele_order = LCD_RGB_ELEMENT_ORDER_BGR;
#else
    panel_cfg.rgb_ele_order = LCD_RGB_ELEMENT_ORDER_RGB;
#endif

#if CONFIG_SEEDMIX_DISPLAY_DRIVER_ST7796
    ESP_ERROR_CHECK(esp_lcd_new_panel_st7796(io, &panel_cfg, &s_panel));
#else
    ESP_ERROR_CHECK(esp_lcd_new_panel_st7789(io, &panel_cfg, &s_panel));
#endif

    ESP_ERROR_CHECK(esp_lcd_panel_reset(s_panel));
    ESP_ERROR_CHECK(esp_lcd_panel_init(s_panel));

    // Orientation / appearance (Kconfig bools may be undefined when off)
    bool invert   = false;
    bool swap_xy  = false;
    bool mirror_x = false;
    bool mirror_y = false;
#if CONFIG_SEEDMIX_DISPLAY_INVERT_COLORS
    invert = true;
#endif
#if CONFIG_SEEDMIX_DISPLAY_SWAP_XY
    swap_xy = true;
#endif
#if CONFIG_SEEDMIX_DISPLAY_MIRROR_X
    mirror_x = true;
#endif
#if CONFIG_SEEDMIX_DISPLAY_MIRROR_Y
    mirror_y = true;
#endif
    esp_lcd_panel_invert_color(s_panel, invert);
    esp_lcd_panel_swap_xy(s_panel, swap_xy);
    esp_lcd_panel_mirror(s_panel, mirror_x, mirror_y);
    esp_lcd_panel_set_gap(s_panel, CONFIG_SEEDMIX_DISPLAY_OFFSET_X,
                          CONFIG_SEEDMIX_DISPLAY_OFFSET_Y);
    ESP_ERROR_CHECK(esp_lcd_panel_disp_on_off(s_panel, true));

    backlight_enable();
}

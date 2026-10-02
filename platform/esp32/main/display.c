/**
 * @file display.c
 * @brief ESP-IDF LVGL display driver using esp_lcd over SPI
 */

#include "display.h"

#include "driver/gpio.h"
#include "driver/ledc.h"
#include "driver/spi_master.h"
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

/* Render buffer: a horizontal strip of the screen (partial refresh). */
#define DRAW_BUF_LINES 40
#define DRAW_BUF_SIZE (DISPLAY_WIDTH * DRAW_BUF_LINES * sizeof(uint16_t))

/* LEDC settings used when the backlight supports PWM dimming. */
#define BACKLIGHT_LEDC_MODE LEDC_LOW_SPEED_MODE
#define BACKLIGHT_LEDC_TIMER LEDC_TIMER_1
#define BACKLIGHT_LEDC_CHANNEL LEDC_CHANNEL_0
#define BACKLIGHT_LEDC_DUTY_RES LEDC_TIMER_10_BIT
#define BACKLIGHT_LEDC_MAX_DUTY ((1u << 10) - 1)

static esp_lcd_panel_handle_t s_panel       = NULL;
static lv_display_t*          s_display     = NULL;
static uint8_t*               s_draw_buf[2] = {NULL, NULL};

/* LVGL renders RGB565 little-endian.  Panels without a hardware byte-order
 * command (e.g. the ST7796 - unlike the ST7789, which has RAMCTL) need every
 * pixel's two bytes swapped before they reach the panel, otherwise red and
 * blue are swapped and anti-aliased edges show colour fringing. */
static bool s_swap_bytes = false;

/* -- LVGL flush callback ---------------------------------------------- */
static void lvgl_flush_cb(lv_display_t* disp, const lv_area_t* area, uint8_t* px_map) {
    (void)disp;
    if (s_swap_bytes) {
        const uint32_t px_count =
            (uint32_t)(area->x2 - area->x1 + 1) * (uint32_t)(area->y2 - area->y1 + 1);
        lv_draw_sw_rgb565_swap(px_map, px_count);
    }

    esp_lcd_panel_draw_bitmap(s_panel, area->x1, area->y1, area->x2 + 1, area->y2 + 1,
                              (const void*)px_map);
}

/* esp_lcd_panel_draw_bitmap() only *queues* the transfer, so it returns long
 * before the panel has seen the pixels.  lv_display_flush_ready() must
 * therefore be called from here - once the DMA has really finished */
static bool on_color_trans_done(esp_lcd_panel_io_handle_t io, esp_lcd_panel_io_event_data_t* edata,
                                void* user_ctx) {
    (void)io;
    (void)edata;
    lv_display_flush_ready((lv_display_t*)user_ctx);
    return false;
}

/* -- Backlight --------------------------------------------------------- */
/* Configure the backlight output dark; backlight_enable() applies the
 * brightness once the panel is initialized, so no bright glitch is shown
 * while the controller is still coming up. */
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
/* Some boards do not wire the panel's RST pin to a GPIO - the Waveshare
 * ESP32-S3-Touch-LCD-3.5(-C) hangs it off a TCA9554 IO expander output
 * instead.  Such a panel needs that pulse before it will accept the init
 * sequence; the SWRESET fallback the esp_lcd driver uses when
 * `reset_gpio_num < 0` is not enough on its own. */
static void panel_reset_via_expander(void) {
#if CONFIG_SEEDMIX_IO_EXPANDER_ENABLE && (CONFIG_SEEDMIX_IO_EXPANDER_LCD_RESET_PIN >= 0)
    const int pin = CONFIG_SEEDMIX_IO_EXPANDER_LCD_RESET_PIN;
    if (!expander_available()) {
        ESP_LOGW(TAG, "no IO expander - skipping the panel reset");
        return;
    }

    /* Pulse it low and back high.  The handle stays alive afterwards: the
     * PWR button on the same chip is polled for the whole run. */
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
    /* Either the panel RST is on a GPIO (CONFIG_SEEDMIX_DISPLAY_RST_GPIO) or
     * this board does not need an expander-driven reset. */
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

    // Reset the panel before anything talks to the controller: on some boards
    // that reset is not a GPIO but an IO expander output.
    panel_reset_via_expander();

    backlight_init();

    // LVGL display + double partial-render buffers. Two buffers are
    // required: esp_lcd_panel_draw_bitmap() is asynchronous (DMA), so while
    // one strip is being sent the other must be free for LVGL to render
    // into - otherwise the next strip overwrites the one still in flight.
    // Created before the panel IO so it can be passed as the flush-completion
    // callback's context.
    s_display = lv_display_create(DISPLAY_WIDTH, DISPLAY_HEIGHT);
    lv_display_set_color_format(s_display, LV_COLOR_FORMAT_RGB565);

    for (int i = 0; i < 2; i++) {
        s_draw_buf[i] = heap_caps_malloc(DRAW_BUF_SIZE, MALLOC_CAP_DMA | MALLOC_CAP_INTERNAL);
        if (!s_draw_buf[i]) {
            s_draw_buf[i] = heap_caps_malloc(DRAW_BUF_SIZE, MALLOC_CAP_INTERNAL);
        }
        ESP_ERROR_CHECK(s_draw_buf[i] ? ESP_OK : ESP_ERR_NO_MEM);
    }

    lv_display_set_buffers(s_display, s_draw_buf[0], s_draw_buf[1], DRAW_BUF_SIZE,
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

    // Panel IO (SPI).  A negative CS GPIO means "no chip-select line": the
    // panel is the only device on the bus and stays selected, which is how
    // the Waveshare board is wired.
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

    // Panel.  `data_endian` only has an effect on controllers with a RAMCTL
    // byte-order command (ST7789); the ST7796 is handled by s_swap_bytes.
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

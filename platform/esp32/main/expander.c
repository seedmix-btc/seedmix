/**
 * @file expander.c
 * @brief Owns the TCA9554 handle shared by the panel reset and the PWR button.
 */

#include "expander.h"

#include "i2c_bus.h"
#include "sdkconfig.h"

#if CONFIG_SEEDMIX_IO_EXPANDER_ENABLE
#include "esp_io_expander_tca9554.h"
#include "esp_log.h"
#endif

#if CONFIG_SEEDMIX_IO_EXPANDER_ENABLE
static const char*              TAG        = "expander";
static esp_io_expander_handle_t s_expander = NULL;
static bool                     s_probed   = false;
#endif

esp_err_t expander_init(void) {
#if !CONFIG_SEEDMIX_IO_EXPANDER_ENABLE
    return ESP_ERR_NOT_SUPPORTED;
#else
    if (s_expander) {
        return ESP_OK;
    }
    if (s_probed) {
        return ESP_ERR_NOT_FOUND;
    }
    s_probed = true;

    i2c_master_bus_handle_t bus = i2c_bus_get();
    if (!bus) {
        ESP_LOGW(TAG, "shared I2C bus not initialized");
        return ESP_ERR_INVALID_STATE;
    }

    const esp_err_t err =
        esp_io_expander_new_i2c_tca9554(bus, CONFIG_SEEDMIX_IO_EXPANDER_I2C_ADDR, &s_expander);
    if (err != ESP_OK) {
        s_expander = NULL;
        ESP_LOGW(TAG, "TCA9554 not found at 0x%02x: %s", CONFIG_SEEDMIX_IO_EXPANDER_I2C_ADDR,
                 esp_err_to_name(err));
        return err;
    }

    ESP_LOGI(TAG, "TCA9554 ready at 0x%02x", CONFIG_SEEDMIX_IO_EXPANDER_I2C_ADDR);
    return ESP_OK;
#endif
}

bool expander_available(void) { return expander_init() == ESP_OK; }

esp_err_t expander_set_output(int pin, bool level) {
#if !CONFIG_SEEDMIX_IO_EXPANDER_ENABLE
    (void)pin;
    (void)level;
    return ESP_ERR_NOT_SUPPORTED;
#else
    const esp_err_t err = expander_init();
    if (err != ESP_OK) {
        return err;
    }

    const uint32_t mask = 1u << pin;
    esp_err_t      out  = esp_io_expander_set_dir(s_expander, mask, IO_EXPANDER_OUTPUT);
    if (out == ESP_OK) {
        out = esp_io_expander_set_level(s_expander, mask, level ? 1 : 0);
    }
    return out;
#endif
}

bool expander_read(int pin, bool* out) {
#if !CONFIG_SEEDMIX_IO_EXPANDER_ENABLE
    (void)pin;
    (void)out;
    return false;
#else
    if (!out || expander_init() != ESP_OK) {
        return false;
    }

    const uint32_t mask = 1u << pin;
    // get_level() reads the input port, so the pin must be an input first.
    // set_dir() only touches the masked pins, keeping the panel reset an output.
    if (esp_io_expander_set_dir(s_expander, mask, IO_EXPANDER_INPUT) != ESP_OK) {
        return false;
    }

    uint32_t levels = 0;
    if (esp_io_expander_get_level(s_expander, mask, &levels) != ESP_OK) {
        return false;
    }

    *out = (levels & mask) != 0;
    return true;
#endif
}

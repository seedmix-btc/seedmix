# ESP32 Build Instructions

Two boards are supported out of the box, selected with `BOARD=`:

| Board | `BOARD=` | Target | Display | Touch | Other input |
|-------|----------|--------|---------|-------|-------------|
| Waveshare ESP32-S3-Touch-LCD-3.5 / -3.5-C | `waveshare_3_5` (default) | esp32s3 | 320x480 ST7796 IPS, SPI, driven as 480x320 landscape | FT6336 capacitive, I2C | touch, BOOT button |
| TTGO T-Display | `ttgo_tdisplay` | esp32 | 240x135 ST7789, SPI | — | 2 GPIO buttons |

## Prerequisites

- ESP-IDF v5.5.x

## Build & flash

```bash
./scripts/build_esp32.sh                     # Waveshare ESP32-S3-Touch-LCD-3.5 (default)
BOARD=ttgo_tdisplay ./scripts/build_esp32.sh # TTGO T-Display

./scripts/build_esp32.sh flash      # build + flash
./scripts/build_esp32.sh monitor    # serial monitor
./scripts/build_esp32.sh menuconfig # edit Kconfig
./scripts/build_esp32.sh fullclean  # wipe build dir + sdkconfig
```

Each board gets its own build directory (`build_ttgo_tdisplay/`,
`build_waveshare_3_5/`). The generated `sdkconfig` has to live in
`platform/esp32/`, so a `.sdkconfig.board` stamp records which board produced it
and the script reconfigures automatically when you switch boards or when the
defaults file changes.

## Configuration

All hardware is configured through Kconfig (`main/Kconfig.projbuild`), shown in
`idf.py menuconfig` under **seedmix Hardware**:

| Menu | Options |
|------|---------|
| Display | resolution (presets + custom), controller (ST7789/ST7796/ILI9341/ST7735/none), SPI host/pins/clock, RST, backlight (plain GPIO or LEDC PWM), window offset, RGB/BGR order, RGB565 byte swap, invert/swap/mirror |
| I2C bus | enable, peripheral, SDA/SCL GPIOs, clock frequency |
| IO expander | enable TCA9554, I2C address, pin wired to the LCD reset |
| Touchscreen | enable, controller (FT5x06 family / XPT2046), I2C address, RST/IRQ GPIO, axis swap/mirror, poll interval, touch detection threshold |
| Camera | enable + model (OV2640/OV7670/OV5640), capture size (QVGA/VGA, switchable while streaming), XCLK frequency, XCLK/PCLK/VSYNC/HREF pins, per-bit data GPIOs (D0..D7, so non-consecutive wiring works), image rotation, mirror/flip |
| Physical buttons | enable, count, per-button GPIO, IO-expander button, left/right swap, active level, debounce, combo window |
| Entropy / TRNG | hardware RNG (`esp_fill_random`) or disabled |

Preset board configs live next to `sdkconfig.defaults` and are selected with
`BOARD=` (or `SDKCONFIG_DEFAULTS=`); add one when bringing up a new board.

## sdkconfig defaults layout

Configuration is composed from two files, applied base-first so a key set in
the overlay wins (ESP-IDF accepts a semicolon-separated `SDKCONFIG_DEFAULTS`):

| File | Contents |
|------|----------|
| `sdkconfig.defaults` | Shared, board-independent: FreeRTOS stack, LVGL (Kconfig, not `lv_conf.h`), fonts, TRNG source, and the whole hardening block |
| `sdkconfig.defaults.ttgo_tdisplay` | Target, flash size, LVGL heap, panel + pins + orientation, buttons |
| `sdkconfig.defaults.waveshare_3_5` | Target, flash/PSRAM, console, LVGL heap, panel + pins + orientation, I2C, IO expander, touchscreen, buttons |

`scripts/build_esp32.sh` composes them for you, which is why this is the
supported way in. Two consequences of ESP-IDF's own defaults handling are worth
knowing:

- `sdkconfig.defaults` is also ESP-IDF's *fallback* file name, so a bare
  `idf.py build` applies only the shared settings and does not configure a
  board. Always go through the script or set `SDKCONFIG_DEFAULTS` yourself.
- ESP-IDF also auto-loads `sdkconfig.defaults.<IDF_TARGET>` right after
  `sdkconfig.defaults` when such a file exists. This project deliberately uses
  *board*-named overlays instead, since one target can host several boards.

`BOARD=` also selects the build directory and is what the script uses to decide
which overlay to apply; the target comes from that board entry unless
`ESP_TARGET` overrides it.

## Hardening

Both boards build hardened:

- **No radio** - `CONFIG_APP_NO_BLOBS=y` drops the WiFi, Bluetooth and RF-PHY
  binary blobs, so the device has no radio capability and cannot transmit or
  receive wirelessly. `main_esp32.c` contains a compile-time `#error`, so the
  build fails if the blobs are re-enabled.
- **No flash storage** - both boards use the custom partition table
  `partitions_hardened.csv`, which contains only the `factory` app partition
  (no NVS, no OTA, no PHY-init and no data partition), and PHY calibration
  storage in NVS is disabled (`CONFIG_ESP_PHY_CALIBRATION_AND_DATA_STORAGE=n`).
  NVS is never initialised, so secrets only ever live in RAM and are wiped on
  power-off.

## What's implemented so far

- Display bring-up via `esp_lcd` over SPI (ST7789 and ST7796) + LVGL flush
  callback, with double partial-render buffers.
- Backlight: plain GPIO or LEDC PWM with a configurable brightness.
- Shared I2C master bus, used by the touchscreen and the TCA9554 IO expander.
- Panel reset through the Waveshare board's TCA9554 IO expander
  (`esp_io_expander_tca9554`), because its ST7796 `RST` pin is not wired to a
  GPIO.
- Non-blocking flush: `lv_display_flush_ready()` is called from the SPI
  transfer-complete callback (`on_color_trans_done`), not straight after
  `esp_lcd_panel_draw_bitmap()` returns
- Capacitive touchscreen on the `esp_lcd_touch` framework (FT5x06 family; the
  Waveshare board's FT6336 is register compatible) registered as an LVGL pointer
  input device. `hal_touch_available()` reports whether the controller actually
  answered at boot, which is what makes the app offer its "Touch Screen"
  entropy source and drop the arrow-button scrolling fallback.
- Physical buttons as an LVGL keypad input device driving focus navigation
  (one button walks backwards, the other forwards, both together confirm).
  A board can route one button through the IO expander instead of a GPIO
  (the Waveshare PWR button is EXIO6), and `SEEDMIX_BUTTONS_SWAP_LR` flips
  which button is which.
- HAL `hal_get_random()` using `esp_fill_random()`.
- Camera on the official `espressif/esp32-camera` driver (OV5640) behind the
  shared HAL camera API, gated by `CONFIG_SEEDMIX_CAMERA_ENABLE`.
- `libwally`, `qrencode` and `quirc` built as ESP-IDF components from the
  vendored sources in `external/`, and the shared app sources compiled into
  the `main` component.
- Boot selection: hold a button during boot to show the hardware debug screen,
  otherwise the normal application (`app_init`) runs.

### Hardware debug screen

Entered by holding a button (BOOT) while the board boots. It shows a config
summary and lists the sub-tests as tappable rows - tapping matters on the
Waveshare board, whose single GPIO button can never produce ENTER:

| Sub-test | What it shows |
|----------|---------------|
| Graphics | Colour swatches, arc and rounded rect; catches RGB565 byte-order and panel-orientation mistakes |
| Touch | Crosshair following the finger plus both coordinate pairs (controller-native and post-swap/mirror); distinguishes wrong axis flags from a dead panel |
| Camera | Live RGB565 preview with frame/format readout; exercises the same HAL path the application uses |

Every sub-test has a **Back** button, and ENTER returns to the summary where
that mapping exists. Outside a sub-test, holding any button shows a
full-screen `PRESSED: <KEY>` indicator, and ENTER twice within 800 ms opens
the graphics test.

## Board notes

### TTGO T-Display

240x135 landscape ST7789 (Jade's TTGO T-Display settings): `swap_xy`,
`mirror_x`, offset 40/53, invert, RGB order, SPI at 20 MHz. Pins:
MOSI 19 / CLK 18 / CS 5 / DC 16 / RST 23 / BL 4. Buttons GPIO 0 + 35,
active-low.

The ST7789 handles LVGL's little-endian RGB565 in hardware (its RAMCTL
byte-order command, driven by `data_endian`), so `SEEDMIX_DISPLAY_SWAP_BYTES`
stays off.

### Waveshare ESP32-S3-Touch-LCD-3.5(-C)

Pin map (from the Waveshare schematic and their ESP-IDF demo's `driver.h`):

| Signal | GPIO |
|--------|------|
| LCD SCLK / MOSI / DC | 5 / 1 / 3 |
| LCD CS / RST | not connected (panel always selected; reset via TCA9554 EXIO1) |
| LCD backlight (PWM) | 6 |
| I2C SDA / SCL | 8 / 7 (shared: touch, TCA9554, PMIC, RTC, IMU, camera SCCB) |
| Touch controller | FT6336 at 0x38, INT/RST not wired |
| TCA9554 IO expander | 0x20, EXIO1 = LCD reset, EXIO6 = PWR button |
| BOOT button | 0 (active-low) |

The board's three buttons are not equal:

| Button | Reachable from software? |
|--------|--------------------------|
| **BOOT** | Yes, GPIO0, active-low |
| **PWR** | Yes, but active-**high** on TCA9554 EXIO6. Holding it ~6 s switches the board off, so no gesture may rely on holding it longer than that |
| **RST** | **No.** It is wired to the module's `CHIP_PU` pin, so pressing it just holds the chip in reset - no GPIO, no expander line, nothing software can read. "Long press RST to reboot" is not something firmware can implement, because the hardware already does exactly that |

Both readable buttons are used exactly like the TTGO's: **PWR = previous**,
**BOOT = next**, **both together = confirm** (`SEEDMIX_BUTTONS_SWAP_LR=y`
only changes which is which). The PWR button needs the expander handle to
stay alive, so `expander.c` owns it and shares it with the panel reset.

The combo window is 60 ms, so the two presses have to overlap that closely.
PWR is read over I2C, and a failed read reports "released" - a device that
cannot see the expander will still navigate, it just cannot confirm.

A few things are worth knowing:

- **Byte order.**  The ST7796 has no equivalent of the ST7789's byte-order
  command, so it always consumes big-endian RGB565. LVGL renders
  little-endian, hence `CONFIG_SEEDMIX_DISPLAY_SWAP_BYTES=y`, which swaps the
  bytes in the LVGL flush callback (`lv_draw_sw_rgb565_swap()`). Without it,
  red and blue are swapped and anti-aliased edges show colour fringing.
- **Rotation.**  The panel is natively 320x480 portrait; the preset runs it as
  480x320 landscape (`SWAP_XY` + `MIRROR_X` + `MIRROR_Y`), which matches the
  shared UI's 480x320 landscape reference layout and reuses the existing
  `splash_480x320` asset. The touch flags (`SWAP_XY` + `MIRROR_Y`) are set to
  agree with it. These are the values Waveshare's own demo uses for its 90°
  rotation; if the image comes up flipped or the touch axes are mirrored on
  your unit, adjust `SEEDMIX_DISPLAY_{SWAP_XY,MIRROR_X,MIRROR_Y}` and the
  matching `SEEDMIX_TOUCHSCREEN_*` options together.
- **If the colours are wrong**, the three settings below are independent bits.
  Flip the one that matches the symptom; each is one `menuconfig` change and a
  re-flash.

  | Symptom | Setting to flip |
  |---------|-----------------|
  | Reds and blues swapped, greens still look green | `SEEDMIX_DISPLAY_BGR` |
  | Greens wrong too, speckled or fringed edges, colours generally scrambled | `SEEDMIX_DISPLAY_SWAP_BYTES` |
  | Looks like a photo negative (light for dark) | `SEEDMIX_DISPLAY_INVERT_COLORS` |

  Note that byte-swapping an RGB565 value is *not* an R/B swap - it moves the
  5-bit fields into the wrong places and corrupts the 6-bit green channel too,
  which is why a byte-order mistake looks different from a BGR/RGB mistake.
  The values above are the ones Waveshare's own ESP-IDF demo uses, so a
  mismatch means this panel revision is wired differently.

  A wrong colour *setting* is wrong everywhere and looks the same in every
  frame, so it is stable while the firmware runs. Colours that are only
  scrambled while the screen is updating (and that settle, or drift, as it
  redraws) are not a colour-format problem at all - they mean the panel is
  reading pixels that are being written underneath it, i.e. the flush handshake
  described above.

The OV5640 camera socket on the -C version is driven by the official
`espressif/esp32-camera` component (see `sdkconfig.defaults.waveshare_3_5` for
the pin map). Three things are worth knowing:

- **The data lines are not consecutive** (Y2..Y9 = 45, 47, 48, 46, 42, 40, 39,
  21), so `SEEDMIX_CAMERA_PIN_DATA0`..`DATA7` each have their own setting;
  `esp_camera` maps every bit to its own GPIO, so any order works.
- **SCCB goes over the shared I2C bus.**  The camera, the touch controller and
  the TCA9554 are all on SDA 8 / SCL 7, so `hal_esp32.c` passes
  `pin_sccb_sda = -1` and `sccb_i2c_port = SEEDMIX_I2C_PORT` instead of letting
  the driver install a bus of its own. That only works because esp32-camera
  uses the new `i2c_master` driver on IDF >= 5.4 (`sccb-ng.c`, selected by
  default); its legacy path would try to install the old driver on the same
  port, which cannot coexist with the one `esp_lcd_touch` and
  `esp_io_expander` are using. If a future component version flips
  `CONFIG_SCCB_HARDWARE_I2C_DRIVER_SELECTION`, the camera will stop being
detected - that is the symptom to look for.
- Frames arrive as **RGB565 in PSRAM** (two buffers, `CAMERA_GRAB_LATEST`), and
  `hal_camera_grab()` byte-swaps them into native-endian RGB565, which is what
  the shared UI expects. `grab()` never blocks: it returns false when no frame
  is ready and the caller keeps showing the previous one.
- **The capture size is the QR decoder's input, so it limits what can be read.**
  The frame reaches `qr_decode()` whole - no crop, no subsample - so the
  capture size sets how many pixels each QR module gets. The preset starts at
  **VGA** (4x QVGA) because QVGA left small or dense codes unreadable, RGB565
  costs 2 bytes per pixel per buffer (VGA = 600 KB, two buffers, both PSRAM),
  and both camera screens carry a `QVGA`/`VGA` button that switches while the
  camera keeps streaming: `hal_camera_set_size()` re-initialises the driver via
  `esp_camera_reconfigure()` (the size lives in the frame buffers, not in a
  sensor register), so the first frames afterwards can be dark while the sensor
  settles. `SEEDMIX_CAMERA_FRAMESIZE` only picks the size it starts at. The
  desktop HAL offers the same control by restarting its V4L2 stream, where the
  size is part of the negotiated format: `VIDIOC_S_FMT` is a *negotiation* -
  A webcam can answer a 320x240 request with 640x360 - so the reply
  is checked rather than assumed (the old code stored the request and reported
  a size the camera was not producing), and when the device cannot capture the
  wanted size at all the HAL captures an **exact multiple** of it (640x480 for
  320x240) and box-filters it down in `hal_camera_grab()` - YUYV only, since
  compressed frames cannot be downscaled. Only the browser build reports
  `hal_camera_size_switchable() == false`, so no button appears there.
- **While scanning, the preview shows the frame's centre square.**  The scan
  screens mark the preview square and `ui_camera_feed_update()` fills it with
  `LV_IMAGE_ALIGN_COVER`: the frame is scaled with its aspect ratio kept, the
  overflow cropped and centred, so the QR fills the box instead of sitting in a
  letterboxed strip. That is display only - the decoder still gets every
  captured pixel.
- **Orientation is fixed up in the HAL, not by the UI.**  The camera is mounted
  a quarter turn off the panel's landscape orientation and mirrored, so the
  preset sets `SEEDMIX_CAMERA_ROTATION_270=y` (= 90 counter-clockwise) and
  `SEEDMIX_CAMERA_HMIRROR=y`; `hal_camera_grab()` applies both while copying,
  so the returned `width`/`height` are already swapped. the mirror/flip flags
  describe the **displayed** image, not the sensor registers -
  `set_hmirror()`/`set_vflip()` run before the rotation, so with a quarter turn
  a sensor flip would show up on screen as the other axis.

#### Touch responsiveness

A light tap has to survive three places where it can be lost:

- **How often the controller is read.**  LVGL reads input devices every
  `LV_DEF_REFR_PERIOD` (33 ms by default), but the FT6336 reports at up to
  100 Hz, so two thirds of its reports were being thrown away and a tap
  shorter than 33 ms could start *and* end between two reads.
  `SEEDMIX_TOUCHSCREEN_POLL_MS=10` reads it at the rate it reports.
- **How precisely the loop can sleep.**  At `CONFIG_FREERTOS_HZ=100` every
  delay is quantised to 10 ms, and the main loop slept a fixed 10 ms on top of
  that, so an event could be a full tick late. The board runs at 1000 Hz and
  the loop now sleeps for as long as `lv_timer_handler()` asks for.
- **How hard the panel has to be touched.**  `SEEDMIX_TOUCHSCREEN_THRESHOLD`
  writes the controller's `G_THGROUP` register. `esp_lcd_touch_ft5x06` sets
  it to 70, which is the value for the larger FT5x06 panels; the preset lowers
  it to 30, the FT6x36 family default. Set it to 0 to leave the driver's
  value alone.

  The polarity is the standard one for FocalTech's `TH*` registers - these are
  thresholds that must be *exceeded*, so a smaller value needs less
  capacitance change to register a touch. This has not been confirmed on
  hardware: if light taps get **worse** rather than better, the polarity is
  the other way round on this revision, and 0 (or a value above 70) goes back.

`CONFIG_LV_DEF_REFR_PERIOD=16` is what makes a registered tap reach the screen
sooner (60 fps instead of 30), at some cost in CPU wakeups and battery.

## Still to do

- Implement the resistive XPT2046 touchscreen driver behind
  `CONFIG_SEEDMIX_TOUCHSCREEN_DRIVER_XPT2046`.
- **Single-button navigation.**  Both boards use the same scheme - *one
  button previous*, *the other next*, *both together confirm* - with
  `SEEDMIX_BUTTONS_SWAP_LR` choosing which is which. A *dedicated* confirm
  button is impossible on the Waveshare board because its third button, RST,
  cannot be read (see the pin map); confirming there means either pressing
  both buttons or tapping the touchscreen.
- Make the manual word-entry flow fully usable without a keyboard (touch
  already works; the on-screen keyboard needs a button-only input method).
- Enlarge the app partition for the 16 MB flash part if the firmware outgrows
  the current 4 MB factory partition (a second hardened table would be needed;
  `partitions_hardened.csv` deliberately contains only the factory partition).

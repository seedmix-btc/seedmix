/**
 * @file camera_test.c
 * @brief Camera test screen: live preview plus frame/format readout.
 *
 * Uses the same HAL entry points as the application, so a working preview
 * here means the camera path works everywhere.  Only RGB565 is rendered; any
 * other format is reported instead of drawn, which is the quickest way to
 * spot a sensor that came up in a mode we did not ask for.
 */

#include "camera_test.h"

#include "display.h"
#include "hal.h"
#include "lvgl.h"
#include "touchscreen.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ~8 fps: fast enough to look live, slow enough to leave the UI responsive
 * while every frame is copied and pushed through the panel. */
#define CAMERA_TEST_INTERVAL_MS 120

static lv_obj_t*      s_scr       = NULL;
static lv_obj_t*      s_img       = NULL;
static lv_obj_t*      s_status    = NULL;
static lv_image_dsc_t s_dsc       = {0};
static uint8_t*       s_buf       = NULL;
static size_t         s_buf_size  = 0;
static uint32_t       s_last_grab = 0;
static uint32_t       s_frames    = 0;
static bool           s_reported  = false;

static const char* pixfmt_name(hal_camera_pixfmt_t f) {
    switch (f) {
    case HAL_CAMERA_FMT_GRAY8:
        return "GRAY8";
    case HAL_CAMERA_FMT_YUYV:
        return "YUYV";
    case HAL_CAMERA_FMT_RGB565:
        return "RGB565";
    case HAL_CAMERA_FMT_JPEG:
        return "JPEG";
    default:
        return "unknown";
    }
}

lv_obj_t* camera_test_create(void) {
    s_scr = lv_obj_create(NULL);
    lv_obj_set_style_bg_color(s_scr, lv_color_hex(0x101418), 0);
    lv_obj_clear_flag(s_scr, LV_OBJ_FLAG_SCROLLABLE);

    lv_obj_t* title = lv_label_create(s_scr);
    lv_label_set_text(title, "CAMERA TEST");
    lv_obj_set_style_text_font(title, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(title, lv_color_white(), 0);
    lv_obj_align(title, LV_ALIGN_TOP_MID, 0, 2);

    s_img = lv_image_create(s_scr);
    lv_obj_align(s_img, LV_ALIGN_TOP_LEFT, 4, 20);

    s_status = lv_label_create(s_scr);
    lv_obj_set_style_text_font(s_status, &lv_font_montserrat_14, 0);
    lv_obj_set_style_text_color(s_status, lv_color_hex(0x888888), 0);
    lv_obj_align(s_status, LV_ALIGN_BOTTOM_LEFT, 4, -4);
    lv_label_set_text(s_status, "starting...");

    return s_scr;
}

void camera_test_update(void) {
    /* Skip the work when the screen is not on display. */
    if (!s_scr || lv_screen_active() != s_scr) {
        return;
    }

    const uint32_t now = lv_tick_get();
    if (now - s_last_grab < CAMERA_TEST_INTERVAL_MS) {
        return;
    }
    s_last_grab = now;

    if (!hal_camera_available()) {
        lv_label_set_text(s_status, "camera not available");
        return;
    }

    hal_camera_t* cam = hal_camera_open();
    if (!cam) {
        lv_label_set_text(s_status, "camera open failed");
        return;
    }

    hal_camera_frame_t frame;
    memset(&frame, 0, sizeof(frame));
    if (!hal_camera_grab(cam, &frame)) {
        hal_camera_close(cam);
        return; /* keep showing the previous frame */
    }
    hal_camera_close(cam);

    char buf[64];
    if (frame.pixfmt != HAL_CAMERA_FMT_RGB565) {
        snprintf(buf, sizeof(buf), "frame %u: %s %ux%u (not drawn)", (unsigned)++s_frames,
                 pixfmt_name(frame.pixfmt), (unsigned)frame.width, (unsigned)frame.height);
        lv_label_set_text(s_status, buf);
        hal_camera_frame_free(&frame);
        return;
    }

    const size_t need = (size_t)frame.width * frame.height * 2u;
    if (s_buf_size < need) {
        free(s_buf);
        s_buf      = malloc(need);
        s_buf_size = s_buf ? need : 0;
    }
    if (!s_buf) {
        lv_label_set_text(s_status, "out of memory for frame");
        hal_camera_frame_free(&frame);
        return;
    }

    memcpy(s_buf, frame.data, need);
    hal_camera_frame_free(&frame);

    /* The descriptor points at s_buf, which is reused, so LVGL has to be told
     * the pixels changed: a new source pointer would reload the image, but
     * invalidating keeps the allocation count at zero. */
    s_dsc.header.magic = LV_IMAGE_HEADER_MAGIC;
    s_dsc.header.cf    = LV_COLOR_FORMAT_RGB565;
    s_dsc.header.w     = (uint32_t)frame.width;
    s_dsc.header.h     = (uint32_t)frame.height;
    s_dsc.data_size    = need;
    s_dsc.data         = s_buf;
    lv_image_set_src(s_img, &s_dsc);
    lv_obj_invalidate(s_img);

    if (!s_reported) {
        s_reported = true;
        snprintf(buf, sizeof(buf), "%ux%u RGB565 - live", (unsigned)frame.width,
                 (unsigned)frame.height);
        lv_label_set_text(s_status, buf);
    }

    /* Draw the preview at its native size, centred in the space left under
     * the title. */
    lv_obj_set_pos(s_img, (DISPLAY_WIDTH - (lv_coord_t)frame.width) / 2, 20);
}

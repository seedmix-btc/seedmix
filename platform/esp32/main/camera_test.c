/**
 * @file camera_test.c
 * @brief Camera test screen: live preview plus frame/format readout.
 *
 * Uses the same HAL entry points as the application, so a working preview here
 * means the camera path works everywhere. Non-RGB565 frames are reported
 * rather than drawn.
 */

#include "camera_test.h"

#include "display.h"
#include "hal.h"
#include "lvgl.h"
#include "touchscreen.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ~8 fps: fast enough to look live, slow enough to keep the UI responsive.
#define CAMERA_TEST_INTERVAL_MS 120

// Area the preview is fitted into: under the title, above the status line.
#define CAMERA_TEST_TOP 22
#define CAMERA_TEST_BOTTOM 22
#define CAMERA_TEST_SIDE 4

// ~8 fps x 25 = about 3 s before we admit the camera is not delivering.
#define CAMERA_TEST_WAIT_WARN 25

static lv_obj_t*      s_scr       = NULL;
static lv_obj_t*      s_img       = NULL;
static lv_obj_t*      s_status    = NULL;
static lv_image_dsc_t s_dsc       = {0};
static uint8_t*       s_buf       = NULL;
static size_t         s_buf_size  = 0;
static uint32_t       s_last_grab = 0;
static uint32_t       s_frames    = 0;
static uint32_t       s_waits     = 0;
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
    // Skip unless this screen is active.
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
        // Keep the previous frame, but report if the camera never delivers one.
        if (++s_waits == CAMERA_TEST_WAIT_WARN) {
            lv_label_set_text(s_status, "no frame from the camera");
        }
        return;
    }
    hal_camera_close(cam);
    s_waits = 0;

    // frame_free() zeroes the struct, so copy the fields needed afterwards
    // first: reading them after the free fed LVGL a 0x0 image.
    const uint32_t            in_w = frame.width;
    const uint32_t            in_h = frame.height;
    const hal_camera_pixfmt_t fmt  = frame.pixfmt;

    char buf[80];
    if (fmt != HAL_CAMERA_FMT_RGB565) {
        snprintf(buf, sizeof(buf), "frame %u: %s %ux%u (not drawn)", (unsigned)++s_frames,
                 pixfmt_name(fmt), (unsigned)in_w, (unsigned)in_h);
        lv_label_set_text(s_status, buf);
        hal_camera_frame_free(&frame);
        return;
    }

    // Fit the preview between title and status line, shrinking but never
    // enlarging: a rotated QVGA frame is 240x320 and would otherwise overflow.
    const uint32_t avail_w = DISPLAY_WIDTH - 2 * CAMERA_TEST_SIDE;
    const uint32_t avail_h = DISPLAY_HEIGHT - CAMERA_TEST_TOP - CAMERA_TEST_BOTTOM;
    uint32_t       disp_w  = in_w;
    uint32_t       disp_h  = in_h;
    if (disp_w > avail_w || disp_h > avail_h) {
        const uint32_t zx = (256u * avail_w) / disp_w;
        const uint32_t zy = (256u * avail_h) / disp_h;
        const uint32_t z  = (zx < zy) ? zx : zy;
        disp_w            = (disp_w * z) / 256u;
        disp_h            = (disp_h * z) / 256u;
    }

    const size_t need = (size_t)in_w * in_h * 2u;
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

    lv_obj_set_size(s_img, (lv_coord_t)disp_w, (lv_coord_t)disp_h);
    lv_obj_align(s_img, LV_ALIGN_TOP_MID, 0, CAMERA_TEST_TOP);

    // s_buf is reused, so invalidate instead of reloading. Stride is explicit
    // and STRETCH scales the frame into the object size above.
    s_dsc.header.magic  = LV_IMAGE_HEADER_MAGIC;
    s_dsc.header.cf     = LV_COLOR_FORMAT_RGB565;
    s_dsc.header.w      = (uint16_t)in_w;
    s_dsc.header.h      = (uint16_t)in_h;
    s_dsc.header.stride = (uint16_t)(in_w * 2u);
    s_dsc.data_size     = need;
    s_dsc.data          = s_buf;
    lv_image_set_src(s_img, &s_dsc);
    lv_image_set_inner_align(s_img, LV_IMAGE_ALIGN_STRETCH);
    lv_obj_invalidate(s_img);

    if (!s_reported) {
        s_reported = true;
        snprintf(buf, sizeof(buf), "%ux%u RGB565 -> %ux%u live", (unsigned)in_w, (unsigned)in_h,
                 (unsigned)disp_w, (unsigned)disp_h);
        lv_label_set_text(s_status, buf);
    }
}

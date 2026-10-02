/**
 * @file platform/linux/hal_linux.c
 * @brief Linux HAL implementation
 *
 * Random source is /dev/urandom.  Camera entropy is captured from a
 * Video4Linux2 device (default /dev/video0, override with HAL_CAMERA_DEV).
 * QR codes can also be read from an image file, picked with the desktop's file
 * chooser (zenity/kdialog).  PNG and GIF are decoded by decoders of their own
 * (png_gray.c, gif_gray.c), JPEG and BMP by LVGL (lvgl_gray.c).
 */

#include "gif_gray.h"
#include "hal.h"
#include "lvgl.h"
#include "lvgl_gray.h"
#include "png_gray.h"
#include "qr.h"
#include "util/error.h"
#include "util/log.h"
#include "util/utils.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/videodev2.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

/* -- Random ----------------------------------------------------------- */
const char* hal_get_random_source() { return "/dev/urandom"; }

void hal_get_random(uint8_t* buf, size_t len) {
    ASSERT_OR_DIE(buf && len > 0, "hal_get_random: invalid buffer");

    FILE* f = fopen("/dev/urandom", "rb");
    ASSERT_OR_DIE(f, "hal_get_random: failed to open /dev/urandom");
    size_t n = fread(buf, 1, len, f);
    ASSERT_OR_DIE(n == len, "hal_get_random: short read from /dev/urandom");
    fclose(f);
}

/* -- Camera ----------------------------------------------------------- */
static int xioctl(int fd, unsigned long request, void* arg) {
    int r;
    do {
        r = ioctl(fd, request, arg);
    } while (r == -1 && errno == EINTR);
    return r;
}

static const char* camera_device(void) {
    const char* dev = getenv("HAL_CAMERA_DEV");
    return (dev && *dev) ? dev : "/dev/video0";
}

bool hal_camera_available(void) {
    int fd = open(camera_device(), O_RDWR);
    if (fd < 0) return false;

    struct v4l2_capability cap;
    if (xioctl(fd, VIDIOC_QUERYCAP, &cap) == -1) {
        close(fd);
        return false;
    }
    close(fd);
    return (cap.capabilities & V4L2_CAP_VIDEO_CAPTURE) != 0;
}

/* Bookkeeping for one mmap'd V4L2 buffer. */
struct v4l2_mmap_buf {
    void*  start;
    size_t length;
};

/** Map a V4L2 pixel format to the HAL enum. */
static hal_camera_pixfmt_t map_pixfmt(uint32_t v4l2_fmt) {
    switch (v4l2_fmt) {
    case V4L2_PIX_FMT_GREY:
        return HAL_CAMERA_FMT_GRAY8;
    case V4L2_PIX_FMT_YUYV:
        return HAL_CAMERA_FMT_YUYV;
    case V4L2_PIX_FMT_RGB565:
        return HAL_CAMERA_FMT_RGB565;
    case V4L2_PIX_FMT_MJPEG:
        return HAL_CAMERA_FMT_JPEG;
    default:
        return HAL_CAMERA_FMT_UNKNOWN;
    }
}

/** Streaming camera session (opaque). */
struct hal_camera {
    int                   fd;
    struct v4l2_mmap_buf* bufs;
    uint32_t              n_mapped;
    uint32_t              width;
    uint32_t              height;
    uint32_t              bytes_per_line;
    uint32_t              pixelformat;
    hal_camera_pixfmt_t   pixfmt;
};

hal_camera_t* hal_camera_open(void) {
    const char* dev = camera_device();

    hal_camera_t* cam = calloc(1, sizeof(*cam));
    if (!cam) {
        LOG_ERROR("out of memory");
        return NULL;
    }
    cam->fd = -1;

    cam->fd = open(dev, O_RDWR);
    if (cam->fd < 0) {
        LOG_ERROR("failed to open %s: %s", dev, strerror(errno));
        free(cam);
        return NULL;
    }

    struct v4l2_capability cap;
    if (xioctl(cam->fd, VIDIOC_QUERYCAP, &cap) == -1 ||
        !(cap.capabilities & V4L2_CAP_VIDEO_CAPTURE) || !(cap.capabilities & V4L2_CAP_STREAMING)) {
        LOG_ERROR("%s is not a streaming capture device", dev);
        hal_camera_close(cam);
        return NULL;
    }

    /* Prefer YUYV; fall back to MJPEG if the device doesn't support it. */
    struct v4l2_format fmt;
    memset(&fmt, 0, sizeof(fmt));
    fmt.type                = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width       = 640;
    fmt.fmt.pix.height      = 480;
    fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_YUYV;
    fmt.fmt.pix.field       = V4L2_FIELD_ANY;
    if (xioctl(cam->fd, VIDIOC_S_FMT, &fmt) == -1) {
        fmt.fmt.pix.pixelformat = V4L2_PIX_FMT_MJPEG;
        if (xioctl(cam->fd, VIDIOC_S_FMT, &fmt) == -1) {
            LOG_ERROR("failed to set capture format on %s", dev);
            hal_camera_close(cam);
            return NULL;
        }
    }

    cam->width          = fmt.fmt.pix.width;
    cam->height         = fmt.fmt.pix.height;
    cam->bytes_per_line = fmt.fmt.pix.bytesperline;
    cam->pixelformat    = fmt.fmt.pix.pixelformat;
    cam->pixfmt         = map_pixfmt(fmt.fmt.pix.pixelformat);

    LOG_INFO("camera %s format %ux%u fourcc '%c%c%c%c' stride=%u sizeimage=%u", dev, cam->width,
             cam->height, (char)(cam->pixelformat & 0xff), (char)((cam->pixelformat >> 8) & 0xff),
             (char)((cam->pixelformat >> 16) & 0xff), (char)((cam->pixelformat >> 24) & 0xff),
             cam->bytes_per_line, fmt.fmt.pix.sizeimage);

    struct v4l2_requestbuffers req;
    memset(&req, 0, sizeof(req));
    req.count  = 4;
    req.type   = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;
    if (xioctl(cam->fd, VIDIOC_REQBUFS, &req) == -1 || req.count < 2) {
        LOG_ERROR("failed to request buffers on %s", dev);
        hal_camera_close(cam);
        return NULL;
    }

    cam->bufs = calloc(req.count, sizeof(*cam->bufs));
    if (!cam->bufs) {
        LOG_ERROR("out of memory");
        hal_camera_close(cam);
        return NULL;
    }

    for (uint32_t i = 0; i < req.count; i++) {
        struct v4l2_buffer vb;
        memset(&vb, 0, sizeof(vb));
        vb.type   = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        vb.memory = V4L2_MEMORY_MMAP;
        vb.index  = i;
        if (xioctl(cam->fd, VIDIOC_QUERYBUF, &vb) == -1) {
            hal_camera_close(cam);
            return NULL;
        }

        cam->bufs[i].length = vb.length;
        cam->bufs[i].start =
            mmap(NULL, vb.length, PROT_READ | PROT_WRITE, MAP_SHARED, cam->fd, vb.m.offset);
        if (cam->bufs[i].start == MAP_FAILED) {
            hal_camera_close(cam);
            return NULL;
        }
        cam->n_mapped++;
    }

    for (uint32_t i = 0; i < req.count; i++) {
        struct v4l2_buffer vb;
        memset(&vb, 0, sizeof(vb));
        vb.type   = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        vb.memory = V4L2_MEMORY_MMAP;
        vb.index  = i;
        if (xioctl(cam->fd, VIDIOC_QBUF, &vb) == -1) {
            hal_camera_close(cam);
            return NULL;
        }
    }

    enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (xioctl(cam->fd, VIDIOC_STREAMON, &type) == -1) {
        hal_camera_close(cam);
        return NULL;
    }

    return cam;
}

bool hal_camera_grab(hal_camera_t* cam, hal_camera_frame_t* out) {
    if (!cam) return false;
    ASSERT_OR_DIE(out, "hal_camera_grab: null frame");
    memset(out, 0, sizeof(*out));

    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(cam->fd, &fds);
    struct timeval tv = {2, 0};

    if (select(cam->fd + 1, &fds, NULL, NULL, &tv) <= 0) {
        return false; /* timeout or interrupted */
    }

    struct v4l2_buffer vb;
    memset(&vb, 0, sizeof(vb));
    vb.type   = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    vb.memory = V4L2_MEMORY_MMAP;
    if (xioctl(cam->fd, VIDIOC_DQBUF, &vb) == -1) return false;

    if (vb.index >= cam->n_mapped) {
        LOG_ERROR("camera returned invalid buffer index %u", vb.index);
        xioctl(cam->fd, VIDIOC_QBUF, &vb);
        return false;
    }

    size_t frame_len = vb.bytesused;
    if (frame_len > cam->bufs[vb.index].length) {
        LOG_ERROR("camera frame length %zu exceeds mapped buffer size %zu", frame_len,
                  cam->bufs[vb.index].length);
        xioctl(cam->fd, VIDIOC_QBUF, &vb);
        return false;
    }

    uint8_t* frame = malloc(frame_len ? frame_len : 1);
    if (!frame) {
        xioctl(cam->fd, VIDIOC_QBUF, &vb);
        return false;
    }
    memcpy(frame, cam->bufs[vb.index].start, frame_len);
    xioctl(cam->fd, VIDIOC_QBUF, &vb);

    out->data           = frame;
    out->size           = frame_len;
    out->width          = cam->width;
    out->height         = cam->height;
    out->bytes_per_line = cam->bytes_per_line;
    out->pixfmt         = cam->pixfmt;
    return true;
}

void hal_camera_close(hal_camera_t* cam) {
    if (!cam) return;
    if (cam->fd >= 0) {
        enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        xioctl(cam->fd, VIDIOC_STREAMOFF, &type);
    }
    for (uint32_t i = 0; i < cam->n_mapped; i++) {
        munmap(cam->bufs[i].start, cam->bufs[i].length);
    }
    free(cam->bufs);
    if (cam->fd >= 0) close(cam->fd);
    free(cam);
}

void hal_camera_frame_free(hal_camera_frame_t* frame) {
    if (!frame) return;
    if (frame->data) {
        secure_memzero(frame->data, frame->size);
        free(frame->data);
    }
    memset(frame, 0, sizeof(*frame));
}

/* -- Image files (QR screenshots) ------------------------------------- */
/*
 * A QR code can also be loaded from a file (a screenshot exported by another
 * wallet, a photo of a printed SeedQR, ...) instead of from the camera.  SDL2
 * has no file chooser, so the picker is one of the desktop dialogs - zenity on
 * GTK systems, kdialog on KDE ones.  When neither is installed the "Open File"
 * button is hidden (hal_file_image_available() returns false).
 *
 * The picked file is decoded into the grayscale frame the QR decoder expects:
 * PNG by png_gray.c, JPEG and BMP by LVGL's bundled decoders, and GIF by
 * gif_gray.c.  LVGL sees paths as "<drive>:<path>", hence the
 * LV_FS_POSIX_LETTER prefix below.  A still image is one frame; an animated
 * GIF is a stream of frames (see the GIF section further down).
 */

typedef enum {
    PICKER_UNKNOWN = -1, /* not probed yet */
    PICKER_NONE    = 0,
    PICKER_ZENITY,
    PICKER_KDIALOG,
} picker_t;

static picker_t           s_picker = PICKER_UNKNOWN;
static hal_camera_frame_t s_picked; /* frame decoded from a picked file */
static bool               s_picked_ready = false;
static bool               s_pick_failed  = false;

/* Animated GIF handed out frame by frame (see the GIF section below). */
static gif_gray_t* s_gif;
static uint32_t    s_gif_w, s_gif_h;  /* logical screen size (frame size) */
static uint32_t    s_gif_due_ms;      /* tick the next frame is handed out at */
static unsigned    s_gif_pass_frames; /* frames decoded since the last rewind */

static void gif_state_reset(void) {
    gif_gray_close(s_gif);
    s_gif             = NULL;
    s_gif_due_ms      = 0;
    s_gif_pass_frames = 0;
}

static bool program_installed(const char* name) {
    char cmd[64];
    int  res = snprintf(cmd, sizeof(cmd), "command -v %s >/dev/null 2>&1", name);
    ASSERT_OR_DIE(res > 0 && (size_t)res < sizeof(cmd), "picker command too long");
    return system(cmd) == 0;
}

static picker_t picker(void) {
    if (s_picker == PICKER_UNKNOWN) {
        if (program_installed("zenity")) {
            s_picker = PICKER_ZENITY;
        } else if (program_installed("kdialog")) {
            s_picker = PICKER_KDIALOG;
        } else {
            s_picker = PICKER_NONE;
        }
    }
    return s_picker;
}

bool hal_file_image_available(void) { return picker() != PICKER_NONE; }

/* Run the file chooser; returns false when it was cancelled or is unavailable. */
static bool pick_image_path(char* out, size_t out_len) {
    const char* cmd = (picker() == PICKER_ZENITY)
                          ? "zenity --file-selection --title='Open QR image' "
                            "--file-filter='Images | *.png *.jpg *.jpeg *.bmp *.gif'"
                          : "kdialog --title 'Open QR image' --getopenfilename . "
                            "'Images (*.png *.jpg *.jpeg *.bmp *.gif)'";

    FILE* pipe = popen(cmd, "r");
    if (!pipe) return false;

    char  line[PATH_MAX];
    char* got = fgets(line, sizeof(line), pipe);
    int   rc  = pclose(pipe); /* non-zero when the dialog was cancelled */
    if (!got || rc != 0) return false;

    size_t n = strlen(line);
    while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
        line[--n] = '\0';
    }
    if (n == 0 || n >= out_len) return false;
    memcpy(out, line, n + 1);
    return true;
}

/* Shrink an image that is larger than what qr_decode() accepts, averaging
 * factor x factor blocks (a plain subsample could drop QR modules). */
static bool fit_gray_size(uint8_t** gray, uint32_t* w, uint32_t* h) {
    if (*w <= QR_DECODE_SIDE_MAX && *h <= QR_DECODE_SIDE_MAX) return true;

    uint32_t fx = (*w + QR_DECODE_SIDE_MAX - 1) / QR_DECODE_SIDE_MAX;
    uint32_t fy = (*h + QR_DECODE_SIDE_MAX - 1) / QR_DECODE_SIDE_MAX;
    uint32_t f  = fx > fy ? fx : fy;

    uint32_t dw = (*w + f - 1) / f;
    uint32_t dh = (*h + f - 1) / f;

    uint8_t* small = malloc((size_t)dw * dh);
    if (!small) return false;

    for (uint32_t y = 0; y < dh; y++) {
        for (uint32_t x = 0; x < dw; x++) {
            uint32_t sum = 0, n = 0;
            for (uint32_t sy = y * f; sy < (y + 1) * f && sy < *h; sy++) {
                const uint8_t* row = *gray + (size_t)sy * *w;
                for (uint32_t sx = x * f; sx < (x + 1) * f && sx < *w; sx++) {
                    sum += row[sx];
                    n++;
                }
            }
            small[(size_t)y * dw + x] = (uint8_t)(sum / n);
        }
    }

    free(*gray);
    *gray = small;
    *w    = dw;
    *h    = dh;
    return true;
}

/* Decode a still image (PNG, JPEG, BMP) into a grayscale frame, or NULL on
 * failure.  Animated GIFs are the one format that is not a single frame and go
 * through gif_poll() instead. */
static hal_camera_frame_t* decode_image_file(const char* path) {
    uint32_t w = 0, h = 0;

    /* PNG is decoded by our own decoder: LVGL's would have to hold the whole
     * image in LVGL's fixed memory pool (LV_MEM_SIZE, sized for widget
     * objects).  JPEG and BMP go through LVGL (see lvgl_gray.c), whose
     * decoders work in small blocks.  Both return an image that fits
     * qr_decode(). */
    uint8_t* gray = png_decode_gray_file(path, &w, &h);
    if (!gray) gray = lvgl_gray_decode_file(path, &w, &h);

    if (!gray) {
        LOG_WARN("cannot decode image %s", path);
        return NULL;
    }

    if (!fit_gray_size(&gray, &w, &h)) {
        free(gray);
        return NULL;
    }

    hal_camera_frame_t* frame = calloc(1, sizeof(*frame));
    if (!frame) {
        free(gray);
        return NULL;
    }

    frame->data           = gray;
    frame->size           = (size_t)w * h;
    frame->width          = w;
    frame->height         = h;
    frame->bytes_per_line = w;
    frame->pixfmt         = HAL_CAMERA_FMT_GRAY8;
    return frame;
}

/* -- Animated GIFs ----------------------------------------------------- */
/*
 * A fountain-encoded multi-part UR is published as an animated GIF holding one
 * QR code per frame.  The frames are therefore handed out one at a time, at
 * the pace the GIF itself asks for, so the multi-part UR decoder can collect
 * parts exactly as it would from a camera watching the animation play on
 * another wallet's screen.  The animation repeats until the scan ends, because
 * a missed frame means a part that still has to be read.
 */
static hal_file_image_status_t gif_poll(hal_camera_frame_t* out) {
    if ((int32_t)(lv_tick_get() - s_gif_due_ms) < 0) {
        return HAL_FILE_IMAGE_NONE; /* the current frame is still playing */
    }

    uint8_t* gray     = NULL;
    uint32_t delay_ms = 0;
    while (!gif_gray_next(s_gif, &gray, &delay_ms)) {
        if (gif_gray_failed(s_gif)) { /* truncated or corrupt */
            LOG_WARN("broken GIF");
            gif_state_reset();
            return HAL_FILE_IMAGE_FAILED;
        }
        if (s_gif_pass_frames <= 1) { /* a still image has nothing to repeat */
            gif_state_reset();
            return HAL_FILE_IMAGE_NONE;
        }
        gif_gray_rewind(s_gif); /* play the animation again */
        s_gif_pass_frames = 0;
    }

    uint32_t w = s_gif_w, h = s_gif_h;
    if (!fit_gray_size(&gray, &w, &h)) {
        free(gray);
        gif_state_reset();
        return HAL_FILE_IMAGE_FAILED;
    }

    s_gif_pass_frames++;
    s_gif_due_ms = lv_tick_get() + delay_ms;

    out->data           = gray;
    out->size           = (size_t)w * h;
    out->width          = w;
    out->height         = h;
    out->bytes_per_line = w;
    out->pixfmt         = HAL_CAMERA_FMT_GRAY8;
    return HAL_FILE_IMAGE_READY;
}

void hal_file_image_pick(void) {
    hal_file_image_reset();

    char path[PATH_MAX];
    if (!pick_image_path(path, sizeof(path))) return; /* cancelled */

    /* An animated GIF (how a fountain-encoded multi-part UR is published as a
     * file) is not a single frame, so it does not go through the still-image
     * path below: gif_gray_open() only succeeds on an actual GIF. */
    uint32_t gw = 0, gh = 0;
    s_gif = gif_gray_open(path, &gw, &gh);
    if (s_gif) {
        s_gif_w           = gw;
        s_gif_h           = gh;
        s_gif_due_ms      = 0; /* first frame is handed out on the next poll */
        s_gif_pass_frames = 0;
        LOG_INFO("decoded %ux%u GIF from %s", (unsigned)gw, (unsigned)gh, path);
        return;
    }

    hal_camera_frame_t* frame = decode_image_file(path);
    if (!frame) {
        LOG_WARN("no image decoded from %s", path);
        s_pick_failed = true;
        return;
    }

    LOG_INFO("decoded %ux%u QR image from %s", (unsigned)frame->width, (unsigned)frame->height,
             path);
    s_picked = *frame; /* the frame struct is only a header; its data stays owned here */
    free(frame);
    s_picked_ready = true;
}

void hal_file_image_reset(void) {
    gif_state_reset();

    if (s_picked_ready) {
        hal_camera_frame_free(&s_picked);
        s_picked_ready = false;
    }
    s_pick_failed = false;
}

hal_file_image_status_t hal_file_image_poll(hal_camera_frame_t* out) {
    if (!out) return HAL_FILE_IMAGE_NONE;

    if (s_gif) return gif_poll(out);

    if (s_picked_ready) {
        *out = s_picked;
        memset(&s_picked, 0, sizeof(s_picked));
        s_picked_ready = false;
        return HAL_FILE_IMAGE_READY;
    }

    if (s_pick_failed) {
        s_pick_failed = false;
        return HAL_FILE_IMAGE_FAILED;
    }

    return HAL_FILE_IMAGE_NONE;
}

/* -- Touch / pointer input ------------------------------------------- */
bool hal_touch_available(void) {
#ifdef ENABLE_BUTTONS
    // Button-emulation build  (no touch)
    return false;
#else
    // The SDL backend always registers a mouse pointer.
    return true;
#endif
}

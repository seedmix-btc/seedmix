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
    uint32_t              dev_width; /* size the device captures at */
    uint32_t              dev_height;
    uint32_t              dev_stride;
    uint32_t              dev_format;
    uint32_t              dev_sizeimage;
    uint8_t               scale; /* dev_width = scale * width */
    uint32_t              width; /* size handed to the caller */
    uint32_t              height;
    uint32_t              bytes_per_line;
    hal_camera_pixfmt_t   pixfmt;
};

/* -- Capture size ------------------------------------------------------ */
/* V4L2 negotiates the format per stream, so a size change means tearing the
 * stream down and starting it again. */
static hal_camera_size_t s_camera_size = HAL_CAMERA_SIZE_VGA;

// The size control belongs to the screen, not a session handle, so the HAL
// remembers the live session in order to restart it.
static hal_camera_t* s_session = NULL;

static uint32_t camera_size_width(hal_camera_size_t size) {
    return (size == HAL_CAMERA_SIZE_QVGA) ? 320u : 640u;
}

static uint32_t camera_size_height(hal_camera_size_t size) {
    return (size == HAL_CAMERA_SIZE_QVGA) ? 240u : 480u;
}

// Stop streaming and release the buffers, leaving the device open so the same
// session can be restarted at another size.
static void camera_stop(hal_camera_t* cam) {
    if (cam->fd >= 0 && cam->n_mapped > 0) {
        enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        xioctl(cam->fd, VIDIOC_STREAMOFF, &type);
    }
    for (uint32_t i = 0; i < cam->n_mapped; i++) {
        munmap(cam->bufs[i].start, cam->bufs[i].length);
    }
    cam->n_mapped = 0;
    free(cam->bufs);
    cam->bufs = NULL;

    if (cam->fd >= 0) {
        // Hand the driver's buffers back too: V4L2 wants that before a fresh
        // VIDIOC_REQBUFS, which is how a restart gets buffers for the new size.
        struct v4l2_requestbuffers req;
        memset(&req, 0, sizeof(req));
        req.type   = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        req.memory = V4L2_MEMORY_MMAP;
        xioctl(cam->fd, VIDIOC_REQBUFS, &req);
    }
}

// Largest box-filter factor used when the device cannot capture the wanted size.
#define CAMERA_DOWNSCALE_MAX 4

/* Ask for w x h in `pixelformat` and record what the device actually agreed to.
 * Returns false when the ioctl fails or the device substitutes another size. */
static bool camera_set_fmt(hal_camera_t* cam, uint32_t w, uint32_t h, uint32_t pixelformat) {
    struct v4l2_format fmt;
    memset(&fmt, 0, sizeof(fmt));
    fmt.type                = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    fmt.fmt.pix.width       = w;
    fmt.fmt.pix.height      = h;
    fmt.fmt.pix.pixelformat = pixelformat;
    fmt.fmt.pix.field       = V4L2_FIELD_ANY;
    if (xioctl(cam->fd, VIDIOC_S_FMT, &fmt) == -1) {
        return false;
    }
    if (fmt.fmt.pix.width != w || fmt.fmt.pix.height != h) {
        // The driver picked a size of its own, so treat the attempt as failed.
        return false;
    }

    cam->dev_width     = fmt.fmt.pix.width;
    cam->dev_height    = fmt.fmt.pix.height;
    cam->dev_stride    = fmt.fmt.pix.bytesperline;
    cam->dev_format    = fmt.fmt.pix.pixelformat;
    cam->dev_sizeimage = fmt.fmt.pix.sizeimage;
    return true;
}

/* Smallest YUYV size the device supports that is an exact 2..4x multiple of the
 * wanted one (keeps the aspect ratio and the bandwidth down). */
static bool camera_pick_multiple(hal_camera_t* cam, uint32_t want_w, uint32_t want_h,
                                 uint32_t* out_w, uint32_t* out_h) {
    uint32_t best_w = 0, best_h = 0;

    struct v4l2_frmsizeenum fs;
    memset(&fs, 0, sizeof(fs));
    fs.pixel_format = V4L2_PIX_FMT_YUYV;
    for (fs.index = 0; xioctl(cam->fd, VIDIOC_ENUM_FRAMESIZES, &fs) == 0; fs.index++) {
        if (fs.type != V4L2_FRMSIZE_TYPE_DISCRETE) {
            continue;
        }
        const uint32_t w = fs.discrete.width;
        const uint32_t h = fs.discrete.height;
        if (want_w == 0 || want_h == 0 || w % want_w != 0 || h % want_h != 0) {
            continue;
        }
        const uint32_t f = w / want_w;
        if (f != h / want_h || f < 2 || f > CAMERA_DOWNSCALE_MAX) {
            continue;
        }
        if (best_w == 0 || w < best_w) {
            best_w = w;
            best_h = h;
        }
    }

    *out_w = best_w;
    *out_h = best_h;
    return best_w != 0;
}

/* Box-filter a YUYV frame down by an integer factor. YUYV packs two pixels
 * around one U and one V, so chroma is averaged over the whole block and shared
 * by the output pair. Caller guarantees dst_w * f == source width. */
static void camera_downscale_yuyv(const uint8_t* src, uint32_t src_stride, uint32_t f, uint8_t* dst,
                                  uint32_t dst_w, uint32_t dst_h) {
    const uint32_t block = f * f;

    for (uint32_t y = 0; y < dst_h; y++) {
        uint8_t* drow = dst + (size_t)y * dst_w * 2u;
        for (uint32_t x = 0; x < dst_w; x += 2u) {
            uint32_t luma0 = 0, luma1 = 0, u_sum = 0, v_sum = 0;

            for (uint32_t j = 0; j < f; j++) {
                const uint8_t* srow = src + (size_t)(y * f + j) * src_stride;
                for (uint32_t i = 0; i < 2u * f; i++) {
                    const uint8_t* p = srow + (size_t)(x * f + i) * 2u;
                    if (i < f) {
                        luma0 += p[0];
                    } else {
                        luma1 += p[0];
                    }
                    /* p[1] is the U and p[3] the V of the two-pixel group */
                    if ((i & 1u) == 0) {
                        u_sum += p[1];
                        v_sum += p[3];
                    }
                }
            }

            drow[(size_t)x * 2u + 0] = (uint8_t)(luma0 / block);
            drow[(size_t)x * 2u + 1] = (uint8_t)(u_sum / block);
            drow[(size_t)x * 2u + 2] = (uint8_t)(luma1 / block);
            drow[(size_t)x * 2u + 3] = (uint8_t)(v_sum / block);
        }
    }
}

/* Apply the requested size and start streaming. On failure the session is left
 * stopped and clean, so it can be retried or closed. */
static bool camera_start(hal_camera_t* cam) {
    const char* dev = camera_device();

    const uint32_t want_w = camera_size_width(s_camera_size);
    const uint32_t want_h = camera_size_height(s_camera_size);

    /* V4L2 treats VIDIOC_S_FMT as a negotiation: several drivers hand back a
     * size they support instead of the one asked for. When the exact size is
     * refused, capture a supported multiple and downscale in hal_camera_grab(). */
    if (!camera_set_fmt(cam, want_w, want_h, V4L2_PIX_FMT_YUYV) &&
        /* MJPEG only at the exact size: compressed frames cannot be downscaled. */
        !camera_set_fmt(cam, want_w, want_h, V4L2_PIX_FMT_MJPEG)) {
        uint32_t mul_w = 0, mul_h = 0;
        if (!camera_pick_multiple(cam, want_w, want_h, &mul_w, &mul_h) ||
            !camera_set_fmt(cam, mul_w, mul_h, V4L2_PIX_FMT_YUYV)) {
            LOG_ERROR("failed to set capture format on %s", dev);
            return false;
        }
    }

    cam->width          = want_w;
    cam->height         = want_h;
    cam->scale          = (uint8_t)(cam->dev_width / want_w);
    cam->bytes_per_line = (cam->scale > 1) ? want_w * 2u : cam->dev_stride;
    cam->pixfmt         = map_pixfmt(cam->dev_format);

    LOG_INFO("camera %s: device %ux%u fourcc '%c%c%c%c' stride=%u sizeimage=%u -> %ux%u%s", dev,
             cam->dev_width, cam->dev_height, (char)(cam->dev_format & 0xff),
             (char)((cam->dev_format >> 8) & 0xff), (char)((cam->dev_format >> 16) & 0xff),
             (char)((cam->dev_format >> 24) & 0xff), cam->dev_stride, cam->dev_sizeimage,
             cam->width, cam->height, cam->scale > 1 ? " (downscaled)" : "");

    struct v4l2_requestbuffers req;
    memset(&req, 0, sizeof(req));
    req.count  = 4;
    req.type   = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    req.memory = V4L2_MEMORY_MMAP;
    if (xioctl(cam->fd, VIDIOC_REQBUFS, &req) == -1 || req.count < 2) {
        LOG_ERROR("failed to request buffers on %s", dev);
        return false;
    }

    cam->bufs = calloc(req.count, sizeof(*cam->bufs));
    if (!cam->bufs) {
        LOG_ERROR("out of memory");
        camera_stop(cam);
        return false;
    }

    for (uint32_t i = 0; i < req.count; i++) {
        struct v4l2_buffer vb;
        memset(&vb, 0, sizeof(vb));
        vb.type   = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        vb.memory = V4L2_MEMORY_MMAP;
        vb.index  = i;
        if (xioctl(cam->fd, VIDIOC_QUERYBUF, &vb) == -1) {
            camera_stop(cam);
            return false;
        }

        cam->bufs[i].length = vb.length;
        cam->bufs[i].start =
            mmap(NULL, vb.length, PROT_READ | PROT_WRITE, MAP_SHARED, cam->fd, vb.m.offset);
        if (cam->bufs[i].start == MAP_FAILED) {
            camera_stop(cam);
            return false;
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
            camera_stop(cam);
            return false;
        }
    }

    enum v4l2_buf_type type = V4L2_BUF_TYPE_VIDEO_CAPTURE;
    if (xioctl(cam->fd, VIDIOC_STREAMON, &type) == -1) {
        camera_stop(cam);
        return false;
    }

    return true;
}

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

    if (!camera_start(cam)) {
        hal_camera_close(cam);
        return NULL;
    }

    s_session = cam;
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

    if (cam->scale > 1) {
        /* The device captured a multiple of the requested size, so filter it
         * down here; YUYV is packed, so the output is simply w * h * 2. */
        const size_t out_len = (size_t)cam->width * cam->height * 2u;
        uint8_t*     frame   = malloc(out_len);
        if (!frame) {
            xioctl(cam->fd, VIDIOC_QBUF, &vb);
            return false;
        }
        camera_downscale_yuyv(cam->bufs[vb.index].start, cam->dev_stride, cam->scale, frame,
                              cam->width, cam->height);
        xioctl(cam->fd, VIDIOC_QBUF, &vb);

        out->data = frame;
        out->size = out_len;
    } else {
        uint8_t* frame = malloc(frame_len ? frame_len : 1);
        if (!frame) {
            xioctl(cam->fd, VIDIOC_QBUF, &vb);
            return false;
        }
        memcpy(frame, cam->bufs[vb.index].start, frame_len);
        xioctl(cam->fd, VIDIOC_QBUF, &vb);

        out->data = frame;
        out->size = frame_len;
    }

    out->width          = cam->width;
    out->height         = cam->height;
    out->bytes_per_line = cam->bytes_per_line;
    out->pixfmt         = cam->pixfmt;
    return true;
}

// V4L2 can re-negotiate the size by restarting the stream, so offer the control.
bool hal_camera_size_switchable(void) { return true; }

hal_camera_size_t hal_camera_size(void) { return s_camera_size; }

bool hal_camera_set_size(hal_camera_size_t size) {
    if (size >= HAL_CAMERA_SIZE_COUNT) {
        return false;
    }

    // Nothing to do when the size is already in force and the stream is up.
    if (size == s_camera_size && (!s_session || s_session->n_mapped > 0)) {
        return true;
    }

    const hal_camera_size_t previous = s_camera_size;
    s_camera_size                    = size;

    // No session yet: the size applies to the next hal_camera_open().
    if (!s_session) {
        return true;
    }

    camera_stop(s_session);
    if (camera_start(s_session)) {
        return true;
    }

    LOG_ERROR("failed to switch the camera to the new size");

    /* Go back to the size that was working. The session stays usable: a stopped
     * one is restarted by the next set_size() or hal_camera_open(), and must not
     * be freed here because the caller still holds it. */
    s_camera_size = previous;
    if (!camera_start(s_session)) {
        LOG_ERROR("failed to restore the previous camera size");
    }
    return false;
}

void hal_camera_close(hal_camera_t* cam) {
    if (!cam) return;
    camera_stop(cam);
    if (cam->fd >= 0) close(cam->fd);
    if (s_session == cam) s_session = NULL;
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

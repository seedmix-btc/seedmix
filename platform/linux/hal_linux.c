/**
 * @file platform/linux/hal_linux.c
 * @brief Linux HAL implementation
 *
 * Random source is /dev/urandom.  Camera entropy is captured from a
 * Video4Linux2 device (default /dev/video0, override with HAL_CAMERA_DEV).
 */

#include "hal.h"
#include "util/error.h"
#include "util/log.h"
#include "util/utils.h"

#include <errno.h>
#include <fcntl.h>
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

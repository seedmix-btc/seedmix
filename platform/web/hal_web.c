/**
 * @file platform/web/hal_web.c
 * @brief Web (Emscripten) HAL implementation.
 *
 * Entropy comes from the Web Crypto API (crypto.getRandomValues), the only
 * CSPRNG available in the browser.  Camera uses getUserMedia: the
 * webcam stream is drawn into a hidden <canvas> and each grab copies a
 * grayscale frame into the C heap.
 */

#include "hal.h"
#include "qr.h"
#include "util/error.h"
#include "util/log.h"
#include "util/utils.h"

#include <emscripten/emscripten.h>
#include <stdlib.h>
#include <string.h>

/* -- Random ----------------------------------------------------------- */
const char* hal_get_random_source(void) { return "WebCrypto getRandomValues"; }

void hal_get_random(uint8_t* buf, size_t len) {
    ASSERT_OR_DIE(buf && len > 0, "hal_get_random: invalid buffer");

    // crypto.getRandomValues caps a single call at 65536 bytes
    while (len > 0) {
        size_t n = len > 65536 ? 65536 : len;
        EM_ASM({ crypto.getRandomValues(new Uint8Array(HEAPU8.buffer, $0, $1)); }, buf, n);
        buf += n;
        len -= n;
    }
}

/* -- Camera ----------------------------------------------------------- */
/* Only one camera session exists at a time in the app, so the JS side is a
 * singleton (Module.__seedmixCam).  getUserMedia is asynchronous, so
 * hal_camera_open() returns immediately and hal_camera_grab() reports "no
 * frame yet" until the stream is ready (the app polls it from an LVGL timer).
 *
 * Note: a browser with no camera still exposes getUserMedia, so
 * hal_camera_available() can only test for the API, not for actual hardware.
 */

struct hal_camera {
    uint32_t width;
    uint32_t height;
};

bool hal_camera_available(void) {
    return (bool)EM_ASM_INT({
        return (window.isSecureContext && typeof navigator != 'undefined' &&
                navigator.mediaDevices && typeof navigator.mediaDevices.getUserMedia == 'function')
                   ? 1
                   : 0;
    });
}

hal_camera_t* hal_camera_open(void) {
    hal_camera_t* cam = (hal_camera_t*)calloc(1, sizeof(*cam));
    if (!cam) {
        LOG_ERROR("out of memory");
        return NULL;
    }

    EM_ASM({
        var c = ({
            video : null,
            canvas : null,
            ctx : null,
            stream : null,
            ready : false,
            width : 0,
            height : 0
        });

        c.video = document.createElement('video');
        c.video.setAttribute('playsinline', '');
        c.video.setAttribute('autoplay', '');
        c.video.muted         = true;
        c.video.style.display = 'none';
        document.body.appendChild(c.video);

        c.canvas = document.createElement('canvas');
        c.ctx    = c.canvas.getContext('2d', {willReadFrequently : true});

        Module.__seedmixCam = c;

        navigator.mediaDevices
            .getUserMedia({
                video : {facingMode : 'user', width : {ideal : 640}, height : {ideal : 480}},
                audio : false
            })
            .then(function(stream) {
                c.stream          = stream;
                c.video.srcObject = stream;
                c.video.addEventListener(
                    'loadedmetadata', function() {
                        c.width  = c.video.videoWidth;
                        c.height = c.video.videoHeight;
                        if (c.width && c.height) {
                            c.canvas.width  = c.width;
                            c.canvas.height = c.height;
                            c.ready         = true;
                        }
                    });
                return c.video.play();
            })
            .catch(function(err) {
                console.error('seedmix: getUserMedia failed: ' + err);
                c.ready = false;
            });
    });

    LOG_INFO("camera: requesting webcam access");
    return cam;
}

bool hal_camera_grab(hal_camera_t* cam, hal_camera_frame_t* out) {
    (void)cam;
    if (!out) return false;
    memset(out, 0, sizeof(*out));

    if (!EM_ASM_INT({ return Module.__seedmixCam && Module.__seedmixCam.ready ? 1 : 0; })) {
        return false;
    }

    uint32_t w = (uint32_t)EM_ASM_INT({ return Module.__seedmixCam.width; });
    uint32_t h = (uint32_t)EM_ASM_INT({ return Module.__seedmixCam.height; });
    if (!w || !h) return false;

    uint8_t* buf = (uint8_t*)malloc((size_t)w * h);
    if (!buf) {
        LOG_ERROR("out of memory");
        return false;
    }

    // Draw the latest video frame and copy its luma into `buf`
    EM_ASM(
        {
            var c = Module.__seedmixCam;
            c.ctx.drawImage(c.video, 0, 0, c.width, c.height);
            var d    = c.ctx.getImageData(0, 0, c.width, c.height).data;
            var n    = c.width * c.height;
            var gray = new Uint8Array(n);
            for (var i = 0; i < n; i++) {
                var r   = d[i * 4];
                var g   = d[i * 4 + 1];
                var b   = d[i * 4 + 2];
                gray[i] = ((r * 299 + g * 587 + b * 114 + 500) / 1000) | 0;
            }
            HEAPU8.set(gray, $0);
        },
        buf);

    out->data           = buf;
    out->size           = (size_t)w * h;
    out->width          = w;
    out->height         = h;
    out->bytes_per_line = w;
    out->pixfmt         = HAL_CAMERA_FMT_GRAY8;
    return true;
}

void hal_camera_close(hal_camera_t* cam) {
    if (!cam) return;
    EM_ASM({
        var c = Module.__seedmixCam;
        if (c) {
            if (c.stream) {
                var tracks = c.stream.getTracks();
                for (var i = 0; i < tracks.length; i++) tracks[i].stop();
            }
            if (c.video && c.video.parentNode) c.video.parentNode.removeChild(c.video);
            Module.__seedmixCam = null;
        }
    });
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
 * Scanning an image file instead of the live camera uses the browser's own
 * <input type="file"> chooser and decodes the picked image by drawing it into
 * a 2D canvas, which covers every format the browser supports (PNG, JPEG, BMP,
 * WebP, GIF, ...) without pulling an image decoder into the wasm build.
 *
 * An animated GIF - how a fountain-encoded multi-part UR is published as a
 * file - is decoded frame by frame with WebCodecs' ImageDecoder where the
 * browser has it, so the multi-part UR decoder can collect its parts from one
 * file.  Without ImageDecoder the first frame is all a GIF gives us.
 *
 * The chooser is asynchronous and a dismissed dialog does not raise an event
 * in every browser, so the pick is not waited for: hal_file_image_poll(),
 * called from the app's scan timer, collects the frames the JS side has ready
 * (status 2).  Status -1 means "cancelled/unusable file" (an event-driven
 * report) and the initial state 0 means "still open".
 *
 * The JS bodies below are EM_JS, which the C preprocessor stringifies: no
 * "==" - "=" ("==="/"!==") and no "=>", which the preprocessor splits into
 * two tokens and so breaks (see the EM_ASM gotchas in the repo notes).
 */

/*
 * Pick a file and decode it into frames.  Module.__seedmixPick then holds:
 *   status  0 while the chooser/detection runs, -1 on failure, 2 when ready
 *   w, h    size of every decoded frame (scaled down to fit the QR decoder)
 *   frames  grayscale images, one per frame of an animated image
 *   starts  when each frame begins, in ms (length == frames.length)
 *   total   length of one animation cycle in ms, 0 for a still image
 *   index   frame the app looked at last, -1 before the first poll
 */
EM_JS(void, seedmix_pick_file, (int max_side), {
    var state            = ({
        status : 0,
        w : 0,
        h : 0,
        frames : [],
        starts : [],
        total : 0,
        started : 0,
        index : -1,
        decoder : null
    });
    Module.__seedmixPick = state;

    function fail() { state.status = -1; }

    /* Shrink to what the QR decoder accepts, keeping the aspect ratio. */
    function scaled(w0, h0) {
        var side  = Math.max(w0, h0);
        var scale = side > max_side ? max_side / side : 1;
        return [ Math.max(1, Math.round(w0 * scale)), Math.max(1, Math.round(h0 * scale)) ];
    }

    function gray_of(src, w, h) {
        var canvas    = document.createElement('canvas');
        canvas.width  = w;
        canvas.height = h;

        var ctx = canvas.getContext('2d', {willReadFrequently : true});
        /* Transparent regions would otherwise read as black. */
        ctx.fillStyle = 'rgb(255,255,255)';
        ctx.fillRect(0, 0, w, h);
        ctx.drawImage(src, 0, 0, w, h);

        var px   = ctx.getImageData(0, 0, w, h).data;
        var gray = new Uint8Array(w * h);
        for (var i = 0; i < w * h; i++) {
            gray[i] =
                ((px[i * 4] * 299 + px[i * 4 + 1] * 587 + px[i * 4 + 2] * 114 + 500) / 1000) | 0;
        }
        return gray;
    }

    function finish(frames, starts, total) {
        if (state.decoder) {
            state.decoder.close();
            state.decoder = null;
        }
        if (!frames.length) {
            fail();
            return;
        }
        state.frames  = frames;
        state.starts  = starts;
        state.total   = total;
        state.started = performance.now();
        state.status  = 2;
    }

    /* One frame, from any format the browser can draw. */
    function load_still(file) {
        var url = URL.createObjectURL(file);
        var img = new Image();

        img.onerror = function() {
            URL.revokeObjectURL(url);
            fail();
        };

        img.onload = function() {
            var d      = scaled(img.naturalWidth, img.naturalHeight);
            state.w    = d[0];
            state.h    = d[1];
            var frames = [gray_of(img, state.w, state.h)];
            URL.revokeObjectURL(url);
            finish(frames, [0], 0);
        };

        img.src = url;
    }

    /* Every frame of an animated image, already composited by ImageDecoder the
     * way a player would draw them. */
    function load_frames(file) {
        file.arrayBuffer().then(
            function(buf) {
                ImageDecoder.isTypeSupported(file.type).then(
                    function(supported) {
                        if (!supported) {
                            load_still(file);
                            return;
                        }

                        var decoder   = new ImageDecoder({data : buf, type : file.type});
                        state.decoder = decoder;

                        decoder.tracks.ready.then(
                            function() {
                                var count  = decoder.tracks.selectedTrack.frameCount;
                                var frames = [], starts = [], total = 0, bytes = 0, i = 0;

                                function step() {
                                    /* A QR animation is a handful of frames; the limits
                         * only guard against something absurd. */
                                    if (i >= count || bytes > 64 * 1024 * 1024) {
                                        if (frames.length)
                                            finish(frames, starts, total);
                                        else
                                            load_still(file);
                                        return;
                                    }

                                    decoder.decode({frameIndex : i})
                                        .then(
                                            function(res) {
                                                var frame = res.image;
                                                if (!frames.length) {
                                                    var d   = scaled(frame.displayWidth,
                                                                   frame.displayHeight);
                                                    state.w = d[0];
                                                    state.h = d[1];
                                                }
                                                frames.push(gray_of(frame, state.w, state.h));
                                                bytes += state.w * state.h;
                                                starts.push(total);
                                                total += Math.max(frame.duration > 0
                                                                      ? frame.duration / 1000
                                                                      : 100,
                                                                  20);
                                                frame.close();
                                                i++;
                                                step();
                                            },
                                            fail);
                                }

                                step();
                            },
                            fail);
                    },
                    function() { load_still(file); });
            },
            fail);
    }

    var input           = document.createElement('input');
    input.type          = 'file';
    input.accept        = 'image/*';
    input.style.display = 'none';
    document.body.appendChild(input);

    input.onchange = function() {
        var file = input.files && input.files[0];
        if (input.parentNode) input.parentNode.removeChild(input);
        if (!file) {
            fail();
            return;
        }
        if (typeof ImageDecoder == 'undefined' || !file.type) {
            load_still(file);
            return;
        }
        load_frames(file);
    };

    input.click();
});

/* Hand the frame the animation is on to the app; -1 means "nothing new",
 * which is the case while the current frame is still playing - and forever
 * for a still image, whose single frame is only interesting once. */
EM_JS(int, seedmix_pick_frame, (uint8_t * gray), {
    var state = Module.__seedmixPick;
    if (!state || state.status != 2 || !state.frames.length) return -1;

    var index = 0;
    if (state.total > 0) { /* the GIF decides the pace, and it loops */
        var t = (performance.now() - state.started) % state.total;
        while (index + 1 < state.frames.length && state.starts[index + 1] <= t) index++;
    }
    if (index == state.index) return -1;

    state.index = index;
    HEAPU8.set(state.frames[index], gray);
    return index;
});

EM_JS(int, seedmix_pick_status, (), {
    var state = Module.__seedmixPick;
    return state ? state.status : 0;
});

EM_JS(int, seedmix_pick_width, (), {
    var state = Module.__seedmixPick;
    return state ? state.w : 0;
});

EM_JS(int, seedmix_pick_height, (), {
    var state = Module.__seedmixPick;
    return state ? state.h : 0;
});

EM_JS(void, seedmix_pick_reset, (), {
    var state = Module.__seedmixPick;
    if (state && state.decoder) state.decoder.close();
    Module.__seedmixPick = null;
});

bool hal_file_image_available(void) { return true; }

void hal_file_image_pick(void) {
    hal_file_image_reset(); /* drop whatever the last pick left behind */
    seedmix_pick_file((int)QR_DECODE_SIDE_MAX);
}

void hal_file_image_reset(void) { seedmix_pick_reset(); }

hal_file_image_status_t hal_file_image_poll(hal_camera_frame_t* out) {
    if (!out) return HAL_FILE_IMAGE_NONE;

    int status = seedmix_pick_status();
    if (status == 0) return HAL_FILE_IMAGE_NONE; /* dialog still open */

    if (status != 2) {
        seedmix_pick_reset();
        return HAL_FILE_IMAGE_FAILED;
    }

    uint32_t w = (uint32_t)seedmix_pick_width();
    uint32_t h = (uint32_t)seedmix_pick_height();
    if (!w || !h) {
        seedmix_pick_reset();
        return HAL_FILE_IMAGE_FAILED;
    }

    uint8_t* gray = malloc((size_t)w * h);
    if (!gray) {
        LOG_ERROR("out of memory");
        seedmix_pick_reset();
        return HAL_FILE_IMAGE_FAILED;
    }

    if (seedmix_pick_frame(gray) < 0) { /* the frame the app already had */
        free(gray);
        return HAL_FILE_IMAGE_NONE;
    }

    out->data           = gray;
    out->size           = (size_t)w * h;
    out->width          = w;
    out->height         = h;
    out->bytes_per_line = w;
    out->pixfmt         = HAL_CAMERA_FMT_GRAY8;
    return HAL_FILE_IMAGE_READY;
}

/* -- Touch / pointer input ------------------------------------------- */
bool hal_touch_available(void) {
    // The SDL backend always registers a mouse pointer
    return true;
}

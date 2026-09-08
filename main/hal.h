/**
 * @file main/hal.h
 * @brief Hardware abstraction layer - platform-specific primitives.
 *
 * Each supported platform provides an implementation of these functions
 * (see platform/<platform>/hal_<platform>.c).  Shared application code
 * should only ever use this header - never platform APIs directly.
 */

#ifndef HAL_H
#define HAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Get the name of the entropy source
 */
const char* hal_get_random_source();

/**
 * @brief Fill @p buf with @p len cryptographically secure random bytes.
 *
 * The entropy source is platform-specific (e.g. /dev/urandom on Linux,
 * the hardware TRNG on ESP32).  On failure this function does not return.
 *
 * @param buf  Output buffer (must not be NULL).
 * @param len  Number of bytes to fill (must be > 0).
 */
void hal_get_random(uint8_t* buf, size_t len);

/**
 * @brief Pixel formats that hal_camera_grab() may return.
 */
typedef enum {
    HAL_CAMERA_FMT_UNKNOWN = 0, /**< Unrecognized format. */
    HAL_CAMERA_FMT_GRAY8,       /**< 8-bit grayscale, 1 byte/pixel. */
    HAL_CAMERA_FMT_YUYV,        /**< YUYV 4:2:2 packed, 2 bytes/pixel. */
    HAL_CAMERA_FMT_RGB565,      /**< RGB565 packed, 2 bytes/pixel. */
    HAL_CAMERA_FMT_JPEG,        /**< JPEG-compressed frame. */
} hal_camera_pixfmt_t;

/**
 * @brief A single captured camera frame.
 *
 * The `data` buffer is owned by this struct and must be released with
 * hal_camera_frame_free() when no longer needed.
 */
typedef struct {
    uint8_t*            data;           /**< Frame bytes. */
    size_t              size;           /**< Number of valid bytes in `data`. */
    uint32_t            width;          /**< Image width in pixels. */
    uint32_t            height;         /**< Image height in pixels. */
    uint32_t            bytes_per_line; /**< Row stride in bytes (0 if packed). */
    hal_camera_pixfmt_t pixfmt;         /**< Pixel format of `data`. */
} hal_camera_frame_t;

/**
 * @brief An open, streaming camera session (opaque).
 *
 * Returned by hal_camera_open(), frames are dequeued with hal_camera_grab()
 * and the session is released with hal_camera_close().
 */
typedef struct hal_camera hal_camera_t;

/**
 * @brief Check whether a camera source is available.
 *
 * On Linux this probes a Video4Linux2 capture device (default /dev/video0,
 * override with the HAL_CAMERA_DEV environment variable).
 *
 * @return true if a camera is present and can be captured.
 */
bool hal_camera_available(void);

/**
 * @brief Open the camera and start streaming.
 *
 * Configures the capture format and starts the device streaming
 *
 * @return An open camera session, or NULL if the camera could not be opened.
 */
hal_camera_t* hal_camera_open(void);

/**
 * @brief Dequeue the next frame from a streaming camera.
 *
 * Blocks until a frame is available or a timeout elapses.  On success the
 * frame's `data` buffer is allocated and must be released with
 * hal_camera_frame_free(). On failure returns false and leaves @p out
 * untouched.
 *
 * @param cam  Open camera session (from hal_camera_open()).
 * @param out  Output frame (must not be NULL).
 * @return true if a frame was captured.
 */
bool hal_camera_grab(hal_camera_t* cam, hal_camera_frame_t* out);

/**
 * @brief Stop streaming and release a camera session.
 *
 * @param cam  Camera session to release (may be NULL).
 */
void hal_camera_close(hal_camera_t* cam);

/**
 * @brief Release a frame dequeued with hal_camera_grab().
 *
 * Zeroes and frees `frame->data` and resets the struct.
 */
void hal_camera_frame_free(hal_camera_frame_t* frame);

/**
 * @brief Check whether the platform can read an image file from disk.
 *
 * The desktop and browser builds let the user scan a QR code straight out of
 * an image file (a screenshot exported by another wallet, a photo of a
 * printed SeedQR, ...) instead of pointing the camera at it.  Embedded targets
 * have no file chooser and always return false, which hides the UI for it.
 *
 * @return true if hal_file_image_pick() can be used.
 */
bool hal_file_image_available(void);

/**
 * @brief Ask the user to pick an image file to scan a QR code from.
 *
 * Returns immediately.  On Linux the native file chooser runs modally, so this
 * call blocks until the dialog is dismissed; in the browser the dialog is
 * asynchronous. Either way the decoded frame is collected with
 * hal_file_image_poll()
 *
 * An animated GIF is decoded frame by frame rather than as a single image, so
 * that an animated multi-part UR (a fountain-encoded PSBT or wallet
 * descriptor) can be collected from one file.
 */
void hal_file_image_pick(void);

/**
 * @brief Forget the file picked last and drop any frames still to come.
 *
 * Called when the scan screen goes away. An animated GIF would otherwise keep
 * handing out frames into a scan that has already ended.
 */
void hal_file_image_reset(void);

/** Outcome of a hal_file_image_poll() call. */
typedef enum {
    HAL_FILE_IMAGE_NONE = 0, /**< Nothing to report (no pick, or it was cancelled). */
    HAL_FILE_IMAGE_READY,    /**< @p out holds the frame decoded from the file. */
    HAL_FILE_IMAGE_FAILED,   /**< The picked file could not be read as an image. */
} hal_file_image_status_t;

/**
 * @brief Collect the next frame decoded from the image file picked last.
 *
 * The frame is a HAL_CAMERA_FMT_GRAY8 image that fits qr_decode()'s size
 * limits, and it is owned by the caller (release it with
 * hal_camera_frame_free()). A still image is reported exactly once; an
 * animated GIF is reported once per frame, at the pace the GIF asks for and
 * looping until hal_file_image_reset(), so a multi-part UR accumulates.
 *
 * @param out  Receives the frame when the call returns HAL_FILE_IMAGE_READY.
 * @return HAL_FILE_IMAGE_READY / HAL_FILE_IMAGE_FAILED / HAL_FILE_IMAGE_NONE.
 */
hal_file_image_status_t hal_file_image_poll(hal_camera_frame_t* out);

/**
 * @brief Check whether touch/pointer input is available for touch entropy.
 *
 * The touch entropy source needs a pointer input device (e.g. an SDL mouse
 * on Linux, or a wired-up touchscreen on embedded targets).
 *
 * @return true if a touchscreen/pointer input device is available.
 */
bool hal_touch_available(void);

#ifdef __cplusplus
}
#endif

#endif /* HAL_H */

/**
 * @file platform/linux/gif_gray.h
 * @brief Minimal GIF decoder for reading a QR code out of an image file.
 */

#ifndef GIF_GRAY_H
#define GIF_GRAY_H

#include <stdbool.h>
#include <stdint.h>

/** Decoder state for one GIF file.  Opaque to the caller. */
typedef struct gif_gray gif_gray_t;

/**
 * @brief Open a GIF file for frame-by-frame grayscale decoding.
 *
 * The desktop build scans QR codes from image files (screenshots, photos), and
 * an animated GIF is how a fountain-encoded multi-part UR (a PSBT or wallet
 * descriptor) is usually published as a single file.  Frames are therefore
 * handed out one at a time: the caller keeps asking for the next frame while
 * the multi-part UR decoder accumulates parts, exactly as it would while a
 * camera watches the animation playing on another wallet's screen.
 *
 * GIF is decoded here rather than with LVGL's bundled support because that one
 * renders into LVGL's fixed memory pool (LV_MEM_SIZE - a size meant for widget
 * objects), which is far too small for a screenshot-sized animation.
 *
 * @param path    File to read.
 * @param out_w   Receives the logical screen width (every frame has this size).
 * @param out_h   Receives the logical screen height.
 * @return A decoder (release with gif_gray_close()), or NULL when the file is
 *         missing, is not a GIF, or cannot be parsed.
 */
gif_gray_t* gif_gray_open(const char* path, uint32_t* out_w, uint32_t* out_h);

/**
 * @brief Decode the next frame.
 *
 * @param g             Decoder.
 * @param out_gray      Receives a malloc'd out_w * out_h grayscale image
 *                      (caller frees).  Untouched when the call returns false.
 * @param out_delay_ms  Receives how long the frame is meant to be shown;
 *                      frames without a delay get the 100 ms browsers use.
 * @return true when a frame was decoded, false at the end of the animation or
 *         on a malformed/truncated file (see gif_gray_failed()).
 */
bool gif_gray_next(gif_gray_t* g, uint8_t** out_gray, uint32_t* out_delay_ms);

/**
 * @brief Check whether decoding stopped on a broken file.
 *
 * @return true when the last gif_gray_next() call failed on a malformed or
 *         truncated file, false when it simply reached the end of the
 *         animation (or nothing has failed yet).
 */
bool gif_gray_failed(const gif_gray_t* g);

/**
 * @brief Restart the animation at its first frame.
 *
 * The decoder keeps its canvas, so after a rewind the frames are composited
 * again from a clean background rather than from the last decoded frame.
 *
 * @param g  Decoder.
 */
void gif_gray_rewind(gif_gray_t* g);

/**
 * @brief Release a decoder and everything it owns.
 *
 * @param g  Decoder (may be NULL).
 */
void gif_gray_close(gif_gray_t* g);

#endif /* GIF_GRAY_H */

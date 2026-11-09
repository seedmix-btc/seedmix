/**
 * @file platform/linux/png_gray.h
 * @brief Minimal PNG decoder for reading a QR code out of an image file.
 */

#ifndef PNG_GRAY_H
#define PNG_GRAY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/**
 * @brief Decode a PNG file into an 8-bit grayscale image.
 *
 * The desktop build scans QR codes from image files (screenshots, photos).
 * PNG is decoded here rather than with LVGL's bundled decoder, because that
 * one has to hold the whole decoded image in LVGL's fixed memory pool
 * (LV_MEM_SIZE), which is sized for widget objects, not for screenshots.
 *
 * @param path   File to read.
 * @param out_w  Receives the image width.
 * @param out_h  Receives the image height.
 * @return A malloc'd out_w * out_h grayscale buffer (caller frees), or NULL if
 *         the file is missing, is not a PNG, or cannot be decoded.
 */
uint8_t* png_decode_gray_file(const char* path, uint32_t* out_w, uint32_t* out_h);

#endif /* PNG_GRAY_H */

/**
 * @file platform/linux/lvgl_gray.h
 * @brief Decode JPEG/BMP image files with LVGL's bundled decoders.
 */

#ifndef LVGL_GRAY_H
#define LVGL_GRAY_H

#include <stdint.h>

/**
 * @brief Decode a JPEG or BMP file into an 8-bit grayscale image.
 *
 * JPEG and BMP do not get a decoder of their own the way PNG (png_gray.c) and
 * GIF (gif_gray.c) do: LVGL's bundled TJpgDec and BMP decoders stream the image
 * block by block, so they never hold more than a single MCU in LVGL's memory
 * pool - the problem that forced PNG and GIF off LVGL does not apply.  They do
 * need LVGL's POSIX file system driver to open the file by path, which
 * lv_init() registers.
 *
 * This is the only place the desktop build decodes with LVGL, so it lives in a
 * translation unit of its own and is covered by tests/test_jpeg.c (which links
 * LVGL for it).
 *
 * Known limits of the LVGL decoders: the decoder is chosen by the file
 * extension, so the path must end in .jpg, .jpeg or .bmp, and TJpgDec only
 * handles baseline JPEG (progressive ones are rejected as an unsupported JPEG
 * standard).
 *
 * @param path   File to read.
 * @param out_w  Receives the image width.
 * @param out_h  Receives the image height.
 * @return A malloc'd out_w * out_h grayscale buffer (caller frees), or NULL
 *         when the file is missing or cannot be decoded.
 */
uint8_t* lvgl_gray_decode_file(const char* path, uint32_t* out_w, uint32_t* out_h);

#endif /* LVGL_GRAY_H */

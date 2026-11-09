/**
 * @file platform/linux/image_file.h
 * @brief Shared file reader for the desktop image decoders.
 */

#ifndef IMAGE_FILE_H
#define IMAGE_FILE_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief Read a whole file into memory.
 *
 * The desktop decoders (png_gray.c, gif_gray.c) parse their input in one pass
 * over the file contents, so they slurp it instead of seeking around it.
 *
 * @param path     File to read.
 * @param out_len  Receives the file length in bytes.
 * @param max_len  Refuse to read anything larger than this.
 * @return A malloc'd buffer (caller frees), or NULL when the file is missing,
 *         unreadable, empty-ish or larger than @p max_len.
 */
uint8_t* image_read_file(const char* path, size_t* out_len, size_t max_len);

#endif /* IMAGE_FILE_H */

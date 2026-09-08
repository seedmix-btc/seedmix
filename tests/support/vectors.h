/**
 * @file tests/support/vectors.h
 * @brief Read generated test vectors from tests/vectors/.
 *
 * The vector files are produced by scripts/gen_vectors.py and consumed here
 * so the C test suite exercises exactly the payloads that get encoded into
 * the QR codes.
 */

#ifndef VECTORS_H
#define VECTORS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** Read the whole file at tests/vectors/<rel> into a malloc'd buffer (caller
 *  frees). The buffer is NUL-terminated, so text files can be used directly.
 *  Returns NULL (and sets *out_len to 0) on any failure. */
uint8_t* vectors_read_file(const char* rel, size_t* out_len);

/** Strip trailing '\r', '\n', spaces and tabs from a text buffer. */
void vectors_trim(char* s);

/** Enumerate slugs under tests/vectors/<rel_dir>: file basenames ending in
 *  <suffix>, with the suffix stripped, sorted lexicographically. Returns
 *  false (with *out_count = 0) if the directory can't be read. Caller frees
 *  the result with vectors_free_slugs(). */
bool vectors_list_slugs(const char* rel_dir, const char* suffix, char*** out_slugs,
                        size_t* out_count);

/** Free a slug list returned by vectors_list_slugs(). */
void vectors_free_slugs(char** slugs, size_t count);

#endif /* VECTORS_H */

/**
 * @file main/util/utils.h
 * @brief General utility functions.
 */

#ifndef UTILS_H
#define UTILS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Securely zero a memory region.
 *
 * The wipe cannot be optimized away by the compiler.  Uses `explicit_bzero`
 * if available and falls back to a volatile write loop elsewhere. 
 * Use this for entropy, key material, and mnemonic buffers instead of plain memset().
 *
 * @param ptr  Buffer to zero (may be NULL, in which case this is a no-op).
 * @param len  Number of bytes to zero.
 */
void secure_memzero(void* ptr, size_t len);

/**
 * @brief Format bytes as lowercase hex.
 * @param data      Input bytes.
 * @param len       Number of bytes.
 * @param out       Output buffer (at least len * 2 + 1 chars).
 * @param out_size  Size of `out` in bytes.
 */
void bytes_to_hex(const uint8_t* data, size_t len, char* out, size_t out_size);

/**
 * @brief Parse a hex string into bytes.
 * @param hex       Input hex string (must have even length).
 * @param out       Output buffer (must have size exactly strlen(hex) / 2).
 * @param out_size  Size of `out` in bytes.
 */
void hex_to_bytes(const char* hex, char* out, size_t out_size);

/**
 * @brief Deterministically expand @p data into @p out_len bytes using
 *        SHA-256 in counter mode (works for any output length).
 *
 * The input is first hashed to a 32-byte seed (SHA-256(data)); each 32-byte
 * output block is then SHA-256(counter || seed) with a 4-byte big-endian
 * counter starting at 0.  This is an expansion, not a KDF.
 *
 * @param data      Input bytes.
 * @param data_len  Number of input bytes.
 * @param out       Output buffer (at least @p out_len bytes).
 * @param out_len   Number of bytes to produce.
 */
void sha256_expand(const uint8_t* data, size_t data_len, uint8_t* out, size_t out_len);

/**
 * @brief True if @p wc is a supported mnemonic word count (12 or 24).
 */
bool utils_word_count_valid(unsigned wc);

/**
 * @brief Entropy bits required for a word count (128 or 256).
 */
unsigned utils_word_count_bits(unsigned wc);

/**
 * @brief Entropy bytes required for a word count (16 or 32).
 */
size_t utils_word_count_bytes(unsigned wc);

/**
 * @brief floor(log2(v)) for v > 0.
 */
unsigned utils_floor_log2(uint64_t v);

#ifdef __cplusplus
}
#endif

#endif /* UTILS_H */

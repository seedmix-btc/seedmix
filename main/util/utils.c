/**
 * @file main/util/utils.c
 * @brief General utility functions.
 */

#include "utils.h"
#include "error.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>

#include <wally_core.h>
#include <wally_crypto.h>

void secure_memzero(void* ptr, size_t len) {
    if (!ptr || len == 0) return;

#if defined(__GLIBC__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) ||   \
    defined(__DragonFly__) || defined(__APPLE__)
    // Non-elidable wipe from the C library
    explicit_bzero(ptr, len);
#else
    // Portable fallback (e.g. ESP-IDF newlib): volatile store loop
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (len--) *p++ = 0;
#endif
}

void bytes_to_hex(const uint8_t* data, size_t len, char* out, size_t out_size) {
    ASSERT_OR_DIE(data && len > 0, "invalid data");
    ASSERT_OR_DIE(out, "null output buffer");
    ASSERT_OR_DIE(out_size >= len * 2 + 1, "hex buffer too small");
    for (size_t i = 0; i < len; i++) {
        int res = snprintf(out + i * 2, 3, "%02x", data[i]);
        ASSERT_OR_DIE(res > 0 && (size_t)res < 3, "hex formatting failed");
    }
    out[len * 2] = '\0';
}

void hex_to_bytes(const char* hex, char* out, size_t out_size) {
    ASSERT_OR_DIE(hex, "null hex input");
    ASSERT_OR_DIE(out, "null output buffer");
    size_t hex_len = strlen(hex);
    ASSERT_OR_DIE(hex_len % 2 == 0, "hex string must have even length");
    ASSERT_OR_DIE(out_size == hex_len / 2, "output buffer size incorrect");

    for (size_t i = 0; i < hex_len / 2; i++) {
        unsigned int byte;
        int          res = sscanf(hex + i * 2, "%2x", &byte);
        ASSERT_OR_DIE(res == 1, "hex parsing failed");
        out[i] = (char)byte;
    }
}

void sha256_expand(const uint8_t* data, size_t data_len, uint8_t* out, size_t out_len) {
    ASSERT_OR_DIE(data && data_len > 0, "sha256_expand: invalid input");
    ASSERT_OR_DIE(out && out_len > 0, "sha256_expand: invalid output");

    uint8_t seed[SHA256_LEN];
    ASSERT_OR_DIE(wally_sha256(data, data_len, seed, SHA256_LEN) == WALLY_OK,
                  "sha256_expand: SHA-256 failed");

    uint32_t counter = 0;
    size_t   off     = 0;
    while (off < out_len) {
        uint8_t block[4 + SHA256_LEN];
        block[0] = (uint8_t)(counter >> 24);
        block[1] = (uint8_t)(counter >> 16);
        block[2] = (uint8_t)(counter >> 8);
        block[3] = (uint8_t)(counter);
        memcpy(block + 4, seed, SHA256_LEN);

        uint8_t h[SHA256_LEN];
        ASSERT_OR_DIE(wally_sha256(block, sizeof(block), h, SHA256_LEN) == WALLY_OK,
                      "sha256_expand: SHA-256 failed");

        size_t n = out_len - off;
        if (n > SHA256_LEN) n = SHA256_LEN;
        memcpy(out + off, h, n);
        off += n;
        counter++;
    }

    secure_memzero(seed, sizeof(seed));
}

bool utils_word_count_valid(unsigned wc) { return wc == 12 || wc == 24; }

unsigned utils_word_count_bits(unsigned wc) {
    ASSERT_OR_DIE(utils_word_count_valid(wc), "word count not valid");
    return wc == 12 ? 128 : 256;
}

size_t utils_word_count_bytes(unsigned wc) {
    ASSERT_OR_DIE(utils_word_count_valid(wc), "word count not valid");
    return wc == 12 ? 16 : 32;
}

unsigned utils_floor_log2(uint64_t v) {
    ASSERT_OR_DIE(v > 0, "floor_log2: value must be > 0");
    unsigned bits = 0;
    for (; v > 1; v >>= 1) bits++;
    return bits;
}

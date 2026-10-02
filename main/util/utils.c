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

bool bytes_to_hex(const uint8_t* data, size_t len, char* out, size_t out_size) {
    if (!data || len == 0 || !out) return false;
    if (out_size == 0 || len > (out_size - 1) / 2) return false;
    for (size_t i = 0; i < len; i++) {
        int res = snprintf(out + i * 2, 3, "%02x", data[i]);
        if (res < 0 || (size_t)res >= 3) return false;
    }
    out[len * 2] = '\0';
    return true;
}

static int hex_digit_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool hex_to_bytes(const char* hex, size_t hex_len, uint8_t* out, size_t out_size) {
    if ((hex_len & 1u) || !out || out_size < hex_len / 2) return false;
    if (hex_len && !hex) return false;

    for (size_t i = 0; i < hex_len / 2; i++) {
        int hi = hex_digit_val(hex[2 * i]);
        int lo = hex_digit_val(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
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

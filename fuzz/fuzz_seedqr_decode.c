/**
 * @file fuzz/fuzz_seedqr_decode.c
 * @brief libFuzzer target for the SeedQR decoders
 */

#include "crypto/mnemonic.h"
#include "crypto/seedqr.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static bool initialized = false;
    if (!initialized) {
        mnemonic_init();
        initialized = true;
    }

    /* Compact decode: pass the raw bytes as entropy candidates. */
    mnemonic_t* c = seedqr_compact_decode(data, size);
    if (c) {
        /* Decoding must have produced a self-consistent mnemonic. */
        if (!mnemonic_words(c)) abort();
        mnemonic_discard(c);
    }

    /* Standard decode: interpret the input as a NUL-terminated digit stream. */
    char* digits = (char*)malloc(size + 1);
    if (!digits) return 0;
    memcpy(digits, data, size);
    digits[size] = '\0';

    mnemonic_t* s = seedqr_standard_decode(digits);
    if (s) {
        if (!mnemonic_words(s)) abort();
        mnemonic_discard(s);
    }

    free(digits);
    return 0;
}

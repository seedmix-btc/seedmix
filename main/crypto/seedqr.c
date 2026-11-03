/**
 * @file main/crypto/seedqr.c
 * @brief SeedQR (Standard + Compact) encode/decode of BIP39 mnemonics.
 *
 * Format reference: SeedSigner docs/seed_qr/README.md
 *  - Standard SeedQR: zero-padded 4-digit BIP39 word indices concatenated
 *    (48 chars for 12 words, 96 for 24 words).
 *  - CompactSeedQR: the raw entropy bytes (16 or 32).
 */

#include "seedqr.h"
#include "bip39_wordlist.h"

#include <stdio.h>
#include <string.h>

size_t seedqr_compact_encode(const mnemonic_t* m, uint8_t* out, size_t out_cap) {
    if (!m || !out) return 0;
    size_t elen = mnemonic_entropy_size(m);
    if (elen != 16 && elen != 32) return 0;
    if (out_cap < elen) return 0;
    return mnemonic_to_entropy(m, out);
}

mnemonic_t* seedqr_compact_decode(const uint8_t* entropy, size_t len) {
    if (!entropy || (len != 16 && len != 32)) return NULL;
    return mnemonic_from_entropy(entropy, len);
}

size_t seedqr_standard_encode(const mnemonic_t* m, char* out, size_t out_cap) {
    if (!m || !out) return 0;

    size_t elen = mnemonic_entropy_size(m);
    if (elen != 16 && elen != 32) return 0;

    size_t expected = (elen == 16) ? SEEDQR_STANDARD_12_DIGITS : SEEDQR_STANDARD_24_DIGITS;
    if (out_cap < expected + 1) return 0;

    const char* words = mnemonic_words(m);
    if (!words) return 0;

    char*  pos   = out;
    size_t total = 0;
    for (const char* p = words;;) {
        while (*p == ' ') p++;
        if (!*p) break;

        const char* start = p;
        while (*p && *p != ' ') p++;
        size_t wlen = (size_t)(p - start);
        if (wlen == 0 || wlen >= 16) return 0;

        char word[16];
        memcpy(word, start, wlen);
        word[wlen] = '\0';

        size_t idx = bip39_wordlist_index(word);
        if (idx == SIZE_MAX) return 0;

        int res = snprintf(pos, 5, "%04zu", idx);
        if (res != 4) return 0;
        pos += 4;
        total += 4;
    }

    if (total != expected) return 0;
    *pos = '\0';
    return total;
}

mnemonic_t* seedqr_standard_decode(const char* digits) {
    if (!digits) return NULL;

    size_t len = strlen(digits);
    if (len != SEEDQR_STANDARD_12_DIGITS && len != SEEDQR_STANDARD_24_DIGITS) return NULL;

    size_t word_count = (len == SEEDQR_STANDARD_12_DIGITS) ? 12u : 24u;
    char   words[512];
    char*  wpos = words;

    for (size_t i = 0; i < word_count; i++) {
        char grp[5];
        memcpy(grp, digits + i * 4, 4);
        grp[4] = '\0';

        // Exactly four decimal digits
        unsigned idx = 0;
        for (size_t d = 0; d < 4; d++) {
            if (grp[d] < '0' || grp[d] > '9') return NULL;
            idx = idx * 10u + (unsigned)(grp[d] - '0');
        }
        if (idx >= BIP39_WORD_COUNT) return NULL;

        const char* word = bip39_wordlist_word((size_t)idx);
        if (!word) return NULL;

        size_t wlen = strlen(word);
        size_t used = (size_t)(wpos - words);
        if (used + wlen + (i ? 1u : 0u) + 1u > sizeof(words)) return NULL;

        if (i) *wpos++ = ' ';
        memcpy(wpos, word, wlen);
        wpos += wlen;
    }
    *wpos = '\0';

    return mnemonic_from_string(words);
}

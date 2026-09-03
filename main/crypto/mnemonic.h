/**
 * @file main/crypto/mnemonic.h
 * @brief BIP39 mnemonic generation & entropy combining using libwally.
 */

#ifndef MNEMONIC_H
#define MNEMONIC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MNEMONIC_MAX_INPUT_LEN 512u

#ifdef __cplusplus
extern "C" {
#endif

typedef struct mnemonic_t mnemonic_t;

typedef void (*mnemonic_process_cb_t)(const char* process);

/**
 * @brief Initialize libwally.
 */
void mnemonic_init(void);

/** Access the words (read-only). */
const char* mnemonic_words(const mnemonic_t* m);

/**
 * @brief Generate `word_count` random words (12 or 24).
 */
mnemonic_t* mnemonic_generate(unsigned word_count, mnemonic_process_cb_t process_cb);

/**
 * @brief Create a mnemonic from raw entropy bytes.
 * @param bytes    Entropy (16 bytes -> 12 words, 32 bytes -> 24 words).
 * @param byte_len Must be 16 or 32.
 */
mnemonic_t* mnemonic_from_entropy(const uint8_t* bytes, size_t byte_len);

/**
 * @brief Extract the raw entropy from a mnemonic.
 * @param out     Buffer (must be at least mnemonic_entropy_size(m)).
 * @return        Number of bytes written (16 or 32).
 */
size_t mnemonic_to_entropy(const mnemonic_t* m, uint8_t* out);

/** Size of the entropy buffer (16 or 32). */
size_t mnemonic_entropy_size(const mnemonic_t* m);

/**
 * @brief XOR the entropy of two mnemonics (must have the same word count).
 *        The result is a new mnemonic.  Both inputs are discarded.
 */
mnemonic_t* mnemonic_combine(mnemonic_t* a, mnemonic_t* b);

/** Parse a space-separated mnemonic string (returns NULL on failure). */
mnemonic_t* mnemonic_from_string(const char* words);

/** Discard (zero + free). */
void mnemonic_discard(mnemonic_t* m);

#ifdef __cplusplus
}
#endif

#endif /* MNEMONIC_H */

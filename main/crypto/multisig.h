/**
 * @file main/crypto/multisig.h
 * @brief Build an m-of-n multisig descriptor from cosigner mnemonics.
 *
 * Each cosigner's BIP48 account key (m/48'/coin'/0'/2') is derived from its
 * words and only the public half is kept: the resulting wallet is a
 * `wsh(sortedmulti(m, ...))` descriptor over those account keys, receive and
 * change coming from the <0;1> multi-path, with a BIP-380 checksum.  Any
 * descriptor wallet (Sparrow, Nunchuk, Bitcoin Core) can import it.
 */

#ifndef MULTISIG_H
#define MULTISIG_H

#include "mnemonic.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Cosigners per wallet. 15 is multisig's own script limit. */
#define MULTISIG_MAX_KEYS 15
/** An extended key is 111 characters. */
#define MULTISIG_XPUB_MAX 128
/** Master fingerprint as lowercase hex, plus the NUL. */
#define MULTISIG_FP_MAX 9
/** "m/48'/0'/0'/2'" */
#define MULTISIG_PATH_MAX 32
/** Room for the largest wallet this module builds (15 keys), checksum included:
 * about 2.2 KB, since each cosigner brings a 147-character key entry. */
#define MULTISIG_DESCRIPTOR_MAX 3072
/** A mainnet bech32 address is 62 characters. */
#define MULTISIG_ADDR_MAX 64

/** Which network the wallet lives on. */
typedef enum {
    MULTISIG_MAINNET = 0, /**< xpub keys, "bc1..." addresses. */
    MULTISIG_TESTNET,     /**< tpub keys, "tb1..." addresses. */
} multisig_network_t;

typedef struct multisig multisig_t;

/**
 * @brief Start a wallet: @p keys cosigners, @p threshold of them needed to spend.
 * @return NULL when the sizes are out of range (2..MULTISIG_MAX_KEYS keys,
 *         1..keys threshold) or memory runs out.
 */
multisig_t* multisig_new(size_t keys, size_t threshold, multisig_network_t network);

/** Why a cosigner key was refused. */
typedef enum {
    MULTISIG_SET_OK = 0,           /**< Key stored. */
    MULTISIG_SET_BAD_SLOT,         /**< No such slot, or no words given. */
    MULTISIG_SET_INVALID_MNEMONIC, /**< Not a BIP39 phrase: word list or checksum. */
    MULTISIG_SET_DUPLICATE_KEY,    /**< Another cosigner already holds this seed. */
} multisig_set_result_t;

/**
 * @brief Fill cosigner @p slot from @p m.
 *
 * Derives m/48'/coin'/0'/2' and keeps the fingerprint, path and account xpub;
 * the words and the private key are wiped before returning.  A seed that is
 * already another cosigner of this wallet is refused: the same key twice would
 * make the spare cosigners meaningless and the descriptor misleading.
 */
bool multisig_set_mnemonic(multisig_t* ms, size_t slot, const mnemonic_t* m);

/** As multisig_set_mnemonic(), from a space-separated word string. */
bool multisig_set_words(multisig_t* ms, size_t slot, const char* words);

/**
 * As multisig_set_words(), reporting why the key was refused.
 *
 * @param duplicate_of When not NULL, receives the slot that already holds the
 *                     same key, or SIZE_MAX when the refusal was for another
 *                     reason.
 */
multisig_set_result_t multisig_set_words_ex(multisig_t* ms, size_t slot, const char* words,
                                            size_t* duplicate_of);

size_t multisig_key_count(const multisig_t* ms);
size_t multisig_threshold(const multisig_t* ms);
/** True when every slot has a key, i.e. the descriptor can be built. */
bool multisig_complete(const multisig_t* ms);
bool multisig_slot_ready(const multisig_t* ms, size_t slot);

/** Fingerprint of a filled slot ("1cf5be08"), NULL when it is empty. */
const char* multisig_slot_fingerprint(const multisig_t* ms, size_t slot);
/** Derivation path of a filled slot ("m/48'/0'/0'/2'"), NULL when empty. */
const char* multisig_slot_path(const multisig_t* ms, size_t slot);
/** Account xpub of a filled slot, NULL when empty. */
const char* multisig_slot_xpub(const multisig_t* ms, size_t slot);

/**
 * @brief The wallet descriptor, checksum included.
 * @return Length written, or 0 when the wallet is incomplete or @p cap is too
 *         small (the buffer is then left empty).
 */
size_t multisig_descriptor(const multisig_t* ms, char* out, size_t cap);

/**
 * @brief The cosigner's descriptor key: "[fp/48'/0'/0'/2']xpub/<0;1>" plus the
 *        `*` wildcard and no checksum.
 *
 * This is the record the other cosigners need from this seed, and it is what a
 * row of the wallet screen exports as a QR code.
 *
 * @return Length written, or 0 when the slot is empty or @p cap is too small.
 */
size_t multisig_cosigner_key(const multisig_t* ms, size_t slot, char* out, size_t cap);

/**
 * @brief A human-readable summary: threshold, one line per cosigner and the
 * first receive address, for the screen that shows the finished wallet.
 * @return Length written, or 0 when the wallet is incomplete or @p cap is small.
 */
size_t multisig_summary(const multisig_t* ms, char* out, size_t cap);

/**
 * @brief Address @p index of @p branch (0 receive, 1 change).
 * @return Length written, or 0 on failure (the buffer is then left empty).
 */
size_t multisig_address(const multisig_t* ms, uint32_t branch, uint32_t index, char* out,
                        size_t cap);

void multisig_free(multisig_t* ms);

#ifdef __cplusplus
}
#endif

#endif /* MULTISIG_H */

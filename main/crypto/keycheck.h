/**
 * @file main/crypto/keycheck.h
 * @brief Show the wallet a BIP39 mnemonic opens: the master fingerprint and,
 *        for each standard derivation policy, the account key and the first
 *        receive and change addresses.
 *
 * The point is verification: a seed that is written down and restored on a
 * wallet should produce the same fingerprint, account key and first address
 * here as it does there. Nothing is signed or stored, and no private key
 * leaves this module.
 */

#ifndef KEYCHECK_H
#define KEYCHECK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "mnemonic.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Longest account key: an extended key is 111 characters. */
#define KEYCHECK_XPUB_MAX 128
/** Longest address: a mainnet taproot address is 62 characters. */
#define KEYCHECK_ADDR_MAX 64
/** Master fingerprint as lowercase hex. */
#define KEYCHECK_FINGERPRINT_HEX_LEN 8
/** BIP44, BIP49, BIP84 and BIP86. */
#define KEYCHECK_POLICY_COUNT 4

/** How account keys and addresses are encoded. */
typedef enum {
    KEYCHECK_MAINNET = 0, /**< xpub/ypub/zpub and "bc1..." addresses. */
    KEYCHECK_TESTNET,     /**< tpub/upub/vpub and "tb1..." addresses. */
} keycheck_network_t;

/** One derivation policy. All strings are NUL-terminated and read-only. */
typedef struct {
    char label[24];                       /**< "Native SegWit (BIP84)" */
    char path[32];                        /**< "m/84'/0'/0'" (testnet uses coin type 1') */
    char account[KEYCHECK_XPUB_MAX];      /**< account key, SLIP-132 version */
    char account_xpub[KEYCHECK_XPUB_MAX]; /**< the same key as xpub/tpub, for descriptors */
    char account_xprv[KEYCHECK_XPUB_MAX]; /**< the matching xprv/tprv: secret */
    char receive[KEYCHECK_ADDR_MAX];      /**< m/.../0/0 */
    char change[KEYCHECK_ADDR_MAX];       /**< m/.../1/0 */
} keycheck_policy_t;

typedef struct keycheck keycheck_t;

/**
 * @brief Derive the master key for @p m.
 *
 * This is the slow part (BIP39's PBKDF2 stretch), so it is separate from the
 * per-policy work below: a UI can run it in the background and derive only the
 * policies it is about to show. The handle keeps the master private key in
 * memory until keycheck_free(); no policy is ready yet.
 *
 * @param m          A valid BIP39 mnemonic.
 * @param passphrase BIP39 passphrase, or NULL/"" for none. ASCII is expected:
 *                   the seed is not Unicode-normalised, so a passphrase with
 *                   non-ASCII characters may not match other wallets.
 * @param network    Which coin type and address encoding to use.
 * @return A handle (caller frees with keycheck_free()), or NULL on failure.
 */
keycheck_t* keycheck_begin(const mnemonic_t* m, const char* passphrase, keycheck_network_t network);

/**
 * @brief As keycheck_begin(), from the words themselves.
 *
 * For a background task, which must own everything it reads: the words are
 * copied before the task starts, so the caller may free its own copy.
 *
 * @param words Space-separated BIP39 mnemonic (validated by the caller).
 */
keycheck_t* keycheck_begin_words(const char* words, const char* passphrase,
                                 keycheck_network_t network);

/**
 * @brief Derive one policy: its account key and first receive/change address.
 *
 * Cheap next to keycheck_begin(), and idempotent: a policy that is already
 * ready is left alone. Call it on the UI task or on a background one, but
 * never for the same handle from two tasks at once.
 *
 * @return true when the policy is ready afterwards.
 */
bool keycheck_policy_derive(keycheck_t* k, size_t index);

/** Whether keycheck_policy_derive() has completed for @p index. */
bool keycheck_policy_ready(const keycheck_t* k, size_t index);

/** Short tab name for a policy: "BIP44", "BIP49", "BIP84", "BIP86". */
const char* keycheck_policy_tab(size_t index);

/**
 * @brief Derive every policy at once.
 *
 * @return A handle with all policies ready, or NULL on failure.
 */
keycheck_t* keycheck_derive(const mnemonic_t* m, const char* passphrase,
                            keycheck_network_t network);

/** Master fingerprint as 8 lowercase hex characters. */
const char* keycheck_fingerprint(const keycheck_t* k);

/** Number of policies (always KEYCHECK_POLICY_COUNT). */
size_t keycheck_policy_count(void);

/**
 * @brief One policy, or NULL when @p index is out of range.
 *
 * The pointer stays valid until keycheck_free().
 */
const keycheck_policy_t* keycheck_policy(const keycheck_t* k, size_t index);

/** "mainnet" / "testnet". */
const char* keycheck_network_name(keycheck_network_t network);

/**
 * @brief Build the output descriptor for a policy's account.
 *
 * Covers both branches, e.g. `wpkh([73c5da0a/84'/0'/0']xpub.../<0;1>/`
 * followed by `*`, and carries its BIP-380 checksum when libwally can
 * compute one.
 *
 * @param out Destination buffer (192 bytes is enough for every policy).
 * @param cap Size of @p out.
 * @return Bytes written excluding the NUL terminator, or 0 when the policy is
 *         not ready or @p out is too small.
 */
size_t keycheck_policy_descriptor(const keycheck_t* k, size_t index, char* out, size_t cap);

/**
 * @brief Render one policy as the text the keys screen shows for it.
 *
 * The label and account path, then the account key, the first receive address
 * and the first change address.
 *
 * @param out Destination buffer.
 * @param cap Size of @p out.
 * @return Bytes written excluding the NUL terminator, or 0 when the policy is
 *         not ready or @p out is too small (nothing is written then).
 */
size_t keycheck_policy_summary(const keycheck_t* k, size_t index, char* out, size_t cap);

/**
 * @brief Render every policy, one block after another (see
 *        keycheck_policy_summary()).
 *
 * @return Bytes written excluding the NUL terminator, or 0 when a policy is
 *         not ready or @p out is too small (nothing is written then).
 */
size_t keycheck_summary(const keycheck_t* k, char* out, size_t cap);

/** Discard (zero + free). */
void keycheck_free(keycheck_t* k);

#ifdef __cplusplus
}
#endif

#endif /* KEYCHECK_H */

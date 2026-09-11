/**
 * @file main/crypto/descriptor.h
 * @brief Parse a wallet output descriptor and match transaction outputs.
 *
 * A wallet descriptor (BIP 380/386 style, e.g. "wpkh([.../84'/0'/0']xpub.../0/<n>)")
 * is scanned from a QR before a transaction/PSBT so the tool can mark which
 * transaction outputs belong to the wallet (receive vs change).  Only public
 * (xpub) descriptors are accepted; descriptors carrying private keys are
 * rejected so no secret material ever has to live in memory.
 */

#ifndef DESCRIPTOR_H
#define DESCRIPTOR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Largest descriptor text accepted from a single QR. */
#define DESCRIPTOR_MAX_PAYLOAD 4096

/** Addresses derived per branch (the "gap limit") when matching outputs. */
#define DESCRIPTOR_GAP_LIMIT 20

typedef struct descriptor descriptor_t;

/** Parse result. */
typedef enum {
    DESCRIPTOR_OK = 0,       /**< Parsed successfully. */
    DESCRIPTOR_ERR_NOT_DESC, /**< Not a recognised descriptor. */
    DESCRIPTOR_ERR_PRIVATE,  /**< Contains private key material. */
    DESCRIPTOR_ERR_TOO_LONG, /**< Payload exceeds DESCRIPTOR_MAX_PAYLOAD. */
} descriptor_status_t;

/** Which part of the wallet an address belongs to. */
typedef enum {
    DESCRIPTOR_MATCH_NONE = 0, /**< Not derivable from the descriptor. */
    DESCRIPTOR_MATCH_RECEIVE,  /**< Derivable on the receive branch. */
    DESCRIPTOR_MATCH_CHANGE,   /**< Derivable on the change branch. */
} descriptor_match_t;

/**
 * @brief Parse a wallet output descriptor from scanned text.
 *
 * @param payload  Raw QR payload (descriptor text; a trailing "#checksum" is
 *                 validated and then ignored for derivation, surrounding
 *                 whitespace is ignored).
 * @param len      Number of bytes in @p payload.
 * @param status   Optional; receives the parse result when NULL is returned.
 * @return A parsed descriptor handle (caller frees with descriptor_free()),
 *         or NULL on failure.
 */
descriptor_t* descriptor_parse(const uint8_t* payload, size_t len, descriptor_status_t* status);

/** Release a handle returned by descriptor_parse(). */
void descriptor_free(descriptor_t* d);

/** True if @p address is derivable from the descriptor (any branch). */
bool descriptor_owns_address(const descriptor_t* d, const char* address);

/** Classify @p address as none / receive / change. */
descriptor_match_t descriptor_classify(const descriptor_t* d, const char* address);

#ifdef __cplusplus
}
#endif

#endif /* DESCRIPTOR_H */

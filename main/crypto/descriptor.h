/**
 * @file main/crypto/descriptor.h
 * @brief Parse a wallet output descriptor and match transaction outputs
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

/**
 * Size of the buffer descriptor_overview() needs. The overview is mostly the
 * descriptor text itself, so it can be as long as an accepted payload plus
 * room for the derived facts listed above it.
 */
#define DESCRIPTOR_OVERVIEW_MAX (DESCRIPTOR_MAX_PAYLOAD + 512)

typedef struct descriptor descriptor_t;

/** Parse result. */
typedef enum {
    DESCRIPTOR_OK = 0,       /**< Parsed successfully. */
    DESCRIPTOR_ERR_NOT_DESC, /**< Not a recognised descriptor. */
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
 *         or NULL on failure.  The handle keeps a copy of the descriptor text
 *         for descriptor_overview().
 */
descriptor_t* descriptor_parse(const uint8_t* payload, size_t len, descriptor_status_t* status);

/** Release a handle returned by descriptor_parse(). */
void descriptor_free(descriptor_t* d);

/** True if @p address is derivable from the descriptor (any branch). */
bool descriptor_owns_address(const descriptor_t* d, const char* address);

/** Classify @p address as none / receive / change. */
descriptor_match_t descriptor_classify(const descriptor_t* d, const char* address);

/**
 * @brief Render a human-readable overview of a parsed descriptor.
 *
 * The text lists what the descriptor is (script shape, key count, multisig
 * threshold), which network it belongs to, the origin (fingerprint and
 * derivation path) of each key, how many addresses of each branch are matched
 * against the transaction, and finally the descriptor text itself.  It is
 * meant to be shown on a scrollable screen between scanning a descriptor and
 * using it, so a wrong wallet can be spotted while it is still cheap to scan
 * another.
 *
 * @param d    Descriptor from descriptor_parse().
 * @param out  Destination buffer (DESCRIPTOR_OVERVIEW_MAX bytes is enough for
 *             any accepted descriptor).
 * @param cap  Size of @p out.
 * @return Number of bytes written, excluding the NUL terminator.  A buffer too
 *         small to hold the whole overview is filled up to the last complete
 *         line and then ends with a "... overview truncated ..." marker; 0 is
 *         returned only when nothing could be written at all.
 */
size_t descriptor_overview(const descriptor_t* d, char* out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif /* DESCRIPTOR_H */

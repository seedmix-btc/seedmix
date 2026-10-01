/**
 * @file main/crypto/ur_descriptor.h
 * @brief Decode wallet output descriptors from Blockchain Commons URs.
 */

#ifndef UR_DESCRIPTOR_H
#define UR_DESCRIPTOR_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Decode a "ur:output-descriptor/..." or "ur:crypto-output/..." UR.
 *
 * Accepts both the current BCR-2023-010 `output-descriptor` type (a CBOR map
 * whose key 1 holds the descriptor text, with optional `@N` key placeholders
 * substituted from the key array in key 2) and the deprecated BCR-2020-010
 * `crypto-output` type (a CBOR expression tree that is reconstructed back to
 * descriptor text).
 *
 * @param ur             UR string (not required to be NUL-terminated).
 * @param ur_len         Length of @p ur.
 * @param out_descriptor On success, set to a malloc'd NUL-terminated string
 *                       (caller frees) containing the descriptor text.
 * @return true on success; false on malformed input, unsupported structure,
 *         or private key material.
 */
bool ur_descriptor_decode(const char* ur, size_t ur_len, char** out_descriptor);

/**
 * @brief Stateful decoder for single-part and animated multi-part descriptor
 * URs ("ur:output-descriptor" / "ur:crypto-output").
 *
 * Descriptors for multi-key wallets are too large for one QR, so the sender
 * animates a BCR-2024-001 multi-part UR.  Feed every scanned QR payload with
 * ur_descriptor_decoder_receive() and show progress with the received() /
 * expected() accessors until it reports completion.
 */
typedef struct ur_descriptor_decoder ur_descriptor_decoder_t;

/** Allocate a descriptor UR decoder. */
ur_descriptor_decoder_t* ur_descriptor_decoder_new(void);

/** Release a descriptor UR decoder and any partially received parts. */
void ur_descriptor_decoder_free(ur_descriptor_decoder_t* d);

/** Fragments received so far (0 if no multi-part sequence in progress). */
size_t ur_descriptor_decoder_received(const ur_descriptor_decoder_t* d);

/** Total fragments expected (0 if no multi-part sequence in progress). */
size_t ur_descriptor_decoder_expected(const ur_descriptor_decoder_t* d);

/**
 * @brief Feed one UR string (single-part or multi-part).
 *
 * @param d               Decoder instance.
 * @param ur              UR string (not required to be NUL-terminated).
 * @param ur_len          Length of @p ur.
 * @param out_descriptor  On completion, set to a malloc'd NUL-terminated
 *                        string (caller frees); may be NULL.
 * @return 1 when the descriptor is complete, 0 when the part was accepted but
 *         more parts are needed (keep scanning), -1 when the input is not a
 *         valid descriptor UR part or decodes to an unsupported structure.
 */
int ur_descriptor_decoder_receive(ur_descriptor_decoder_t* d, const char* ur, size_t ur_len,
                                  char** out_descriptor);

#ifdef __cplusplus
}
#endif

#endif /* UR_DESCRIPTOR_H */

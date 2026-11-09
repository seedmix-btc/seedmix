/**
 * @file main/crypto/ur_psbt.h
 * @brief Decode/encode the PSBT UR payload type (BCR-2020-006).
 *
 * The PSBT UR type encodes the raw BIP-174 PSBT as the payload of a single
 * top-level CBOR byte string. This is the payload half of the UR stack; the
 * BCR-2020-005 framing (Bytewords, CRC-32) and the BCR-2024-001 multi-part
 * fountain decoder live in ur.h.
 */

#ifndef UR_PSBT_H
#define UR_PSBT_H

#include "ur.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Decode a "ur:psbt/..." (or deprecated "ur:crypto-psbt/...") UR.
 *
 * @param ur            UR string (not required to be NUL-terminated).
 * @param ur_len        Length of @p ur.
 * @param out_psbt      On success, set to a malloc'd buffer (caller frees)
 *                      containing the raw PSBT bytes.
 * @param out_psbt_len  On success, set to the PSBT byte length.
 * @return true on success; false on malformed input or invalid PSBT payload.
 */
bool ur_psbt_decode(const char* ur, size_t ur_len, uint8_t** out_psbt, size_t* out_psbt_len);

/**
 * @brief Encode raw PSBT bytes as a "ur:psbt/..." UR.
 *
 * @param psbt      Raw PSBT bytes.
 * @param psbt_len  Number of PSBT bytes.
 * @param out_ur    On success, set to a malloc'd NUL-terminated string
 *                  (caller frees).
 * @return true on success.
 */
bool ur_psbt_encode(const uint8_t* psbt, size_t psbt_len, char** out_ur);

/**
 * @brief Stateful decoder for single-part and animated multi-part PSBT URs.
 *
 * Specialisation of ur_decoder_t for the "psbt" / "crypto-psbt" types which
 * additionally unwraps the raw PSBT from its CBOR byte string. Feed each
 * scanned QR payload with ur_psbt_decoder_receive().
 */
typedef ur_decoder_t ur_psbt_decoder_t;

/** Allocate a PSBT UR decoder */
ur_psbt_decoder_t* ur_psbt_decoder_new(void);

/** Release a PSBT UR decoder and any partially received parts */
void ur_psbt_decoder_free(ur_psbt_decoder_t* d);

/**
 * @brief Feed one UR string (single-part or multi-part "ur:psbt")
 *
 * @param d          Decoder instance.
 * @param ur         UR string (not required to be NUL-terminated).
 * @param ur_len     Length of @p ur.
 * @param out_psbt   On completion, set to a malloc'd buffer (caller frees)
 *                   containing the raw PSBT bytes.
 * @param out_psbt_len  On completion, set to the PSBT byte length.
 * @return 1 when the PSBT is complete, 0 when the part was accepted but more
 *         parts are needed (keep scanning), -1 when the input is not a valid
 *         PSBT UR part
 */
int ur_psbt_decoder_receive(ur_psbt_decoder_t* d, const char* ur, size_t ur_len, uint8_t** out_psbt,
                            size_t* out_psbt_len);

/** Fragments received so far (0 if no multi-part sequence in progress). */
size_t ur_psbt_decoder_received(const ur_psbt_decoder_t* d);

/** Total fragments expected (0 if no multi-part sequence in progress). */
size_t ur_psbt_decoder_expected(const ur_psbt_decoder_t* d);

#ifdef __cplusplus
}
#endif

#endif /* UR_PSBT_H */

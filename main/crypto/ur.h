/**
 * @file main/crypto/ur.h
 * @brief Decode Blockchain Commons Uniform Resource (UR) payloads.
 *
 * Supports single-part "ur:<type>/<message>" strings as specified by
 * BCR-2020-005.  The message is minimal-Bytewords encoded (BCR-2020-012)
 * CBOR followed by a 4-byte big-endian CRC-32 checksum of the CBOR.
 *
 * The PSBT UR type (BCR-2020-006) encodes the raw BIP-174 PSBT as the payload
 * of a single top-level CBOR byte string.
 */

#ifndef UR_H
#define UR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Decode a single-part UR into its raw CBOR message bytes.
 *
 * @param ur         UR string (not required to be NUL-terminated).
 * @param ur_len     Length of @p ur.
 * @param type       Expected UR type (e.g. "seed", "psbt"); compared
 *                   case-insensitively.
 * @param out_cbor   On success, set to a malloc'd buffer (caller frees)
 *                   containing the CBOR message (checksum removed).
 * @param out_cbor_len  On success, set to the CBOR byte length.
 * @return true on success; false on malformed input, type mismatch, bad
 *         Bytewords, or checksum failure.
 */
bool ur_decode(const char* ur, size_t ur_len, const char* type, uint8_t** out_cbor,
               size_t* out_cbor_len);

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
 * @brief Encode raw CBOR bytes as a single-part "ur:<type>/..." UR.
 *
 * @param type     UR type string (e.g. "psbt", "output-descriptor"); must be
 *                 NUL-terminated and non-empty.
 * @param cbor     Raw CBOR message bytes.
 * @param cbor_len Number of CBOR bytes.
 * @param out_ur   On success, set to a malloc'd NUL-terminated string
 *                 (caller frees).
 * @return true on success; false on invalid arguments or length overflow.
 */
bool ur_encode(const char* type, const uint8_t* cbor, size_t cbor_len, char** out_ur);

/**
 * @brief CRC-32 (IEEE 802.3, same as zlib) of a byte range.
 */
uint32_t ur_crc32(const uint8_t* data, size_t len);

/**
 * @brief Stateful decoder for single-part and animated multi-part URs.
 *
 * Feed each scanned QR payload with ur_decoder_receive(); multi-part parts are
 * accumulated (using the BCR-2024-001 fountain code) until the complete CBOR
 * message has been reassembled.  Only the UR types passed to ur_decoder_new()
 * are accepted.
 */
typedef struct ur_decoder ur_decoder_t;

/**
 * @brief Allocate a decoder that accepts the given UR types.
 *
 * @param types    Array of NUL-terminated UR type strings (e.g. "psbt").
 *                 The array must remain valid for the decoder's lifetime.
 * @param n_types  Number of entries in @p types (must be > 0).
 * @return A decoder handle, or NULL on invalid arguments / out of memory.
 */
ur_decoder_t* ur_decoder_new(const char* const* types, size_t n_types);

/** Release a decoder and any partially received parts. */
void ur_decoder_free(ur_decoder_t* d);

/**
 * @brief Feed one UR string (single-part or multi-part) to a decoder.
 *
 * @param d             Decoder instance.
 * @param ur            UR string (not required to be NUL-terminated).
 * @param ur_len        Length of @p ur.
 * @param out_cbor      On completion, set to a malloc'd buffer (caller frees)
 *                      containing the raw CBOR message (checksum removed).
 * @param out_cbor_len  On completion, set to the CBOR byte length.
 * @return 1 when the message is complete, 0 when the part was accepted but
 *         more parts are needed (keep scanning), -1 when the input is not a
 *         valid part of one of the expected UR types.
 */
int ur_decoder_receive(ur_decoder_t* d, const char* ur, size_t ur_len, uint8_t** out_cbor,
                       size_t* out_cbor_len);

/** Fragments received so far (0 if no multi-part sequence in progress). */
size_t ur_decoder_received(const ur_decoder_t* d);

/** Total fragments expected (0 if no multi-part sequence in progress). */
size_t ur_decoder_expected(const ur_decoder_t* d);

/**
 * @brief Stateful decoder for single-part and animated multi-part PSBT URs.
 *
 * Specialisation of ur_decoder_t for the "psbt" / "crypto-psbt" types which
 * additionally unwraps the raw PSBT from its CBOR byte string.  Feed each
 * scanned QR payload with ur_psbt_decoder_receive().
 */
typedef ur_decoder_t ur_psbt_decoder_t;

/** Allocate a PSBT UR decoder. */
ur_psbt_decoder_t* ur_psbt_decoder_new(void);

/** Release a PSBT UR decoder and any partially received parts. */
void ur_psbt_decoder_free(ur_psbt_decoder_t* d);

/**
 * @brief Feed one UR string (single-part or multi-part "ur:psbt").
 *
 * @param d          Decoder instance.
 * @param ur         UR string (not required to be NUL-terminated).
 * @param ur_len     Length of @p ur.
 * @param out_psbt   On completion, set to a malloc'd buffer (caller frees)
 *                   containing the raw PSBT bytes.
 * @param out_psbt_len  On completion, set to the PSBT byte length.
 * @return 1 when the PSBT is complete, 0 when the part was accepted but more
 *         parts are needed (keep scanning), -1 when the input is not a valid
 *         PSBT UR part.
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

#endif /* UR_H */

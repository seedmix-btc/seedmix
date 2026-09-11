/**
 * @file main/crypto/fountain.h
 * @brief Fountain-code (Luby transform) decoding for Multipart URs (BCR-2024-001).
 *
 * A multipart UR message is split into `seq_len` equal-sized fragments; parts
 * are either a single fragment (seqNum <= seqLen) or the XOR of several
 * fragments chosen deterministically (seqNum > seqLen).  This decoder
 * reassembles the original message from an arbitrary subset of parts.
 */

#ifndef FOUNTAIN_H
#define FOUNTAIN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct fountain_decoder fountain_decoder_t;

fountain_decoder_t* fountain_decoder_new(void);
void                fountain_decoder_free(fountain_decoder_t* d);

/**
 * @brief Feed one fountain part.
 *
 * @param d            Decoder instance.
 * @param seq_num      Part sequence number (>= 1).
 * @param seq_len      Total number of fragments.
 * @param message_len  Final (unpadded) message length.
 * @param checksum     CRC-32 of the message (verifies reassembly).
 * @param data         Part payload (exactly @p data_len bytes; all parts have
 *                     the same length).
 * @param data_len     Length of @p data.
 * @param out_message  On success, set to a malloc'd buffer (caller frees).
 * @param out_message_len  On success, set to @p message_len.
 * @return 1 when the message has been reassembled, 0 when the part was
 *         accepted but more parts are needed (this includes duplicates, so a
 *         caller that re-scans the same QR keeps going), -1 when the part is
 *         invalid (bad geometry) or out of memory.
 *
 * The geometry is validated against BCR-2024-001 (equal fragments of
 * ``ceil(message_len / seq_len)`` bytes) before anything is allocated, so a
 * hostile part cannot drive a large allocation or make reassembly read past
 * the fragment store.  A rejected part leaves the decoder reusable.
 */
int fountain_decoder_receive(fountain_decoder_t* d, uint32_t seq_num, size_t seq_len,
                             size_t message_len, uint32_t checksum, const uint8_t* data,
                             size_t data_len, uint8_t** out_message, size_t* out_message_len);

/** Number of distinct fragments received so far. */
size_t fountain_decoder_received(const fountain_decoder_t* d);

/** Total number of fragments needed (0 until the first valid part). */
size_t fountain_decoder_expected(const fountain_decoder_t* d);

/**
 * @brief Compute the fragment indexes chosen for a fountain part.
 *
 * For @p seq_num <= @p seq_len this is the single fragment {@p seq_num - 1};
 * otherwise the deterministic fountain selection is used.  @p mask must have
 * at least @p mask_len bytes (bits beyond @p seq_len are left clear).
 *
 * @return true on success; false when the selection state cannot be allocated
 *         (in which case @p mask is left empty and the part must be rejected).
 */
bool fountain_choose_fragments(uint32_t seq_num, size_t seq_len, uint32_t checksum, uint8_t* mask,
                               size_t mask_len);

#ifdef __cplusplus
}
#endif

#endif /* FOUNTAIN_H */

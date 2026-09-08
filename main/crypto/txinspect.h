/**
 * @file main/crypto/txinspect.h
 * @brief Parse and summarise a Bitcoin transaction or PSBT scanned from a QR.
 *
 * The input payload may be:
 *  - a raw transaction in hex (with or without witness data),
 *  - a PSBT as raw bytes (magic "psbt\xff"),
 *  - a PSBT as base64 ("cHNidP..."),
 *  - a PSBT as a UR ("ur:psbt/..." or deprecated "ur:crypto-psbt/...").
 *
 * The summary exposes the transaction inputs and outputs, and a warning
 * when signature nonce reuse is detected (a strong signal that signatures
 * were produced by a broken RNG rather than deterministically per RFC 6979).
 */

#ifndef TXINSPECT_H
#define TXINSPECT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Largest payload accepted by tx_inspect_parse() (single QR v40 ~2953 bytes). */
#define TXINSPECT_MAX_PAYLOAD 4096

/** Largest rendered summary text (including NUL terminator). */
#define TXINSPECT_RENDER_MAX 4096

/** Largest nonce-warning message (including NUL terminator). */
#define TXINSPECT_WARNING_MAX 256

typedef enum {
    TX_INSPECT_KIND_TX = 0, /**< Raw (possibly witness) transaction. */
    TX_INSPECT_KIND_PSBT,   /**< Partially signed bitcoin transaction. */
} tx_inspect_kind_t;

typedef struct tx_inspect tx_inspect_t;

/**
 * @brief Parse a transaction/PSBT payload.
 *
 * @param payload  Raw bytes (hex string, PSBT bytes, PSBT base64, or a
 *                 UR-encoded PSBT).
 * @param len      Number of bytes in @p payload.
 * @return A parsed inspection handle, or NULL if the payload is not a
 *         recognised transaction or PSBT.
 */
tx_inspect_t* tx_inspect_parse(const uint8_t* payload, size_t len);

/** Release a handle returned by tx_inspect_parse(). */
void tx_inspect_free(tx_inspect_t* t);

/** The detected input kind (TX or PSBT). */
tx_inspect_kind_t tx_inspect_kind(const tx_inspect_t* t);

/** Human-readable kind name ("Transaction" / "PSBT"). */
const char* tx_inspect_kind_name(const tx_inspect_t* t);

/** Number of transaction inputs. */
size_t tx_inspect_num_inputs(const tx_inspect_t* t);

/** Number of transaction outputs. */
size_t tx_inspect_num_outputs(const tx_inspect_t* t);

/**
 * @brief Total input value in satoshi.
 *
 * Only known for PSBTs that carry witness/non-witness UTXOs for every input;
 * returns 0 when any input amount is unknown (raw transactions).
 */
uint64_t tx_inspect_total_in(const tx_inspect_t* t);

/** Total output value in satoshi. */
uint64_t tx_inspect_total_out(const tx_inspect_t* t);

/** Ownership classification for a transaction output. */
typedef enum {
    TX_OUTPUT_NONE = 0, /**< Not matched against a wallet descriptor. */
    TX_OUTPUT_RECEIVE,  /**< Matches the descriptor receive branch. */
    TX_OUTPUT_CHANGE,   /**< Matches the descriptor change branch. */
} tx_output_kind_t;

/**
 * @brief Classify a rendered output address (e.g. via a wallet descriptor).
 *
 * @param ctx        Opaque caller context.
 * @param out_index  Zero-based output index.
 * @param address    Rendered address of that output (NUL-terminated).
 * @return The ownership classification for the output.
 */
typedef tx_output_kind_t (*tx_inspect_output_cb)(void* ctx, size_t out_index, const char* address);

/**
 * @brief Render a multi-line, human-readable summary into @p out.
 *
 * Includes the kind, txid, input outpoints (with amounts when known), output
 * amounts/addresses and the fee when it can be computed.  When @p classify is
 * non-NULL each output line is annotated with its ownership ("<- receive" /
 * "<- change") as reported by the callback.
 */
void tx_inspect_render_ex(const tx_inspect_t* t, char* out, size_t out_size,
                          tx_inspect_output_cb classify, void* ctx);

/**
 * @brief Render a summary without output ownership annotation.
 *
 * Equivalent to tx_inspect_render_ex(t, out, out_size, NULL, NULL).
 */
void tx_inspect_render(const tx_inspect_t* t, char* out, size_t out_size);

/**
 * @brief Report a signature nonce reuse warning.
 *
 * @return true when nonce reuse was detected (signatures were not produced
 *         with a fresh, deterministic RFC 6979 nonce); @p msg is then filled
 *         with a warning string.  Returns false otherwise.
 */
bool tx_inspect_nonce_warning(const tx_inspect_t* t, char* msg, size_t msg_size);

#ifdef __cplusplus
}
#endif

#endif /* TXINSPECT_H */

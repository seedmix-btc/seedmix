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
 * The summary exposes the network, the (un)signed txid, locktime, RBF and
 * sighash type, the transaction inputs and outputs, and a warning when
 * signature nonce reuse is detected (a strong signal that signatures were
 * produced by a broken RNG rather than deterministically per RFC 6979).
 *
 * Bitcoin is not self-describing about the network it is used on: the same
 * output script is spendable on mainnet and on testnet alike, and only the
 * address *encoding* differs.  The caller must therefore say which network a
 * payload should be interpreted as (tx_inspect_set_network); the default is
 * mainnet.
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

/**
 * Bitcoin network a payload is interpreted against.
 *
 * This only affects presentation: the Bech32 HRP and the Base58 version
 * bytes used when rendering output scripts as addresses.  Parsing is network
 * agnostic because the network is not encoded in the transaction itself.
 */
typedef enum {
    TX_INSPECT_NETWORK_MAINNET = 0, /**< "bc" / mainnet version bytes. */
    TX_INSPECT_NETWORK_TESTNET,     /**< "tb" / testnet version bytes. */
    TX_INSPECT_NETWORK_SIGNET,      /**< "tb" / testnet version bytes. */
    TX_INSPECT_NETWORK_REGTEST,     /**< "bcrt" / testnet version bytes. */
} tx_inspect_network_t;

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

/**
 * @brief Set the network used to render output addresses.
 *
 * Call this before tx_inspect_render*(); the default for a freshly parsed
 * handle is TX_INSPECT_NETWORK_MAINNET.  Passing NULL is a no-op.
 */
void tx_inspect_set_network(tx_inspect_t* t, tx_inspect_network_t network);

/** The network used for address rendering. */
tx_inspect_network_t tx_inspect_network(const tx_inspect_t* t);

/** Human-readable network name ("mainnet", "testnet", "signet", "regtest"). */
const char* tx_inspect_network_name(tx_inspect_network_t network);

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

/**
 * @brief Whether the transaction is fully signed (its txid is final).
 *
 * For a PSBT this is true when every input has been finalised (a final
 * scriptSig or final scriptWitness is present); for a raw transaction it is
 * true when every input carries a non-empty scriptSig or witness.  A PSBT
 * whose inputs only carry partial signatures is *not* signed: for a
 * non-segwit input the scriptSig is still to be filled in, which changes the
 * txid.
 */
bool tx_inspect_is_signed(const tx_inspect_t* t);

/** Transaction locktime (0 when disabled). */
uint32_t tx_inspect_locktime(const tx_inspect_t* t);

/**
 * @brief Whether any input signals BIP-125 replace-by-fee.
 *
 * True when any input sequence is below 0xfffffffe.  Note that 0xfffffffe and
 * 0xffffffff do *not* opt in to replacement.
 */
bool tx_inspect_rbf(const tx_inspect_t* t);

/**
 * @brief Collect the distinct sighash types used by the transaction.
 *
 * Values are taken from the PSBT per-input sighash fields when present and
 * otherwise from the trailing byte of the DER signatures found in the input
 * scriptSigs/witnesses.
 *
 * @param out  Buffer for up to @p max distinct sighash values (may be NULL to
 *             only count).
 * @return The number of distinct sighash types found (0 when none are known).
 */
size_t tx_inspect_sighash(const tx_inspect_t* t, uint32_t* out, size_t max);

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
 * Includes the kind, network, txid (marked signed/unsigned), locktime, RBF,
 * sighash, input outpoints (with amounts when known), output
 * amounts/addresses and the fee when it can be computed.  When @p classify is
 * non-NULL each output line is annotated with its ownership ("<- receive" /
 * "<- change") as reported by the callback.
 *
 * If the summary does not fit in @p out_size the text is cut at a line
 * boundary and an explicit "... truncated ..." marker is appended, so a
 * summary is never silently shortened.
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

/**
 * @file fuzz/fuzz_txinspect.c
 * @brief libFuzzer target for tx_inspect_parse() (untrusted QR-scan input).
 *
 * Feeds arbitrary bytes into the transaction/PSBT parser and, on success,
 * exercises the accessors, renderer and nonce-warning path.  The parser must
 * never crash or over-read on hostile input.
 */

#include "crypto/txinspect.h"

#include <stdint.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0 || size > TXINSPECT_MAX_PAYLOAD) return 0;

    tx_inspect_t* t = tx_inspect_parse(data, size);
    if (!t) return 0;

    (void)tx_inspect_kind(t);
    (void)tx_inspect_kind_name(t);
    (void)tx_inspect_num_inputs(t);
    (void)tx_inspect_num_outputs(t);
    (void)tx_inspect_total_in(t);
    (void)tx_inspect_total_out(t);

    char body[TXINSPECT_RENDER_MAX];
    tx_inspect_render(t, body, sizeof(body));

    char warn[TXINSPECT_WARNING_MAX];
    tx_inspect_nonce_warning(t, warn, sizeof(warn));

    tx_inspect_free(t);
    return 0;
}

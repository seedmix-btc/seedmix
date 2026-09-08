/**
 * @file fuzz/fuzz_ur.c
 * @brief libFuzzer target for the UR/Bytewords PSBT decoder (untrusted QR input).
 */

#include "crypto/ur.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0 || size > 4096) return 0;

    char* buf = (char*)malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    uint8_t* out     = NULL;
    size_t   out_len = 0;
    if (ur_psbt_decode(buf, size, &out, &out_len)) free(out);

    /* Also exercise the stateful single/multi-part decoder. */
    ur_psbt_decoder_t* d = ur_psbt_decoder_new();
    if (d) {
        out     = NULL;
        out_len = 0;
        if (ur_psbt_decoder_receive(d, buf, size, &out, &out_len) == 1) free(out);
        ur_psbt_decoder_free(d);
    }

    free(buf);
    return 0;
}

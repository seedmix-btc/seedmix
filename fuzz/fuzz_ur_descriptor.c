/**
 * @file fuzz/fuzz_ur_descriptor.c
 * @brief libFuzzer target for the descriptor UR decoder (untrusted QR input).
 *
 * Feeds arbitrary bytes into ur_descriptor_decode() and, on success, into the
 * wallet-descriptor parser.  Both parsers must never crash or over-read on
 * hostile input.
 */

#include "crypto/descriptor.h"
#include "crypto/ur_descriptor.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0 || size > DESCRIPTOR_MAX_PAYLOAD) return 0;

    char* buf = (char*)malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    char* desc = NULL;
    if (ur_descriptor_decode(buf, size, &desc)) {
        descriptor_status_t st = DESCRIPTOR_ERR_NOT_DESC;
        descriptor_t*       d  = descriptor_parse((const uint8_t*)desc, strlen(desc), &st);
        descriptor_free(d);
        free(desc);
    }

    free(buf);
    return 0;
}

/**
 * @file main/crypto/ur_psbt.c
 * @brief Decode/encode the PSBT UR payload type (BCR-2020-006).
 *
 * The PSBT UR payload is the raw BIP-174 PSBT wrapped in a single top-level
 * CBOR byte string. Only ur.h's public transport API is used here (ur_decode,
 * ur_encode, ur_decoder_*), so this file needs no libwally and no knowledge of
 * the other payload types
 */

#include "ur_psbt.h"
#include "ur.h"

#include <stdlib.h>
#include <string.h>

/* PSBT magic bytes: "psbt" + 0xff (BIP 174) */
static const uint8_t PSBT_MAGIC[5] = {0x70, 0x73, 0x62, 0x74, 0xff};

/* -- CBOR byte string -------------------------------------------------- */
/* Parse a definite-length CBOR byte string (major type 2).  On success sets
 * *hdr (header length) and *data_len (payload length). */
static int cbor_byte_string(const uint8_t* buf, size_t len, size_t* hdr, size_t* data_len) {
    if (len == 0 || (buf[0] >> 5) != 2) return -1;
    uint8_t ai = buf[0] & 0x1Fu;
    if (ai < 24) {
        *hdr      = 1;
        *data_len = ai;
        return 0;
    }
    if (ai == 24) {
        if (len < 2) return -1;
        *hdr      = 2;
        *data_len = buf[1];
        return 0;
    }
    if (ai == 25) {
        if (len < 3) return -1;
        *hdr      = 3;
        *data_len = ((size_t)buf[1] << 8) | buf[2];
        return 0;
    }
    if (ai == 26) {
        if (len < 5) return -1;
        *hdr = 5;
        *data_len =
            ((size_t)buf[1] << 24) | ((size_t)buf[2] << 16) | ((size_t)buf[3] << 8) | buf[4];
        return 0;
    }
    /* 8-byte length and indefinite-length byte strings are unsupported. */
    return -1;
}

/* -- Decode ------------------------------------------------------------ */
bool ur_psbt_decode(const char* ur, size_t ur_len, uint8_t** out_psbt, size_t* out_psbt_len) {
    if (!ur || !out_psbt || !out_psbt_len) return false;
    *out_psbt     = NULL;
    *out_psbt_len = 0;

    uint8_t* cbor     = NULL;
    size_t   cbor_len = 0;
    if (!ur_decode(ur, ur_len, "psbt", &cbor, &cbor_len) &&
        !ur_decode(ur, ur_len, "crypto-psbt", &cbor, &cbor_len))
        return false;

    /* The PSBT UR type wraps the raw PSBT in a single CBOR byte string. */
    size_t hdr = 0, psbt_len = 0;
    if (cbor_byte_string(cbor, cbor_len, &hdr, &psbt_len) != 0 || hdr + psbt_len != cbor_len ||
        psbt_len < sizeof(PSBT_MAGIC) || memcmp(cbor + hdr, PSBT_MAGIC, sizeof(PSBT_MAGIC)) != 0) {
        free(cbor);
        return false;
    }

    uint8_t* psbt = malloc(psbt_len);
    if (!psbt) {
        free(cbor);
        return false;
    }
    memcpy(psbt, cbor + hdr, psbt_len);
    free(cbor);

    *out_psbt     = psbt;
    *out_psbt_len = psbt_len;
    return true;
}

/* -- Encode ------------------------------------------------------------ */
bool ur_psbt_encode(const uint8_t* psbt, size_t psbt_len, char** out_ur) {
    if (!psbt || psbt_len == 0 || !out_ur) return false;
    *out_ur = NULL;

    /* CBOR byte-string header for the PSBT payload */
    uint8_t hdr[5];
    size_t  hdr_len = 0;
    if (psbt_len < 24) {
        hdr[0]  = (uint8_t)(0x40 | psbt_len);
        hdr_len = 1;
    } else if (psbt_len <= 0xFF) {
        hdr[0]  = 0x58;
        hdr[1]  = (uint8_t)psbt_len;
        hdr_len = 2;
    } else if (psbt_len <= 0xFFFF) {
        hdr[0]  = 0x59;
        hdr[1]  = (uint8_t)(psbt_len >> 8);
        hdr[2]  = (uint8_t)psbt_len;
        hdr_len = 3;
    } else if (psbt_len <= 0xFFFFFFFFu) {
        hdr[0]  = 0x5A;
        hdr[1]  = (uint8_t)(psbt_len >> 24);
        hdr[2]  = (uint8_t)(psbt_len >> 16);
        hdr[3]  = (uint8_t)(psbt_len >> 8);
        hdr[4]  = (uint8_t)psbt_len;
        hdr_len = 5;
    } else {
        return false;
    }

    size_t   cbor_len = hdr_len + psbt_len;
    uint8_t* cbor     = malloc(cbor_len);
    if (!cbor) return false;
    memcpy(cbor, hdr, hdr_len);
    memcpy(cbor + hdr_len, psbt, psbt_len);

    bool ok = ur_encode("psbt", cbor, cbor_len, out_ur);
    free(cbor);
    return ok;
}

/* -- Stateful decoder (specialisation of the generic decoder) ---------- */
static const char* const UR_PSBT_TYPES[] = {"psbt", "crypto-psbt"};

ur_psbt_decoder_t* ur_psbt_decoder_new(void) {
    return ur_decoder_new(UR_PSBT_TYPES, sizeof(UR_PSBT_TYPES) / sizeof(UR_PSBT_TYPES[0]));
}

void ur_psbt_decoder_free(ur_psbt_decoder_t* d) { ur_decoder_free(d); }

size_t ur_psbt_decoder_received(const ur_psbt_decoder_t* d) { return ur_decoder_received(d); }

size_t ur_psbt_decoder_expected(const ur_psbt_decoder_t* d) { return ur_decoder_expected(d); }

int ur_psbt_decoder_receive(ur_psbt_decoder_t* d, const char* ur, size_t ur_len, uint8_t** out_psbt,
                            size_t* out_psbt_len) {
    if (out_psbt) *out_psbt = NULL;
    if (out_psbt_len) *out_psbt_len = 0;

    uint8_t* msg     = NULL;
    size_t   msg_len = 0;
    int      r       = ur_decoder_receive(d, ur, ur_len, &msg, &msg_len);
    if (r != 1) return r;

    /* The PSBT UR type wraps the raw PSBT in a single CBOR byte string. */
    size_t hdr = 0, psbt_len = 0;
    if (cbor_byte_string(msg, msg_len, &hdr, &psbt_len) != 0 || hdr + psbt_len != msg_len ||
        psbt_len < sizeof(PSBT_MAGIC) || memcmp(msg + hdr, PSBT_MAGIC, sizeof(PSBT_MAGIC)) != 0) {
        free(msg);
        return -1;
    }

    uint8_t* psbt = malloc(psbt_len);
    if (!psbt) {
        free(msg);
        return -1;
    }
    memcpy(psbt, msg + hdr, psbt_len);
    free(msg);
    if (out_psbt) {
        *out_psbt = psbt;
    } else {
        free(psbt);
    }
    if (out_psbt_len) *out_psbt_len = psbt_len;
    return 1;
}

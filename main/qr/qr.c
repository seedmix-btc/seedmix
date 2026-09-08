/**
 * @file main/qr/qr.c
 * @brief Thin wrapper over libqrencode (encode) and quirc (decode).
 */

#include "qr.h"

#include <qrencode.h>
#include <quirc.h>

#include <limits.h>
#include <stdlib.h>
#include <string.h>

/* Largest side accepted by qr_decode().  Must exceed the camera's largest
 * dimension (the Linux HAL requests 640x480), otherwise webcam frames are
 * rejected outright before quirc gets a chance to decode them. */
#define QR_SIDE_MAX 1024u
#define QR_SIZE_MAX (QR_SIDE_MAX * QR_SIDE_MAX)

bool qr_encode(const uint8_t* data, size_t len, qr_mode_t mode, qr_grid_t* out) {
    if (!data || len == 0 || len > INT_MAX || !out) return false;

    QRinput* input = QRinput_new2(0, QR_ECLEVEL_L);
    if (!input) return false;

    QRencodeMode m = (mode == QR_MODE_NUMERIC) ? QR_MODE_NUM : QR_MODE_8;
    if (QRinput_append(input, m, (int)len, data) < 0) {
        QRinput_free(input);
        return false;
    }

    QRcode* qr = QRcode_encodeInput(input);
    QRinput_free(input);
    if (!qr) return false;

    uint32_t n     = (uint32_t)qr->width;
    uint8_t* cells = (uint8_t*)calloc((size_t)n * n, 1);
    if (!cells) {
        QRcode_free(qr);
        return false;
    }

    for (uint32_t y = 0; y < n; y++) {
        for (uint32_t x = 0; x < n; x++) {
            // libqrencode stores one byte per module (0/1), row-major
            cells[(size_t)y * n + x] = (qr->data[y * n + x] & 1) ? 1u : 0u;
        }
    }

    QRcode_free(qr);

    out->cells = cells;
    out->size  = n;
    return true;
}

void qr_grid_free(qr_grid_t* g) {
    if (!g) return;
    free(g->cells);
    g->cells = NULL;
    g->size  = 0;
}

bool qr_decode(const uint8_t* gray, uint32_t w, uint32_t h, uint8_t* payload, size_t payload_cap,
               size_t* out_len) {
    if (!gray || !payload || !out_len || w == 0 || h == 0 || payload_cap == 0) return false;

    if (w > QR_SIDE_MAX || h > QR_SIDE_MAX || (size_t)w * (size_t)h > QR_SIZE_MAX) return false;

    struct quirc* q = quirc_new();
    if (!q) return false;
    if (quirc_resize(q, (int)w, (int)h) < 0) {
        quirc_destroy(q);
        return false;
    }

    uint8_t* buf = quirc_begin(q, NULL, NULL);
    memcpy(buf, gray, (size_t)w * h);
    quirc_end(q);

    bool ok = false;
    int  n  = quirc_count(q);
    for (int i = 0; i < n; i++) {
        struct quirc_code code;
        struct quirc_data data;
        quirc_extract(q, i, &code);
        if (quirc_decode(&code, &data) == QUIRC_SUCCESS && (size_t)data.payload_len > 0 &&
            (size_t)data.payload_len <= payload_cap) {
            memcpy(payload, data.payload, data.payload_len);
            *out_len = data.payload_len;
            ok       = true;
            break;
        }
    }

    quirc_destroy(q);
    return ok;
}

/**
 * @file main/qr/qr.h
 * @brief Thin wrapper over libqrencode (encode) and quirc (decode).
 */

#ifndef QR_H
#define QR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/** A square QR bitmap: `size` x `size` modules, 1 = dark, 0 = light. */
typedef struct {
    uint8_t* cells; /* size*size bytes */
    uint32_t size;
} qr_grid_t;

/** QR data mode. */
typedef enum { QR_MODE_BYTE, QR_MODE_NUMERIC } qr_mode_t;

/**
 * @brief Encode @p len bytes as a QR bitmap (ECC "L").
 *
 * @param mode QR_MODE_BYTE for binary data, QR_MODE_NUMERIC for a digit string.
 * @return true on success; the caller owns @p out and must qr_grid_free() it.
 */
bool qr_encode(const uint8_t* data, size_t len, qr_mode_t mode, qr_grid_t* out);

/** Release a grid produced by qr_encode(). */
void qr_grid_free(qr_grid_t* g);

/**
 * Largest image side accepted by qr_decode().
 *
 * Images read from a file (screenshots, photos) can be much larger than a
 * camera frame, so platform code that loads them must downscale to this limit
 * before calling qr_decode().
 */
#define QR_DECODE_SIDE_MAX 1024u

/** Largest image (width * height) accepted by qr_decode(). */
#define QR_DECODE_PIXELS_MAX ((size_t)QR_DECODE_SIDE_MAX * (size_t)QR_DECODE_SIDE_MAX)

/**
 * @brief Decode a QR from a row-major grayscale image (1 byte/pixel).
 * @return true and writes the raw payload into @p payload on success.
 */
bool qr_decode(const uint8_t* gray, uint32_t w, uint32_t h, uint8_t* payload, size_t payload_cap,
               size_t* out_len);

#endif /* QR_H */

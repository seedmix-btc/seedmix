/**
 * @file main/crypto/touch.c
 * @brief Touch-screen entropy collection.
 */

#include "touch.h"
#include "util/error.h"
#include "util/utils.h"
#include <stdlib.h>
#include <string.h>

// Twice the seed size: half the tapped bits are assumed to be noise, and hashing
// two bits of raw material per seed bit is the usual hedge for a hand-entered
// source.  512 bits covers a 24-word seed.
#define TOUCH_OVERSAMPLE 2u
#define TOUCH_BUF_BYTES ((256u * TOUCH_OVERSAMPLE) / 8u)

struct touch_entropy_t {
    uint8_t  bits_buf[TOUCH_BUF_BYTES]; // tapped bits, most-significant first
    uint32_t bits;
    uint32_t target;
    uint32_t res_x, res_y;
    unsigned taps;
    unsigned last_tile;
    size_t   entropy_len; // 16 or 32 bytes
};

// Append one bit, stopping at the target (the buffer is already full).
static void touch_append_bit(touch_entropy_t* t, unsigned bit) {
    if (t->bits >= t->target) return;
    if (bit) t->bits_buf[t->bits >> 3] |= (uint8_t)(0x80u >> (t->bits & 7u));
    t->bits++;
}

touch_entropy_t* touch_entropy_begin(unsigned word_count, uint32_t res_x, uint32_t res_y) {
    ASSERT_OR_DIE(utils_word_count_valid(word_count), "word count must be 12 or 24");
    ASSERT_OR_DIE(res_x > 0 && res_y > 0, "invalid resolution");

    touch_entropy_t* t = calloc(1, sizeof(*t));
    ASSERT_OR_DIE(t, "out of memory");

    t->entropy_len = utils_word_count_bytes(word_count);
    t->target      = (uint32_t)t->entropy_len * 8u * TOUCH_OVERSAMPLE;
    t->res_x       = res_x;
    t->res_y       = res_y;
    t->last_tile   = 0;
    return t;
}

void touch_entropy_add_tap(touch_entropy_t* t, int32_t x, int32_t y) {
    ASSERT_OR_DIE(t, "null touch entropy");
    ASSERT_OR_DIE(!touch_entropy_ready(t), "touch entropy already complete");

    // Snap the tap to its tile, clamping to the panel first so a tap that lands
    // just outside it - a negative coordinate from calibration, or one past the
    // far edge - belongs to the nearest tile rather than the opposite one. The
    // tile's index is then written as whole bits, most significant first.
    uint64_t px = (x < 0) ? 0u : (uint64_t)x;
    uint64_t py = (y < 0) ? 0u : (uint64_t)y;
    if (px >= t->res_x) px = t->res_x - 1u;
    if (py >= t->res_y) py = t->res_y - 1u;
    const unsigned col  = (unsigned)(px * TOUCH_TILES_PER_AXIS / t->res_x);
    const unsigned row  = (unsigned)(py * TOUCH_TILES_PER_AXIS / t->res_y);
    const unsigned tile = row * TOUCH_TILES_PER_AXIS + col;

    for (unsigned i = TOUCH_BITS_PER_TAP; i-- > 0;) touch_append_bit(t, (tile >> i) & 1u);
    t->taps++;
    t->last_tile = tile;
}

bool touch_entropy_ready(const touch_entropy_t* t) {
    ASSERT_OR_DIE(t, "null touch entropy");
    return t->bits >= t->target;
}

uint32_t touch_entropy_bits(const touch_entropy_t* t) {
    ASSERT_OR_DIE(t, "null touch entropy");
    return t->bits;
}

uint32_t touch_entropy_target_bits(const touch_entropy_t* t) {
    ASSERT_OR_DIE(t, "null touch entropy");
    return t->target;
}

unsigned touch_entropy_taps(const touch_entropy_t* t) {
    ASSERT_OR_DIE(t, "null touch entropy");
    return t->taps;
}

unsigned touch_entropy_last_tile(const touch_entropy_t* t) {
    ASSERT_OR_DIE(t, "null touch entropy");
    return t->last_tile;
}

const uint8_t* touch_entropy_bytes(const touch_entropy_t* t) {
    ASSERT_OR_DIE(t, "null touch entropy");
    return t->bits_buf;
}

size_t touch_entropy_derive(touch_entropy_t* t, uint8_t* out, size_t out_len) {
    ASSERT_OR_DIE(t, "null touch entropy");
    ASSERT_OR_DIE(out, "null out");
    if (!touch_entropy_ready(t)) return 0;

    ASSERT_OR_DIE(out_len >= t->entropy_len, "out buffer too small");
    sha256_expand(t->bits_buf, (t->bits + 7u) / 8u, out, t->entropy_len);
    return t->entropy_len;
}

void touch_entropy_discard(touch_entropy_t* t) {
    if (!t) return;
    secure_memzero(t, sizeof(*t));
    free(t);
}

/**
 * @file main/crypto/dice.c
 * @brief Dice-roll entropy collection.
 */

#include "dice.h"
#include "util/error.h"
#include "util/utils.h"
#include <stdlib.h>
#include <string.h>

struct dice_entropy_t {
    uint8_t  bytes[32]; // collected entropy, most-significant-bit first
    uint32_t bits;      // bits collected
    uint32_t needed;    // 128 or 256
    unsigned sides;
    unsigned count;     // rolls
    unsigned last_roll; // 1..sides
    uint32_t last_bits; // bits the last roll contributed
};

// Append one bit, stopping at the target (the seed is already full).
static void dice_append_bit(dice_entropy_t* d, unsigned bit) {
    if (d->bits >= d->needed) return;
    if (bit) d->bytes[d->bits >> 3] |= (uint8_t)(0x80u >> (d->bits & 7u));
    d->bits++;
}

/* Faces are taken in power-of-two parts, largest first, which is just the die
 * rewritten as a sum of power-of-two dice: a d6 is a d4 plus a coin, a d12 is a
 * d8 plus a d4, a d20 is a d16 plus a d4.  A part of 2^k faces is worth k bits
 * written as the face's offset within that part, and the faces above it are
 * worth whatever the same rule makes of the remainder.
 *
 * Where the interval method got log2(sides) bits per roll by carrying the
 * fraction, this pays whole bits immediately and drops the rest: a d6 averages
 * 2*(4/6) + 1*(2/6) = 1.67 bits per roll rather than 2.58.  The bits that do
 * come out are still uniform and independent, so a seed has exactly as much
 * entropy as it has bits - it just takes more rolls to fill.  A single leftover
 * face (d3, d5, and the last face of every odd die) is worth nothing at all.
 *
 * Iterative rather than recursive: the remainder is smaller than the part just
 * taken, so at most log2(sides) parts are walked. */
unsigned dice_entropy_roll_bits(unsigned sides, unsigned value) {
    ASSERT_OR_DIE(sides >= 2, "dice sides must be at least 2");
    ASSERT_OR_DIE(value >= 1 && value <= sides, "dice value out of range");

    for (unsigned remaining = sides; remaining >= 2;) {
        const unsigned width = utils_floor_log2(remaining);
        const unsigned span  = 1u << width;
        if (value <= span) return width;
        value -= span;
        remaining -= span;
    }
    return 0;
}

static void dice_append_split(dice_entropy_t* d, unsigned value) {
    for (unsigned remaining = d->sides; remaining >= 2;) {
        const unsigned width = utils_floor_log2(remaining);
        const unsigned span  = 1u << width;
        if (value <= span) {
            const unsigned v = value - 1; // already inside this part
            for (int i = (int)width - 1; i >= 0; i--) dice_append_bit(d, (v >> i) & 1u);
            return;
        }
        value -= span;
        remaining -= span;
    }
}

dice_entropy_t* dice_entropy_begin(unsigned word_count, unsigned sides) {
    ASSERT_OR_DIE(utils_word_count_valid(word_count), "word count must be 12 or 24");
    ASSERT_OR_DIE(sides >= 2 && sides <= 256, "dice sides must be between 2 and 256");

    dice_entropy_t* d = calloc(1, sizeof(*d));
    ASSERT_OR_DIE(d, "out of memory");

    d->sides  = sides;
    d->needed = utils_word_count_bits(word_count);
    return d;
}

void dice_entropy_add_roll(dice_entropy_t* d, unsigned value) {
    ASSERT_OR_DIE(d, "null dice entropy");
    ASSERT_OR_DIE(value >= 1 && value <= d->sides, "dice value out of range");
    ASSERT_OR_DIE(!dice_entropy_ready(d), "dice accumulator already full");

    const uint32_t before = d->bits;
    d->count++;
    d->last_roll = value;
    dice_append_split(d, value);
    d->last_bits = d->bits - before;
}

bool dice_entropy_ready(const dice_entropy_t* d) {
    ASSERT_OR_DIE(d, "null dice entropy");
    return d->bits >= d->needed;
}

uint32_t dice_entropy_bits(const dice_entropy_t* d) {
    ASSERT_OR_DIE(d, "null dice entropy");
    return d->bits;
}

uint32_t dice_entropy_needed(const dice_entropy_t* d) {
    ASSERT_OR_DIE(d, "null dice entropy");
    return d->needed;
}

unsigned dice_entropy_rolls(const dice_entropy_t* d) {
    ASSERT_OR_DIE(d, "null dice entropy");
    return d->count;
}

unsigned dice_entropy_last_roll(const dice_entropy_t* d) {
    ASSERT_OR_DIE(d, "null dice entropy");
    return d->last_roll;
}

uint32_t dice_entropy_last_bits(const dice_entropy_t* d) {
    ASSERT_OR_DIE(d, "null dice entropy");
    return d->last_bits;
}

unsigned dice_entropy_sides(const dice_entropy_t* d) {
    ASSERT_OR_DIE(d, "null dice entropy");
    return d->sides;
}

const uint8_t* dice_entropy_bytes(const dice_entropy_t* d) {
    ASSERT_OR_DIE(d, "null dice entropy");
    return d->bytes;
}

size_t dice_entropy_derive(dice_entropy_t* d, uint8_t* out, size_t out_len) {
    ASSERT_OR_DIE(d, "null dice entropy");
    ASSERT_OR_DIE(out, "null out");
    if (!dice_entropy_ready(d)) return 0;

    size_t n = d->needed / 8;
    ASSERT_OR_DIE(out_len >= n, "out buffer too small");
    memcpy(out, d->bytes, n);
    return n;
}

void dice_entropy_discard(dice_entropy_t* d) {
    if (!d) return;
    secure_memzero(d, sizeof(*d));
    free(d);
}

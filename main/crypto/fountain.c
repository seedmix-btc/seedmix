/**
 * @file main/crypto/fountain.c
 * @brief Fountain-code (Luby transform) decoding for Multipart URs.
 *
 * This is a C port of the reference bc-ur C++ implementation
 * (BlockchainCommons/bc-ur): the xoshiro256** PRNG, the Walker-Vose alias
 * sampler for degree selection, the deterministic fragment chooser, and the
 * "peeling" decoder.
 */

#include "fountain.h"
#include "ur.h" /* ur_crc32 */

#include <stdlib.h>
#include <string.h>

#include <wally_core.h>
#include <wally_crypto.h>

#define FOUNTAIN_MAX_SEQ_LEN 1024
#define FOUNTAIN_MASK_BYTES (FOUNTAIN_MAX_SEQ_LEN / 8)

/* -- xoshiro256** ------------------------------------------------------ */
typedef struct {
    uint64_t s[4];
} xoshiro256_t;

static uint64_t rotl64(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }

static void xoshiro_seed(xoshiro256_t* r, const uint8_t seed[32]) {
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int n = 0; n < 8; n++) v = (v << 8) | seed[i * 8 + n];
        r->s[i] = v;
    }
}

static uint64_t xoshiro_next(xoshiro256_t* r) {
    const uint64_t result = rotl64(r->s[1] * 5, 7) * 9;
    const uint64_t t      = r->s[1] << 17;
    r->s[2] ^= r->s[0];
    r->s[3] ^= r->s[1];
    r->s[1] ^= r->s[2];
    r->s[0] ^= r->s[3];
    r->s[2] ^= t;
    r->s[3] = rotl64(r->s[3], 45);
    return result;
}

static double xoshiro_next_double(xoshiro256_t* r) {
    /* next() / 2^64 (2^64 is exactly representable as a double). */
    return (double)xoshiro_next(r) / 18446744073709551616.0;
}

static uint64_t xoshiro_next_int(xoshiro256_t* r, uint64_t low, uint64_t high) {
    return (uint64_t)(xoshiro_next_double(r) * (double)(high - low + 1)) + low;
}

/* -- Walker-Vose alias sampler (degree chooser) ------------------------- */
/* Picks the number of fragments for a mixed part.  Returns false when the
 * sampler state cannot be allocated (seq_len is attacker-controlled, so a
 * large seq_len is a real allocation-failure case on the embedded targets). */
static bool choose_degree(size_t seq_len, xoshiro256_t* rng, size_t* out_degree) {
    double* probs = (double*)malloc(seq_len * sizeof(double));
    double* P     = (double*)malloc(seq_len * sizeof(double));
    double* out_p = (double*)calloc(seq_len, sizeof(double));
    int*    alias = (int*)malloc(seq_len * sizeof(int));
    int*    S     = (int*)malloc(seq_len * sizeof(int));
    int*    L     = (int*)malloc(seq_len * sizeof(int));
    size_t  nS = 0, nL = 0;

    if (!probs || !P || !out_p || !alias || !S || !L) {
        free(probs);
        free(P);
        free(out_p);
        free(alias);
        free(S);
        free(L);
        return false;
    }

    double sum = 0.0;
    for (size_t i = 0; i < seq_len; i++) {
        probs[i] = 1.0 / (double)(i + 1);
        sum += probs[i];
    }
    for (size_t i = 0; i < seq_len; i++) P[i] = probs[i] * (double)seq_len / sum;

    /* Separate into small (<1) and large (>=1); iterate in REVERSE order so
     * the lists are in descending index order and back() is the smallest. */
    for (size_t ii = seq_len; ii-- > 0;) {
        if (P[ii] < 1.0)
            S[nS++] = (int)ii;
        else
            L[nL++] = (int)ii;
    }

    while (nS > 0 && nL > 0) {
        int a    = S[--nS];
        int g    = L[--nL];
        out_p[a] = P[a];
        alias[a] = g;
        P[g] += P[a] - 1.0;
        if (P[g] < 1.0)
            S[nS++] = g;
        else
            L[nL++] = g;
    }
    while (nL > 0) out_p[L[--nL]] = 1.0;
    while (nS > 0) out_p[S[--nS]] = 1.0;

    double r1  = xoshiro_next_double(rng);
    double r2  = xoshiro_next_double(rng);
    size_t i   = (size_t)((double)seq_len * r1);
    size_t deg = (r2 < out_p[i] ? i : (size_t)alias[i]) + 1;

    free(probs);
    free(P);
    free(out_p);
    free(alias);
    free(S);
    free(L);
    *out_degree = deg;
    return true;
}

/* Fisher-Yates shuffle of [0..n-1] using next_int.  Returns false when the
 * scratch buffer cannot be allocated. */
static bool shuffled_indexes(xoshiro256_t* rng, size_t n, size_t* out) {
    size_t* remaining = (size_t*)malloc(n * sizeof(size_t));
    if (!remaining) return false;
    for (size_t i = 0; i < n; i++) remaining[i] = i;
    for (size_t o = 0; o < n; o++) {
        size_t sz    = n - o;
        size_t index = (size_t)xoshiro_next_int(rng, 0, sz - 1);
        out[o]       = remaining[index];
        for (size_t j = index; j + 1 < sz; j++) remaining[j] = remaining[j + 1];
    }
    free(remaining);
    return true;
}

/* Fill a bitmask with the fragments chosen for `seq_num` (1-indexed).
 * Returns false (with the mask left empty) when the sampler runs out of
 * memory; the caller must then reject the part rather than decode it. */
bool fountain_choose_fragments(uint32_t seq_num, size_t seq_len, uint32_t checksum,
                               uint8_t* out_mask, size_t mask_bytes) {
    /* The mask must be able to hold seq_len bits. */
    if (!out_mask || seq_len == 0 || mask_bytes < (seq_len + 7) / 8) return false;

    memset(out_mask, 0, mask_bytes);
    if (seq_num <= seq_len) {
        size_t idx = seq_num - 1;
        out_mask[idx >> 3] |= (uint8_t)(1u << (idx & 7));
        return true;
    }

    uint8_t seed[8];
    seed[0] = (uint8_t)(seq_num >> 24);
    seed[1] = (uint8_t)(seq_num >> 16);
    seed[2] = (uint8_t)(seq_num >> 8);
    seed[3] = (uint8_t)seq_num;
    seed[4] = (uint8_t)(checksum >> 24);
    seed[5] = (uint8_t)(checksum >> 16);
    seed[6] = (uint8_t)(checksum >> 8);
    seed[7] = (uint8_t)checksum;

    uint8_t digest[SHA256_LEN];
    wally_sha256(seed, sizeof(seed), digest, sizeof(digest));

    xoshiro256_t rng;
    xoshiro_seed(&rng, digest);

    size_t degree = 0;
    if (!choose_degree(seq_len, &rng, &degree)) return false;

    size_t* shuffled = (size_t*)malloc(seq_len * sizeof(size_t));
    if (!shuffled) return false;
    if (!shuffled_indexes(&rng, seq_len, shuffled)) {
        free(shuffled);
        return false;
    }
    for (size_t i = 0; i < degree; i++) {
        size_t idx = shuffled[i];
        out_mask[idx >> 3] |= (uint8_t)(1u << (idx & 7));
    }
    free(shuffled);
    return true;
}

/* -- bitmask helpers ---------------------------------------------------- */
static bool mask_bit(const uint8_t* m, size_t i) { return (m[i >> 3] >> (i & 7)) & 1u; }

static void mask_set(uint8_t* m, size_t i) { m[i >> 3] |= (uint8_t)(1u << (i & 7)); }

static size_t mask_popcount(const uint8_t* m, size_t nbytes) {
    size_t c = 0;
    for (size_t i = 0; i < nbytes; i++) {
        uint8_t b = m[i];
        while (b) {
            c += b & 1u;
            b >>= 1;
        }
    }
    return c;
}

static bool mask_subset(const uint8_t* a, const uint8_t* b, size_t nbytes) {
    /* true if every bit set in `a` is also set in `b`. */
    for (size_t i = 0; i < nbytes; i++) {
        if (a[i] & ~b[i]) return false;
    }
    return true;
}

static bool mask_equal(const uint8_t* a, const uint8_t* b, size_t nbytes) {
    return memcmp(a, b, nbytes) == 0;
}

/* -- decoder state ------------------------------------------------------ */
typedef struct {
    uint8_t  mask[FOUNTAIN_MASK_BYTES];
    uint8_t* data;
    size_t   data_len;
} fp_part_t;

struct fountain_decoder {
    bool     initialized;
    size_t   seq_len;
    size_t   message_len;
    uint32_t checksum;
    size_t   fragment_len;
    size_t   mask_bytes;

    uint8_t  received_mask[FOUNTAIN_MASK_BYTES];
    size_t   received_count;
    uint8_t* fragments; /* seq_len * fragment_len, filled as fragments arrive */

    fp_part_t* queue;
    size_t     queue_head;
    size_t     queue_tail;
    size_t     queue_cap;

    fp_part_t* mixed;
    size_t     mixed_count;
    size_t     mixed_cap;

    bool     complete;
    uint8_t* result;
    size_t   result_len;
};

fountain_decoder_t* fountain_decoder_new(void) {
    return (fountain_decoder_t*)calloc(1, sizeof(fountain_decoder_t));
}

static void part_free(fp_part_t* p) { free(p->data); }

void fountain_decoder_free(fountain_decoder_t* d) {
    if (!d) return;
    for (size_t i = d->queue_head; i < d->queue_tail; i++) part_free(&d->queue[i]);
    for (size_t i = 0; i < d->mixed_count; i++) part_free(&d->mixed[i]);
    free(d->queue);
    free(d->mixed);
    free(d->fragments);
    free(d->result);
    free(d);
}

size_t fountain_decoder_received(const fountain_decoder_t* d) { return d ? d->received_count : 0; }

size_t fountain_decoder_expected(const fountain_decoder_t* d) {
    return (d && d->initialized) ? d->seq_len : 0;
}

/* Move `p` onto the pending queue.  Returns false on allocation failure, in
 * which case the caller still owns `p` (and must free it). */
static bool queue_push(fountain_decoder_t* d, fp_part_t* p) {
    if (d->queue_tail == d->queue_cap) {
        size_t     cap = d->queue_cap ? d->queue_cap * 2 : 16;
        fp_part_t* q   = (fp_part_t*)realloc(d->queue, cap * sizeof(fp_part_t));
        if (!q) return false; /* allocation failure: leave the part to the caller */
        d->queue     = q;
        d->queue_cap = cap;
    }
    d->queue[d->queue_tail++] = *p;
    p->data                   = NULL; /* ownership transferred */
    p->data_len               = 0;
    return true;
}

/* Reduce part `a` by part `b`: if b's indexes are a strict subset of a's,
 * XOR b's data into a's and remove b's indexes.  Returns true if reduced. */
static bool reduce_part(fp_part_t* a, const fp_part_t* b, size_t mask_bytes) {
    if (!mask_subset(b->mask, a->mask, mask_bytes) || mask_equal(a->mask, b->mask, mask_bytes))
        return false;
    for (size_t i = 0; i < mask_bytes; i++) a->mask[i] &= (uint8_t)~b->mask[i];
    for (size_t i = 0; i < a->data_len; i++) a->data[i] ^= b->data[i];
    return true;
}

static bool part_is_simple(const fp_part_t* p, size_t mask_bytes) {
    return mask_popcount(p->mask, mask_bytes) == 1;
}

/* Reduce all mixed parts by the given (simple) part; parts that become simple
 * are re-queued, the rest stay in the mixed list. */
static void reduce_mixed_by(fountain_decoder_t* d, const fp_part_t* p) {
    size_t i = 0;
    while (i < d->mixed_count) {
        if (reduce_part(&d->mixed[i], p, d->mask_bytes) &&
            part_is_simple(&d->mixed[i], d->mask_bytes)) {
            if (!queue_push(d, &d->mixed[i])) part_free(&d->mixed[i]);
            d->mixed[i] = d->mixed[--d->mixed_count];
            /* reprocess the swapped-in part without advancing i */
        } else {
            i++;
        }
    }
}

static void process_simple_part(fountain_decoder_t* d, fp_part_t* p) {
    /* Find the single index. */
    size_t idx = 0;
    while (idx < d->seq_len && !mask_bit(p->mask, idx)) idx++;
    if (idx == d->seq_len) return;

    if (mask_bit(d->received_mask, idx)) return; /* duplicate */

    memcpy(d->fragments + idx * d->fragment_len, p->data, d->fragment_len);
    mask_set(d->received_mask, idx);
    d->received_count++;

    if (d->received_count == d->seq_len) {
        d->result     = (uint8_t*)malloc(d->message_len);
        d->result_len = d->message_len;
        if (d->result) {
            memcpy(d->result, d->fragments, d->message_len);
            if (ur_crc32(d->result, d->result_len) == d->checksum)
                d->complete = true;
            else {
                free(d->result);
                d->result = NULL;
            }
        }
    } else {
        reduce_mixed_by(d, p);
    }
}

static void process_mixed_part(fountain_decoder_t* d, fp_part_t* p) {
    /* Skip duplicates (same index set as an existing mixed part). */
    for (size_t i = 0; i < d->mixed_count; i++) {
        if (mask_equal(d->mixed[i].mask, p->mask, d->mask_bytes)) return;
    }

    /* Reduce by all simple parts. */
    for (size_t i = 0; i < d->seq_len; i++) {
        if (!mask_bit(d->received_mask, i)) continue;
        fp_part_t sp;
        sp.data_len = d->fragment_len;
        sp.data     = d->fragments + i * d->fragment_len;
        memset(sp.mask, 0, d->mask_bytes);
        mask_set(sp.mask, i);
        reduce_part(p, &sp, d->mask_bytes);
    }
    /* Reduce by all mixed parts. */
    for (size_t i = 0; i < d->mixed_count; i++) reduce_part(p, &d->mixed[i], d->mask_bytes);

    if (part_is_simple(p, d->mask_bytes)) {
        /* On failure ownership stays with the caller (process_queue frees it). */
        (void)queue_push(d, p);
        return;
    }

    reduce_mixed_by(d, p);
    if (d->mixed_count == d->mixed_cap) {
        size_t     cap = d->mixed_cap ? d->mixed_cap * 2 : 16;
        fp_part_t* m   = (fp_part_t*)realloc(d->mixed, cap * sizeof(fp_part_t));
        if (!m) return;
        d->mixed     = m;
        d->mixed_cap = cap;
    }
    d->mixed[d->mixed_count++] = *p;
    p->data                    = NULL; /* ownership transferred */
    p->data_len                = 0;
}

static void process_queue(fountain_decoder_t* d) {
    while (!d->complete && d->queue_head < d->queue_tail) {
        fp_part_t p = d->queue[d->queue_head++];
        if (part_is_simple(&p, d->mask_bytes))
            process_simple_part(d, &p);
        else
            process_mixed_part(d, &p);
        part_free(&p);
    }
}

int fountain_decoder_receive(fountain_decoder_t* d, uint32_t seq_num, size_t seq_len,
                             size_t message_len, uint32_t checksum, const uint8_t* data,
                             size_t data_len, uint8_t** out_message, size_t* out_message_len) {
    if (out_message) *out_message = NULL;
    if (out_message_len) *out_message_len = 0;
    if (!d || d->complete || seq_num < 1 || seq_len < 1 || seq_len > FOUNTAIN_MAX_SEQ_LEN || !data)
        return -1;

    if (!d->initialized) {
        if (message_len == 0 || data_len == 0) return -1;

        /* BCR-2024-001 splits the message into `seq_len` equal fragments, so a
         * well-formed part has fragment_len == ceil(message_len / seq_len).
         * Check that geometry before allocating anything: without it a small
         * crafted part can declare a huge fragment store, and the reassembly
         * in process_simple_part() would read past `fragments` whenever
         * message_len exceeds seq_len * data_len. */
        if (seq_len > SIZE_MAX / data_len) return -1; /* seq_len * data_len would wrap */
        size_t frag_store = seq_len * data_len;
        if (message_len > frag_store) return -1; /* fragments cannot cover the message */
        if (seq_len > 1 && (seq_len - 1) > message_len / data_len) {
            return -1; /* more than one fragment's worth of padding */
        }

        uint8_t* fragments = (uint8_t*)malloc(frag_store);
        if (!fragments) return -1;

        /* Only mark the decoder initialized once the whole state exists:
         * otherwise a failed part would leave it half-initialized and the next
         * part would write through a NULL `fragments`. */
        d->seq_len        = seq_len;
        d->message_len    = message_len;
        d->checksum       = checksum;
        d->fragment_len   = data_len;
        d->mask_bytes     = (seq_len + 7) / 8;
        d->fragments      = fragments;
        d->received_count = 0;
        memset(d->received_mask, 0, sizeof(d->received_mask));
        d->initialized = true;
    } else {
        if (seq_len != d->seq_len || message_len != d->message_len || checksum != d->checksum ||
            data_len != d->fragment_len)
            return -1;
    }

    fp_part_t p;
    memset(p.mask, 0, sizeof(p.mask));
    p.data     = (uint8_t*)malloc(data_len);
    p.data_len = data_len;
    if (!p.data) return -1;
    memcpy(p.data, data, data_len);
    if (!fountain_choose_fragments(seq_num, seq_len, checksum, p.mask, d->mask_bytes)) {
        part_free(&p);
        return -1; /* out of sampler memory: reject rather than mis-decode */
    }
    if (!queue_push(d, &p)) part_free(&p);
    process_queue(d);

    if (d->complete) {
        if (out_message) {
            *out_message = d->result;
            d->result    = NULL; /* ownership transferred to caller */
        }
        if (out_message_len) *out_message_len = d->result_len;
        return 1;
    }
    return 0;
}

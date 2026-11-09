/**
 * @file main/crypto/txinspect.c
 * @brief Parse and summarise a Bitcoin transaction or PSBT (via libwally)
 */

#include "txinspect.h"
#include "ur_psbt.h"
#include "util/utils.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_address.h>
#include <wally_core.h>
#include <wally_psbt.h>
#include <wally_script.h>
#include <wally_transaction.h>

/* PSBT magic bytes: "psbt" + 0xff (BIP 174) */
static const uint8_t PSBT_MAGIC[5] = {0x70, 0x73, 0x62, 0x74, 0xff};

#define MAX_PUBKEY_LEN 65 /* 33 compressed or 65 uncompressed */

struct tx_inspect {
    tx_inspect_kind_t    kind;
    struct wally_tx*     tx;   /* borrowed from psbt when kind == PSBT */
    struct wally_psbt*   psbt; /* owned, NULL for raw tx */
    tx_inspect_network_t network;
    bool                 nonce_reuse;
    bool                 all_inputs_known;
    bool                 is_signed;
};

/* -- Small, non-fatal helpers (parse must never abort) ---------------- */
/* Normalise a big-endian integer into 32 bytes (left-padded, leading sign
 * zero stripped).  Returns false when the value does not fit in 32 bytes. */
static bool normalize_scalar(const uint8_t* v, size_t vlen, uint8_t out[32]) {
    if (vlen == 0) return false;
    size_t off = 0;
    while (off < vlen - 1 && v[off] == 0x00) off++;
    size_t n = vlen - off;
    if (n > 32) return false;
    memset(out, 0, 32);
    memcpy(out + (32 - n), v + off, n);
    return true;
}

/* Parse the r component of a DER ECDSA signature at the start of `d`.
 * Tolerates a trailing sighash byte after the DER structure; when `sighash` is
 * non-NULL it receives that byte, and the function fails if the signature is
 * not followed by one. */
static bool der_sig_parse(const uint8_t* d, size_t len, uint8_t r32[32], uint8_t* sighash) {
    if (!d || len < 8 || d[0] != 0x30) return false;

    size_t seq_len = d[1];
    size_t hdr     = 2;
    if (seq_len >= 0x80) {
        if (seq_len != 0x81 || len < 3) return false;
        seq_len = d[2];
        hdr     = 3;
    }
    if (seq_len < 6 || hdr + seq_len > len) return false;

    const uint8_t* p   = d + hdr;
    const uint8_t* end = p + seq_len;
    if (p[0] != 0x02) return false;
    size_t rlen = p[1];
    if (rlen == 0 || p + 2 + rlen > end) return false;
    const uint8_t* r = p + 2;
    p += 2 + rlen;
    if (p >= end || p[0] != 0x02) return false;
    size_t slen = p[1];
    if (slen == 0 || p + 2 + slen > end) return false;

    if (sighash) {
        size_t der_end = hdr + seq_len;
        if (der_end >= len) return false; /* no trailing sighash byte */
        *sighash = d[der_end];
    }

    return normalize_scalar(r, rlen, r32);
}

static bool der_sig_r(const uint8_t* d, size_t len, uint8_t r32[32]) {
    return der_sig_parse(d, len, r32, NULL);
}

/* -- Sighash types ---------------------------------------------------- */
/* More distinct values than this are reported as "mixed" anyway. */
#define SIGHASH_MAX 8

static void sighash_add(uint32_t* vals, size_t max, size_t* n, uint32_t sh) {
    for (size_t i = 0; i < *n; i++) {
        if (vals[i] == sh) return;
    }
    if (*n < max) vals[(*n)++] = sh;
}

static void scan_sighash(const uint8_t* buf, size_t len, uint32_t* vals, size_t max, size_t* n) {
    for (size_t i = 0; i + 9 <= len; i++) {
        if (buf[i] != 0x30) continue;
        uint8_t r32[32];
        uint8_t sh = 0;
        if (der_sig_parse(buf + i, len - i, r32, &sh)) sighash_add(vals, max, n, sh);
    }
}

/* Distinct sighash types used by the transaction.  A PSBT states them
 * explicitly (and may state one per input); otherwise they are read from the
 * trailing byte of the signatures in the input scripts/witnesses. */
static size_t collect_sighash(const tx_inspect_t* t, uint32_t* vals, size_t max) {
    size_t n = 0;
    if (!t || !t->tx) return 0;

    if (t->kind == TX_INSPECT_KIND_PSBT && t->psbt) {
        for (size_t i = 0; i < t->psbt->num_inputs; i++) {
            const struct wally_psbt_input* in = &t->psbt->inputs[i];
            if (in->sighash) {
                sighash_add(vals, max, &n, in->sighash);
                continue;
            }
            for (size_t j = 0; j < in->signatures.num_items; j++) {
                uint8_t r32[32];
                uint8_t sh = 0;
                if (der_sig_parse(in->signatures.items[j].value, in->signatures.items[j].value_len,
                                  r32, &sh))
                    sighash_add(vals, max, &n, sh);
            }
        }
        return n;
    }

    for (size_t i = 0; i < t->tx->num_inputs; i++) {
        const struct wally_tx_input* in = &t->tx->inputs[i];
        if (in->script && in->script_len) scan_sighash(in->script, in->script_len, vals, max, &n);
        if (in->witness) {
            for (size_t j = 0; j < in->witness->num_items; j++)
                scan_sighash(in->witness->items[j].witness, in->witness->items[j].witness_len, vals,
                             max, &n);
        }
    }
    return n;
}

/* Whether the transaction is final: a PSBT whose inputs are all finalised, or
 * a raw transaction whose inputs all carry a scriptSig or witness. */
static bool tx_is_signed(const tx_inspect_t* t) {
    if (!t) return false;

    if (t->kind == TX_INSPECT_KIND_PSBT && t->psbt) {
        size_t finalized = 0;
        if (wally_psbt_is_finalized(t->psbt, &finalized) != WALLY_OK) return false;
        return finalized != 0;
    }

    if (!t->tx || t->tx->num_inputs == 0) return false;
    for (size_t i = 0; i < t->tx->num_inputs; i++) {
        const struct wally_tx_input* in      = &t->tx->inputs[i];
        bool                         script  = in->script && in->script_len > 0;
        bool                         witness = in->witness && in->witness->num_items > 0;
        if (!script && !witness) return false;
    }
    return true;
}

/* -- Nonce reuse detection ------------------------------------------- */
/* Bounded comparison tables: the first R_SET_MAX distinct signatures are
 * remembered.  A duplicate whose first occurrence fell outside the table is
 * not detected, which is fine for the intended signal (a broken RNG repeats a
 * nonce long before 64 signatures) and keeps the state small on embedded. */
#define R_SET_MAX 64

typedef struct {
    uint8_t rs[R_SET_MAX][32];
    size_t  n;
    bool    reuse;
} r_set_t;

static bool r_seen(r_set_t* s, const uint8_t* r32) {
    for (size_t i = 0; i < s->n; i++) {
        if (memcmp(s->rs[i], r32, 32) == 0) {
            s->reuse = true;
            return true;
        }
    }
    if (s->n < R_SET_MAX) memcpy(s->rs[s->n++], r32, 32);
    return false;
}

typedef struct {
    uint8_t keys[R_SET_MAX][MAX_PUBKEY_LEN + 32];
    size_t  key_lens[R_SET_MAX];
    size_t  n;
    bool    reuse;
} pk_r_set_t;

static bool pk_r_seen(pk_r_set_t* s, const uint8_t* pk, size_t pk_len, const uint8_t* r32) {
    if (pk_len > MAX_PUBKEY_LEN) return false;
    size_t klen = pk_len + 32;
    for (size_t i = 0; i < s->n; i++) {
        if (s->key_lens[i] == klen && memcmp(s->keys[i], pk, pk_len) == 0 &&
            memcmp(s->keys[i] + pk_len, r32, 32) == 0) {
            s->reuse = true;
            return true;
        }
    }
    if (s->n < R_SET_MAX) {
        memcpy(s->keys[s->n], pk, pk_len);
        memcpy(s->keys[s->n] + pk_len, r32, 32);
        s->key_lens[s->n] = klen;
        s->n++;
    }
    return false;
}

static void scan_der_sigs(const uint8_t* buf, size_t len, r_set_t* s) {
    for (size_t i = 0; i + 8 <= len; i++) {
        if (buf[i] != 0x30) continue;
        uint8_t r32[32];
        if (der_sig_r(buf + i, len - i, r32) && r_seen(s, r32)) return;
    }
}

/* PSBT: the same (pubkey, r) on two inputs means the nonce was reused.  The
 * comparison table is ~6.7KB, so it is heap-allocated: this runs on the LVGL /
 * camera task, whose stack is only a few KB bigger than the table on the
 * embedded targets. */
static bool detect_psbt_nonce_reuse(const struct wally_psbt* psbt) {
    /* Nothing to compare unless at least two signatures are present. */
    size_t nsigs = 0;
    for (size_t i = 0; i < psbt->num_inputs; i++) {
        nsigs += psbt->inputs[i].signatures.num_items;
        if (nsigs > 1) break;
    }
    if (nsigs < 2) return false;

    pk_r_set_t* s = (pk_r_set_t*)calloc(1, sizeof(*s));
    if (!s) return false; /* cannot allocate the check state: stay silent */

    bool reuse = false;
    for (size_t i = 0; i < psbt->num_inputs && !reuse; i++) {
        const struct wally_map* sigs = &psbt->inputs[i].signatures;
        for (size_t j = 0; j < sigs->num_items; j++) {
            uint8_t r32[32];
            if (der_sig_r(sigs->items[j].value, sigs->items[j].value_len, r32) &&
                pk_r_seen(s, sigs->items[j].key, sigs->items[j].key_len, r32)) {
                reuse = true;
                break;
            }
        }
    }
    free(s);
    return reuse;
}

/* Raw transaction: reuse of any r across inputs is a red flag. */
static bool detect_raw_nonce_reuse(const struct wally_tx* tx) {
    r_set_t s;
    memset(&s, 0, sizeof(s));
    for (size_t i = 0; i < tx->num_inputs; i++) {
        const struct wally_tx_input* in = &tx->inputs[i];
        if (in->script && in->script_len) scan_der_sigs(in->script, in->script_len, &s);
        if (s.reuse) return true;
        if (in->witness) {
            for (size_t j = 0; j < in->witness->num_items; j++) {
                scan_der_sigs(in->witness->items[j].witness, in->witness->items[j].witness_len, &s);
                if (s.reuse) return true;
            }
        }
    }
    return false;
}

static bool detect_nonce_reuse(const tx_inspect_t* t) {
    if (!t->tx) return false;
    if (t->kind == TX_INSPECT_KIND_PSBT && t->psbt) return detect_psbt_nonce_reuse(t->psbt);
    return detect_raw_nonce_reuse(t->tx);
}

/* -- Formatting helpers ---------------------------------------------- */
static void fmt_txid(const uint8_t* h, char* out, size_t cap) {
    if (cap < 65) {
        if (cap) out[0] = '\0';
        return;
    }
    for (size_t i = 0; i < 32; i++) {
        int r = snprintf(out + 2 * i, 3, "%02x", h[31 - i]);
        (void)r;
    }
    out[64] = '\0';
}

static void fmt_btc(uint64_t sats, char* out, size_t cap) {
    snprintf(out, cap, "%llu.%08llu", (unsigned long long)(sats / 100000000ULL),
             (unsigned long long)(sats % 100000000ULL));
}

/* Bech32 HRP and Base58 version bytes for a network.  Signet reuses testnet's
 * "tb" prefix and version bytes. */
static void network_params(tx_inspect_network_t net, const char** hrp, int* wally_net) {
    switch (net) {
    case TX_INSPECT_NETWORK_TESTNET:
    case TX_INSPECT_NETWORK_SIGNET:
        *hrp       = "tb";
        *wally_net = WALLY_NETWORK_BITCOIN_TESTNET;
        break;
    case TX_INSPECT_NETWORK_REGTEST:
        *hrp       = "bcrt";
        *wally_net = WALLY_NETWORK_BITCOIN_REGTEST;
        break;
    case TX_INSPECT_NETWORK_MAINNET:
    default:
        *hrp       = "bc";
        *wally_net = WALLY_NETWORK_BITCOIN_MAINNET;
        break;
    }
}

static void script_to_address(const uint8_t* script, size_t len, tx_inspect_network_t net,
                              char* out, size_t cap) {
    const char* hrp;
    int         wally_net;
    network_params(net, &hrp, &wally_net);

    size_t type = 0;
    if (wally_scriptpubkey_get_type(script, len, &type) != WALLY_OK)
        type = WALLY_SCRIPT_TYPE_UNKNOWN;

    char* addr = NULL;
    if (type == WALLY_SCRIPT_TYPE_P2WPKH || type == WALLY_SCRIPT_TYPE_P2WSH ||
        type == WALLY_SCRIPT_TYPE_P2TR) {
        if (wally_addr_segwit_from_bytes(script, len, hrp, 0, &addr) == WALLY_OK && addr) {
            snprintf(out, cap, "%s", addr);
            wally_free_string(addr);
            return;
        }
    } else if (type == WALLY_SCRIPT_TYPE_P2PKH || type == WALLY_SCRIPT_TYPE_P2SH) {
        if (wally_scriptpubkey_to_address(script, len, wally_net, &addr) == WALLY_OK && addr) {
            snprintf(out, cap, "%s", addr);
            wally_free_string(addr);
            return;
        }
    }

    if (len == 0) {
        snprintf(out, cap, "<empty script>");
        return;
    }
    if (len * 2 + 1 > cap) {
        snprintf(out, cap, "<script %zu bytes>", len);
        return;
    }
    for (size_t i = 0; i < len; i++) {
        int r = snprintf(out + 2 * i, 3, "%02x", script[i]);
        (void)r;
    }
    out[len * 2] = '\0';
}

/* -- Rendering buffer ------------------------------------------------- */
/* Appends into a fixed buffer and records when it runs out of room, so the
 * summary can say it was cut short instead of silently losing the tail (which
 * would hide outputs or the fee from the user). */
typedef struct {
    char*  out;
    size_t cap;
    size_t off;
    bool   full;
} rbuf_t;

static void rb_addf(rbuf_t* rb, const char* fmt, ...) {
    if (rb->full || rb->off >= rb->cap) {
        rb->full = true;
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(rb->out + rb->off, rb->cap - rb->off, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n >= rb->cap - rb->off) {
        rb->full = true; /* vsnprintf truncated this line */
        return;
    }
    rb->off += (size_t)n;
}

static const char RB_TRUNCATED[] = "... summary truncated ...\n";

static void rb_finish(rbuf_t* rb) {
    if (rb->cap == 0) return;
    if (!rb->full) {
        rb->out[rb->off < rb->cap ? rb->off : rb->cap - 1] = '\0';
        return;
    }

    /* Drop the partial last line, then state that the summary is incomplete. */
    size_t mlen = sizeof(RB_TRUNCATED) - 1;
    size_t cut  = rb->off < rb->cap ? rb->off : rb->cap - 1;
    while (cut > 0 && rb->out[cut - 1] != '\n') cut--;

    if (rb->cap < mlen + 1) { /* no room for the marker at all */
        rb->out[rb->cap - 1] = '\0';
        return;
    }
    if (cut > rb->cap - 1 - mlen) cut = rb->cap - 1 - mlen;

    memcpy(rb->out + cut, RB_TRUNCATED, mlen);
    rb->out[cut + mlen] = '\0';
    rb->off             = cut + mlen;
}

static bool input_value(const tx_inspect_t* t, size_t i, uint64_t* out) {
    if (!out) return false;
    if (t->kind == TX_INSPECT_KIND_PSBT && t->psbt && i < t->psbt->num_inputs) {
        const struct wally_psbt_input* in = &t->psbt->inputs[i];
        if (in->witness_utxo) {
            *out = in->witness_utxo->satoshi;
            return true;
        }
        if (in->utxo) {
            /* Which output of the UTXO is spent is *not* stored in a v0 PSBT
             * input map: it is the vout of the corresponding input of the
             * unsigned transaction.  (libwally only fills input->index when
             * converting a PSBT to v2, so it is 0 for a v0 PSBT parsed from
             * bytes - using it directly reads the wrong output and reports a
             * bogus input value and fee.)  A v2 PSBT/PSET carries its own
             * txhash/index and has no unsigned transaction to consult. */
            uint32_t vout = in->index;
            if (t->tx && t->psbt->version == WALLY_PSBT_VERSION_0 &&
                t->tx->num_inputs == t->psbt->num_inputs)
                vout = t->tx->inputs[i].index;
            if (vout < in->utxo->num_outputs) {
                *out = in->utxo->outputs[vout].satoshi;
                return true;
            }
        }
    }
    return false;
}

/* -- Public API ------------------------------------------------------- */
tx_inspect_t* tx_inspect_parse(const uint8_t* payload, size_t len) {
    if (!payload || len == 0 || len > TXINSPECT_MAX_PAYLOAD) return NULL;

    struct wally_psbt* psbt = NULL;
    struct wally_tx*   tx   = NULL;
    tx_inspect_kind_t  kind = TX_INSPECT_KIND_TX;

    if (len >= sizeof(PSBT_MAGIC) && memcmp(payload, PSBT_MAGIC, sizeof(PSBT_MAGIC)) == 0) {
        if (wally_psbt_from_bytes(payload, len, 0, &psbt) != WALLY_OK) return NULL;
        kind = TX_INSPECT_KIND_PSBT;
    } else {
        /* Text payloads (hex or base64). */
        char* str = malloc(len + 1);
        if (!str) return NULL;
        memcpy(str, payload, len);
        str[len] = '\0';

        if (len >= 6 && strncmp(str, "cHNidP", 6) == 0) {
            if (wally_psbt_from_base64(str, 0, &psbt) == WALLY_OK) kind = TX_INSPECT_KIND_PSBT;
        }

        /* UR-encoded PSBT ("ur:psbt/..." / "ur:crypto-psbt/..."). */
        if (!psbt && !tx && len >= 3 && (str[0] == 'u' || str[0] == 'U') &&
            (str[1] == 'r' || str[1] == 'R') && str[2] == ':') {
            uint8_t* ur_psbt     = NULL;
            size_t   ur_psbt_len = 0;
            if (ur_psbt_decode(str, len, &ur_psbt, &ur_psbt_len)) {
                if (wally_psbt_from_bytes(ur_psbt, ur_psbt_len, 0, &psbt) == WALLY_OK)
                    kind = TX_INSPECT_KIND_PSBT;
                secure_memzero(ur_psbt, ur_psbt_len);
                free(ur_psbt);
            }
        }

        if (!psbt && !tx) {
            size_t   blen = len / 2;
            uint8_t* bin  = malloc(blen ? blen : 1);
            if (bin && hex_to_bytes(str, len, bin, blen)) {
                if (wally_tx_from_bytes(bin, blen, WALLY_TX_FLAG_USE_WITNESS, &tx) != WALLY_OK) {
                    tx = NULL;
                    if (wally_psbt_from_bytes(bin, blen, 0, &psbt) == WALLY_OK)
                        kind = TX_INSPECT_KIND_PSBT;
                } else {
                    kind = TX_INSPECT_KIND_TX;
                }
            }
            free(bin);
        }

        free(str);
    }

    if (!psbt && !tx) return NULL;

    tx_inspect_t* t = calloc(1, sizeof(*t));
    if (!t) {
        if (psbt) wally_psbt_free(psbt);
        if (tx) wally_tx_free(tx);
        return NULL;
    }
    t->kind    = kind;
    t->psbt    = psbt;
    t->tx      = psbt ? psbt->tx : tx;
    t->network = TX_INSPECT_NETWORK_MAINNET;

    t->all_inputs_known = t->tx && t->tx->num_inputs > 0;
    if (t->all_inputs_known) {
        for (size_t i = 0; i < t->tx->num_inputs; i++) {
            uint64_t v;
            if (!input_value(t, i, &v)) {
                t->all_inputs_known = false;
                break;
            }
        }
    }

    t->is_signed   = tx_is_signed(t);
    t->nonce_reuse = detect_nonce_reuse(t);
    return t;
}

void tx_inspect_free(tx_inspect_t* t) {
    if (!t) return;
    if (t->psbt)
        wally_psbt_free(t->psbt);
    else if (t->tx)
        wally_tx_free(t->tx);
    free(t);
}

tx_inspect_kind_t tx_inspect_kind(const tx_inspect_t* t) {
    return t ? t->kind : TX_INSPECT_KIND_TX;
}

const char* tx_inspect_kind_name(const tx_inspect_t* t) {
    return tx_inspect_kind(t) == TX_INSPECT_KIND_PSBT ? "PSBT" : "Transaction";
}

size_t tx_inspect_num_inputs(const tx_inspect_t* t) { return (t && t->tx) ? t->tx->num_inputs : 0; }

size_t tx_inspect_num_outputs(const tx_inspect_t* t) {
    return (t && t->tx) ? t->tx->num_outputs : 0;
}

uint64_t tx_inspect_total_in(const tx_inspect_t* t) {
    if (!t || !t->tx) return 0;
    uint64_t total = 0;
    for (size_t i = 0; i < t->tx->num_inputs; i++) {
        uint64_t v;
        if (!input_value(t, i, &v)) return 0;
        total += v;
    }
    return total;
}

uint64_t tx_inspect_total_out(const tx_inspect_t* t) {
    if (!t || !t->tx) return 0;
    uint64_t total = 0;
    for (size_t i = 0; i < t->tx->num_outputs; i++) total += t->tx->outputs[i].satoshi;
    return total;
}

void tx_inspect_set_network(tx_inspect_t* t, tx_inspect_network_t network) {
    if (t) t->network = network;
}

tx_inspect_network_t tx_inspect_network(const tx_inspect_t* t) {
    return t ? t->network : TX_INSPECT_NETWORK_MAINNET;
}

const char* tx_inspect_network_name(tx_inspect_network_t network) {
    switch (network) {
    case TX_INSPECT_NETWORK_TESTNET:
        return "testnet";
    case TX_INSPECT_NETWORK_SIGNET:
        return "signet";
    case TX_INSPECT_NETWORK_REGTEST:
        return "regtest";
    case TX_INSPECT_NETWORK_MAINNET:
    default:
        return "mainnet";
    }
}

bool tx_inspect_is_signed(const tx_inspect_t* t) { return t && t->is_signed; }

uint32_t tx_inspect_locktime(const tx_inspect_t* t) { return (t && t->tx) ? t->tx->locktime : 0; }

bool tx_inspect_rbf(const tx_inspect_t* t) {
    if (!t || !t->tx) return false;
    /* BIP-125 opt-in: strictly below 0xfffffffe.  0xfffffffe only enables
     * locktime and 0xffffffff is final; neither is replaceable. */
    for (size_t i = 0; i < t->tx->num_inputs; i++) {
        if (t->tx->inputs[i].sequence < 0xfffffffeu) return true;
    }
    return false;
}

size_t tx_inspect_sighash(const tx_inspect_t* t, uint32_t* out, size_t max) {
    uint32_t vals[SIGHASH_MAX];
    size_t   n = collect_sighash(t, vals, sizeof(vals) / sizeof(vals[0]));
    if (out) {
        size_t copy = n < max ? n : max;
        for (size_t i = 0; i < copy; i++) out[i] = vals[i];
    }
    return n;
}

static const char* sighash_name(uint32_t sh) {
    switch (sh & 0xffu) {
    case 0x01:
        return (sh & 0x80u) ? "ALL|ANYONECANPAY" : "ALL";
    case 0x02:
        return (sh & 0x80u) ? "NONE|ANYONECANPAY" : "NONE";
    case 0x03:
        return (sh & 0x80u) ? "SINGLE|ANYONECANPAY" : "SINGLE";
    default:
        return NULL;
    }
}

static void render_sighash(rbuf_t* rb, const tx_inspect_t* t) {
    uint32_t vals[SIGHASH_MAX];
    size_t   n = tx_inspect_sighash(t, vals, sizeof(vals) / sizeof(vals[0]));
    if (n == 0) return; /* no signatures and no declared type: nothing to say */

    if (n > 1) {
        rb_addf(rb, "sighash: mixed\n");
        return;
    }
    const char* name = sighash_name(vals[0]);
    if (name)
        rb_addf(rb, "sighash: %s (0x%02x)\n", name, (unsigned)(vals[0] & 0xffu));
    else
        rb_addf(rb, "sighash: 0x%02x\n", (unsigned)(vals[0] & 0xffu));
}

void tx_inspect_render_ex(const tx_inspect_t* t, char* out, size_t out_size,
                          tx_inspect_output_cb classify, void* ctx) {
    if (!out || out_size == 0) return;
    out[0] = '\0';
    if (!t) return;

    rbuf_t rb = {.out = out, .cap = out_size, .off = 0, .full = false};

    rb_addf(&rb, "%s\n", tx_inspect_kind_name(t));
    rb_addf(&rb, "network: %s\n", tx_inspect_network_name(t->network));

    uint8_t txid[WALLY_TXHASH_LEN];
    if (t->tx && wally_tx_get_txid(t->tx, txid, sizeof(txid)) == WALLY_OK) {
        char id[65];
        fmt_txid(txid, id, sizeof(id));
        /* Only a fully signed transaction has its final txid: filling in a
         * legacy scriptSig changes it. */
        rb_addf(&rb, "txid (%s): %s\n", t->is_signed ? "signed" : "unsigned", id);
    }

    rb_addf(&rb, "locktime: %u\n", (unsigned)tx_inspect_locktime(t));
    rb_addf(&rb, "RBF: %s\n", tx_inspect_rbf(t) ? "yes" : "no");
    render_sighash(&rb, t);

    rb_addf(&rb, "\nInputs: %zu\n", tx_inspect_num_inputs(t));
    if (t->tx) {
        for (size_t i = 0; i < t->tx->num_inputs; i++) {
            char id[65];
            fmt_txid(t->tx->inputs[i].txhash, id, sizeof(id));
            uint64_t v;
            if (input_value(t, i, &v)) {
                char btc[32];
                fmt_btc(v, btc, sizeof(btc));
                rb_addf(&rb, "  #%zu  %s:%u  %s BTC\n", i, id, (unsigned)t->tx->inputs[i].index,
                        btc);
            } else {
                rb_addf(&rb, "  #%zu  %s:%u\n", i, id, (unsigned)t->tx->inputs[i].index);
            }
        }
    }

    rb_addf(&rb, "\nOutputs: %zu\n", tx_inspect_num_outputs(t));
    if (t->tx) {
        for (size_t i = 0; i < t->tx->num_outputs; i++) {
            char btc[32];
            char addr[128];
            fmt_btc(t->tx->outputs[i].satoshi, btc, sizeof(btc));
            script_to_address(t->tx->outputs[i].script, t->tx->outputs[i].script_len, t->network,
                              addr, sizeof(addr));

            const char* marker = NULL;
            if (classify) {
                switch (classify(ctx, i, addr)) {
                case TX_OUTPUT_CHANGE:
                    marker = "  <- change";
                    break;
                case TX_OUTPUT_RECEIVE:
                    marker = "  <- receive";
                    break;
                case TX_OUTPUT_NONE:
                    break;
                }
            }

            if (marker)
                rb_addf(&rb, "  #%zu  %s BTC  %s%s\n", i, btc, addr, marker);
            else
                rb_addf(&rb, "  #%zu  %s BTC  %s\n", i, btc, addr);
        }
    }

    if (t->all_inputs_known) {
        uint64_t total_in  = tx_inspect_total_in(t);
        uint64_t total_out = tx_inspect_total_out(t);
        if (total_in >= total_out) {
            char btc[32];
            fmt_btc(total_in - total_out, btc, sizeof(btc));
            rb_addf(&rb, "\nFee: %s BTC\n", btc);
        }
    } else if (tx_inspect_num_inputs(t) > 0) {
        /* Say so instead of omitting the fee: a missing fee line reads like
         * "no fee" on a device the user is about to sign with. */
        rb_addf(&rb, "\nFee: unknown (need input amounts)\n");
    }

    rb_finish(&rb);
}

void tx_inspect_render(const tx_inspect_t* t, char* out, size_t out_size) {
    tx_inspect_render_ex(t, out, out_size, NULL, NULL);
}

bool tx_inspect_nonce_warning(const tx_inspect_t* t, char* msg, size_t msg_size) {
    if (!t || !t->nonce_reuse) return false;
    if (msg && msg_size) {
        snprintf(msg, msg_size,
                 "Nonce reuse detected: signature nonce is not RFC 6979 "
                 "(broken RNG). Private key may be compromised.");
    }
    return true;
}

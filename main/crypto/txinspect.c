/**
 * @file main/crypto/txinspect.c
 * @brief Parse and summarise a Bitcoin transaction or PSBT (via libwally)
 */

#include "txinspect.h"
#include "ur.h"
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
    tx_inspect_kind_t  kind;
    struct wally_tx*   tx;   /* borrowed from psbt when kind == PSBT */
    struct wally_psbt* psbt; /* owned, NULL for raw tx */
    bool               nonce_reuse;
    bool               all_inputs_known;
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
 * Tolerates a trailing sighash byte after the DER structure. */
static bool der_sig_r(const uint8_t* d, size_t len, uint8_t r32[32]) {
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

    return normalize_scalar(r, rlen, r32);
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

static void script_to_address(const uint8_t* script, size_t len, char* out, size_t cap) {
    size_t type = 0;
    if (wally_scriptpubkey_get_type(script, len, &type) != WALLY_OK)
        type = WALLY_SCRIPT_TYPE_UNKNOWN;

    char* addr = NULL;
    if (type == WALLY_SCRIPT_TYPE_P2WPKH || type == WALLY_SCRIPT_TYPE_P2WSH ||
        type == WALLY_SCRIPT_TYPE_P2TR) {
        if (wally_addr_segwit_from_bytes(script, len, "bc", 0, &addr) == WALLY_OK && addr) {
            snprintf(out, cap, "%s", addr);
            wally_free_string(addr);
            return;
        }
    } else if (type == WALLY_SCRIPT_TYPE_P2PKH || type == WALLY_SCRIPT_TYPE_P2SH) {
        if (wally_scriptpubkey_to_address(script, len, WALLY_NETWORK_BITCOIN_MAINNET, &addr) ==
                WALLY_OK &&
            addr) {
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

static size_t appendf(char* out, size_t cap, size_t off, const char* fmt, ...) {
    if (off >= cap) return off;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out + off, cap - off, fmt, ap);
    va_end(ap);
    if (n < 0) return off;
    size_t add = (size_t)n;
    if (add >= cap - off) return cap;
    return off + add;
}

static bool input_value(const tx_inspect_t* t, size_t i, uint64_t* out) {
    if (!out) return false;
    if (t->kind == TX_INSPECT_KIND_PSBT && t->psbt && i < t->psbt->num_inputs) {
        const struct wally_psbt_input* in = &t->psbt->inputs[i];
        if (in->witness_utxo) {
            *out = in->witness_utxo->satoshi;
            return true;
        }
        if (in->utxo && in->index < in->utxo->num_outputs) {
            *out = in->utxo->outputs[in->index].satoshi;
            return true;
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
    t->kind = kind;
    t->psbt = psbt;
    t->tx   = psbt ? psbt->tx : tx;

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

void tx_inspect_render_ex(const tx_inspect_t* t, char* out, size_t out_size,
                          tx_inspect_output_cb classify, void* ctx) {
    if (!out || out_size == 0) return;
    out[0] = '\0';
    if (!t) return;

    size_t off = 0;
    off        = appendf(out, out_size, off, "%s\n", tx_inspect_kind_name(t));

    uint8_t txid[WALLY_TXHASH_LEN];
    if (t->tx && wally_tx_get_txid(t->tx, txid, sizeof(txid)) == WALLY_OK) {
        char id[65];
        fmt_txid(txid, id, sizeof(id));
        off = appendf(out, out_size, off, "txid: %s\n", id);
    }

    off = appendf(out, out_size, off, "\nInputs: %zu\n", t->tx ? t->tx->num_inputs : 0);
    if (t->tx) {
        for (size_t i = 0; i < t->tx->num_inputs; i++) {
            char id[65];
            fmt_txid(t->tx->inputs[i].txhash, id, sizeof(id));
            uint64_t v;
            if (input_value(t, i, &v)) {
                char btc[32];
                fmt_btc(v, btc, sizeof(btc));
                off = appendf(out, out_size, off, "  #%zu  %s:%u  %s BTC\n", i, id,
                              (unsigned)t->tx->inputs[i].index, btc);
            } else {
                off = appendf(out, out_size, off, "  #%zu  %s:%u\n", i, id,
                              (unsigned)t->tx->inputs[i].index);
            }
        }
    }

    off = appendf(out, out_size, off, "\nOutputs: %zu\n", t->tx ? t->tx->num_outputs : 0);
    if (t->tx) {
        for (size_t i = 0; i < t->tx->num_outputs; i++) {
            char btc[32];
            char addr[128];
            fmt_btc(t->tx->outputs[i].satoshi, btc, sizeof(btc));
            script_to_address(t->tx->outputs[i].script, t->tx->outputs[i].script_len, addr,
                              sizeof(addr));

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
                off = appendf(out, out_size, off, "  #%zu  %s BTC  %s%s\n", i, btc, addr, marker);
            else
                off = appendf(out, out_size, off, "  #%zu  %s BTC  %s\n", i, btc, addr);
        }
    }

    if (t->all_inputs_known) {
        uint64_t total_in  = tx_inspect_total_in(t);
        uint64_t total_out = tx_inspect_total_out(t);
        if (total_in >= total_out) {
            char btc[32];
            fmt_btc(total_in - total_out, btc, sizeof(btc));
            off = appendf(out, out_size, off, "\nFee: %s BTC\n", btc);
        }
    }
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

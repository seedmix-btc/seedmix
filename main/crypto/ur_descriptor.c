/**
 * @file main/crypto/ur_descriptor.c
 * @brief Decode wallet output descriptors from Blockchain Commons URs.
 *
 * Implements the two Blockchain Commons output-descriptor UR encodings:
 *
 *  - `output-descriptor` (BCR-2023-010, tag #6.40308): a CBOR map
 *      { 1: text, 2?: [key...], 3?: name, 4?: note } where the text may
 *      contain "@N" placeholders replaced by the corresponding decoded key.
 *  - `crypto-output` (BCR-2020-010, tag #6.308, deprecated): a CBOR
 *      expression tree (tags #6.400..#6.410) that is reconstructed back into
 *      descriptor text.
 *
 * Keys are decoded from `crypto-eckey` / `eckey` (tags #6.306 / #6.40306),
 * `crypto-hdkey` / `hdkey` (tags #6.303 / #6.40303) and `crypto-address` /
 * `address` (tags #6.307 / #6.40307).  Private key material is rejected.
 */

#include "ur_descriptor.h"
#include "ur.h"
#include "util/utils.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_script.h>

#define UR_DESC_MAX 4096
#define CBOR_MAX_DEPTH 40
#define CBOR_NODE_BUDGET 1024

/* Blockchain Commons CBOR tag numbers (v1 / v2). */
#define TAG_CRYPTO_OUTPUT 308
#define TAG_OUTPUT_DESCRIPTOR 40308
#define TAG_CRYPTO_ECKEY 306
#define TAG_ECKEY 40306
#define TAG_CRYPTO_HDKEY 303
#define TAG_HDKEY 40303
#define TAG_CRYPTO_ADDRESS 307
#define TAG_ADDRESS 40307
#define TAG_CRYPTO_KEYPATH 304
#define TAG_KEYPATH 40304
#define TAG_COININFO 40305
#define TAG_CRYPTO_COININFO 305

/* Script-expression tags (BCR-2020-010). */
#define TAG_SH 400
#define TAG_WSH 401
#define TAG_PK 402
#define TAG_PKH 403
#define TAG_WPKH 404
#define TAG_COMBO 405
#define TAG_MULTI 406
#define TAG_SORTMULTI 407
#define TAG_RAW 408
#define TAG_TR 409

/* -- Small CBOR value tree ------------------------------------------- */
typedef enum {
    CBOR_UINT,
    CBOR_BYTES,
    CBOR_TEXT,
    CBOR_ARRAY,
    CBOR_MAP,
    CBOR_BOOL,
    CBOR_TAG,
} cbor_kind_t;

typedef struct cbor_val cbor_val_t;
struct cbor_val {
    cbor_kind_t  kind;
    uint64_t     u; /* UINT value / TAG number */
    bool         b; /* BOOL value */
    uint8_t*     data;
    size_t       len;
    cbor_val_t** kids;
    size_t       n;
};

static cbor_val_t* cbor_new(cbor_kind_t kind) {
    cbor_val_t* v = calloc(1, sizeof(*v));
    if (v) v->kind = kind;
    return v;
}

static void cbor_free(cbor_val_t* v) {
    if (!v) return;
    for (size_t i = 0; i < v->n; i++) cbor_free(v->kids[i]);
    free(v->kids);
    free(v->data);
    free(v);
}

/* Parse one CBOR header (initial byte + argument).  Advances *off past the
 * header.  Returns false on truncated/indefinite input. */
static bool cbor_head(const uint8_t* buf, size_t len, size_t* off, uint8_t* major, uint64_t* arg) {
    if (!buf || *off >= len) return false;
    uint8_t ib  = buf[(*off)++];
    *major      = ib >> 5;
    uint8_t  ai = ib & 0x1Fu;
    uint64_t a  = 0;
    if (ai < 24) {
        *arg = ai;
        return true;
    }
    size_t extra = 0;
    switch (ai) {
    case 24:
        extra = 1;
        break;
    case 25:
        extra = 2;
        break;
    case 26:
        extra = 4;
        break;
    case 27:
        extra = 8;
        break;
    default:
        return false; /* indefinite length or reserved */
    }
    if (*off + extra > len) return false;
    for (size_t i = 0; i < extra; i++) a = (a << 8) | buf[(*off)++];
    *arg = a;
    return true;
}

static cbor_val_t* cbor_parse(const uint8_t* buf, size_t len, size_t* used, int depth,
                              int* budget) {
    if (depth > CBOR_MAX_DEPTH || *budget <= 0) return NULL;
    (*budget)--;

    size_t   start = *used;
    uint8_t  major = 0;
    uint64_t arg   = 0;
    if (!cbor_head(buf, len, used, &major, &arg)) return NULL;

    switch (major) {
    case 0:   /* unsigned */
    case 1: { /* negative (treated as unsigned arg) */
        cbor_val_t* v = cbor_new(CBOR_UINT);
        if (!v) return NULL;
        v->u = arg;
        return v;
    }
    case 2:
    case 3: { /* byte / text string */
        if (*used + arg > len) return NULL;
        cbor_val_t* v = cbor_new(major == 2 ? CBOR_BYTES : CBOR_TEXT);
        if (!v) return NULL;
        v->data = malloc(arg ? arg : 1);
        if (!v->data) {
            cbor_free(v);
            return NULL;
        }
        memcpy(v->data, buf + *used, arg);
        v->len = arg;
        *used += arg;
        return v;
    }
    case 4:
    case 5: { /* array / map */
        size_t n = (major == 5) ? arg * 2 : arg;
        if (n > CBOR_NODE_BUDGET) return NULL;
        cbor_val_t* v = cbor_new(major == 4 ? CBOR_ARRAY : CBOR_MAP);
        if (!v) return NULL;
        v->kids = calloc(n ? n : 1, sizeof(*v->kids));
        if (!v->kids) {
            cbor_free(v);
            return NULL;
        }
        /* Record the child count up front: `kids` is zero-initialised, so a
         * partially built container can still be freed safely (cbor_free()
         * ignores NULL children) instead of leaking the parsed prefix. */
        v->n = n;
        for (size_t i = 0; i < n; i++) {
            cbor_val_t* k = cbor_parse(buf, len, used, depth + 1, budget);
            if (!k) {
                cbor_free(v);
                return NULL;
            }
            v->kids[i] = k;
        }
        return v;
    }
    case 6: { /* tag */
        cbor_val_t* v = cbor_new(CBOR_TAG);
        if (!v) return NULL;
        v->u    = arg;
        v->kids = calloc(1, sizeof(*v->kids));
        if (!v->kids) {
            cbor_free(v);
            return NULL;
        }
        v->kids[0] = cbor_parse(buf, len, used, depth + 1, budget);
        if (!v->kids[0]) {
            cbor_free(v);
            return NULL;
        }
        v->n = 1;
        return v;
    }
    case 7: { /* simple / bool */
        cbor_val_t* v = cbor_new(CBOR_BOOL);
        if (!v) return NULL;
        v->b = (arg == 21); /* 20=false, 21=true; others => false */
        return v;
    }
    default:
        return NULL;
    }
    (void)start;
}

/* Peel a single wrapping tag (or return the value as-is). */
static cbor_val_t* cbor_untag(cbor_val_t* v) {
    while (v && v->kind == CBOR_TAG && v->n == 1) v = v->kids[0];
    return v;
}

/* Find an integer-keyed entry in a map. */
static cbor_val_t* cbor_map_get(const cbor_val_t* m, uint64_t key) {
    if (!m || m->kind != CBOR_MAP) return NULL;
    for (size_t i = 0; i + 1 < m->n; i += 2) {
        cbor_val_t* k = cbor_untag(m->kids[i]);
        if (k && k->kind == CBOR_UINT && k->u == key) return m->kids[i + 1];
    }
    return NULL;
}

static cbor_val_t* cbor_arr_get(const cbor_val_t* a, size_t idx) {
    if (!a || a->kind != CBOR_ARRAY || idx >= a->n) return NULL;
    return a->kids[idx];
}

/* -- String helpers --------------------------------------------------- */
static size_t append_str(char* out, size_t cap, size_t off, const char* s) {
    if (!out || !s) return off;
    size_t n = strlen(s);
    if (off + n >= cap) return cap;
    memcpy(out + off, s, n);
    return off + n;
}

static size_t append_hex(char* out, size_t cap, size_t off, const uint8_t* b, size_t n) {
    if (!out) return off;
    for (size_t i = 0; i < n; i++) {
        if (off + 2 >= cap) return cap;
        static const char* H = "0123456789abcdef";
        out[off++]           = H[b[i] >> 4];
        out[off++]           = H[b[i] & 0xFu];
    }
    return off;
}

/* -- Key decoding ----------------------------------------------------- */
/* Decode a crypto-eckey / eckey into hex pubkey text. */
static bool key_eckey(cbor_val_t* v, char* out, size_t cap, size_t* off) {
    cbor_val_t* m = cbor_untag(v);
    if (!m || m->kind != CBOR_MAP) return false;

    cbor_val_t* priv = cbor_map_get(m, 2);
    if (priv && priv->kind == CBOR_BOOL && priv->b) return false; /* private */

    cbor_val_t* data = cbor_map_get(m, 3);
    if (!data || data->kind != CBOR_BYTES || data->len == 0) return false;
    *off = append_hex(out, cap, *off, data->data, data->len);
    return *off < cap;
}

/* Decode one keypath component (BCR-2020-007) into descriptor path syntax. */
static bool keypath_component(cbor_val_t* c, char* out, size_t cap, size_t* off) {
    cbor_val_t* a = cbor_untag(c);
    if (!a || a->kind != CBOR_ARRAY || a->n < 1 || a->n > 2) return false;

    cbor_val_t* first = cbor_untag(a->kids[0]);
    if (first && first->kind == CBOR_ARRAY) {
        if (first->n == 0 && a->n == 2) { /* wildcard */
            cbor_val_t* hard = cbor_untag(a->kids[1]);
            if (hard && hard->kind == CBOR_BOOL && hard->b) return false;
            *off = append_str(out, cap, *off, "*");
            return *off < cap;
        }
        if (first->n == 2 && a->n == 2) {
            cbor_val_t* second = cbor_untag(a->kids[1]);
            if (second && second->kind == CBOR_ARRAY) {
                /* child pair [child, child] -> "<a;b>" */
                *off = append_str(out, cap, *off, "<");
                if (!keypath_component(first, out, cap, off)) return false;
                *off = append_str(out, cap, *off, ";");
                if (!keypath_component(second, out, cap, off)) return false;
                *off = append_str(out, cap, *off, ">");
                return *off < cap;
            }
            /* child range [low, high] -> "<low;high>" */
            cbor_val_t* lo = cbor_untag(first->kids[0]);
            cbor_val_t* hi = cbor_untag(first->kids[1]);
            if (!lo || lo->kind != CBOR_UINT || !hi || hi->kind != CBOR_UINT) return false;
            char buf[48];
            int  n = snprintf(buf, sizeof(buf), "<%llu;%llu>", (unsigned long long)lo->u,
                             (unsigned long long)hi->u);
            if (n < 0 || (size_t)n >= sizeof(buf)) return false;
            *off = append_str(out, cap, *off, buf);
            return *off < cap;
        }
        return false;
    }

    /* child-index-component: [child_index, is_hardened] */
    cbor_val_t* idx = cbor_untag(a->kids[0]);
    if (!idx || idx->kind != CBOR_UINT) return false;
    bool hardened = a->n == 2 && a->kids[1] && a->kids[1]->kind == CBOR_BOOL && a->kids[1]->b;

    char buf[32];
    int  n = snprintf(buf, sizeof(buf), "%llu%s", (unsigned long long)idx->u, hardened ? "'" : "");
    if (n < 0 || (size_t)n >= sizeof(buf)) return false;
    *off = append_str(out, cap, *off, buf);
    return *off < cap;
}

/* Decode a keypath map into "/a/b/c" (or "" when empty).  Returns the
 * source fingerprint via *srcfp when present. */
static bool keypath_to_path(cbor_val_t* v, uint32_t* srcfp, char* out, size_t cap) {
    cbor_val_t* m = cbor_untag(v);
    if (!m || m->kind != CBOR_MAP) return false;

    if (srcfp) {
        *srcfp         = 0;
        cbor_val_t* fp = cbor_map_get(m, 2);
        if (fp && fp->kind == CBOR_UINT) *srcfp = (uint32_t)fp->u;
    }

    cbor_val_t* comps = cbor_map_get(m, 1);
    if (!comps || comps->kind != CBOR_ARRAY) return false;

    size_t off = 0;
    for (size_t i = 0; i < comps->n; i++) {
        if (i > 0) off = append_str(out, cap, off, "/");
        if (!keypath_component(comps->kids[i], out, cap, &off)) return false;
        if (off >= cap) return false;
    }
    out[off] = '\0';
    return true;
}

/* Decode a crypto-hdkey / hdkey into descriptor key text
 * ([fingerprint/origin]xpub/children).  Rejects private keys. */
static bool key_hdkey(cbor_val_t* v, char* out, size_t cap, size_t* off) {
    cbor_val_t* m = cbor_untag(v);
    if (!m || m->kind != CBOR_MAP) return false;

    cbor_val_t* priv = cbor_map_get(m, 2);
    if (priv && priv->kind == CBOR_BOOL && priv->b) return false;

    cbor_val_t* keydata = cbor_map_get(m, 3);
    cbor_val_t* cc      = cbor_map_get(m, 4);
    if (!keydata || keydata->kind != CBOR_BYTES || keydata->len != 33) return false;
    if (!cc || cc->kind != CBOR_BYTES || cc->len != 32) return false;

    /* Network defaults to mainnet; coininfo {2: network} overrides to testnet. */
    uint32_t    version = BIP32_VER_MAIN_PUBLIC;
    cbor_val_t* use     = cbor_map_get(m, 5);
    use                 = cbor_untag(use);
    if (use && use->kind == CBOR_MAP) {
        cbor_val_t* net = cbor_map_get(use, 2);
        if (net && net->kind == CBOR_UINT && net->u == 1) version = BIP32_VER_TEST_PUBLIC;
    }

    struct ext_key* key = NULL;
    if (bip32_key_init_alloc(version, 0, 0, cc->data, cc->len, keydata->data, keydata->len, NULL, 0,
                             NULL, 0, NULL, 0, &key) != WALLY_OK)
        return false;
    char* b58 = NULL;
    if (bip32_key_to_base58(key, BIP32_FLAG_KEY_PUBLIC, &b58) != WALLY_OK) {
        bip32_key_free(key);
        return false;
    }
    bip32_key_free(key);

    uint32_t srcfp            = 0;
    char     origin_path[256] = {0};
    char     child_path[256]  = {0};

    cbor_val_t* origin = cbor_map_get(m, 6);
    if (origin) {
        if (!keypath_to_path(origin, &srcfp, origin_path, sizeof(origin_path))) {
            wally_free_string(b58);
            return false;
        }
    }

    cbor_val_t* children = cbor_map_get(m, 7);
    if (children) {
        uint32_t dummy = 0;
        if (!keypath_to_path(children, &dummy, child_path, sizeof(child_path))) {
            wally_free_string(b58);
            return false;
        }
    }

    if (srcfp != 0 || origin_path[0]) {
        char buf[288];
        /* PRIx32: on some targets (xtensa-esp32) uint32_t is not `unsigned int`,
         * so a bare "%08x" fails -Wformat (which is -Werror there). */
        int n = snprintf(buf, sizeof(buf), "[%08" PRIx32 "/%s]", srcfp, origin_path);
        if (n < 0 || (size_t)n >= sizeof(buf)) {
            wally_free_string(b58);
            return false;
        }
        *off = append_str(out, cap, *off, buf);
    }
    *off = append_str(out, cap, *off, b58);
    if (child_path[0]) {
        *off = append_str(out, cap, *off, "/");
        *off = append_str(out, cap, *off, child_path);
    }
    wally_free_string(b58);
    return *off < cap;
}

/* Decode a crypto-address / address into an address string. */
static bool key_address(cbor_val_t* v, char* out, size_t cap, size_t* off) {
    cbor_val_t* m = cbor_untag(v);
    if (!m || m->kind != CBOR_MAP) return false;

    cbor_val_t* data = cbor_map_get(m, 3);
    if (!data || data->kind != CBOR_BYTES) return false;

    cbor_val_t* type = cbor_map_get(m, 2);
    uint64_t    t    = (type && type->kind == CBOR_UINT) ? type->u : 0;

    uint8_t spk[42];
    size_t  spk_len = 0;
    char*   addr    = NULL;
    int     r       = WALLY_ERROR;

    if (t == 0 && data->len == 20) {
        r = wally_scriptpubkey_p2pkh_from_bytes(data->data, data->len, 0, spk, sizeof(spk),
                                                &spk_len);
        if (r == WALLY_OK)
            r = wally_scriptpubkey_to_address(spk, spk_len, WALLY_NETWORK_BITCOIN_MAINNET, &addr);
    } else if (t == 1 && data->len == 20) {
        r = wally_scriptpubkey_p2sh_from_bytes(data->data, data->len, 0, spk, sizeof(spk),
                                               &spk_len);
        if (r == WALLY_OK)
            r = wally_scriptpubkey_to_address(spk, spk_len, WALLY_NETWORK_BITCOIN_MAINNET, &addr);
    } else if (t == 2 && (data->len == 20 || data->len == 32)) {
        r = wally_witness_program_from_bytes(data->data, data->len, 0, spk, sizeof(spk), &spk_len);
        if (r == WALLY_OK) r = wally_addr_segwit_from_bytes(spk, spk_len, "bc", 0, &addr);
    }

    if (r != WALLY_OK || !addr) return false;
    *off = append_str(out, cap, *off, addr);
    wally_free_string(addr);
    return *off < cap;
}

/* Decode any key value (eckey/hdkey/address) into descriptor key text. */
static bool key_to_text(cbor_val_t* v, char* out, size_t cap, size_t* off) {
    cbor_val_t* tagged = v;
    while (tagged && tagged->kind == CBOR_TAG && tagged->n == 1) {
        switch (tagged->u) {
        case TAG_ECKEY:
        case TAG_CRYPTO_ECKEY:
            return key_eckey(tagged, out, cap, off);
        case TAG_HDKEY:
        case TAG_CRYPTO_HDKEY:
            return key_hdkey(tagged, out, cap, off);
        case TAG_ADDRESS:
        case TAG_CRYPTO_ADDRESS:
            return key_address(tagged, out, cap, off);
        default:
            tagged = tagged->kids[0];
        }
    }
    return false;
}

/* -- v3: output-descriptor -------------------------------------------- */
/* Replace "@N" placeholders in src with the decoded keys array. */
static bool substitute_placeholders(const char* src, cbor_val_t* keys, char* out, size_t cap) {
    size_t off = 0;
    size_t i   = 0;
    while (src[i]) {
        if (src[i] == '@') {
            size_t j = i + 1;
            if (src[j] >= '0' && src[j] <= '9') {
                unsigned long idx = 0;
                while (src[j] >= '0' && src[j] <= '9') {
                    idx = idx * 10 + (unsigned long)(src[j] - '0');
                    j++;
                }
                cbor_val_t* key = cbor_arr_get(keys, (size_t)idx);
                if (!key) return false;
                if (!key_to_text(key, out, cap, &off)) return false;
                i = j;
                continue;
            }
        }
        if (off + 1 >= cap) return false;
        out[off++] = src[i++];
    }
    out[off] = '\0';
    return true;
}

static bool decode_output_descriptor(const uint8_t* cbor, size_t len, char* out, size_t cap) {
    size_t      used   = 0;
    int         budget = CBOR_NODE_BUDGET;
    cbor_val_t* root   = cbor_parse(cbor, len, &used, 0, &budget);
    if (!root) return false;

    cbor_val_t* m  = cbor_untag(root);
    bool        ok = false;
    if (m && m->kind == CBOR_MAP) {
        cbor_val_t* src  = cbor_map_get(m, 1);
        cbor_val_t* keys = cbor_map_get(m, 2);
        if (src && src->kind == CBOR_TEXT) {
            char   tmp[UR_DESC_MAX];
            size_t n = src->len < sizeof(tmp) - 1 ? src->len : sizeof(tmp) - 1;
            memcpy(tmp, src->data, n);
            tmp[n] = '\0';

            if (keys && keys->kind != CBOR_ARRAY) {
                ok = false;
            } else if (keys) {
                ok = substitute_placeholders(tmp, keys, out, cap);
            } else {
                ok = strlen(tmp) < cap;
                if (ok) strcpy(out, tmp);
            }
        }
    }
    cbor_free(root);
    return ok;
}

/* -- v1: crypto-output expression tree --------------------------------- */
static bool script_exp_to_text(cbor_val_t* v, char* out, size_t cap, size_t* off);

static bool append_named(const char* name, cbor_val_t* arg, char* out, size_t cap, size_t* off) {
    *off = append_str(out, cap, *off, name);
    *off = append_str(out, cap, *off, "(");
    if (!script_exp_to_text(arg, out, cap, off)) return false;
    *off = append_str(out, cap, *off, ")");
    return *off < cap;
}

static bool script_exp_to_text(cbor_val_t* v, char* out, size_t cap, size_t* off) {
    if (!v) return false;

    /* Key / address leaf tags. */
    if (v->kind == CBOR_TAG) {
        switch (v->u) {
        case TAG_ECKEY:
        case TAG_CRYPTO_ECKEY:
        case TAG_HDKEY:
        case TAG_CRYPTO_HDKEY:
        case TAG_ADDRESS:
        case TAG_CRYPTO_ADDRESS:
            return key_to_text(v, out, cap, off);
        case TAG_RAW: { /* raw(<hex>) */
            cbor_val_t* raw = v->n == 1 ? cbor_untag(v->kids[0]) : NULL;
            if (!raw || raw->kind != CBOR_BYTES) return false;
            *off = append_str(out, cap, *off, "raw(");
            *off = append_hex(out, cap, *off, raw->data, raw->len);
            *off = append_str(out, cap, *off, ")");
            return *off < cap;
        }
        case TAG_MULTI:
        case TAG_SORTMULTI: {
            cbor_val_t* mk = v->n == 1 ? cbor_untag(v->kids[0]) : NULL;
            if (!mk || mk->kind != CBOR_MAP) return false;
            cbor_val_t* thr  = cbor_map_get(mk, 1);
            cbor_val_t* keys = cbor_map_get(mk, 2);
            if (!thr || thr->kind != CBOR_UINT || !keys || keys->kind != CBOR_ARRAY) return false;

            char buf[32];
            int  n = snprintf(buf, sizeof(buf), "%llu", (unsigned long long)thr->u);
            if (n < 0 || (size_t)n >= sizeof(buf)) return false;

            *off = append_str(out, cap, *off, (v->u == TAG_SORTMULTI) ? "sortedmulti(" : "multi(");
            *off = append_str(out, cap, *off, buf);
            for (size_t i = 0; i < keys->n; i++) {
                *off = append_str(out, cap, *off, ",");
                if (!script_exp_to_text(keys->kids[i], out, cap, off)) return false;
            }
            *off = append_str(out, cap, *off, ")");
            return *off < cap;
        }
        case TAG_SH:
            return append_named("sh", v->kids[0], out, cap, off);
        case TAG_WSH:
            return append_named("wsh", v->kids[0], out, cap, off);
        case TAG_PK:
            return append_named("pk", v->kids[0], out, cap, off);
        case TAG_PKH:
            return append_named("pkh", v->kids[0], out, cap, off);
        case TAG_WPKH:
            return append_named("wpkh", v->kids[0], out, cap, off);
        case TAG_COMBO:
            return append_named("combo", v->kids[0], out, cap, off);
        case TAG_TR:
            return append_named("tr", v->kids[0], out, cap, off);
        default:
            return false;
        }
    }
    return false;
}

static bool decode_crypto_output(const uint8_t* cbor, size_t len, char* out, size_t cap) {
    size_t      used   = 0;
    int         budget = CBOR_NODE_BUDGET;
    cbor_val_t* root   = cbor_parse(cbor, len, &used, 0, &budget);
    if (!root) return false;
    size_t off = 0;
    bool   ok  = script_exp_to_text(root, out, cap, &off);
    if (ok) out[off] = '\0';
    cbor_free(root);
    return ok;
}

/* -- Public API ------------------------------------------------------- */
/* Decode a reassembled CBOR message into descriptor text. */
static bool decode_message(const uint8_t* cbor, size_t cbor_len, char** out_descriptor) {
    char* out = malloc(UR_DESC_MAX);
    if (!out) return false;

    /* The two type strings encode the descriptor differently; try the v3 map
     * first and fall back to the v1 expression tree (each parse is strict
     * enough that they don't accept each other's structure). */
    bool ok = decode_output_descriptor(cbor, cbor_len, out, UR_DESC_MAX) ||
              decode_crypto_output(cbor, cbor_len, out, UR_DESC_MAX);
    if (!ok) {
        free(out);
        return false;
    }
    *out_descriptor = out;
    return true;
}

bool ur_descriptor_decode(const char* ur, size_t ur_len, char** out_descriptor) {
    if (out_descriptor) *out_descriptor = NULL;
    if (!ur || !out_descriptor) return false;

    ur_descriptor_decoder_t* d = ur_descriptor_decoder_new();
    if (!d) return false;

    char* text = NULL;
    int   r    = ur_descriptor_decoder_receive(d, ur, ur_len, &text);
    ur_descriptor_decoder_free(d);
    if (r != 1) return false;

    *out_descriptor = text;
    return true;
}

/* -- Multipart UR decoding -------------------------------------------- */
static const char* const DESC_UR_TYPES[] = {"output-descriptor", "crypto-output"};

struct ur_descriptor_decoder {
    ur_decoder_t* ur;
};

ur_descriptor_decoder_t* ur_descriptor_decoder_new(void) {
    ur_descriptor_decoder_t* d = calloc(1, sizeof(*d));
    if (!d) return NULL;
    d->ur = ur_decoder_new(DESC_UR_TYPES, sizeof(DESC_UR_TYPES) / sizeof(DESC_UR_TYPES[0]));
    if (!d->ur) {
        free(d);
        return NULL;
    }
    return d;
}

void ur_descriptor_decoder_free(ur_descriptor_decoder_t* d) {
    if (!d) return;
    ur_decoder_free(d->ur);
    free(d);
}

size_t ur_descriptor_decoder_received(const ur_descriptor_decoder_t* d) {
    return d ? ur_decoder_received(d->ur) : 0;
}

size_t ur_descriptor_decoder_expected(const ur_descriptor_decoder_t* d) {
    return d ? ur_decoder_expected(d->ur) : 0;
}

int ur_descriptor_decoder_receive(ur_descriptor_decoder_t* d, const char* ur, size_t ur_len,
                                  char** out_descriptor) {
    if (out_descriptor) *out_descriptor = NULL;
    if (!d || !d->ur) return -1;

    uint8_t* cbor     = NULL;
    size_t   cbor_len = 0;
    int      r        = ur_decoder_receive(d->ur, ur, ur_len, &cbor, &cbor_len);
    if (r != 1) return r;

    char* text = NULL;
    bool  ok   = decode_message(cbor, cbor_len, &text);
    free(cbor);
    if (!ok) return -1;

    if (out_descriptor) {
        *out_descriptor = text;
    } else {
        free(text);
    }
    return 1;
}

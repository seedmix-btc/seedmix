/**
 * @file main/crypto/descriptor.c
 * @brief Parse a wallet output descriptor and match transaction outputs.
 */

#include "descriptor.h"
#include "util/utils.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_core.h>
#include <wally_descriptor.h>

/* Upper bounds to keep derived-address caches small on embedded targets. */
#define DESCRIPTOR_MAX_PATHS 8
#define DESCRIPTOR_MAX_ADDRS (DESCRIPTOR_MAX_PATHS * DESCRIPTOR_GAP_LIMIT * 2)

/* Longest script shape shown by descriptor_overview(), e.g.
 * "sh(wsh(sortedmulti_a))". */
#define DESCRIPTOR_SHAPE_MAX 32

/* Longest network name stored per descriptor. */
#define DESCRIPTOR_NETWORK_MAX 16

/* Key origins descriptor_overview() lists before it summarises the rest. */
#define DESCRIPTOR_OVERVIEW_MAX_KEYS 16

typedef struct {
    char* addr;
    bool  change;
} desc_addr_t;

struct descriptor {
    struct wally_descriptor* receive; /* primary descriptor (as scanned)   */
    struct wally_descriptor* change;  /* change-branch sibling (branch 1)  */
    desc_addr_t*             addrs;   /* cached derived addresses          */
    size_t                   n_addrs;
    char*                    text; /* descriptor text, "#checksum" stripped */
    char                     shape[DESCRIPTOR_SHAPE_MAX];     /* see shape_of() */
    char                     network[DESCRIPTOR_NETWORK_MAX]; /* display name  */
    uint32_t                 keys;            /* keys in the descriptor            */
    uint32_t                 threshold;       /* multisig m, 0 when not a multisig */
    bool                     network_assumed; /* text carried no network      */
};

/* -- Shape / threshold helpers ---------------------------------------- */

/* Copy the function name at @p s into @p out and return its length, or 0 when
 * @p s does not start with a "name(" call.  Requiring the parenthesis keeps
 * raw keys (hex strings that also read as identifiers) out. */
static size_t func_name_at(const char* s, char* out, size_t cap) {
    size_t n = 0;
    while (s[n] && (isalnum((unsigned char)s[n]) || s[n] == '_')) n++;
    if (cap) out[0] = '\0';
    if (n == 0 || !cap || s[n] != '(') return 0;
    size_t copy = n < cap - 1 ? n : cap - 1;
    memcpy(out, s, copy);
    out[copy] = '\0';
    return n;
}

/* Join "outer(inner)" into `out`, truncating if needed. Hand-rolled because the
 * snprintf form trips -Werror=format-truncation at -O2. */
static void shape_join(char* out, size_t cap, const char* outer, const char* inner) {
    if (cap == 0) return;
    size_t n = 0;
    for (size_t i = 0; outer[i] && n + 1 < cap; i++) out[n++] = outer[i];
    if (inner[0] && n + 1 < cap) {
        out[n++] = '(';
        for (size_t i = 0; inner[i] && n + 1 < cap; i++) out[n++] = inner[i];
        if (n + 1 < cap) out[n++] = ')';
    }
    out[n] = '\0';
}

/* Describe the script shape of descriptor text @p s, e.g. "wpkh", "tr",
 * "sh(wpkh)" or "wsh(sortedmulti)".  The two nesting wrappers are spelled out
 * because sh()/wsh() decide the address type; anything deeper (a miniscript
 * tree) reports only its outermost expression.  Display only: a shape this
 * doesn't recognise is shown as the outermost name on its own. */
static void shape_of(const char* s, char* out, size_t cap) {
    out[0] = '\0';
    if (!s || cap == 0) return;

    char   outer[DESCRIPTOR_SHAPE_MAX / 2];
    size_t n = func_name_at(s, outer, sizeof(outer));
    if (n == 0) {
        snprintf(out, cap, "expression");
        return;
    }

    if (strcmp(outer, "sh") != 0 && strcmp(outer, "wsh") != 0) {
        snprintf(out, cap, "%s", outer);
        return;
    }

    char inner[DESCRIPTOR_SHAPE_MAX / 2];
    if (func_name_at(s + n + 1, inner, sizeof(inner)) > 0)
        shape_join(out, cap, outer, inner);
    else
        snprintf(out, cap, "%s", outer);
}

/* Threshold of a multisig expression ("multi(m,...)", "sortedmulti(m,...)"
 * and their tapscript "_a" variants); 0 when the descriptor has none.  Read
 * from the text rather than the parse tree, and used for display only. */
static uint32_t multisig_threshold(const char* s) {
    for (const char* p = s; p && *p; p++) {
        if (strncmp(p, "multi", 5) != 0) continue;
        const char* q = p + 5;
        if (strncmp(q, "_a", 2) == 0) q += 2;
        if (*q++ != '(') continue;
        if (*q < '0' || *q > '9') continue;

        uint32_t m = 0;
        while (*q >= '0' && *q <= '9' && m < 1000) m = m * 10 + (uint32_t)(*q++ - '0');
        if (*q != ',') continue;
        return m;
    }
    return 0;
}

/* Network a descriptor's keys belong to, from the base58 version prefix of an
 * extended key: it is the only network information the text carries.
 * libwally reports WALLY_NETWORK_NONE for a descriptor parsed without one
 * (even when its keys are xpub/tpub), so the prefix decides.  The "#checksum"
 * is skipped: it is base58 too and could fake a prefix.  Returns
 * WALLY_NETWORK_NONE when the text says nothing (raw keys). */
static uint32_t network_from_text(const char* s) {
    for (const char* p = s; *p && *p != '#'; p++) {
        if (strncmp(p, "tpub", 4) == 0) return WALLY_NETWORK_BITCOIN_TESTNET;
        if (strncmp(p, "xpub", 4) == 0) return WALLY_NETWORK_BITCOIN_MAINNET;
    }
    return WALLY_NETWORK_NONE;
}

/* Give @p wd a network if it has none: the one its keys' prefix implies, and
 * mainnet otherwise, so addresses can still be generated from raw-key
 * descriptors (which carry no network at all).  @p network_out receives the
 * network in use, @p assumed_out (optional) whether it had to be assumed.
 * Either out pointer may be NULL.  Returns false when it could not be set. */
static bool apply_default_network(struct wally_descriptor* wd, const char* text,
                                  uint32_t* network_out, bool* assumed_out) {
    uint32_t net     = WALLY_NETWORK_NONE;
    bool     assumed = false;

    if (wally_descriptor_get_network(wd, &net) != WALLY_OK) return false;
    if (net == WALLY_NETWORK_NONE) {
        net = network_from_text(text);
        if (net == WALLY_NETWORK_NONE) {
            net     = WALLY_NETWORK_BITCOIN_MAINNET;
            assumed = true;
        }
        if (wally_descriptor_set_network(wd, net) != WALLY_OK) return false;
    }

    if (network_out) *network_out = net;
    if (assumed_out) *assumed_out = assumed;
    return true;
}

/* Display name of an address network.  A descriptor can only carry the two
 * bitcoin ones: its keys' base58 prefix is all the network information there
 * is (see network_from_text()), and Elements descriptors are not built. */
static const char* network_name(uint32_t network) {
    switch (network) {
    case WALLY_NETWORK_BITCOIN_MAINNET:
        return "mainnet";
    case WALLY_NETWORK_BITCOIN_TESTNET:
        return "testnet";
    default:
        return "unknown";
    }
}

/* -- Helpers ---------------------------------------------------------- */
/* Return the hardcoded derivation branch (0 or 1) of a descriptor whose key
 * path ends in "/N/" + range wildcard (N optionally followed by ' or h).
 * Return -1 for a plain range, a double range (equivalent to <0;1> + range),
 * "<...>" multi-paths, or non-ranged descriptors.  The branch is the last
 * path component before the trailing wildcard, so key-origin components
 * (inside [...]) never match. */
static int trailing_branch(const char* s) {
    if (!s) return -1;
    const char* star = strrchr(s, '*');
    if (!star || star == s || star[-1] != '/') return -1; /* no range suffix */

    const char* slash1 = star - 1; /* '/' immediately before '*' */
    const char* p      = slash1 - 1;
    while (p > s && p[-1] != '/') p--;

    size_t tok_len = (size_t)(slash1 - p);
    if (tok_len != 1 && tok_len != 2) return -1;

    char digit = p[0];
    if (digit != '0' && digit != '1') return -1;
    if (tok_len == 2 && p[1] != '\'' && p[1] != 'h') return -1;
    return digit - '0';
}

/* Write `s` with the trailing branch (0<->1) flipped into `out`.  Only valid
 * when trailing_branch() returned 0 or 1. */
static bool flip_branch_str(const char* s, char* out, size_t cap) {
    if (!s || !out || cap == 0) return false;
    const char* star = strrchr(s, '*');
    if (!star || star == s || star[-1] != '/') return false;

    const char* slash1 = star - 1;
    const char* p      = slash1 - 1;
    while (p > s && p[-1] != '/') p--;

    size_t prefix = (size_t)(p - s);
    if (prefix + 2 + strlen(slash1 + 1) >= cap) return false;

    memcpy(out, s, prefix);
    out[prefix] = (p[0] == '0') ? '1' : '0';
    strcpy(out + prefix + 1, p + 1);
    return true;
}

static void add_addr(descriptor_t* d, const char* addr, bool change) {
    if (!d || !d->addrs || !addr || !addr[0]) return;
    if (d->n_addrs >= DESCRIPTOR_MAX_ADDRS) return;
    char* copy = strdup(addr);
    if (!copy) return;
    d->addrs[d->n_addrs].addr   = copy;
    d->addrs[d->n_addrs].change = change;
    d->n_addrs++;
}

static void derive_into(descriptor_t* d, struct wally_descriptor* wd, uint32_t num_paths,
                        bool multi_change, bool change_only, bool ranged) {
    if (!wd) return;
    uint32_t gap = ranged ? DESCRIPTOR_GAP_LIMIT : 1;

    for (uint32_t mi = 0; mi < num_paths && mi < DESCRIPTOR_MAX_PATHS; mi++) {
        bool is_change = change_only || (multi_change && mi > 0);

        char* addrs[DESCRIPTOR_GAP_LIMIT];
        memset(addrs, 0, sizeof(addrs));
        if (wally_descriptor_to_addresses(wd, 0, mi, 0, 0, addrs, gap) != WALLY_OK) continue;
        for (uint32_t i = 0; i < gap; i++) {
            if (!addrs[i]) break;
            add_addr(d, addrs[i], is_change);
            wally_free_string(addrs[i]);
        }
    }
}

/* -- Public API ------------------------------------------------------- */
descriptor_t* descriptor_parse(const uint8_t* payload, size_t len, descriptor_status_t* status) {
    descriptor_status_t st = DESCRIPTOR_ERR_NOT_DESC;
    if (status) *status = st;

    if (!payload || len == 0) return NULL;
    if (len > DESCRIPTOR_MAX_PAYLOAD) {
        st = DESCRIPTOR_ERR_TOO_LONG;
        if (status) *status = st;
        return NULL;
    }

    /* NUL-terminate and trim surrounding whitespace. */
    char* str = malloc(len + 1);
    if (!str) return NULL;
    memcpy(str, payload, len);
    str[len] = '\0';
    char* e  = str + len;
    while (e > str && (e[-1] == '\n' || e[-1] == '\r' || e[-1] == ' ' || e[-1] == '\t'))
        *--e = '\0';
    char* b = str;
    while (*b == ' ' || *b == '\t' || *b == '\n' || *b == '\r') b++;

    struct wally_descriptor* wd = NULL;
    if (wally_descriptor_parse(b, NULL, WALLY_NETWORK_NONE, 0, &wd) != WALLY_OK) {
        free(str);
        return NULL;
    }

    uint32_t features = 0;
    if (wally_descriptor_get_features(wd, &features) != WALLY_OK) {
        wally_descriptor_free(wd);
        free(str);
        return NULL;
    }

    /* Networks are absent from most descriptor text, so a descriptor that
     * carries none is given the one its keys imply, and mainnet when even they
     * say nothing (raw keys): addresses cannot be derived without a network. */
    uint32_t network         = WALLY_NETWORK_NONE;
    bool     network_assumed = false;
    if (!apply_default_network(wd, b, &network, &network_assumed)) {
        wally_descriptor_free(wd);
        free(str);
        return NULL;
    }

    bool     ranged    = (features & WALLY_MS_IS_RANGED) != 0;
    uint32_t num_paths = 1;
    {
        uint32_t np = 0;
        if (wally_descriptor_get_num_paths(wd, &np) == WALLY_OK && np > 0) num_paths = np;
    }

    descriptor_t* d = calloc(1, sizeof(*d));
    if (!d) {
        wally_descriptor_free(wd);
        free(str);
        return NULL;
    }
    d->addrs = calloc(DESCRIPTOR_MAX_ADDRS, sizeof(*d->addrs));
    if (!d->addrs) {
        free(d);
        wally_descriptor_free(wd);
        free(str);
        return NULL;
    }
    d->receive         = wd;
    d->network_assumed = network_assumed;
    snprintf(d->network, sizeof(d->network), "%s", network_name(network));

    /* Drop a trailing BIP-380 "#checksum".  libwally validates the checksum
     * when parsing (above), but it must not be carried into the flipped
     * branch-1 sibling: flipping the branch invalidates the checksum and
     * libwally re-validates on parse, so the sibling parse would fail and
     * change detection would silently stop working. */
    char* hash = strrchr(b, '#');
    if (hash) *hash = '\0';

    /* Facts for the overview screen shown before the descriptor is used. */
    shape_of(b, d->shape, sizeof(d->shape));
    d->threshold = multisig_threshold(b);
    {
        uint32_t nk = 0;
        if (wally_descriptor_get_num_keys(wd, &nk) == WALLY_OK) d->keys = nk;
    }
    d->text = strdup(b);
    if (!d->text) {
        descriptor_free(d);
        free(str);
        return NULL;
    }

    int branch = trailing_branch(b);

    if (ranged && num_paths == 1 && branch == 0) {
        /* Receive descriptor (branch 0): derive change from the branch-1
         * sibling. */
        derive_into(d, d->receive, 1, false, false, true);

        char sibling[DESCRIPTOR_MAX_PAYLOAD + 1];
        if (flip_branch_str(b, sibling, sizeof(sibling))) {
            struct wally_descriptor* wc = NULL;
            if (wally_descriptor_parse(sibling, NULL, WALLY_NETWORK_NONE, 0, &wc) == WALLY_OK) {
                /* Same network as the scanned branch, so both branches derive
                 * addresses of the same kind. */
                if (apply_default_network(wc, sibling, NULL, NULL)) {
                    d->change = wc;
                    derive_into(d, wc, 1, false, true, true);
                } else {
                    wally_descriptor_free(wc);
                }
            }
        }
    } else if (ranged && num_paths == 1 && branch == 1) {
        /* Change-only descriptor (branch 1): all addresses are change. */
        derive_into(d, d->receive, 1, false, true, true);
    } else {
        /* Plain range, double range, or <...> multi-path: mi 0 = receive,
         * mi >= 1 = change. */
        derive_into(d, d->receive, num_paths, true, false, ranged);
    }

    free(str);
    st = DESCRIPTOR_OK;
    if (status) *status = st;
    return d;
}

void descriptor_free(descriptor_t* d) {
    if (!d) return;
    for (size_t i = 0; i < d->n_addrs; i++) {
        if (d->addrs[i].addr) {
            secure_memzero(d->addrs[i].addr, strlen(d->addrs[i].addr));
            free(d->addrs[i].addr);
        }
    }
    free(d->addrs);
    if (d->text) {
        secure_memzero(d->text, strlen(d->text));
        free(d->text);
    }
    if (d->change) wally_descriptor_free(d->change);
    if (d->receive) wally_descriptor_free(d->receive);
    free(d);
}

descriptor_match_t descriptor_classify(const descriptor_t* d, const char* address) {
    if (!d || !address) return DESCRIPTOR_MATCH_NONE;
    for (size_t i = 0; i < d->n_addrs; i++) {
        if (d->addrs[i].addr && strcmp(d->addrs[i].addr, address) == 0) {
            return d->addrs[i].change ? DESCRIPTOR_MATCH_CHANGE : DESCRIPTOR_MATCH_RECEIVE;
        }
    }
    return DESCRIPTOR_MATCH_NONE;
}

bool descriptor_owns_address(const descriptor_t* d, const char* address) {
    return descriptor_classify(d, address) != DESCRIPTOR_MATCH_NONE;
}

/* -- Overview --------------------------------------------------------- */
/* Appends into a fixed buffer and records when it runs out of room, so the
 * overview says it was cut short instead of silently losing the end of the
 * descriptor text. */
typedef struct {
    char*  out;
    size_t cap;
    size_t off;
    bool   full;
} obuf_t;

static void ob_addf(obuf_t* ob, const char* fmt, ...) {
    if (ob->full || ob->off >= ob->cap) {
        ob->full = true;
        return;
    }
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(ob->out + ob->off, ob->cap - ob->off, fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n >= ob->cap - ob->off) {
        ob->full = true; /* vsnprintf truncated this line */
        return;
    }
    ob->off += (size_t)n;
}

static const char OB_TRUNCATED[] = "... overview truncated ...\n";

static void ob_finish(obuf_t* ob) {
    if (ob->cap == 0) return;
    if (!ob->full) {
        ob->out[ob->off < ob->cap ? ob->off : ob->cap - 1] = '\0';
        return;
    }

    /* End at the last whole line: the failing vsnprintf left a partial one
     * behind it. */
    size_t cut = ob->off < ob->cap ? ob->off : ob->cap - 1;
    while (cut > 0 && ob->out[cut - 1] != '\n') cut--;

    /* Then say the overview is incomplete, dropping whole lines until the
     * marker fits so the text never stops mid-line. */
    size_t mlen = sizeof(OB_TRUNCATED) - 1;
    if (ob->cap > mlen) {
        size_t limit = ob->cap - mlen - 1;
        while (cut > limit) {
            size_t prev = cut - 1;
            while (prev > 0 && ob->out[prev - 1] != '\n') prev--;
            cut = prev;
        }
        memcpy(ob->out + cut, OB_TRUNCATED, mlen);
        ob->out[cut + mlen] = '\0';
        ob->off             = cut + mlen;
        return;
    }

    /* Not even the marker fits: keep whatever whole lines there were. */
    if (cut >= ob->cap) cut = ob->cap - 1;
    ob->out[cut] = '\0';
    ob->off      = cut;
}

size_t descriptor_overview(const descriptor_t* d, char* out, size_t cap) {
    if (!d || !out || cap == 0) return 0;

    obuf_t ob = {.out = out, .cap = cap, .off = 0, .full = false};

    ob_addf(&ob, "%s\n", d->shape[0] ? d->shape : "descriptor");
    if (d->keys > 0) {
        if (d->threshold > 0)
            ob_addf(&ob, "keys: %u of %u\n", (unsigned)d->threshold, (unsigned)d->keys);
        else
            ob_addf(&ob, "keys: %u\n", (unsigned)d->keys);
    }
    ob_addf(&ob, "network: %s%s\n", d->network, d->network_assumed ? " (assumed)" : "");

    size_t n_recv = 0, n_change = 0;
    for (size_t i = 0; i < d->n_addrs; i++) {
        if (d->addrs[i].change)
            n_change++;
        else
            n_recv++;
    }
    if (n_recv > 0 || n_change > 0)
        ob_addf(&ob, "watch: %zu receive + %zu change\n", n_recv, n_change);

    if (d->keys > 0) {
        ob_addf(&ob, "\nkey origins:\n");
        for (uint32_t i = 0; i < d->keys; i++) {
            if (i == DESCRIPTOR_OVERVIEW_MAX_KEYS) {
                ob_addf(&ob, "  ... and %u more\n", (unsigned)(d->keys - i));
                break;
            }

            unsigned char fp[BIP32_KEY_FINGERPRINT_LEN];
            bool          have_fp = wally_descriptor_get_key_origin_fingerprint(d->receive, i, fp,
                                                                       sizeof(fp)) == WALLY_OK;
            if (!have_fp) {
                ob_addf(&ob, "  #%u (no key origin)\n", (unsigned)i);
                continue;
            }

            char* path = NULL;
            if (wally_descriptor_get_key_origin_path_str(d->receive, i, &path) != WALLY_OK) {
                path = NULL;
            }
            if (path && path[0]) {
                ob_addf(&ob, "  #%u [%02x%02x%02x%02x/%s]\n", (unsigned)i, (unsigned)fp[0],
                        (unsigned)fp[1], (unsigned)fp[2], (unsigned)fp[3], path);
            } else {
                ob_addf(&ob, "  #%u [%02x%02x%02x%02x]\n", (unsigned)i, (unsigned)fp[0],
                        (unsigned)fp[1], (unsigned)fp[2], (unsigned)fp[3]);
            }
            if (path) wally_free_string(path);
        }
    }

    if (d->text && d->text[0]) ob_addf(&ob, "\ndescriptor:\n%s\n", d->text);

    ob_finish(&ob);
    return ob.off;
}

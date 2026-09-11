/**
 * @file main/crypto/descriptor.c
 * @brief Parse a wallet output descriptor and match transaction outputs.
 */

#include "descriptor.h"
#include "util/utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_address.h>
#include <wally_core.h>
#include <wally_descriptor.h>

/* Upper bounds to keep derived-address caches small on embedded targets. */
#define DESCRIPTOR_MAX_PATHS 8
#define DESCRIPTOR_MAX_ADDRS (DESCRIPTOR_MAX_PATHS * DESCRIPTOR_GAP_LIMIT * 2)

typedef struct {
    char* addr;
    bool  change;
} desc_addr_t;

struct descriptor {
    struct wally_descriptor* receive; /* primary descriptor (as scanned)   */
    struct wally_descriptor* change;  /* change-branch sibling (branch 1)  */
    desc_addr_t*             addrs;   /* cached derived addresses          */
    size_t                   n_addrs;
};

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

    /* Never hold private key material. */
    if (features & WALLY_MS_IS_PRIVATE) {
        wally_descriptor_free(wd);
        free(str);
        st = DESCRIPTOR_ERR_PRIVATE;
        if (status) *status = st;
        return NULL;
    }

    /* Raw-key descriptors carry no network; default to mainnet so addresses
     * match tx_inspect's mainnet rendering. */
    uint32_t network = 0;
    if (wally_descriptor_get_network(wd, &network) != WALLY_OK) {
        wally_descriptor_free(wd);
        free(str);
        return NULL;
    }
    if (network == WALLY_NETWORK_NONE) {
        if (wally_descriptor_set_network(wd, WALLY_NETWORK_BITCOIN_MAINNET) != WALLY_OK) {
            wally_descriptor_free(wd);
            free(str);
            return NULL;
        }
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
    d->receive = wd;

    /* Drop a trailing BIP-380 "#checksum".  libwally validates the checksum
     * when parsing (above), but it must not be carried into the flipped
     * branch-1 sibling: flipping the branch invalidates the checksum and
     * libwally re-validates on parse, so the sibling parse would fail and
     * change detection would silently stop working. */
    char* hash = strrchr(b, '#');
    if (hash) *hash = '\0';

    int branch = trailing_branch(b);

    if (ranged && num_paths == 1 && branch == 0) {
        /* Receive descriptor (branch 0): derive change from the branch-1
         * sibling. */
        derive_into(d, d->receive, 1, false, false, true);

        char sibling[DESCRIPTOR_MAX_PAYLOAD + 1];
        if (flip_branch_str(b, sibling, sizeof(sibling))) {
            struct wally_descriptor* wc = NULL;
            if (wally_descriptor_parse(sibling, NULL, WALLY_NETWORK_NONE, 0, &wc) == WALLY_OK) {
                uint32_t cnet = 0;
                if (wally_descriptor_get_network(wc, &cnet) == WALLY_OK &&
                    cnet == WALLY_NETWORK_NONE) {
                    wally_descriptor_set_network(wc, WALLY_NETWORK_BITCOIN_MAINNET);
                }
                d->change = wc;
                derive_into(d, wc, 1, false, true, true);
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

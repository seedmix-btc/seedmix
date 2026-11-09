/**
 * @file main/crypto/multisig.c
 * @brief m-of-n multisig descriptor builder, see multisig.h.
 */

#include "multisig.h"
#include "util/utils.h"

#include "wally_address.h"
#include "wally_bip32.h"
#include "wally_bip39.h"
#include "wally_core.h"
#include "wally_descriptor.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* BIP48: the account level of a multisig wallet.  The script type is the last
 * hardened step, 2' for native segwit (1' is the legacy sh(wsh) convention). */
#define MULTISIG_PURPOSE 48
#define MULTISIG_SCRIPT_TYPE 2

typedef struct {
    bool ready;
    char fingerprint[MULTISIG_FP_MAX];
    char path[MULTISIG_PATH_MAX];
    char xpub[MULTISIG_XPUB_MAX];
} multisig_slot_t;

struct multisig {
    size_t             keys;
    size_t             threshold;
    uint32_t           coin;
    multisig_network_t network;
    multisig_slot_t    slots[MULTISIG_MAX_KEYS];
};

multisig_t* multisig_new(size_t keys, size_t threshold, multisig_network_t network) {
    if (keys < 2 || keys > MULTISIG_MAX_KEYS || threshold < 1 || threshold > keys) return NULL;

    multisig_t* ms = calloc(1, sizeof(*ms));
    if (!ms) return NULL;
    ms->keys      = keys;
    ms->threshold = threshold;
    ms->network   = network;
    ms->coin      = network == MULTISIG_TESTNET ? 1u : 0u;
    return ms;
}

/* base58check of the 78-byte BIP32 serialization with an arbitrary version
 * prefix: libwally only serializes keys whose own version is xpub/tpub. */
static bool serialize_pub(const struct ext_key* key, uint32_t version, char* out, size_t cap) {
    unsigned char ser[BIP32_SERIALIZED_LEN];

    ser[0] = (unsigned char)(version >> 24);
    ser[1] = (unsigned char)(version >> 16);
    ser[2] = (unsigned char)(version >> 8);
    ser[3] = (unsigned char)version;
    ser[4] = key->depth;
    memcpy(ser + 5, key->parent160, BIP32_KEY_FINGERPRINT_LEN);
    ser[9]  = (unsigned char)(key->child_num >> 24);
    ser[10] = (unsigned char)(key->child_num >> 16);
    ser[11] = (unsigned char)(key->child_num >> 8);
    ser[12] = (unsigned char)key->child_num;
    memcpy(ser + 13, key->chain_code, 32);
    memcpy(ser + 45, key->pub_key, sizeof(key->pub_key));

    char* b58 = NULL;
    bool  ok  = wally_base58_from_bytes(ser, sizeof(ser), BASE58_FLAG_CHECKSUM, &b58) == WALLY_OK &&
              b58 != NULL && strlen(b58) < cap;
    if (ok) memcpy(out, b58, strlen(b58) + 1);
    if (b58) wally_free_string(b58);
    secure_memzero(ser, sizeof(ser));
    return ok;
}

/* Derive the BIP48 account key of one cosigner. The master private key is only
 * needed because hardened steps cannot be taken with a public key. */
static bool fill_slot(multisig_slot_t* slot, const char* words, uint32_t coin,
                      multisig_network_t network) {
    if (!slot || !words || !words[0]) return false;

    /* PBKDF2 will happily stretch anything into a seed, so the words have to be
     * a real BIP39 mnemonic before they are allowed in. */
    size_t    written = 0;
    uint8_t   entropy[32]; /* 24 words of entropy */
    const int valid = bip39_mnemonic_to_bytes(NULL, words, entropy, sizeof(entropy), &written);
    secure_memzero(entropy, sizeof(entropy));
    if (valid != WALLY_OK || (written != 16 && written != 32)) return false;

    uint8_t seed[BIP39_SEED_LEN_512];
    size_t  seed_len = 0;
    if (bip39_mnemonic_to_seed(words, NULL, seed, sizeof(seed), &seed_len) != WALLY_OK ||
        seed_len != BIP39_SEED_LEN_512) {
        secure_memzero(seed, sizeof(seed));
        return false;
    }

    struct ext_key master;
    const uint32_t private_version =
        network == MULTISIG_TESTNET ? BIP32_VER_TEST_PRIVATE : BIP32_VER_MAIN_PRIVATE;
    const uint32_t public_version =
        network == MULTISIG_TESTNET ? BIP32_VER_TEST_PUBLIC : BIP32_VER_MAIN_PUBLIC;
    const int rc = bip32_key_from_seed(seed, seed_len, private_version, 0, &master);
    secure_memzero(seed, sizeof(seed));
    if (rc != WALLY_OK) return false;

    uint8_t fp[BIP32_KEY_FINGERPRINT_LEN];
    bool    ok = bip32_key_get_fingerprint(&master, fp, sizeof(fp)) == WALLY_OK &&
              bytes_to_hex(fp, sizeof(fp), slot->fingerprint, sizeof(slot->fingerprint));

    const uint32_t path[4] = {
        BIP32_INITIAL_HARDENED_CHILD | MULTISIG_PURPOSE,
        BIP32_INITIAL_HARDENED_CHILD | coin,
        BIP32_INITIAL_HARDENED_CHILD,
        BIP32_INITIAL_HARDENED_CHILD | MULTISIG_SCRIPT_TYPE,
    };
    struct ext_key account;
    ok = ok &&
         bip32_key_from_parent_path(&master, path, 4, BIP32_FLAG_KEY_PRIVATE, &account) == WALLY_OK;
    secure_memzero(&master, sizeof(master));

    if (ok) {
        ok = serialize_pub(&account, public_version, slot->xpub, sizeof(slot->xpub)) &&
             snprintf(slot->path, sizeof(slot->path), "m/48'/%u'/0'/%u'", (unsigned)coin,
                      (unsigned)MULTISIG_SCRIPT_TYPE) > 0;
    }
    secure_memzero(&account, sizeof(account));
    if (ok) slot->ready = true;
    return ok;
}

multisig_set_result_t multisig_set_words_ex(multisig_t* ms, size_t slot, const char* words,
                                            size_t* duplicate_of) {
    if (duplicate_of) *duplicate_of = SIZE_MAX;
    if (!ms || slot >= ms->keys || !words || !words[0]) return MULTISIG_SET_BAD_SLOT;

    /* Derive into a scratch slot: a refused key must leave the wallet as it was. */
    multisig_slot_t candidate;
    memset(&candidate, 0, sizeof(candidate));
    if (!fill_slot(&candidate, words, ms->coin, ms->network)) {
        secure_memzero(&candidate, sizeof(candidate));
        return MULTISIG_SET_INVALID_MNEMONIC;
    }

    /* One seed can only ever be one cosigner: its account xpub is the same
     * wherever it is entered. */
    for (size_t i = 0; i < ms->keys; i++) {
        if (i == slot || !ms->slots[i].ready) continue;
        if (strcmp(ms->slots[i].xpub, candidate.xpub) == 0) {
            if (duplicate_of) *duplicate_of = i;
            secure_memzero(&candidate, sizeof(candidate));
            return MULTISIG_SET_DUPLICATE_KEY;
        }
    }

    ms->slots[slot] = candidate;
    secure_memzero(&candidate, sizeof(candidate));
    return MULTISIG_SET_OK;
}

bool multisig_set_mnemonic(multisig_t* ms, size_t slot, const mnemonic_t* m) {
    if (!m) return false;
    return multisig_set_words(ms, slot, mnemonic_words(m));
}

bool multisig_set_words(multisig_t* ms, size_t slot, const char* words) {
    return multisig_set_words_ex(ms, slot, words, NULL) == MULTISIG_SET_OK;
}

size_t multisig_key_count(const multisig_t* ms) { return ms ? ms->keys : 0; }
size_t multisig_threshold(const multisig_t* ms) { return ms ? ms->threshold : 0; }

bool multisig_complete(const multisig_t* ms) {
    if (!ms) return false;
    for (size_t i = 0; i < ms->keys; i++) {
        if (!ms->slots[i].ready) return false;
    }
    return true;
}

bool multisig_slot_ready(const multisig_t* ms, size_t slot) {
    return ms && slot < ms->keys && ms->slots[slot].ready;
}

const char* multisig_slot_fingerprint(const multisig_t* ms, size_t slot) {
    return multisig_slot_ready(ms, slot) ? ms->slots[slot].fingerprint : NULL;
}

const char* multisig_slot_path(const multisig_t* ms, size_t slot) {
    return multisig_slot_ready(ms, slot) ? ms->slots[slot].path : NULL;
}

const char* multisig_slot_xpub(const multisig_t* ms, size_t slot) {
    return multisig_slot_ready(ms, slot) ? ms->slots[slot].xpub : NULL;
}

/* Append the descriptor text (without checksum) to out. */
static size_t build_text(const multisig_t* ms, char* out, size_t cap) {
    size_t used = 0;
    int    n    = snprintf(out, cap, "wsh(sortedmulti(%u", (unsigned)ms->threshold);
    if (n <= 0 || (size_t)n >= cap) return 0;
    used = (size_t)n;

    for (size_t i = 0; i < ms->keys; i++) {
        const multisig_slot_t* s = &ms->slots[i];
        /* "m/48'/0'/0'/2'" -> "48'/0'/0'/2'": a descriptor key origin drops the m. */
        const char* origin = (s->path[0] == 'm' && s->path[1] == '/') ? s->path + 2 : s->path;
        n = snprintf(out + used, cap - used, ",[%s/%s]%s/<0;1>/*", s->fingerprint, origin, s->xpub);
        if (n <= 0 || (size_t)n >= cap - used) return 0;
        used += (size_t)n;
    }

    n = snprintf(out + used, cap - used, "))");
    if (n <= 0 || (size_t)n >= cap - used) return 0;
    return used + (size_t)n;
}

size_t multisig_descriptor(const multisig_t* ms, char* out, size_t cap) {
    if (!out || cap == 0) return 0;
    out[0] = '\0';
    if (!ms || !multisig_complete(ms)) return 0;

    const size_t len = build_text(ms, out, cap);
    if (len == 0) {
        out[0] = '\0';
        return 0;
    }

    /* BIP-380 checksum, so wallets that require one accept the text as is. */
    size_t                   res = len;
    struct wally_descriptor* wd  = NULL;
    if (wally_descriptor_parse(out, NULL, WALLY_NETWORK_NONE, 0, &wd) == WALLY_OK) {
        char* checksum = NULL;
        if (wally_descriptor_get_checksum(wd, 0, &checksum) == WALLY_OK && checksum) {
            const int n = snprintf(out + len, cap - len, "#%s", checksum);
            if (n > 0 && (size_t)n < cap - len)
                res = len + (size_t)n;
            else
                res = 0;
            wally_free_string(checksum);
        }
        wally_descriptor_free(wd);
    }
    if (res == 0) out[0] = '\0';
    return res;
}

size_t multisig_cosigner_key(const multisig_t* ms, size_t slot, char* out, size_t cap) {
    if (!out || cap == 0) return 0;
    out[0] = '\0';
    if (!multisig_slot_ready(ms, slot)) return 0;

    const multisig_slot_t* s = &ms->slots[slot];
    /* "m/48'/0'/0'/2'" -> "48'/0'/0'/2'": a descriptor key origin drops the m. */
    const char* origin = (s->path[0] == 'm' && s->path[1] == '/') ? s->path + 2 : s->path;
    const int   n      = snprintf(out, cap, "[%s/%s]%s/<0;1>/*", s->fingerprint, origin, s->xpub);
    if (n <= 0 || (size_t)n >= cap) {
        out[0] = '\0';
        return 0;
    }
    return (size_t)n;
}

static size_t summary_write(const multisig_t* ms, char* out, size_t cap) {

    size_t    used = 0;
    const int n =
        snprintf(out, cap, "%u of %u signatures\n%s\n", (unsigned)ms->threshold, (unsigned)ms->keys,
                 ms->network == MULTISIG_TESTNET ? "network: testnet" : "network: mainnet");
    if (n <= 0 || (size_t)n >= cap) return 0;
    used = (size_t)n;

    for (size_t i = 0; i < ms->keys; i++) {
        const multisig_slot_t* s = &ms->slots[i];
        const int m = snprintf(out + used, cap - used, "#%u  %s  %s\n", (unsigned)(i + 1),
                               s->fingerprint, s->path);
        if (m <= 0 || (size_t)m >= cap - used) return 0;
        used += (size_t)m;
    }

    char addr[MULTISIG_ADDR_MAX];
    if (multisig_address(ms, 0, 0, addr, sizeof(addr)) > 0) {
        const int m = snprintf(out + used, cap - used, "\nfirst receive address\n%s\n", addr);
        if (m <= 0 || (size_t)m >= cap - used) return 0;
        used += (size_t)m;
    }

    char desc[MULTISIG_DESCRIPTOR_MAX];
    if (multisig_descriptor(ms, desc, sizeof(desc)) > 0) {
        const int m = snprintf(out + used, cap - used, "\n%s\n", desc);
        if (m <= 0 || (size_t)m >= cap - used) return 0;
        used += (size_t)m;
    }
    return used;
}

size_t multisig_summary(const multisig_t* ms, char* out, size_t cap) {
    if (!out || cap == 0) return 0;
    out[0] = '\0';
    if (!ms || !multisig_complete(ms)) return 0;

    const size_t len = summary_write(ms, out, cap);
    if (len == 0) out[0] = '\0';
    return len;
}

size_t multisig_address(const multisig_t* ms, uint32_t branch, uint32_t index, char* out,
                        size_t cap) {
    if (!ms || !out || cap == 0) return 0;
    out[0] = '\0';

    char desc[MULTISIG_DESCRIPTOR_MAX];
    if (multisig_descriptor(ms, desc, sizeof(desc)) == 0) return 0;

    size_t                   res = 0;
    struct wally_descriptor* wd  = NULL;
    if (wally_descriptor_parse(desc, NULL, WALLY_NETWORK_NONE, 0, &wd) == WALLY_OK) {
        const uint32_t network = ms->network == MULTISIG_TESTNET ? WALLY_NETWORK_BITCOIN_TESTNET
                                                                 : WALLY_NETWORK_BITCOIN_MAINNET;
        if (wally_descriptor_set_network(wd, network) == WALLY_OK) {
            char* addr = NULL;
            if (wally_descriptor_to_addresses(wd, 0, branch, index, 0, &addr, 1) == WALLY_OK &&
                addr) {
                const size_t n = strlen(addr);
                if (n < cap) {
                    memcpy(out, addr, n + 1);
                    res = n;
                }
                wally_free_string(addr);
            }
        }
        wally_descriptor_free(wd);
    }
    secure_memzero(desc, sizeof(desc));
    return res;
}

void multisig_free(multisig_t* ms) {
    if (!ms) return;
    secure_memzero(ms, sizeof(*ms));
    free(ms);
}

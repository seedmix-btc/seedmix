/**
 * @file main/crypto/keycheck.c
 * @brief Master fingerprint, account keys and first addresses for a mnemonic.
 */

#include "keycheck.h"
#include "util/utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_address.h>
#include <wally_bip32.h>
#include <wally_bip39.h>
#include <wally_core.h>
#include <wally_crypto.h>
#include <wally_descriptor.h>
#include <wally_script.h>

/** SLIP-132 account-key versions (mainnet, testnet). Wallets that only speak
 * BIP32 would use the xpub/tpub prefix for every policy; the y/z variants
 * name the script type the account key belongs to. */
#define KEYCHECK_YPUB_MAIN 0x049D7CB2u
#define KEYCHECK_UPUB_TEST 0x044A5262u
#define KEYCHECK_ZPUB_MAIN 0x04B24746u
#define KEYCHECK_VPUB_TEST 0x045F1CF6u

typedef struct {
    const char* label;
    uint32_t    purpose;
    uint32_t    version_main;
    uint32_t    version_test;
    bool        taproot;
} policy_def_t;

static const policy_def_t policy_defs[KEYCHECK_POLICY_COUNT] = {
    {"Legacy (BIP44)", 44, BIP32_VER_MAIN_PUBLIC, BIP32_VER_TEST_PUBLIC, false},
    {"Nested SegWit (BIP49)", 49, KEYCHECK_YPUB_MAIN, KEYCHECK_UPUB_TEST, false},
    {"Native SegWit (BIP84)", 84, KEYCHECK_ZPUB_MAIN, KEYCHECK_VPUB_TEST, false},
    {"Taproot (BIP86)", 86, BIP32_VER_MAIN_PUBLIC, BIP32_VER_TEST_PUBLIC, true},
};

static const char* const policy_tabs[KEYCHECK_POLICY_COUNT] = {"BIP44", "BIP49", "BIP84", "BIP86"};

struct keycheck {
    struct ext_key    master; /* private, so a policy can be derived later */
    bool              have_master;
    uint32_t          coin;
    bool              testnet;
    char              fingerprint[KEYCHECK_FINGERPRINT_HEX_LEN + 1];
    bool              ready[KEYCHECK_POLICY_COUNT];
    keycheck_policy_t policies[KEYCHECK_POLICY_COUNT];
};

static bool copy_str(char* out, size_t cap, const char* in) {
    if (!out || cap == 0 || !in) return false;
    const size_t n = strlen(in);
    if (n >= cap) return false;
    memcpy(out, in, n + 1);
    return true;
}

/* The account key of one policy. It stays private because the xprv is one of
 * the things the keys screen can export; the public side is serialized from it
 * when needed. */
static bool derive_account(const struct ext_key* master, const policy_def_t* def, uint32_t coin,
                           struct ext_key* out) {
    const uint32_t path[3] = {
        BIP32_INITIAL_HARDENED_CHILD | def->purpose,
        BIP32_INITIAL_HARDENED_CHILD | coin,
        BIP32_INITIAL_HARDENED_CHILD,
    };
    return bip32_key_from_parent_path(master, path, 3, BIP32_FLAG_KEY_PRIVATE, out) == WALLY_OK;
}

/* base58check-encode an account key with an arbitrary version prefix.
 * libwally only serializes keys whose version is xpub/tpub, so the 78-byte
 * BIP32 serialization is assembled here and handed to base58 with a checksum. */
static bool account_to_base58(const struct ext_key* key, uint32_t version, bool priv, char** out) {
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
    memcpy(ser + 45, priv ? key->priv_key : key->pub_key, sizeof(key->pub_key));

    const int rc = wally_base58_from_bytes(ser, sizeof(ser), BASE58_FLAG_CHECKSUM, out);
    secure_memzero(ser, sizeof(ser));
    return rc == WALLY_OK && *out != NULL;
}

/* Address of account/branch/0. Taproot is built by hand because libwally has
 * no `bip32_key_to_address` case for it: BIP341 tweaks the x-only key with a
 * key-path-only merkle root, and the result is a version 1 witness program. */
static bool derive_address(const struct ext_key* account, uint32_t branch, const policy_def_t* def,
                           bool testnet, char* out, size_t cap) {
    const char*    hrp     = testnet ? "tb" : "bc";
    const uint32_t path[2] = {branch, 0};
    struct ext_key child;
    if (bip32_key_from_parent_path(account, path, 2, BIP32_FLAG_KEY_PUBLIC, &child) != WALLY_OK)
        return false;

    char* addr = NULL;
    int   rc;
    if (def->taproot) {
        unsigned char tweaked[EC_PUBLIC_KEY_LEN];
        unsigned char program[WALLY_SEGWIT_V1_ADDRESS_PUBKEY_LEN];
        rc = wally_ec_public_key_bip341_tweak(child.pub_key, sizeof(child.pub_key), NULL, 0, 0,
                                              tweaked, sizeof(tweaked));
        if (rc == WALLY_OK) {
            program[0] = OP_1;
            program[1] = SHA256_LEN;
            memcpy(program + 2, tweaked + 1, SHA256_LEN);
            rc = wally_addr_segwit_from_bytes(program, sizeof(program), hrp, 0, &addr);
        }
        secure_memzero(tweaked, sizeof(tweaked));
        secure_memzero(program, sizeof(program));
    } else if (def->purpose == 84) {
        rc = wally_bip32_key_to_addr_segwit(&child, hrp, 0, &addr);
    } else if (def->purpose == 49) {
        rc = wally_bip32_key_to_address(&child, WALLY_ADDRESS_TYPE_P2SH_P2WPKH,
                                        testnet ? WALLY_ADDRESS_VERSION_P2SH_TESTNET
                                                : WALLY_ADDRESS_VERSION_P2SH_MAINNET,
                                        &addr);
    } else {
        rc = wally_bip32_key_to_address(&child, WALLY_ADDRESS_TYPE_P2PKH,
                                        testnet ? WALLY_ADDRESS_VERSION_P2PKH_TESTNET
                                                : WALLY_ADDRESS_VERSION_P2PKH_MAINNET,
                                        &addr);
    }
    secure_memzero(&child, sizeof(child));

    bool ok = rc == WALLY_OK && addr && copy_str(out, cap, addr);
    if (addr) wally_free_string(addr);
    return ok;
}

/* -- Public API ------------------------------------------------------- */
keycheck_t* keycheck_begin_words(const char* words, const char* passphrase,
                                 keycheck_network_t network) {
    if (!words || !words[0]) return NULL;
    if (passphrase && !passphrase[0]) passphrase = NULL; /* both mean "none" */

    uint8_t seed[BIP39_SEED_LEN_512];
    size_t  seed_len = 0;
    if (bip39_mnemonic_to_seed(words, passphrase, seed, sizeof(seed), &seed_len) != WALLY_OK ||
        seed_len != BIP39_SEED_LEN_512) {
        secure_memzero(seed, sizeof(seed));
        return NULL;
    }

    const bool     testnet = (network == KEYCHECK_TESTNET);
    struct ext_key master;
    const int      rc = bip32_key_from_seed(
        seed, seed_len, testnet ? BIP32_VER_TEST_PRIVATE : BIP32_VER_MAIN_PRIVATE, 0, &master);
    secure_memzero(seed, sizeof(seed));
    if (rc != WALLY_OK) return NULL;

    keycheck_t* k = calloc(1, sizeof(*k));
    if (!k) {
        secure_memzero(&master, sizeof(master));
        return NULL;
    }
    memcpy(&k->master, &master, sizeof(master));
    secure_memzero(&master, sizeof(master));
    k->have_master = true;
    k->testnet     = testnet;
    k->coin        = testnet ? 1u : 0u;

    uint8_t fp[BIP32_KEY_FINGERPRINT_LEN];
    if (bip32_key_get_fingerprint(&k->master, fp, sizeof(fp)) != WALLY_OK ||
        !bytes_to_hex(fp, sizeof(fp), k->fingerprint, sizeof(k->fingerprint))) {
        keycheck_free(k);
        return NULL;
    }

    /* Labels and paths are known up front, so a UI can draw its tabs and say
     * where each one derives from before any key material exists. */
    for (size_t i = 0; i < KEYCHECK_POLICY_COUNT; i++) {
        keycheck_policy_t* out = &k->policies[i];
        char               path[sizeof(out->path)];

        int res = snprintf(path, sizeof(path), "m/%u'/%u'/0'", (unsigned)policy_defs[i].purpose,
                           (unsigned)k->coin);
        if (res <= 0 || (size_t)res >= sizeof(path) ||
            !copy_str(out->label, sizeof(out->label), policy_defs[i].label) ||
            !copy_str(out->path, sizeof(out->path), path)) {
            keycheck_free(k);
            return NULL;
        }
    }
    return k;
}

keycheck_t* keycheck_begin(const mnemonic_t* m, const char* passphrase,
                           keycheck_network_t network) {
    if (!m) return NULL;
    return keycheck_begin_words(mnemonic_words(m), passphrase, network);
}

bool keycheck_policy_derive(keycheck_t* k, size_t index) {
    if (!k || !k->have_master || index >= KEYCHECK_POLICY_COUNT) return false;
    if (k->ready[index]) return true;

    const policy_def_t* def = &policy_defs[index];
    keycheck_policy_t*  out = &k->policies[index];
    struct ext_key      account;
    char*               base58      = NULL;
    char*               base58_xpub = NULL;
    char*               base58_xprv = NULL;
    const uint32_t      pub_version = k->testnet ? BIP32_VER_TEST_PUBLIC : BIP32_VER_MAIN_PUBLIC;
    const uint32_t      prv_version = k->testnet ? BIP32_VER_TEST_PRIVATE : BIP32_VER_MAIN_PRIVATE;

    memset(&account, 0, sizeof(account));
    bool ok = derive_account(&k->master, def, k->coin, &account);
    if (ok)
        ok = account_to_base58(&account, k->testnet ? def->version_test : def->version_main, false,
                               &base58);
    if (ok) ok = copy_str(out->account, sizeof(out->account), base58);
    if (ok) ok = account_to_base58(&account, pub_version, false, &base58_xpub);
    if (ok) ok = account_to_base58(&account, prv_version, true, &base58_xprv);
    if (ok) ok = derive_address(&account, 0, def, k->testnet, out->receive, sizeof(out->receive));
    if (ok) ok = derive_address(&account, 1, def, k->testnet, out->change, sizeof(out->change));

    if (ok) ok = copy_str(out->account_xpub, sizeof(out->account_xpub), base58_xpub);
    if (ok) ok = copy_str(out->account_xprv, sizeof(out->account_xprv), base58_xprv);

    if (base58) wally_free_string(base58);
    if (base58_xpub) wally_free_string(base58_xpub);
    if (base58_xprv) wally_free_string(base58_xprv);
    secure_memzero(&account, sizeof(account));

    k->ready[index] = ok;
    return ok;
}

bool keycheck_policy_ready(const keycheck_t* k, size_t index) {
    return k && index < KEYCHECK_POLICY_COUNT && k->ready[index];
}

const char* keycheck_policy_tab(size_t index) {
    return index < KEYCHECK_POLICY_COUNT ? policy_tabs[index] : "";
}

keycheck_t* keycheck_derive(const mnemonic_t* m, const char* passphrase,
                            keycheck_network_t network) {
    keycheck_t* k = keycheck_begin(m, passphrase, network);
    if (!k) return NULL;
    for (size_t i = 0; i < KEYCHECK_POLICY_COUNT; i++) {
        if (!keycheck_policy_derive(k, i)) {
            keycheck_free(k);
            return NULL;
        }
    }
    return k;
}

const char* keycheck_fingerprint(const keycheck_t* k) { return k ? k->fingerprint : ""; }

size_t keycheck_policy_count(void) { return KEYCHECK_POLICY_COUNT; }

const keycheck_policy_t* keycheck_policy(const keycheck_t* k, size_t index) {
    if (!k || index >= KEYCHECK_POLICY_COUNT) return NULL;
    return &k->policies[index];
}

const char* keycheck_network_name(keycheck_network_t network) {
    return network == KEYCHECK_TESTNET ? "testnet" : "mainnet";
}

/* Append `s` to a fixed buffer, keeping it NUL-terminated. Used instead of
 * snprintf in a loop: the format-truncation check cannot see that the parts
 * already added are bounded, and a silent cut must not happen here. */
static bool summary_append(char* out, size_t cap, size_t* used, const char* s) {
    const size_t n = strlen(s);
    if (*used + n >= cap) return false;
    memcpy(out + *used, s, n + 1);
    *used += n;
    return true;
}

/* Output descriptor around the account key, one per policy: receive and change
 * branches (`<0;1>`) so a watch-only wallet gets the whole account. */
static const char* const descriptor_prefix[KEYCHECK_POLICY_COUNT] = {
    "pkh(",
    "sh(wpkh(",
    "wpkh(",
    "tr(",
};
static const char* const descriptor_suffix[KEYCHECK_POLICY_COUNT] = {")", "))", ")", ")"};

size_t keycheck_policy_descriptor(const keycheck_t* k, size_t index, char* out, size_t cap) {
    if (!k || !out || cap == 0 || !keycheck_policy_ready(k, index)) return 0;

    const keycheck_policy_t* p = &k->policies[index];
    /* "m/84'/0'/0'" -> "84'/0'/0'": a descriptor key origin drops the m. */
    const char* origin = (p->path[0] == 'm' && p->path[1] == '/') ? p->path + 2 : p->path;

    int res = snprintf(out, cap, "%s[%s/%s]%s/<0;1>/*%s", descriptor_prefix[index], k->fingerprint,
                       origin, p->account_xpub, descriptor_suffix[index]);
    if (res <= 0 || (size_t)res >= cap) {
        secure_memzero(out, cap);
        return 0;
    }

    /* BIP-380 checksum, so wallets that require one accept the text as is. */
    struct wally_descriptor* wd = NULL;
    if (wally_descriptor_parse(out, NULL, WALLY_NETWORK_NONE, 0, &wd) == WALLY_OK) {
        char* checksum = NULL;
        if (wally_descriptor_get_checksum(wd, 0, &checksum) == WALLY_OK && checksum) {
            const size_t n = strlen(out);
            int          r = snprintf(out + n, cap - n, "#%s", checksum);
            if (r > 0 && (size_t)r < cap - n) res = (int)(n + (size_t)r);
            wally_free_string(checksum);
        }
        wally_descriptor_free(wd);
    }

    return (size_t)res;
}

size_t keycheck_policy_summary(const keycheck_t* k, size_t index, char* out, size_t cap) {
    if (!k || !out || cap == 0 || !keycheck_policy_ready(k, index)) return 0;

    const keycheck_policy_t* p    = &k->policies[index];
    size_t                   used = 0;
    bool                     ok   = true;
    out[0]                        = '\0';
    ok                            = ok && summary_append(out, cap, &used, p->label);
    ok                            = ok && summary_append(out, cap, &used, "  ");
    ok                            = ok && summary_append(out, cap, &used, p->path);
    ok                            = ok && summary_append(out, cap, &used, "\naccount  ");
    ok                            = ok && summary_append(out, cap, &used, p->account);
    ok                            = ok && summary_append(out, cap, &used, "\nreceive  ");
    ok                            = ok && summary_append(out, cap, &used, p->receive);
    ok                            = ok && summary_append(out, cap, &used, "\nchange   ");
    ok                            = ok && summary_append(out, cap, &used, p->change);

    if (!ok) {
        secure_memzero(out, cap);
        return 0;
    }
    return used;
}

size_t keycheck_summary(const keycheck_t* k, char* out, size_t cap) {
    if (!k || !out || cap == 0) return 0;

    size_t used = 0;
    out[0]      = '\0';
    for (size_t i = 0; i < KEYCHECK_POLICY_COUNT; i++) {
        char block[KEYCHECK_XPUB_MAX + KEYCHECK_ADDR_MAX * 2 + 64];
        if (keycheck_policy_summary(k, i, block, sizeof(block)) == 0 ||
            !summary_append(out, cap, &used, block) || !summary_append(out, cap, &used, "\n\n")) {
            secure_memzero(out, cap);
            return 0;
        }
    }
    return used;
}

void keycheck_free(keycheck_t* k) {
    if (!k) return;
    secure_memzero(k, sizeof(*k));
    free(k);
}

/**
 * @file tests/test_keycheck.c
 * @brief Unity tests for main/crypto/keycheck.c.
 *
 * The expected values come from an independent implementation of BIP39,
 * BIP32 and the address encodings, cross-checked against the published
 * BIP49, BIP84 and BIP86 test vectors and the BIP39 "TREZOR" passphrase vector.
 */

#include "crypto/descriptor.h"
#include "crypto/keycheck.h"
#include "crypto/mnemonic.h"
#include "unity.h"

#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <wally_bip32.h>

void setUp(void) {}
void tearDown(void) {}

typedef struct {
    const char* account;
    const char* receive;
    const char* change;
} policy_vector_t;

typedef struct {
    const char*     mnemonic;
    const char*     passphrase;
    bool            testnet;
    const char*     fingerprint;
    policy_vector_t policy[KEYCHECK_POLICY_COUNT];
} key_vector_t;

static const key_vector_t v_m12 = {
    .mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                "abandon about",
    .passphrase  = NULL,
    .testnet     = false,
    .fingerprint = "73c5da0a",
    .policy =
        {
            {
                "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3"
                "DSSSSoekkudhUd9yLb6qx39T9nMdj",
                "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
                "1J3J6EvPrv8q6AC3VCjWV45Uf3nssNMRtH",
            },
            {
                "ypub6Ww3ibxVfGzLrAH1PNcjyAWenMTbbAosGNB6VvmSEgytSER9azLDWCxoJwW7Ke7icmizBMXrzBx997"
                "9FfaHxHcrArf3zbeJJJUZPf663zsP",
                "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
                "34K56kSjgUCUSD8GTtuF7c9Zzwokbs6uZ7",
            },
            {
                "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868Rv"
                "UUkgDKf31mGDtKsAYz2oz2AGutZYs",
                "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
                "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
            },
            {
                "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ"
                "3VCECoY49yfdDEHGCtMMj92pReUsQ",
                "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
                "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
            },
        },
};

static const key_vector_t v_m12_pass = {
    .mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                "abandon about",
    .passphrase  = "TREZOR",
    .testnet     = false,
    .fingerprint = "b4e3f5ed",
    .policy =
        {
            {
                "xpub6D3Cj1d8RgE6BRaEyYiRsJ8T17QA6Vq8F4P8f13BvDQTfgiBVT5iSdeSJ2QLSRijq2PMBXRSgduEUq"
                "11mYggQz6vUEe7Ga9e86urZjkrmeR",
                "1PEha8dk5Me5J1rZWpgqSt5F4BroTBLS5y",
                "1MVkh45Zn9A7ZBga697r34DBiRFLXD4UKG",
            },
            {
                "ypub6XRZqAj8R959SPF3UeP8gLsosvY7dskBv68N1rtd6pBwRwvAYJob7XS2VdxawoSdBdNEi32eQatwPB"
                "m412BZyfig481iqZKgseAZbdQdmMK",
                "3Aho3kS7vgVWKTpRHjcqBoPXiCujiSuTaZ",
                "36hpTv8xkBPWMgLouhUcVstoXBPS1uF1wg",
            },
            {
                "zpub6rXDN3yuixCtvAyzKn3uWLDr8qXKEQ2orduEL5AAysdHZmuPVUL2vbMQDEhp8L9hRsgM8J8idDNPdZ"
                "jrob8R5e7x7UoYXVdfjDG96TLa7La",
                "bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu",
                "bc1qest2x6zfncjezklycdghhjxzlptky4xx6rgewa",
            },
            {
                "xpub6CvFPYhCVDRVnfFhxGZH5WXD79vRUoR1Mqh7o1uSaG7Qya2Z4vm67vihWr8io7zcfy4ehfAuZ5k2Bz"
                "k8pT1wAehqhZVEyfHwsWVMud7omCf",
                "bc1p3ryfth56dp058avv97ppn065ctsk263puvwp4rcka3wpg6cudp9qd3jsuu",
                "bc1p4rrhkwexgc4vu3ffpmkv9qm88hu8zezp4e2h6eczu5jcaam5a3wqkzuwus",
            },
        },
};

static const key_vector_t v_m12_testnet = {
    .mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                "abandon about",
    .passphrase  = NULL,
    .testnet     = true,
    .fingerprint = "73c5da0a",
    .policy =
        {
            {
                "tpubDC5FSnBiZDMmhiuCmWAYsLwgLYrrT9rAqvTySfuCCrgsWz8wxMXUS9Tb9iVMvcRbvFcAHGkMD5Kx8k"
                "oh4GquNGNTfohfk7pgjhaPCdXpoba",
                "mkpZhYtJu2r87Js3pDiWJDmPte2NRZ8bJV",
                "mi8nhzZgGZQthq6DQHbru9crMDerUdTKva",
            },
            {
                "upub5EFU65HtV5TeiSHmZZm7FUffBGy8UKeqp7vw43jYbvZPpoVsgU93oac7Wk3u6moKegAEWtGNF8Dehr"
                "nHtv21XXEMYRUocHqguyjknFHYfgY",
                "2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2",
                "2MvdUi5o3f2tnEFh9yGvta6FzptTZtkPJC8",
            },
            {
                "vpub5Y6cjg78GGuNLsaPhmYsiw4gYX3HoQiRBiSwDaBXKUafCt9bNwWQiitDk5VZ5BVxYnQdwoTyXSs2JH"
                "RPAgjAvtbBrf8ZhDYe2jWAqvZVnsc",
                "tb1q6rz28mcfaxtmd6v789l9rrlrusdprr9pqcpvkl",
                "tb1q9u62588spffmq4dzjxsr5l297znf3z6j5p2688",
            },
            {
                "tpubDDfvzhdVV4unsoKt5aE6dcsNsfeWbTgmLZPi8LQDYU2xixrYemMfWJ3BaVneH3u7DBQePdTwhpybaK"
                "RU95pi6PMUtLPBJLVQRpzEnjfjZzX",
                "tb1p8wpt9v4frpf3tkn0srd97pksgsxc5hs52lafxwru9kgeephvs7rqlqt9zj",
                "tb1p6uav7en8k7zsumsqugdmg5j6930zmzy4dg7jcddshsr0fvxlqx7q7p5els",
            },
        },
};

static const key_vector_t v_m24 = {
    .mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon "
                "abandon abandon abandon art",
    .passphrase  = NULL,
    .testnet     = false,
    .fingerprint = "5436d724",
    .policy =
        {
            {
                "xpub6CDwootAjK1YycduSmTrAAXjfW9A8bPhVamZeofd8wX6rvGm2vLz6qtnqx4FagbFeXJwFThkzDPGkE"
                "rrjFpLpr1wsj7NXgHHkevPUxHYjUP",
                "1KBdbBJRVYffWHWWZ1moECfdVBSEnDpLHi",
                "1Jp3eQcCLpdE36vt5jguwjYaL2dWZCEgwB",
            },
            {
                "ypub6XHaCH3J7SSMemKiiYq9rDmKxYnyLMiEAoSEuWKgidbgeQXnTp9sNRRGByuorXbGMaRUj2jobjTxjs"
                "ygCmHqLPe2s3TfRigzpwYWqAE9d3V",
                "3D9piUVfmbS7UzNsFYad9YRmGjuEshvrWH",
                "399y41ahJeBsiEA92iXdWNh4q8EUJBCnWw",
            },
            {
                "zpub6qTBTNftBzVTjgVcSUw7vW5N1KQbV93Jnrw314RHGkCkSx4vk6nEWH1MJfReXi2WThvuDRiRpyT7cD"
                "oakEcZMQ1iZPgfJgQrcVMR4aJWh6S",
                "bc1qzmtrqsfuaf6l6kkcsseumq26ukaphfj9skkug6",
                "bc1qes80p0st92xjem9aw48v57fk35f44kjzm2064m",
            },
            {
                "xpub6CAYwo2AfKJy1cdFGBAgLvCrZULhEkZ9C9s4GGXwXzHvNPguMWBcVrGEDjP2ZJdX92gVWLeLrNVVmi"
                "pTrKqrwMy2eT282xKEyHMbPDrcD9e",
                "bc1p68a8a3vuv2cxzs7e2gjc5v3qy3zdnfaxwftyqe9k9nquvm6r4w2ssldtzp",
                "bc1pgf0v3a655f4xyyhslq8gjly9qpt9zn2wfyd5na0vsfsukk844x4s96r8jv",
            },
        },
};

static void check_vector(const key_vector_t* v) {
    mnemonic_t* m = mnemonic_from_string(v->mnemonic);
    TEST_ASSERT_NOT_NULL(m);

    keycheck_t* k =
        keycheck_derive(m, v->passphrase, v->testnet ? KEYCHECK_TESTNET : KEYCHECK_MAINNET);
    TEST_ASSERT_NOT_NULL(k);
    TEST_ASSERT_EQUAL_STRING(v->fingerprint, keycheck_fingerprint(k));
    TEST_ASSERT_EQUAL_UINT(KEYCHECK_POLICY_COUNT, (unsigned)keycheck_policy_count());

    static const char* const purposes[KEYCHECK_POLICY_COUNT] = {"m/44'", "m/49'", "m/84'", "m/86'"};
    for (size_t i = 0; i < KEYCHECK_POLICY_COUNT; i++) {
        const keycheck_policy_t* p = keycheck_policy(k, i);
        TEST_ASSERT_NOT_NULL(p);
        TEST_ASSERT_EQUAL_STRING(v->policy[i].account, p->account);
        TEST_ASSERT_EQUAL_STRING(v->policy[i].receive, p->receive);
        TEST_ASSERT_EQUAL_STRING(v->policy[i].change, p->change);
        TEST_ASSERT_EQUAL_STRING_LEN(purposes[i], p->path, strlen(purposes[i]));
        TEST_ASSERT_NOT_NULL(strstr(p->label, "BIP"));
    }

    keycheck_free(k);
    mnemonic_discard(m);
}

static void test_mainnet_12_words(void) { check_vector(&v_m12); }

static void test_mainnet_24_words(void) { check_vector(&v_m24); }

static void test_passphrase(void) { check_vector(&v_m12_pass); }

static void test_testnet(void) { check_vector(&v_m12_testnet); }

static void test_empty_passphrase_is_no_passphrase(void) {
    mnemonic_t* a = mnemonic_from_string(v_m12.mnemonic);
    mnemonic_t* b = mnemonic_from_string(v_m12.mnemonic);
    TEST_ASSERT_NOT_NULL(a);
    TEST_ASSERT_NOT_NULL(b);

    keycheck_t* ka = keycheck_derive(a, NULL, KEYCHECK_MAINNET);
    keycheck_t* kb = keycheck_derive(b, "", KEYCHECK_MAINNET);
    TEST_ASSERT_NOT_NULL(ka);
    TEST_ASSERT_NOT_NULL(kb);
    TEST_ASSERT_EQUAL_STRING(keycheck_fingerprint(ka), keycheck_fingerprint(kb));
    for (size_t i = 0; i < KEYCHECK_POLICY_COUNT; i++) {
        TEST_ASSERT_EQUAL_STRING(keycheck_policy(ka, i)->account, keycheck_policy(kb, i)->account);
        TEST_ASSERT_EQUAL_STRING(keycheck_policy(ka, i)->receive, keycheck_policy(kb, i)->receive);
    }

    keycheck_free(ka);
    keycheck_free(kb);
    mnemonic_discard(a);
    mnemonic_discard(b);
}

static void test_policy_bounds(void) {
    TEST_ASSERT_EQUAL_UINT(KEYCHECK_POLICY_COUNT, (unsigned)keycheck_policy_count());
    TEST_ASSERT_NULL(keycheck_policy(NULL, 0));

    mnemonic_t* m = mnemonic_from_string(v_m12.mnemonic);
    TEST_ASSERT_NOT_NULL(m);
    keycheck_t* k = keycheck_derive(m, NULL, KEYCHECK_MAINNET);
    TEST_ASSERT_NOT_NULL(k);
    TEST_ASSERT_NULL(keycheck_policy(k, KEYCHECK_POLICY_COUNT));
    TEST_ASSERT_NOT_NULL(keycheck_policy(k, KEYCHECK_POLICY_COUNT - 1));

    keycheck_free(k);
    mnemonic_discard(m);
}

static void test_network_names(void) {
    TEST_ASSERT_EQUAL_STRING("mainnet", keycheck_network_name(KEYCHECK_MAINNET));
    TEST_ASSERT_EQUAL_STRING("testnet", keycheck_network_name(KEYCHECK_TESTNET));
}

static void test_begin_is_lazy(void) {
    mnemonic_t* m = mnemonic_from_string(v_m12.mnemonic);
    TEST_ASSERT_NOT_NULL(m);

    keycheck_t* k = keycheck_begin(m, NULL, KEYCHECK_MAINNET);
    TEST_ASSERT_NOT_NULL(k);
    /* The fingerprint is known before any policy is, so the screen has
     * something to show while the slow part runs. */
    TEST_ASSERT_EQUAL_STRING(v_m12.fingerprint, keycheck_fingerprint(k));
    for (size_t i = 0; i < KEYCHECK_POLICY_COUNT; i++) {
        TEST_ASSERT_FALSE(keycheck_policy_ready(k, i));
        TEST_ASSERT_EQUAL_UINT(0, (unsigned)keycheck_policy_summary(k, i, NULL, 0));
    }

    char body[512];
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)keycheck_summary(k, body, sizeof(body)));

    /* Deriving one policy leaves the others alone. */
    TEST_ASSERT_TRUE(keycheck_policy_derive(k, 2));
    TEST_ASSERT_TRUE(keycheck_policy_ready(k, 2));
    for (size_t i = 0; i < KEYCHECK_POLICY_COUNT; i++) {
        if (i != 2) TEST_ASSERT_FALSE(keycheck_policy_ready(k, i));
    }
    TEST_ASSERT_GREATER_THAN(0, (int)keycheck_policy_summary(k, 2, body, sizeof(body)));
    TEST_ASSERT_NOT_NULL(strstr(body, v_m12.policy[2].account));
    TEST_ASSERT_NOT_NULL(strstr(body, v_m12.policy[2].receive));
    TEST_ASSERT_NOT_NULL(strstr(body, v_m12.policy[2].change));
    TEST_ASSERT_NOT_NULL(strstr(body, "m/84'/0'/0'"));

    /* Idempotent: asking again keeps the same key. */
    TEST_ASSERT_TRUE(keycheck_policy_derive(k, 2));
    TEST_ASSERT_EQUAL_STRING(v_m12.policy[2].account, keycheck_policy(k, 2)->account);

    /* Out of range and no handle are refused, not crashed on. */
    TEST_ASSERT_FALSE(keycheck_policy_derive(k, KEYCHECK_POLICY_COUNT));
    TEST_ASSERT_FALSE(keycheck_policy_derive(NULL, 0));
    TEST_ASSERT_FALSE(keycheck_policy_ready(NULL, 0));
    TEST_ASSERT_FALSE(keycheck_policy_ready(k, KEYCHECK_POLICY_COUNT));

    keycheck_free(k);
    mnemonic_discard(m);
}

static void test_begin_words(void) {
    mnemonic_t* m = mnemonic_from_string(v_m12_pass.mnemonic);
    TEST_ASSERT_NOT_NULL(m);

    keycheck_t* from_words =
        keycheck_begin_words(v_m12_pass.mnemonic, v_m12_pass.passphrase, KEYCHECK_MAINNET);
    keycheck_t* from_mnemonic = keycheck_begin(m, v_m12_pass.passphrase, KEYCHECK_MAINNET);
    TEST_ASSERT_NOT_NULL(from_words);
    TEST_ASSERT_NOT_NULL(from_mnemonic);
    TEST_ASSERT_EQUAL_STRING(keycheck_fingerprint(from_mnemonic), keycheck_fingerprint(from_words));

    TEST_ASSERT_TRUE(keycheck_policy_derive(from_words, 3));
    TEST_ASSERT_TRUE(keycheck_policy_derive(from_mnemonic, 3));
    TEST_ASSERT_EQUAL_STRING(keycheck_policy(from_mnemonic, 3)->account,
                             keycheck_policy(from_words, 3)->account);
    TEST_ASSERT_EQUAL_STRING(v_m12_pass.policy[3].receive, keycheck_policy(from_words, 3)->receive);

    keycheck_free(from_words);
    keycheck_free(from_mnemonic);
    mnemonic_discard(m);
}

static void test_policy_tabs(void) {
    TEST_ASSERT_EQUAL_STRING("BIP44", keycheck_policy_tab(0));
    TEST_ASSERT_EQUAL_STRING("BIP49", keycheck_policy_tab(1));
    TEST_ASSERT_EQUAL_STRING("BIP84", keycheck_policy_tab(2));
    TEST_ASSERT_EQUAL_STRING("BIP86", keycheck_policy_tab(3));
    TEST_ASSERT_EQUAL_STRING("", keycheck_policy_tab(KEYCHECK_POLICY_COUNT));
}

static void test_policy_descriptors(void) {
    mnemonic_t* m = mnemonic_from_string(v_m12.mnemonic);
    TEST_ASSERT_NOT_NULL(m);
    keycheck_t* k = keycheck_derive(m, NULL, KEYCHECK_MAINNET);
    TEST_ASSERT_NOT_NULL(k);

    static const char* const wrappers[KEYCHECK_POLICY_COUNT] = {"pkh(", "sh(wpkh(", "wpkh(", "tr("};
    char                     d[192];
    for (size_t i = 0; i < KEYCHECK_POLICY_COUNT; i++) {
        const keycheck_policy_t* p = keycheck_policy(k, i);
        size_t                   n = keycheck_policy_descriptor(k, i, d, sizeof(d));
        TEST_ASSERT_GREATER_THAN(0, (int)n);
        TEST_ASSERT_EQUAL_UINT(n, (unsigned)strlen(d));

        TEST_ASSERT_EQUAL_STRING_LEN(wrappers[i], d, strlen(wrappers[i]));
        /* The plain xpub, not the SLIP-132 form, is what a descriptor carries. */
        TEST_ASSERT_NOT_NULL(strstr(d, p->account_xpub));
        if (strcmp(p->account, p->account_xpub) != 0) TEST_ASSERT_NULL(strstr(d, p->account));
        TEST_ASSERT_NOT_NULL(strstr(d, "/<0;1>/*"));

        /* BIP-380 checksum: "#" and eight characters. */
        const char* hash = strrchr(d, '#');
        TEST_ASSERT_NOT_NULL(hash);
        TEST_ASSERT_EQUAL_UINT(8, (unsigned)strlen(hash + 1));

        /* It must be a descriptor the inspector in this project accepts, and
         * it must own the addresses the policy reports. */
        descriptor_status_t st;
        descriptor_t*       desc = descriptor_parse((const uint8_t*)d, n, &st);
        TEST_ASSERT_NOT_NULL(desc);
        TEST_ASSERT_EQUAL_INT(DESCRIPTOR_OK, st);
        TEST_ASSERT_TRUE(descriptor_owns_address(desc, p->receive));
        TEST_ASSERT_TRUE(descriptor_owns_address(desc, p->change));
        descriptor_free(desc);
    }

    /* Nothing is written for a policy that is not ready or a buffer too small. */
    char small[16];
    TEST_ASSERT_EQUAL_UINT(0, keycheck_policy_descriptor(k, 0, small, sizeof(small)));
    keycheck_t* lazy = keycheck_begin(m, NULL, KEYCHECK_MAINNET);
    TEST_ASSERT_NOT_NULL(lazy);
    TEST_ASSERT_EQUAL_UINT(0, keycheck_policy_descriptor(lazy, 0, d, sizeof(d)));
    TEST_ASSERT_EQUAL_UINT(0, keycheck_policy_descriptor(NULL, 0, d, sizeof(d)));
    keycheck_free(lazy);

    keycheck_free(k);
    mnemonic_discard(m);
}

static void test_policy_xprv(void) {
    mnemonic_t* m = mnemonic_from_string(v_m12.mnemonic);
    TEST_ASSERT_NOT_NULL(m);
    keycheck_t* k = keycheck_derive(m, NULL, KEYCHECK_MAINNET);
    TEST_ASSERT_NOT_NULL(k);

    for (size_t i = 0; i < KEYCHECK_POLICY_COUNT; i++) {
        const keycheck_policy_t* p = keycheck_policy(k, i);
        TEST_ASSERT_EQUAL_STRING_LEN("xprv", p->account_xprv, 4);
        TEST_ASSERT_EQUAL_UINT(111, (unsigned)strlen(p->account_xprv));

        /* The private key must be the one behind this policy's xpub. */
        struct ext_key priv, pub;
        TEST_ASSERT_EQUAL_INT(WALLY_OK, bip32_key_from_base58(p->account_xprv, &priv));
        TEST_ASSERT_EQUAL_INT(WALLY_OK, bip32_key_from_base58(p->account_xpub, &pub));
        TEST_ASSERT_EQUAL_MEMORY(pub.pub_key, priv.pub_key, sizeof(pub.pub_key));
        TEST_ASSERT_EQUAL_UINT(pub.depth, priv.depth);
        TEST_ASSERT_EQUAL_MEMORY(pub.chain_code, priv.chain_code, sizeof(pub.chain_code));
    }

    /* Testnet uses tprv/tpub. */
    keycheck_t* t = keycheck_derive(m, NULL, KEYCHECK_TESTNET);
    TEST_ASSERT_NOT_NULL(t);
    TEST_ASSERT_TRUE(keycheck_policy_derive(t, 0));
    TEST_ASSERT_EQUAL_STRING_LEN("tprv", keycheck_policy(t, 0)->account_xprv, 4);
    TEST_ASSERT_EQUAL_STRING_LEN("tpub", keycheck_policy(t, 0)->account_xpub, 4);

    keycheck_free(t);
    keycheck_free(k);
    mnemonic_discard(m);
}

static void test_summary_lists_every_policy(void) {
    mnemonic_t* m = mnemonic_from_string(v_m12.mnemonic);
    TEST_ASSERT_NOT_NULL(m);
    keycheck_t* k = keycheck_derive(m, NULL, KEYCHECK_MAINNET);
    TEST_ASSERT_NOT_NULL(k);

    char   body[1536];
    size_t n = keycheck_summary(k, body, sizeof(body));
    TEST_ASSERT_GREATER_THAN(0, (int)n);
    TEST_ASSERT_EQUAL_UINT(n, (unsigned)strlen(body));

    for (size_t i = 0; i < KEYCHECK_POLICY_COUNT; i++) {
        const keycheck_policy_t* p = keycheck_policy(k, i);
        TEST_ASSERT_NOT_NULL(strstr(body, p->label));
        TEST_ASSERT_NOT_NULL(strstr(body, p->path));
        TEST_ASSERT_NOT_NULL(strstr(body, p->account));
        TEST_ASSERT_NOT_NULL(strstr(body, p->receive));
        TEST_ASSERT_NOT_NULL(strstr(body, p->change));
    }

    /* A buffer that cannot hold the whole summary reports failure and writes
     * nothing, rather than showing a cut-off key. */
    char   small[64];
    size_t got = keycheck_summary(k, small, sizeof(small));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)got);
    TEST_ASSERT_EQUAL_CHAR('\0', small[0]);
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)keycheck_summary(NULL, body, sizeof(body)));

    keycheck_free(k);
    mnemonic_discard(m);
}

static void test_discards_null(void) { keycheck_free(NULL); /* must not crash */ }

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_mainnet_12_words);
    RUN_TEST(test_mainnet_24_words);
    RUN_TEST(test_passphrase);
    RUN_TEST(test_testnet);
    RUN_TEST(test_empty_passphrase_is_no_passphrase);
    RUN_TEST(test_policy_bounds);
    RUN_TEST(test_network_names);
    RUN_TEST(test_begin_is_lazy);
    RUN_TEST(test_begin_words);
    RUN_TEST(test_policy_tabs);
    RUN_TEST(test_policy_descriptors);
    RUN_TEST(test_policy_xprv);
    RUN_TEST(test_summary_lists_every_policy);
    RUN_TEST(test_discards_null);
    return UNITY_END();
}

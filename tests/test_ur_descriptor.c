/**
 * @file tests/test_ur_descriptor.c
 * @brief Unity tests for main/crypto/ur_descriptor.c
 *
 * Builds arbitrary CBOR payloads, wraps them as URs via ur_encode(), and feeds
 * them to ur_descriptor_decode() so the CBOR parser and every key/path decoder
 * error path is exercised (not just the generated "good" vectors).
 */

#include "crypto/fountain.h"
#include "crypto/ur.h"
#include "crypto/ur_descriptor.h"
#include "unity.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_address.h>
#include <wally_core.h>
#include <wally_script.h>

void setUp(void) {}
void tearDown(void) {}

/* -- Minimal CBOR encoder (definite-length only) ---------------------- */
static size_t cbor_head(uint8_t* b, uint8_t major, uint64_t arg) {
    if (arg < 24) {
        b[0] = (uint8_t)((major << 5) | arg);
        return 1;
    }
    if (arg < 256) {
        b[0] = (uint8_t)((major << 5) | 24);
        b[1] = (uint8_t)arg;
        return 2;
    }
    if (arg < 65536) {
        b[0] = (uint8_t)((major << 5) | 25);
        b[1] = (uint8_t)(arg >> 8);
        b[2] = (uint8_t)arg;
        return 3;
    }
    b[0] = (uint8_t)((major << 5) | 26);
    b[1] = (uint8_t)(arg >> 24);
    b[2] = (uint8_t)(arg >> 16);
    b[3] = (uint8_t)(arg >> 8);
    b[4] = (uint8_t)arg;
    return 5;
}

static size_t cuint(uint8_t* b, uint64_t v) { return cbor_head(b, 0, v); }
static size_t cbool(uint8_t* b, bool v) {
    b[0] = (uint8_t)((7 << 5) | (v ? 21 : 20));
    return 1;
}
static size_t cbytes(uint8_t* b, const uint8_t* d, size_t n) {
    size_t h = cbor_head(b, 2, n);
    memcpy(b + h, d, n);
    return h + n;
}
static size_t ctext(uint8_t* b, const char* s) {
    size_t n = strlen(s);
    size_t h = cbor_head(b, 3, n);
    memcpy(b + h, s, n);
    return h + n;
}
static size_t carr(uint8_t* b, size_t n) { return cbor_head(b, 4, n); }
static size_t cmap(uint8_t* b, size_t n) { return cbor_head(b, 5, n); }
static size_t ctag(uint8_t* b, uint64_t t) { return cbor_head(b, 6, t); }

/* Wrap CBOR as a UR of the given type and run ur_descriptor_decode(). */
static bool decode_type(const char* type, const uint8_t* cbor, size_t n, char** out) {
    char* ur = NULL;
    TEST_ASSERT_TRUE(ur_encode(type, cbor, n, &ur));
    bool ok = ur_descriptor_decode(ur, strlen(ur), out);
    free(ur);
    return ok;
}

/* Build a crypto-eckey { ?2: is-private, 3: data } (optionally tagged). */
static size_t eckey(uint8_t* b, const uint8_t* data, size_t len, bool priv, bool v2) {
    size_t off = 0;
    off += ctag(b + off, v2 ? 40306 : 306);
    off += cmap(b + off, priv ? 2 : 1);
    if (priv) {
        off += cuint(b + off, 2);
        off += cbool(b + off, true);
    }
    off += cuint(b + off, 3);
    off += cbytes(b + off, data, len);
    return off;
}

/* Build a crypto-hdkey { ?2: priv, 3: key-data, 4: chain-code, ?5: coininfo }. */
static size_t hdkey(uint8_t* b, const uint8_t* kd, size_t kdlen, const uint8_t* cc, size_t cclen,
                    bool priv, bool with_coininfo, uint64_t network, bool v2) {
    size_t off = 0;
    off += ctag(b + off, v2 ? 40303 : 303);
    off += cmap(b + off, 2 + (priv ? 1 : 0) + (with_coininfo ? 1 : 0));
    if (priv) {
        off += cuint(b + off, 2);
        off += cbool(b + off, true);
    }
    off += cuint(b + off, 3);
    off += cbytes(b + off, kd, kdlen);
    off += cuint(b + off, 4);
    off += cbytes(b + off, cc, cclen);
    if (with_coininfo) {
        off += cuint(b + off, 5);
        off += ctag(b + off, 40305);
        off += cmap(b + off, 1);
        off += cuint(b + off, 2);
        off += cuint(b + off, network);
    }
    return off;
}

/* Build a crypto-address { 2: type, 3: data } (optionally tagged). */
static size_t addr_key(uint8_t* b, const uint8_t* data, size_t len, uint64_t type, bool v2) {
    size_t off = 0;
    off += ctag(b + off, v2 ? 40307 : 307);
    off += cmap(b + off, 2);
    off += cuint(b + off, 2);
    off += cuint(b + off, type);
    off += cuint(b + off, 3);
    off += cbytes(b + off, data, len);
    return off;
}

/* Build a v3 output-descriptor map {1: source text, 2: [key]}. */
static size_t v3_desc(uint8_t* b, const char* src, const uint8_t* key, size_t key_len) {
    size_t off = 0;
    off += cmap(b + off, 2);
    off += cuint(b + off, 1);
    off += ctext(b + off, src);
    off += cuint(b + off, 2);
    off += carr(b + off, 1);
    memcpy(b + off, key, key_len);
    off += key_len;
    return off;
}

static const uint8_t PUB[33] = {0x02, 0xf9, 0x30, 0x8a, 0x01, 0x92, 0x58, 0xc3, 0x10, 0x49, 0x34,
                                0x4f, 0x85, 0xf8, 0x9d, 0x52, 0x29, 0xb5, 0x31, 0xc8, 0x45, 0x83,
                                0x6f, 0x99, 0xb0, 0x86, 0x01, 0xf1, 0x13, 0xbc, 0xe0, 0x36, 0xf9};

/* Valid xpub key-data / chain-code (from libwally's descriptor fixtures). */
static const uint8_t KD[33] = {0x02, 0xd2, 0xb3, 0x69, 0x00, 0x39, 0x6c, 0x92, 0x82, 0xfa, 0x14,
                               0x62, 0x85, 0x66, 0x58, 0x2f, 0x20, 0x6a, 0x5d, 0xd0, 0xbc, 0xc8,
                               0xd5, 0xe8, 0x92, 0x61, 0x18, 0x06, 0xca, 0xfb, 0x03, 0x01, 0xf0};
static const uint8_t CC[32] = {0x63, 0x78, 0x07, 0x03, 0x0d, 0x55, 0xd0, 0x1f, 0x9a, 0x0c, 0xb3,
                               0xa7, 0x83, 0x95, 0x15, 0xd7, 0x96, 0xbd, 0x07, 0x70, 0x63, 0x86,
                               0xa6, 0xed, 0xdf, 0x06, 0xcc, 0x29, 0xa6, 0x5a, 0x0e, 0x29};

static char* p2pkh_address(const uint8_t* h160) {
    uint8_t spk[25];
    size_t  slen = 0;
    char*   addr = NULL;
    if (wally_scriptpubkey_p2pkh_from_bytes(h160, 20, 0, spk, sizeof(spk), &slen) != WALLY_OK)
        return NULL;
    if (wally_scriptpubkey_to_address(spk, slen, WALLY_NETWORK_BITCOIN_MAINNET, &addr) != WALLY_OK)
        return NULL;
    return addr;
}

static char* p2sh_address(const uint8_t* h160) {
    uint8_t spk[23];
    size_t  slen = 0;
    char*   addr = NULL;
    if (wally_scriptpubkey_p2sh_from_bytes(h160, 20, 0, spk, sizeof(spk), &slen) != WALLY_OK)
        return NULL;
    if (wally_scriptpubkey_to_address(spk, slen, WALLY_NETWORK_BITCOIN_MAINNET, &addr) != WALLY_OK)
        return NULL;
    return addr;
}

static char* p2wpkh_address(const uint8_t* h160) {
    uint8_t spk[34];
    size_t  slen = 0;
    char*   addr = NULL;
    if (wally_witness_program_from_bytes(h160, 20, 0, spk, sizeof(spk), &slen) != WALLY_OK)
        return NULL;
    if (wally_addr_segwit_from_bytes(spk, slen, "bc", 0, &addr) != WALLY_OK) return NULL;
    return addr;
}

/* -- Decode success paths --------------------------------------------- */
static void test_decode_eckey(void) {
    uint8_t b[256];
    size_t  n = 0;
    n += eckey(b + n, PUB, sizeof(PUB), false, true);

    uint8_t v3[256];
    size_t  v3n = 0;
    v3n += v3_desc(v3, "wpkh(@0)", b, n);

    char* out = NULL;
    TEST_ASSERT_TRUE(decode_type("output-descriptor", v3, v3n, &out));
    TEST_ASSERT_EQUAL_STRING(
        "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)", out);
    free(out);
}

static void test_decode_hdkey_testnet(void) {
    uint8_t b[256];
    size_t  n = 0;
    n += hdkey(b + n, KD, sizeof(KD), CC, sizeof(CC), false, true, 1, true);

    uint8_t v3[256];
    size_t  v3n = 0;
    v3n += v3_desc(v3, "wpkh(@0)", b, n);

    char* out = NULL;
    TEST_ASSERT_TRUE(decode_type("output-descriptor", v3, v3n, &out));
    TEST_ASSERT_NOT_NULL(strstr(out, "tpub"));
    free(out);
}

static void test_decode_address_key(void) {
    uint8_t h160[20];
    for (size_t i = 0; i < sizeof(h160); i++) h160[i] = (uint8_t)(0x40 + i);

    char* expect = p2pkh_address(h160);
    TEST_ASSERT_NOT_NULL(expect);

    uint8_t b[256];
    size_t  n = 0;
    n += addr_key(b + n, h160, sizeof(h160), 0, true);

    uint8_t v3[256];
    size_t  v3n = 0;
    v3n += v3_desc(v3, "addr(@0)", b, n);

    char expect_txt[160];
    snprintf(expect_txt, sizeof(expect_txt), "addr(%s)", expect);
    wally_free_string(expect);

    char* out = NULL;
    TEST_ASSERT_TRUE(decode_type("output-descriptor", v3, v3n, &out));
    TEST_ASSERT_EQUAL_STRING(expect_txt, out);
    free(out);
}

static void test_decode_raw(void) {
    /* v1 crypto-output: tag 408 (raw) wrapping a byte string. */
    uint8_t b[256];
    size_t  n = 0;
    n += ctag(b + n, 408);
    n += cbytes(b + n, (const uint8_t*)"\x6a\x04\xde\xad", 4);

    char* out = NULL;
    TEST_ASSERT_TRUE(decode_type("crypto-output", b, n, &out));
    TEST_ASSERT_EQUAL_STRING("raw(6a04dead)", out);
    free(out);
}

/* -- Decode failure paths (private keys, malformed CBOR) -------------- */
static void test_reject_private_eckey(void) {
    uint8_t b[256];
    size_t  n = 0;
    n += eckey(b + n, PUB, sizeof(PUB), true, true);

    uint8_t v3[256];
    size_t  v3n = 0;
    v3n += v3_desc(v3, "wpkh(@0)", b, n);

    char* out = NULL;
    TEST_ASSERT_FALSE(decode_type("output-descriptor", v3, v3n, &out));
}

static void test_reject_private_hdkey(void) {
    uint8_t b[256];
    size_t  n = 0;
    n += hdkey(b + n, KD, sizeof(KD), CC, sizeof(CC), true, false, 0, true);

    uint8_t v3[256];
    size_t  v3n = 0;
    v3n += v3_desc(v3, "wpkh(@0)", b, n);

    char* out = NULL;
    TEST_ASSERT_FALSE(decode_type("output-descriptor", v3, v3n, &out));
}

static void test_hdkey_bad_keydata_len(void) {
    uint8_t bad[34] = {0};
    uint8_t b[256];
    size_t  n = 0;
    n += hdkey(b + n, bad, sizeof(bad), CC, sizeof(CC), false, false, 0, true);

    uint8_t v3[256];
    size_t  v3n = 0;
    v3n += v3_desc(v3, "wpkh(@0)", b, n);

    char* out = NULL;
    TEST_ASSERT_FALSE(decode_type("output-descriptor", v3, v3n, &out));
}

static void test_hdkey_invalid_pubkey(void) {
    uint8_t bad[33] = {0x02}; /* x = 0, not on secp256k1 */
    uint8_t b[256];
    size_t  n = 0;
    n += hdkey(b + n, bad, sizeof(bad), CC, sizeof(CC), false, false, 0, true);

    uint8_t v3[256];
    size_t  v3n = 0;
    v3n += v3_desc(v3, "wpkh(@0)", b, n);

    char* out = NULL;
    TEST_ASSERT_FALSE(decode_type("output-descriptor", v3, v3n, &out));
}

static void test_hdkey_missing_chaincode(void) {
    /* {3: key-data} only. */
    uint8_t b[256];
    size_t  n = 0;
    n += ctag(b + n, 40303);
    n += cmap(b + n, 1);
    n += cuint(b + n, 3);
    n += cbytes(b + n, KD, sizeof(KD));

    uint8_t v3[256];
    size_t  v3n = 0;
    v3n += v3_desc(v3, "wpkh(@0)", b, n);

    char* out = NULL;
    TEST_ASSERT_FALSE(decode_type("output-descriptor", v3, v3n, &out));
}

static void test_unresolvable_placeholder(void) {
    /* Source references @5 but only one key is present. */
    uint8_t b[256];
    size_t  n = 0;
    n += cmap(b + n, 2);
    n += cuint(b + n, 1);
    n += ctext(b + n, "wpkh(@5)");
    n += cuint(b + n, 2);
    n += carr(b + n, 1);
    n += eckey(b + n, PUB, sizeof(PUB), false, true);

    char* out = NULL;
    TEST_ASSERT_FALSE(decode_type("output-descriptor", b, n, &out));
}

static void test_literal_at(void) {
    /* "@" not followed by a digit is copied literally. */
    uint8_t b[256];
    size_t  n = 0;
    n += cmap(b + n, 1);
    n += cuint(b + n, 1);
    n += ctext(b + n, "wpkh(@)");

    char* out = NULL;
    TEST_ASSERT_TRUE(decode_type("output-descriptor", b, n, &out));
    TEST_ASSERT_EQUAL_STRING("wpkh(@)", out);
    free(out);
}

static void test_output_descriptor_bad_shape(void) {
    /* Map without key 1. */
    uint8_t b[64];
    size_t  n = 0;
    n += cmap(b + n, 1);
    n += cuint(b + n, 2);
    n += carr(b + n, 0);
    char* out = NULL;
    TEST_ASSERT_FALSE(decode_type("output-descriptor", b, n, &out));

    /* Key 1 present but not text. */
    n = 0;
    n += cmap(b + n, 1);
    n += cuint(b + n, 1);
    n += cbytes(b + n, PUB, sizeof(PUB));
    TEST_ASSERT_FALSE(decode_type("output-descriptor", b, n, &out));

    /* Key 2 present but not an array. */
    n = 0;
    n += cmap(b + n, 2);
    n += cuint(b + n, 1);
    n += ctext(b + n, "wpkh(@0)");
    n += cuint(b + n, 2);
    n += cuint(b + n, 42);
    TEST_ASSERT_FALSE(decode_type("output-descriptor", b, n, &out));
}

static void test_cbor_malformed(void) {
    char* out = NULL;

    /* Byte string whose header length exceeds the remaining bytes. */
    uint8_t b[64];
    size_t  n = 0;
    n += cbytes(b + n, (const uint8_t*)"ab", 2); /* header says 2, but... */
    /* Truncated: header claims length 10 with only 2 bytes of payload. */
    b[0] = (uint8_t)((2 << 5) | 10);
    TEST_ASSERT_FALSE(decode_type("output-descriptor", b, n, &out));

    /* Indefinite-length map (major 5, ai 31). */
    b[0] = (uint8_t)((5 << 5) | 31);
    TEST_ASSERT_FALSE(decode_type("output-descriptor", b, 1, &out));

    /* Array with more elements than the node budget. */
    n = carr(b, 2000);
    TEST_ASSERT_FALSE(decode_type("output-descriptor", b, n, &out));
}

static void test_cbor_depth_limit(void) {
    /* 41 nested tags exceed CBOR_MAX_DEPTH (40). */
    uint8_t b[256];
    size_t  n = 0;
    for (int i = 0; i < 41; i++) n += ctag(b + n, 404);
    n += cbytes(b + n, PUB, sizeof(PUB));

    char* out = NULL;
    TEST_ASSERT_FALSE(decode_type("crypto-output", b, n, &out));
}

static void test_crypto_output_unknown_tag(void) {
    uint8_t b[64];
    size_t  n = 0;
    n += ctag(b + n, 999);
    n += cbytes(b + n, PUB, sizeof(PUB));

    char* out = NULL;
    TEST_ASSERT_FALSE(decode_type("crypto-output", b, n, &out));
}

static void test_crypto_output_raw_bad_child(void) {
    /* TAG_RAW wrapping a text string instead of a byte string. */
    uint8_t b[64];
    size_t  n = 0;
    n += ctag(b + n, 408);
    n += ctext(b + n, "nope");

    char* out = NULL;
    TEST_ASSERT_FALSE(decode_type("crypto-output", b, n, &out));
}

static void test_multi_missing_threshold(void) {
    /* TAG_MULTI wrapping a multikey map without key 1. */
    uint8_t b[128];
    size_t  n = 0;
    n += ctag(b + n, 406);
    n += cmap(b + n, 1);
    n += cuint(b + n, 2);
    n += carr(b + n, 0);

    char* out = NULL;
    TEST_ASSERT_FALSE(decode_type("crypto-output", b, n, &out));
}

static void test_decode_address_key_types(void) {
    uint8_t h160[20];
    for (size_t i = 0; i < sizeof(h160); i++) h160[i] = (uint8_t)(0x40 + i);

    /* p2sh (type 1). */
    char* exp = p2sh_address(h160);
    TEST_ASSERT_NOT_NULL(exp);
    uint8_t b[256];
    size_t  n = 0;
    n += addr_key(b + n, h160, sizeof(h160), 1, true);
    uint8_t v3[256];
    size_t  v3n = 0;
    v3n += v3_desc(v3, "addr(@0)", b, n);
    char expect_txt[160];
    snprintf(expect_txt, sizeof(expect_txt), "addr(%s)", exp);
    wally_free_string(exp);
    char* out = NULL;
    TEST_ASSERT_TRUE(decode_type("output-descriptor", v3, v3n, &out));
    TEST_ASSERT_EQUAL_STRING(expect_txt, out);
    free(out);

    /* p2wpkh (type 2). */
    exp = p2wpkh_address(h160);
    TEST_ASSERT_NOT_NULL(exp);
    n = 0;
    n += addr_key(b + n, h160, sizeof(h160), 2, true);
    v3n = 0;
    v3n += v3_desc(v3, "addr(@0)", b, n);
    snprintf(expect_txt, sizeof(expect_txt), "addr(%s)", exp);
    wally_free_string(exp);
    TEST_ASSERT_TRUE(decode_type("output-descriptor", v3, v3n, &out));
    TEST_ASSERT_EQUAL_STRING(expect_txt, out);
    free(out);
}

static void test_key_unknown_tag_wrapper(void) {
    /* An unknown outer tag is peeled off before reaching the eckey. */
    uint8_t b[256];
    size_t  n = 0;
    n += ctag(b + n, 999);
    n += eckey(b + n, PUB, sizeof(PUB), false, true);

    uint8_t v3[256];
    size_t  v3n = 0;
    v3n += v3_desc(v3, "wpkh(@0)", b, n);

    char* out = NULL;
    TEST_ASSERT_TRUE(decode_type("output-descriptor", v3, v3n, &out));
    TEST_ASSERT_EQUAL_STRING(
        "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)", out);
    free(out);
}

static void test_cbor_8byte_arg_and_pk(void) {
    /* Tag header with an 8-byte argument (CBOR ai 27), plus the pk() branch. */
    uint8_t b[256];
    size_t  n = 0;
    b[n++]    = (uint8_t)((6 << 5) | 27); /* tag, 8-byte argument */
    for (int i = 0; i < 6; i++) b[n++] = 0x00;
    b[n++] = 0x01;
    b[n++] = 0x92; /* tag 402 = pk */
    n += eckey(b + n, PUB, sizeof(PUB), false, false);

    char* out = NULL;
    TEST_ASSERT_TRUE(decode_type("crypto-output", b, n, &out));
    TEST_ASSERT_EQUAL_STRING(
        "pk(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)", out);
    free(out);
}

static void test_cbor_array_truncated_child(void) {
    uint8_t b[64];
    size_t  n = 0;
    n += carr(b + n, 2);  /* two children declared */
    n += cuint(b + n, 1); /* only one present */

    char* out = NULL;
    TEST_ASSERT_FALSE(decode_type("crypto-output", b, n, &out));
}

static void test_decode_range_path(void) {
    /* hdkey with a child range [[5,10], false] -> "/<5;10>". */
    uint8_t b[512];
    size_t  n  = 0;
    size_t  kp = n;
    n += ctag(b + n, 40304);
    n += cmap(b + n, 1);
    n += cuint(b + n, 1);
    n += carr(b + n, 1);
    n += carr(b + n, 2); /* component = [[5,10], bool] */
    n += carr(b + n, 2); /* [5,10] */
    n += cuint(b + n, 5);
    n += cuint(b + n, 10);
    n += cbool(b + n, false);
    size_t kp_len = n - kp;

    n += ctag(b + n, 40303);
    n += cmap(b + n, 3);
    n += cuint(b + n, 3);
    n += cbytes(b + n, KD, sizeof(KD));
    n += cuint(b + n, 4);
    n += cbytes(b + n, CC, sizeof(CC));
    n += cuint(b + n, 7);
    memcpy(b + n, b + kp, kp_len);
    n += kp_len;

    uint8_t v3[600];
    size_t  v3n = 0;
    v3n += v3_desc(v3, "pkh(@0)", b + kp_len, n - kp_len);

    char* out = NULL;
    TEST_ASSERT_TRUE(decode_type("output-descriptor", v3, v3n, &out));
    TEST_ASSERT_NOT_NULL(strstr(out, "/<5;10>"));
    free(out);
}

static void test_range_bad_shape(void) {
    /* component [[0,1]] (2-elem array, no trailing bool/array) is rejected. */
    uint8_t b[512];
    size_t  n  = 0;
    size_t  kp = n;
    n += ctag(b + n, 40304);
    n += cmap(b + n, 1);
    n += cuint(b + n, 1);
    n += carr(b + n, 1);
    n += carr(b + n, 1); /* component = [[0,1]] */
    n += carr(b + n, 2);
    n += cuint(b + n, 0);
    n += cuint(b + n, 1);
    size_t kp_len = n - kp;

    n += ctag(b + n, 40303);
    n += cmap(b + n, 3);
    n += cuint(b + n, 3);
    n += cbytes(b + n, KD, sizeof(KD));
    n += cuint(b + n, 4);
    n += cbytes(b + n, CC, sizeof(CC));
    n += cuint(b + n, 7);
    memcpy(b + n, b + kp, kp_len);
    n += kp_len;

    uint8_t v3[600];
    size_t  v3n = 0;
    v3n += v3_desc(v3, "pkh(@0)", b + kp_len, n - kp_len);

    char* out = NULL;
    TEST_ASSERT_FALSE(decode_type("output-descriptor", v3, v3n, &out));
}

static void test_hdkey_bad_origin(void) {
    /* origin keypath with a fingerprint but no components. */
    uint8_t b[512];
    size_t  n = 0;
    n += ctag(b + n, 40303);
    n += cmap(b + n, 3);
    n += cuint(b + n, 3);
    n += cbytes(b + n, KD, sizeof(KD));
    n += cuint(b + n, 4);
    n += cbytes(b + n, CC, sizeof(CC));
    n += cuint(b + n, 6);
    n += ctag(b + n, 40304);
    n += cmap(b + n, 1);
    n += cuint(b + n, 2);
    n += cuint(b + n, 0xd34db33f);

    uint8_t v3[600];
    size_t  v3n = 0;
    v3n += v3_desc(v3, "pkh(@0)", b, n);

    char* out = NULL;
    TEST_ASSERT_FALSE(decode_type("output-descriptor", v3, v3n, &out));
}

static void test_hdkey_bad_children(void) {
    /* children keypath with a fingerprint but no components. */
    uint8_t b[512];
    size_t  n = 0;
    n += ctag(b + n, 40303);
    n += cmap(b + n, 3);
    n += cuint(b + n, 3);
    n += cbytes(b + n, KD, sizeof(KD));
    n += cuint(b + n, 4);
    n += cbytes(b + n, CC, sizeof(CC));
    n += cuint(b + n, 7);
    n += ctag(b + n, 40304);
    n += cmap(b + n, 1);
    n += cuint(b + n, 2);
    n += cuint(b + n, 0xd34db33f);

    uint8_t v3[600];
    size_t  v3n = 0;
    v3n += v3_desc(v3, "pkh(@0)", b, n);

    char* out = NULL;
    TEST_ASSERT_FALSE(decode_type("output-descriptor", v3, v3n, &out));
}

/* -- Multipart (animated) descriptor UR decoding ---------------------- */
/* Build the CBOR array [seq_num, seq_len, message_len, checksum, data]. */
static size_t part_cbor(uint8_t* b, uint32_t seq_num, uint32_t seq_len, size_t message_len,
                        uint32_t checksum, const uint8_t* data, size_t data_len) {
    size_t off = 0;
    off += carr(b + off, 5);
    off += cuint(b + off, seq_num);
    off += cuint(b + off, seq_len);
    off += cuint(b + off, message_len);
    off += cuint(b + off, checksum);
    off += cbytes(b + off, data, data_len);
    return off;
}

/* Copy fragment `idx` of `msg` into `out`, zero-padded to the shared length. */
static size_t fragment(const uint8_t* msg, size_t msg_len, size_t n_frags, size_t idx,
                       uint8_t* out) {
    size_t frag_len = (msg_len + n_frags - 1) / n_frags;
    memset(out, 0, frag_len);
    size_t off = idx * frag_len;
    if (off < msg_len) {
        size_t n = msg_len - off;
        if (n > frag_len) n = frag_len;
        memcpy(out, msg + off, n);
    }
    return frag_len;
}

/* Encode one part as "ur:<type>/<seq>-<n_frags>/<bytewords>". */
static char* encode_part(const char* type, uint32_t seq_num, size_t n_frags, size_t msg_len,
                         uint32_t checksum, const uint8_t* data, size_t data_len) {
    uint8_t part[2048];
    size_t  pn = part_cbor(part, seq_num, (uint32_t)n_frags, msg_len, checksum, data, data_len);

    char type_str[64];
    snprintf(type_str, sizeof(type_str), "%s/%u-%u", type, (unsigned)seq_num, (unsigned)n_frags);

    char* ur = NULL;
    TEST_ASSERT_TRUE(ur_encode(type_str, part, pn, &ur));
    return ur;
}

/* Simple fragment `idx` (0-based) of `msg`. */
static char* simple_part(const char* type, const uint8_t* msg, size_t msg_len, size_t n_frags,
                         size_t idx, uint32_t checksum) {
    uint8_t frag[1024];
    size_t  frag_len = fragment(msg, msg_len, n_frags, idx, frag);
    return encode_part(type, (uint32_t)(idx + 1), n_frags, msg_len, checksum, frag, frag_len);
}

/* Fountain (XOR) part `seq_num` (> n_frags): XOR of the fragments selected by
 * the deterministic fountain mask. */
static char* mixed_part(const char* type, const uint8_t* msg, size_t msg_len, size_t n_frags,
                        uint32_t seq_num, uint32_t checksum) {
    uint8_t mask[128];
    memset(mask, 0, sizeof(mask));
    TEST_ASSERT_TRUE(fountain_choose_fragments(seq_num, n_frags, checksum, mask, sizeof(mask)));

    size_t  frag_len = (msg_len + n_frags - 1) / n_frags;
    uint8_t acc[1024];
    memset(acc, 0, frag_len);
    for (size_t i = 0; i < n_frags; i++) {
        if (!((mask[i >> 3] >> (i & 7)) & 1u)) continue;
        uint8_t frag[1024];
        fragment(msg, msg_len, n_frags, i, frag);
        for (size_t k = 0; k < frag_len; k++) acc[k] ^= frag[k];
    }
    return encode_part(type, seq_num, n_frags, msg_len, checksum, acc, frag_len);
}

/* CBOR message for "wpkh(@0)" + the expected decoded descriptor text. */
#define MPART_EXPECT "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)"

static size_t build_desc_message(uint8_t* msg, size_t cap, uint32_t* crc) {
    uint8_t key[256];
    size_t  kn = eckey(key, PUB, sizeof(PUB), false, true);
    size_t  mn = v3_desc(msg, "wpkh(@0)", key, kn);
    TEST_ASSERT_TRUE(mn < cap);
    *crc = ur_crc32(msg, mn);
    return mn;
}

static void test_multipart_descriptor(void) {
    uint8_t  msg[512];
    uint32_t crc = 0;
    size_t   mn  = build_desc_message(msg, sizeof(msg), &crc);

    char* p1 = simple_part("output-descriptor", msg, mn, 2, 0, crc);
    char* p2 = simple_part("output-descriptor", msg, mn, 2, 1, crc);

    ur_descriptor_decoder_t* d = ur_descriptor_decoder_new();
    TEST_ASSERT_NOT_NULL(d);
    TEST_ASSERT_EQUAL_UINT(0, ur_descriptor_decoder_received(d));
    TEST_ASSERT_EQUAL_UINT(0, ur_descriptor_decoder_expected(d));

    char* out = NULL;
    TEST_ASSERT_EQUAL_INT(0, ur_descriptor_decoder_receive(d, p1, strlen(p1), &out));
    TEST_ASSERT_NULL(out);
    TEST_ASSERT_EQUAL_UINT(1, ur_descriptor_decoder_received(d));
    TEST_ASSERT_EQUAL_UINT(2, ur_descriptor_decoder_expected(d));

    /* Re-scanning the same QR must not disturb the sequence. */
    TEST_ASSERT_EQUAL_INT(0, ur_descriptor_decoder_receive(d, p1, strlen(p1), &out));
    TEST_ASSERT_EQUAL_UINT(1, ur_descriptor_decoder_received(d));

    /* The out-of-order second fragment completes the message. */
    TEST_ASSERT_EQUAL_INT(1, ur_descriptor_decoder_receive(d, p2, strlen(p2), &out));
    TEST_ASSERT_EQUAL_STRING(MPART_EXPECT, out);
    free(out);

    /* Nothing more is accepted once the message is complete. */
    TEST_ASSERT_EQUAL_INT(-1, ur_descriptor_decoder_receive(d, p1, strlen(p1), &out));

    ur_descriptor_decoder_free(d);
    free(p1);
    free(p2);
}

/* A part of a sequence whose message is split three ways is only completed by
 * the last fragment. */
static void test_multipart_descriptor_three_fragments(void) {
    uint8_t  msg[512];
    uint32_t crc = 0;
    size_t   mn  = build_desc_message(msg, sizeof(msg), &crc);

    char* p0 = simple_part("output-descriptor", msg, mn, 3, 0, crc);
    char* p1 = simple_part("output-descriptor", msg, mn, 3, 1, crc);
    char* p2 = simple_part("output-descriptor", msg, mn, 3, 2, crc);

    ur_descriptor_decoder_t* d   = ur_descriptor_decoder_new();
    char*                    out = NULL;
    TEST_ASSERT_EQUAL_INT(0, ur_descriptor_decoder_receive(d, p0, strlen(p0), &out));
    TEST_ASSERT_EQUAL_UINT(3, ur_descriptor_decoder_expected(d));
    TEST_ASSERT_EQUAL_INT(0, ur_descriptor_decoder_receive(d, p1, strlen(p1), &out));
    TEST_ASSERT_EQUAL_UINT(2, ur_descriptor_decoder_received(d));
    TEST_ASSERT_EQUAL_INT(1, ur_descriptor_decoder_receive(d, p2, strlen(p2), &out));
    TEST_ASSERT_EQUAL_STRING(MPART_EXPECT, out);

    free(out);
    ur_descriptor_decoder_free(d);
    free(p0);
    free(p1);
    free(p2);
}

/* The deprecated v1 "crypto-output" type works multi-part too. */
static void test_multipart_crypto_output(void) {
    /* Expression tree: tag 404 (wpkh) wrapping a crypto-eckey. */
    uint8_t msg[256];
    size_t  mn = 0;
    mn += ctag(msg + mn, 404);
    mn += eckey(msg + mn, PUB, sizeof(PUB), false, false);
    uint32_t crc = ur_crc32(msg, mn);

    char* p1 = simple_part("crypto-output", msg, mn, 2, 0, crc);
    char* p2 = simple_part("crypto-output", msg, mn, 2, 1, crc);

    ur_descriptor_decoder_t* d   = ur_descriptor_decoder_new();
    char*                    out = NULL;
    TEST_ASSERT_EQUAL_INT(0, ur_descriptor_decoder_receive(d, p1, strlen(p1), &out));
    TEST_ASSERT_EQUAL_INT(1, ur_descriptor_decoder_receive(d, p2, strlen(p2), &out));
    TEST_ASSERT_EQUAL_STRING(MPART_EXPECT, out);

    free(out);
    ur_descriptor_decoder_free(d);
    free(p1);
    free(p2);
}

/* A fountain (mixed) part recovers a fragment that was never scanned on its
 * own - the normal case for an animated descriptor QR. */
static void test_multipart_descriptor_fountain(void) {
    uint8_t  msg[512];
    uint32_t crc = 0;
    size_t   mn  = build_desc_message(msg, sizeof(msg), &crc);

    /* Pick a deterministic fountain part that mixes fragment 2 (the missing
     * one) with at least one already-scanned fragment. */
    uint32_t seq = 0;
    for (uint32_t s = 4; s < 64 && !seq; s++) {
        uint8_t mask[8];
        memset(mask, 0, sizeof(mask));
        TEST_ASSERT_TRUE(fountain_choose_fragments(s, 3, crc, mask, sizeof(mask)));

        int bits = 0;
        for (size_t i = 0; i < 3; i++) {
            if ((mask[i >> 3] >> (i & 7)) & 1u) bits++;
        }
        if (bits > 1 && ((mask[2 >> 3] >> (2 & 7)) & 1u)) seq = s;
    }
    TEST_ASSERT_TRUE(seq != 0);

    char* p0  = simple_part("output-descriptor", msg, mn, 3, 0, crc);
    char* p1  = simple_part("output-descriptor", msg, mn, 3, 1, crc);
    char* mix = mixed_part("output-descriptor", msg, mn, 3, seq, crc);

    ur_descriptor_decoder_t* d   = ur_descriptor_decoder_new();
    char*                    out = NULL;
    TEST_ASSERT_EQUAL_INT(0, ur_descriptor_decoder_receive(d, p0, strlen(p0), &out));
    TEST_ASSERT_EQUAL_INT(0, ur_descriptor_decoder_receive(d, p1, strlen(p1), &out));
    TEST_ASSERT_EQUAL_INT(1, ur_descriptor_decoder_receive(d, mix, strlen(mix), &out));
    TEST_ASSERT_EQUAL_STRING(MPART_EXPECT, out);

    free(out);
    ur_descriptor_decoder_free(d);
    free(p0);
    free(p1);
    free(mix);
}

/* A wrong message checksum (CRC-32) must never complete. */
static void test_multipart_descriptor_bad_checksum(void) {
    uint8_t  msg[512];
    uint32_t crc = 0;
    size_t   mn  = build_desc_message(msg, sizeof(msg), &crc);

    char* p1 = simple_part("output-descriptor", msg, mn, 2, 0, crc ^ 0xFFu);
    char* p2 = simple_part("output-descriptor", msg, mn, 2, 1, crc ^ 0xFFu);

    ur_descriptor_decoder_t* d   = ur_descriptor_decoder_new();
    char*                    out = NULL;
    TEST_ASSERT_EQUAL_INT(0, ur_descriptor_decoder_receive(d, p1, strlen(p1), &out));
    TEST_ASSERT_EQUAL_INT(0, ur_descriptor_decoder_receive(d, p2, strlen(p2), &out));
    TEST_ASSERT_NULL(out);

    ur_descriptor_decoder_free(d);
    free(p1);
    free(p2);
}

/* The stateful decoder also handles single-part descriptor URs. */
static void test_descriptor_ur_decoder_single_part(void) {
    uint8_t  msg[512];
    uint32_t crc = 0;
    size_t   mn  = build_desc_message(msg, sizeof(msg), &crc);

    char* ur = NULL;
    TEST_ASSERT_TRUE(ur_encode("output-descriptor", msg, mn, &ur));

    ur_descriptor_decoder_t* d   = ur_descriptor_decoder_new();
    char*                    out = NULL;
    TEST_ASSERT_EQUAL_INT(1, ur_descriptor_decoder_receive(d, ur, strlen(ur), &out));
    TEST_ASSERT_EQUAL_STRING(MPART_EXPECT, out);
    TEST_ASSERT_EQUAL_UINT(0, ur_descriptor_decoder_received(d));
    free(out);
    ur_descriptor_decoder_free(d);

    /* A NULL out_descriptor still reports completion. */
    d = ur_descriptor_decoder_new();
    TEST_ASSERT_EQUAL_INT(1, ur_descriptor_decoder_receive(d, ur, strlen(ur), NULL));
    ur_descriptor_decoder_free(d);

    free(ur);
}

static void test_multipart_descriptor_errors(void) {
    uint8_t  msg[512];
    uint32_t crc = 0;
    size_t   mn  = build_desc_message(msg, sizeof(msg), &crc);

    char* p1 = simple_part("output-descriptor", msg, mn, 2, 0, crc);

    /* One part of a multi-part sequence is not a complete descriptor. */
    char* out = NULL;
    TEST_ASSERT_FALSE(ur_descriptor_decode(p1, strlen(p1), &out));
    TEST_ASSERT_NULL(out);

    ur_descriptor_decoder_t* d = ur_descriptor_decoder_new();

    /* A UR of an unrelated type is rejected (and not accumulated). */
    char* other = NULL;
    TEST_ASSERT_TRUE(ur_encode("psbt", msg, mn, &other));
    TEST_ASSERT_EQUAL_INT(-1, ur_descriptor_decoder_receive(d, other, strlen(other), &out));
    TEST_ASSERT_EQUAL_UINT(0, ur_descriptor_decoder_expected(d));
    free(other);

    /* Malformed sequence component, then a part body with no sequence
     * component at all (which is not a valid single-part descriptor either). */
    char bad[512];
    snprintf(bad, sizeof(bad), "ur:output-descriptor/x-2/%s", strrchr(p1, '/') + 1);
    TEST_ASSERT_EQUAL_INT(-1, ur_descriptor_decoder_receive(d, bad, strlen(bad), &out));

    snprintf(bad, sizeof(bad), "ur:output-descriptor/%s", strrchr(p1, '/') + 1);
    TEST_ASSERT_EQUAL_INT(-1, ur_descriptor_decoder_receive(d, bad, strlen(bad), &out));

    /* Non-UR garbage. */
    TEST_ASSERT_EQUAL_INT(-1, ur_descriptor_decoder_receive(d, "not a ur", 8, &out));

    /* Guards. */
    TEST_ASSERT_EQUAL_INT(-1, ur_descriptor_decoder_receive(NULL, p1, strlen(p1), &out));
    TEST_ASSERT_EQUAL_INT(-1, ur_descriptor_decoder_receive(d, NULL, 0, &out));

    ur_descriptor_decoder_free(d);
    free(p1);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_decode_eckey);
    RUN_TEST(test_decode_hdkey_testnet);
    RUN_TEST(test_decode_address_key);
    RUN_TEST(test_decode_raw);
    RUN_TEST(test_decode_address_key_types);
    RUN_TEST(test_key_unknown_tag_wrapper);
    RUN_TEST(test_cbor_8byte_arg_and_pk);
    RUN_TEST(test_cbor_array_truncated_child);
    RUN_TEST(test_decode_range_path);
    RUN_TEST(test_range_bad_shape);
    RUN_TEST(test_hdkey_bad_origin);
    RUN_TEST(test_hdkey_bad_children);
    RUN_TEST(test_reject_private_eckey);
    RUN_TEST(test_reject_private_hdkey);
    RUN_TEST(test_hdkey_bad_keydata_len);
    RUN_TEST(test_hdkey_invalid_pubkey);
    RUN_TEST(test_hdkey_missing_chaincode);
    RUN_TEST(test_unresolvable_placeholder);
    RUN_TEST(test_literal_at);
    RUN_TEST(test_output_descriptor_bad_shape);
    RUN_TEST(test_cbor_malformed);
    RUN_TEST(test_cbor_depth_limit);
    RUN_TEST(test_crypto_output_unknown_tag);
    RUN_TEST(test_crypto_output_raw_bad_child);
    RUN_TEST(test_multi_missing_threshold);
    RUN_TEST(test_multipart_descriptor);
    RUN_TEST(test_multipart_descriptor_three_fragments);
    RUN_TEST(test_multipart_crypto_output);
    RUN_TEST(test_multipart_descriptor_fountain);
    RUN_TEST(test_multipart_descriptor_bad_checksum);
    RUN_TEST(test_descriptor_ur_decoder_single_part);
    RUN_TEST(test_multipart_descriptor_errors);
    return UNITY_END();
}

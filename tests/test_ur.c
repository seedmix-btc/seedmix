/**
 * @file tests/test_ur.c
 * @brief Unity tests for main/crypto/ur.c (UR / Bytewords decoding).
 */

#include "crypto/fountain.h"
#include "crypto/ur.h"
#include "unity.h"
#include "util/utils.h"
#include "vectors.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_core.h>
#include <wally_psbt.h>
#include <wally_script.h>
#include <wally_transaction.h>

void setUp(void) {}
void tearDown(void) {}

/* Build a legacy transaction with `num_inputs` empty inputs and `num_outputs`
 * P2PKH outputs of 100000 + i*1000 satoshi. */
static struct wally_tx* build_tx(size_t num_inputs, size_t num_outputs) {
    struct wally_tx* tx = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_init_alloc(2, 0, num_inputs, num_outputs, &tx));

    for (size_t i = 0; i < num_inputs; i++) {
        uint8_t txhash[32];
        for (size_t j = 0; j < sizeof(txhash); j++) txhash[j] = (uint8_t)(i + 1 + j);
        TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_add_raw_input(tx, txhash, sizeof(txhash), (uint32_t)i,
                                                           0xfffffffd, NULL, 0, NULL, 0));
    }
    for (size_t i = 0; i < num_outputs; i++) {
        uint8_t hash160[20];
        uint8_t script[25];
        size_t  slen = 0;
        for (size_t j = 0; j < sizeof(hash160); j++) hash160[j] = (uint8_t)(0x40 + i + j);
        TEST_ASSERT_EQUAL(WALLY_OK,
                          wally_scriptpubkey_p2pkh_from_bytes(hash160, sizeof(hash160), 0, script,
                                                              sizeof(script), &slen));
        TEST_ASSERT_EQUAL(WALLY_OK,
                          wally_tx_add_raw_output(tx, 100000 + i * 1000, script, slen, 0));
    }
    return tx;
}

/* Serialize a PSBT built from a test transaction into `*out` / `*out_len`. */
static void build_psbt_bytes(uint8_t** out, size_t* out_len) {
    struct wally_tx*   tx   = build_tx(1, 2);
    struct wally_psbt* psbt = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_from_tx(tx, WALLY_PSBT_VERSION_0, 0, &psbt));
    wally_tx_free(tx);

    size_t len = 0;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_get_length(psbt, 0, &len));

    uint8_t* bytes = (uint8_t*)malloc(len);
    TEST_ASSERT_NOT_NULL(bytes);
    size_t written = 0;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_to_bytes(psbt, 0, bytes, len, &written));
    wally_psbt_free(psbt);
    TEST_ASSERT_EQUAL_UINT(len, (unsigned)written);

    *out     = bytes;
    *out_len = len;
}

/* Seed UR test vector from BCR-2020-005 (independently validates the
 * Bytewords word list and the CRC-32 checksum). */
static void test_ur_seed_vector(void) {
    const char* ur = "ur:seed/oyadgdstaslplabghydrpfmkbggufgludprfgmamdpwmox";

    uint8_t* cbor     = NULL;
    size_t   cbor_len = 0;
    TEST_ASSERT_TRUE(ur_decode(ur, strlen(ur), "seed", &cbor, &cbor_len));

    const char* expect_hex = "a10150c7098580125e2ab0981253468b2dbc52";
    uint8_t     expect[19];
    TEST_ASSERT_TRUE(hex_to_bytes(expect_hex, strlen(expect_hex), expect, sizeof(expect)));

    TEST_ASSERT_EQUAL_UINT(sizeof(expect), (unsigned)cbor_len);
    TEST_ASSERT_EQUAL_MEMORY(expect, cbor, sizeof(expect));
    free(cbor);
}

static void test_ur_psbt_roundtrip(void) {
    uint8_t* bytes = NULL;
    size_t   len   = 0;
    build_psbt_bytes(&bytes, &len);

    char* ur = NULL;
    TEST_ASSERT_TRUE(ur_psbt_encode(bytes, len, &ur));
    TEST_ASSERT_NOT_NULL(strstr(ur, "ur:psbt/"));

    uint8_t* dec     = NULL;
    size_t   dec_len = 0;
    TEST_ASSERT_TRUE(ur_psbt_decode(ur, strlen(ur), &dec, &dec_len));
    TEST_ASSERT_EQUAL_UINT(len, (unsigned)dec_len);
    TEST_ASSERT_EQUAL_MEMORY(bytes, dec, len);

    /* The decoded bytes must re-parse as a valid PSBT. */
    struct wally_psbt* psbt = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_from_bytes(dec, dec_len, 0, &psbt));
    wally_psbt_free(psbt);

    free(dec);
    free(ur);
    free(bytes);
}

static void test_ur_psbt_case_insensitive(void) {
    uint8_t* bytes = NULL;
    size_t   len   = 0;
    build_psbt_bytes(&bytes, &len);

    char* ur = NULL;
    TEST_ASSERT_TRUE(ur_psbt_encode(bytes, len, &ur));

    for (size_t i = 0; i < strlen(ur); i++) {
        if (ur[i] >= 'a' && ur[i] <= 'z') ur[i] = (char)(ur[i] - 'a' + 'A');
    }

    uint8_t* dec     = NULL;
    size_t   dec_len = 0;
    TEST_ASSERT_TRUE(ur_psbt_decode(ur, strlen(ur), &dec, &dec_len));
    TEST_ASSERT_EQUAL_UINT(len, (unsigned)dec_len);
    TEST_ASSERT_EQUAL_MEMORY(bytes, dec, len);

    free(dec);
    free(ur);
    free(bytes);
}

static void test_ur_decode_invalid(void) {
    uint8_t* out = NULL;
    size_t   len = 0;

    TEST_ASSERT_FALSE(ur_decode(NULL, 0, "psbt", &out, &len));
    TEST_ASSERT_FALSE(ur_decode("", 0, "psbt", &out, &len));
    TEST_ASSERT_FALSE(ur_decode("not-a-ur", 9, "psbt", &out, &len));
    TEST_ASSERT_FALSE(ur_decode("ur:psbt", 7, "psbt", &out, &len));      /* missing '/' */
    TEST_ASSERT_FALSE(ur_decode("ur:psbt/abc", 11, "psbt", &out, &len)); /* odd length */
    TEST_ASSERT_FALSE(ur_decode("ur:psbt/aa", 10, "psbt", &out, &len));  /* too short for CRC */
    TEST_ASSERT_FALSE(ur_decode("ur:seed/oyadgdstaslplabghydrpfmkbggufgludprfgmamdpwmox", 46,
                                "psbt", &out, &len)); /* type mismatch */
}

static void test_ur_psbt_invalid(void) {
    uint8_t* bytes = NULL;
    size_t   len   = 0;
    build_psbt_bytes(&bytes, &len);

    char* ur = NULL;
    TEST_ASSERT_TRUE(ur_psbt_encode(bytes, len, &ur));

    /* Corrupt the final checksum character. */
    size_t last      = strlen(ur) - 1;
    ur[last]         = (char)(ur[last] == 'a' ? 'b' : 'a');
    uint8_t* out     = NULL;
    size_t   out_len = 0;
    TEST_ASSERT_FALSE(ur_psbt_decode(ur, strlen(ur), &out, &out_len));

    free(ur);
    free(bytes);
}

static void test_ur_psbt_8byte_length(void) {
    /* A CBOR byte string whose length uses the unsupported 8-byte form. */
    uint8_t cbor[16];
    cbor[0] = (uint8_t)((2 << 5) | 27); /* byte string, 8-byte length */
    for (int i = 1; i < 9; i++) cbor[i] = 0;

    char* ur = NULL;
    TEST_ASSERT_TRUE(ur_encode("psbt", cbor, 9, &ur));

    uint8_t* out     = NULL;
    size_t   out_len = 0;
    TEST_ASSERT_FALSE(ur_psbt_decode(ur, strlen(ur), &out, &out_len));
    free(ur);
}

/* -- Fountain decoder (reference vector from bc-ur test suite) --------- */
static const char* const FOUNTAIN_FRAGS[9] = {
    "916ec65cf77cadf55cd7f9cda1a1030026ddd42e905b77adc36e4f2d3c",
    "cba44f7f04f2de44f42d84c374a0e149136f25b01852545961d55f7f7a",
    "8cde6d0e2ec43f3b2dcb644a2209e8c9e34af5c4747984a5e873c9cf5f",
    "965e25ee29039fdf8ca74f1c769fc07eb7ebaec46e0695aea6cbd60b3e",
    "c4bbff1b9ffe8a9e7240129377b9d3711ed38d412fbb4442256f1e6f59",
    "5e0fc57fed451fb0a0101fb76b1fb1e1b88cfdfdaa946294a47de8fff1",
    "73f021c0e6f65b05c0a494e50791270a0050a73ae69b6725505a2ec8a5",
    "791457c9876dd34aadd192a53aa0dc66b556c0c215c7ceb8248b717c22",
    "951e65305b56a3706e3e86eb01c803bbf915d80edcd64d4d0000000000",
};
static const char* const FOUNTAIN_MIX10 =
    "330f0f33a05eead4f331df229871bee733b50de71afd2e5a79f196de09";
#define FOUNTAIN_CHECKSUM 0x0167aa07u
#define FOUNTAIN_MSG_LEN 256u
#define FOUNTAIN_FRAG_LEN 29u

static void fountain_expected_message(uint8_t msg[FOUNTAIN_MSG_LEN]) {
    uint8_t f[FOUNTAIN_FRAG_LEN];
    for (int i = 0; i < 9; i++) {
        /* Fragments are zero-padded to equal length; the message is the
         * first FOUNTAIN_MSG_LEN bytes, so the last fragment is truncated. */
        size_t n = FOUNTAIN_FRAG_LEN;
        if (i * FOUNTAIN_FRAG_LEN + n > FOUNTAIN_MSG_LEN)
            n = FOUNTAIN_MSG_LEN - i * FOUNTAIN_FRAG_LEN;
        TEST_ASSERT_TRUE(hex_to_bytes(FOUNTAIN_FRAGS[i], FOUNTAIN_FRAG_LEN * 2, f, sizeof(f)));
        memcpy(msg + i * FOUNTAIN_FRAG_LEN, f, n);
    }
}

static void test_fountain_simple(void) {
    uint8_t expect[FOUNTAIN_MSG_LEN];
    fountain_expected_message(expect);
    TEST_ASSERT_EQUAL_UINT(FOUNTAIN_CHECKSUM, ur_crc32(expect, sizeof(expect)));

    fountain_decoder_t* d = fountain_decoder_new();
    TEST_ASSERT_NOT_NULL(d);
    uint8_t f[FOUNTAIN_FRAG_LEN];
    for (uint32_t s = 1; s <= 9; s++) {
        TEST_ASSERT_TRUE(hex_to_bytes(FOUNTAIN_FRAGS[s - 1], FOUNTAIN_FRAG_LEN * 2, f, sizeof(f)));
        uint8_t* msg  = NULL;
        size_t   mlen = 0;
        int r = fountain_decoder_receive(d, s, 9, FOUNTAIN_MSG_LEN, FOUNTAIN_CHECKSUM, f, sizeof(f),
                                         &msg, &mlen);
        if (s < 9) {
            TEST_ASSERT_EQUAL_INT(0, r);
        } else {
            TEST_ASSERT_EQUAL_INT(1, r);
            TEST_ASSERT_EQUAL_UINT(FOUNTAIN_MSG_LEN, (unsigned)mlen);
            TEST_ASSERT_EQUAL_MEMORY(expect, msg, FOUNTAIN_MSG_LEN);
            free(msg);
        }
    }
    fountain_decoder_free(d);
}

static void test_fountain_mixed(void) {
    uint8_t expect[FOUNTAIN_MSG_LEN];
    fountain_expected_message(expect);

    fountain_decoder_t* d = fountain_decoder_new();
    uint8_t             f[FOUNTAIN_FRAG_LEN];
    for (uint32_t s = 1; s <= 8; s++) {
        TEST_ASSERT_TRUE(hex_to_bytes(FOUNTAIN_FRAGS[s - 1], FOUNTAIN_FRAG_LEN * 2, f, sizeof(f)));
        uint8_t* msg  = NULL;
        size_t   mlen = 0;
        TEST_ASSERT_EQUAL_INT(0,
                              fountain_decoder_receive(d, s, 9, FOUNTAIN_MSG_LEN, FOUNTAIN_CHECKSUM,
                                                       f, sizeof(f), &msg, &mlen));
    }
    /* A fountain (mixed) part recovers the missing fragment. */
    TEST_ASSERT_TRUE(hex_to_bytes(FOUNTAIN_MIX10, FOUNTAIN_FRAG_LEN * 2, f, sizeof(f)));
    uint8_t* msg  = NULL;
    size_t   mlen = 0;
    TEST_ASSERT_EQUAL_INT(1, fountain_decoder_receive(d, 10, 9, FOUNTAIN_MSG_LEN, FOUNTAIN_CHECKSUM,
                                                      f, sizeof(f), &msg, &mlen));
    TEST_ASSERT_EQUAL_MEMORY(expect, msg, FOUNTAIN_MSG_LEN);
    free(msg);
    fountain_decoder_free(d);
}

/* -- Multipart UR (fountain) PSBT -------------------------------------- */
static const char* const MPSBT_HEX =
    "70736274ff01009a020000000258e87a21b56daf0c23be8e7070456c336f7c"
    "baa5c8757924f545887bb2abdd750000000000ffffffff838d0427d0ec650a68aa46bb0b098aea4422c071b2ca7835"
    "2a077959d07cea1d0100000000ffffffff"
    "0270aaf00800000000160014d85c2b71d0060b09c9886aeb815e50991dda124d00e1f5050000000016001400aea9a2"
    "e5f0f876a588df5546e8742d1d87008f000000000000000000";

static const char* const MPART_1 =
    "ur:psbt/1-2/"
    "lpadaocsptcybkgdcarhhdgohdosjojkidjyzmadaenyaoaeaeaeaohdvsknclrejnpebncnrnmnjojofejzeojlkerdon"
    "spkpkkdkykfelokgprpyutkpaeaeaeaeaezmzmzmzmlslgaaditiwpihbkispkfgrkbdaslewdfycprtjsprsgksecdrat"
    "kkhkti";
static const char* const MPART_2 =
    "ur:psbt/2-2/"
    "lpaoaocsptcybkgdcarhhdgokewdcaadaeaeaeaezmzmzmzmaojopkwtayaeaeaeaecmaebbtphhdnjstiambdassoloim"
    "wmlyhygdnlcatnbggtaevyykahaeaeaeaecmaebbaeplptoevwwtyakoonlourgofgvsjydpcaltaemyaeaeaeaeaeaeae"
    "aeaeae";
static const char* const MPART_3 =
    "ur:psbt/3-2/"
    "lpaxaocsptcybkgdcarhhdgodkgtjnjpidjyzmadzmihzczmaojopdpdvtknclrejnrhbnemiytdhpadmdimetiyreeytk"
    "cnwkdijyjzhdgminzmpyfnlaahaeaeaeaewlzmwmzmdpdkolsacxbbbwpevtkpbwzcvlkiosylsrcpgwjsprsgksecdrat"
    "kkhkti";

static void test_ur_psbt_multipart(void) {
    uint8_t expect[167];
    TEST_ASSERT_TRUE(hex_to_bytes(MPSBT_HEX, 334, expect, sizeof(expect)));

    uint8_t* psbt = NULL;
    size_t   plen = 0;

    /* Simple parts. */
    ur_psbt_decoder_t* d = ur_psbt_decoder_new();
    TEST_ASSERT_EQUAL_INT(0, ur_psbt_decoder_receive(d, MPART_1, strlen(MPART_1), &psbt, &plen));
    TEST_ASSERT_EQUAL_INT(1, ur_psbt_decoder_receive(d, MPART_2, strlen(MPART_2), &psbt, &plen));
    TEST_ASSERT_EQUAL_UINT(sizeof(expect), (unsigned)plen);
    TEST_ASSERT_EQUAL_MEMORY(expect, psbt, sizeof(expect));
    free(psbt);
    ur_psbt_decoder_free(d);

    /* Completing with a NULL out_psbt still frees the reassembled bytes. */
    d    = ur_psbt_decoder_new();
    plen = 0;
    TEST_ASSERT_EQUAL_INT(0, ur_psbt_decoder_receive(d, MPART_1, strlen(MPART_1), NULL, &plen));
    TEST_ASSERT_EQUAL_INT(1, ur_psbt_decoder_receive(d, MPART_2, strlen(MPART_2), NULL, &plen));
    TEST_ASSERT_EQUAL_UINT(sizeof(expect), (unsigned)plen);
    ur_psbt_decoder_free(d);

    /* A fountain part (part 3 mixes both fragments) recovers the message. */
    d    = ur_psbt_decoder_new();
    psbt = NULL;
    plen = 0;
    TEST_ASSERT_EQUAL_INT(0, ur_psbt_decoder_receive(d, MPART_1, strlen(MPART_1), &psbt, &plen));
    TEST_ASSERT_EQUAL_INT(1, ur_psbt_decoder_receive(d, MPART_3, strlen(MPART_3), &psbt, &plen));
    TEST_ASSERT_EQUAL_UINT(sizeof(expect), (unsigned)plen);
    TEST_ASSERT_EQUAL_MEMORY(expect, psbt, sizeof(expect));
    free(psbt);
    ur_psbt_decoder_free(d);
}

/* -- Generated PSBT vectors (tests/vectors/psbt/) ---------------------- */
static void test_psbt_vector_files(void) {
    char** slugs   = NULL;
    size_t n_slugs = 0;
    TEST_ASSERT_TRUE(vectors_list_slugs("psbt/raw", ".hex", &slugs, &n_slugs));
    TEST_ASSERT_TRUE(n_slugs > 0);

    for (size_t s = 0; s < n_slugs; s++) {
        const char* slug = slugs[s];
        char        path[256];

        /* Expected raw PSBT from the .hex file. */
        snprintf(path, sizeof(path), "psbt/raw/%s.hex", slug);
        char* hex = (char*)vectors_read_file(path, NULL);
        TEST_ASSERT_NOT_NULL(hex);
        vectors_trim(hex);
        size_t   expect_len = strlen(hex) / 2;
        uint8_t* expect     = (uint8_t*)malloc(expect_len);
        TEST_ASSERT_NOT_NULL(expect);
        TEST_ASSERT_TRUE(hex_to_bytes(hex, strlen(hex), expect, expect_len));
        free(hex);

        /* Single-part v2 (ur:psbt). */
        snprintf(path, sizeof(path), "psbt/ur/%s.v2.ur", slug);
        char* ur = (char*)vectors_read_file(path, NULL);
        TEST_ASSERT_NOT_NULL(ur);
        vectors_trim(ur);
        uint8_t* psbt = NULL;
        size_t   plen = 0;
        TEST_ASSERT_TRUE(ur_psbt_decode(ur, strlen(ur), &psbt, &plen));
        TEST_ASSERT_EQUAL_UINT(expect_len, (unsigned)plen);
        TEST_ASSERT_EQUAL_MEMORY(expect, psbt, expect_len);
        free(psbt);
        free(ur);

        /* Single-part v1 (ur:crypto-psbt). */
        snprintf(path, sizeof(path), "psbt/ur/%s.v1.ur", slug);
        ur = (char*)vectors_read_file(path, NULL);
        TEST_ASSERT_NOT_NULL(ur);
        vectors_trim(ur);
        TEST_ASSERT_TRUE(ur_psbt_decode(ur, strlen(ur), &psbt, &plen));
        TEST_ASSERT_EQUAL_UINT(expect_len, (unsigned)plen);
        TEST_ASSERT_EQUAL_MEMORY(expect, psbt, expect_len);
        free(psbt);
        free(ur);

        /* Animated multipart (fountain) parts, one per line. */
        snprintf(path, sizeof(path), "psbt/ur/%s.multipart.ur", slug);
        char* parts = (char*)vectors_read_file(path, NULL);
        TEST_ASSERT_NOT_NULL(parts);

        ur_psbt_decoder_t* d = ur_psbt_decoder_new();
        TEST_ASSERT_NOT_NULL(d);
        int    done = 0;
        size_t np   = 0;
        for (char* line = strtok(parts, "\r\n"); line; line = strtok(NULL, "\r\n")) {
            np++;
            psbt = NULL;
            plen = 0;
            done = ur_psbt_decoder_receive(d, line, strlen(line), &psbt, &plen);
            TEST_ASSERT_TRUE(done >= 0);
        }
        TEST_ASSERT_EQUAL_UINT((unsigned)ur_psbt_decoder_expected(d), (unsigned)np);
        TEST_ASSERT_EQUAL_INT(1, done);
        TEST_ASSERT_EQUAL_UINT(expect_len, (unsigned)plen);
        TEST_ASSERT_EQUAL_MEMORY(expect, psbt, expect_len);
        free(psbt);
        ur_psbt_decoder_free(d);
        free(parts);

        /* The reassembled bytes must re-parse as a valid PSBT. */
        struct wally_psbt* wp = NULL;
        TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_from_bytes(expect, expect_len, 0, &wp));
        wally_psbt_free(wp);

        free(expect);
    }

    vectors_free_slugs(slugs, n_slugs);
}

/* -- Error / boundary paths -------------------------------------------- */
static void test_ur_psbt_encode_lengths(void) {
    /* Exercise every CBOR byte-string header width in ur_psbt_encode(). */
    static const size_t  lens[]   = {5, 23, 24, 255, 256, 65535, 65536};
    static const uint8_t magic[5] = {0x70, 0x73, 0x62, 0x74, 0xff}; /* "psbt\xff" */

    for (size_t k = 0; k < sizeof(lens) / sizeof(lens[0]); k++) {
        size_t   len = lens[k];
        uint8_t* buf = (uint8_t*)malloc(len);
        TEST_ASSERT_NOT_NULL(buf);
        memset(buf, 0, len);
        memcpy(buf, magic, sizeof(magic));

        char* ur = NULL;
        TEST_ASSERT_TRUE(ur_psbt_encode(buf, len, &ur));
        TEST_ASSERT_NOT_NULL(strstr(ur, "ur:psbt/"));

        uint8_t* dec     = NULL;
        size_t   dec_len = 0;
        TEST_ASSERT_TRUE(ur_psbt_decode(ur, strlen(ur), &dec, &dec_len));
        TEST_ASSERT_EQUAL_UINT(len, (unsigned)dec_len);
        TEST_ASSERT_EQUAL_MEMORY(buf, dec, len);

        free(dec);
        free(ur);
        free(buf);
    }
}

static void test_fountain_errors(void) {
    uint8_t data[FOUNTAIN_FRAG_LEN];
    memset(data, 0xAA, sizeof(data));
    uint8_t* msg  = NULL;
    size_t   mlen = 0;

    /* Accessors handle NULL decoders. */
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)fountain_decoder_received(NULL));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)fountain_decoder_expected(NULL));

    /* NULL decoder. */
    TEST_ASSERT_EQUAL_INT(-1,
                          fountain_decoder_receive(NULL, 1, 9, FOUNTAIN_MSG_LEN, FOUNTAIN_CHECKSUM,
                                                   data, sizeof(data), &msg, &mlen));

    fountain_decoder_t* d = fountain_decoder_new();
    TEST_ASSERT_NOT_NULL(d);

    /* Out-of-range seq_num / seq_len, NULL data, zero lengths. */
    TEST_ASSERT_EQUAL_INT(-1, fountain_decoder_receive(d, 0, 9, FOUNTAIN_MSG_LEN, FOUNTAIN_CHECKSUM,
                                                       data, sizeof(data), &msg, &mlen));
    TEST_ASSERT_EQUAL_INT(-1, fountain_decoder_receive(d, 1, 0, FOUNTAIN_MSG_LEN, FOUNTAIN_CHECKSUM,
                                                       data, sizeof(data), &msg, &mlen));
    TEST_ASSERT_EQUAL_INT(-1,
                          fountain_decoder_receive(d, 1, 1025, FOUNTAIN_MSG_LEN, FOUNTAIN_CHECKSUM,
                                                   data, sizeof(data), &msg, &mlen));
    TEST_ASSERT_EQUAL_INT(-1, fountain_decoder_receive(d, 1, 9, FOUNTAIN_MSG_LEN, FOUNTAIN_CHECKSUM,
                                                       NULL, sizeof(data), &msg, &mlen));
    TEST_ASSERT_EQUAL_INT(-1, fountain_decoder_receive(d, 1, 9, 0, FOUNTAIN_CHECKSUM, data,
                                                       sizeof(data), &msg, &mlen));
    TEST_ASSERT_EQUAL_INT(-1, fountain_decoder_receive(d, 1, 9, FOUNTAIN_MSG_LEN, FOUNTAIN_CHECKSUM,
                                                       data, 0, &msg, &mlen));
    fountain_decoder_free(d);

    /* Mismatched parameters after the sequence has started. */
    d = fountain_decoder_new();
    TEST_ASSERT_NOT_NULL(d);
    TEST_ASSERT_EQUAL_INT(0, fountain_decoder_receive(d, 1, 9, FOUNTAIN_MSG_LEN, FOUNTAIN_CHECKSUM,
                                                      data, sizeof(data), &msg, &mlen));
    TEST_ASSERT_EQUAL_INT(-1,
                          fountain_decoder_receive(d, 2, 10, FOUNTAIN_MSG_LEN, FOUNTAIN_CHECKSUM,
                                                   data, sizeof(data), &msg, &mlen));
    TEST_ASSERT_EQUAL_INT(-1,
                          fountain_decoder_receive(d, 2, 9, FOUNTAIN_MSG_LEN, FOUNTAIN_CHECKSUM + 1,
                                                   data, sizeof(data), &msg, &mlen));
    fountain_decoder_free(d);

    /* A duplicate simple part is ignored, not treated as an error. */
    d = fountain_decoder_new();
    TEST_ASSERT_NOT_NULL(d);
    uint8_t f[FOUNTAIN_FRAG_LEN];
    TEST_ASSERT_TRUE(hex_to_bytes(FOUNTAIN_FRAGS[0], FOUNTAIN_FRAG_LEN * 2, f, sizeof(f)));
    TEST_ASSERT_EQUAL_INT(0, fountain_decoder_receive(d, 1, 9, FOUNTAIN_MSG_LEN, FOUNTAIN_CHECKSUM,
                                                      f, sizeof(f), &msg, &mlen));
    TEST_ASSERT_EQUAL_INT(0, fountain_decoder_receive(d, 1, 9, FOUNTAIN_MSG_LEN, FOUNTAIN_CHECKSUM,
                                                      f, sizeof(f), &msg, &mlen));
    fountain_decoder_free(d);

    /* A wrong checksum assembles the fragments but fails validation. */
    d = fountain_decoder_new();
    TEST_ASSERT_NOT_NULL(d);
    for (uint32_t s = 1; s <= 9; s++) {
        uint8_t frag[FOUNTAIN_FRAG_LEN];
        TEST_ASSERT_TRUE(
            hex_to_bytes(FOUNTAIN_FRAGS[s - 1], FOUNTAIN_FRAG_LEN * 2, frag, sizeof(frag)));
        TEST_ASSERT_EQUAL_INT(0, fountain_decoder_receive(d, s, 9, FOUNTAIN_MSG_LEN,
                                                          FOUNTAIN_CHECKSUM + 1, frag, sizeof(frag),
                                                          &msg, &mlen));
    }
    TEST_ASSERT_EQUAL_UINT(9, (unsigned)fountain_decoder_received(d));
    fountain_decoder_free(d);
}

/* Animated scans deliver parts in any order and repeat them: a mixed part can
 * arrive before the simple fragment that completes it (it is parked and
 * reduced later), and the same part is normally seen more than once. */
static void test_fountain_mixed_out_of_order(void) {
    uint8_t expect[FOUNTAIN_MSG_LEN];
    fountain_expected_message(expect);
    TEST_ASSERT_EQUAL_UINT(FOUNTAIN_CHECKSUM, ur_crc32(expect, sizeof(expect)));

    uint8_t frags[9][FOUNTAIN_FRAG_LEN];
    for (size_t i = 0; i < 9; i++) {
        TEST_ASSERT_TRUE(
            hex_to_bytes(FOUNTAIN_FRAGS[i], FOUNTAIN_FRAG_LEN * 2, frags[i], sizeof(frags[i])));
    }

    /* Pick a fountain part that covers the last two fragments (7 and 8), so it
     * is still mixed once the fragments fed below have been reduced away. */
    uint32_t mix = 0;
    uint8_t  mask[2];
    for (uint32_t s = 10; s < 512 && !mix; s++) {
        TEST_ASSERT_TRUE(fountain_choose_fragments(s, 9, FOUNTAIN_CHECKSUM, mask, sizeof(mask)));
        if ((mask[0] & 0x80u) && (mask[1] & 0x01u)) mix = s;
    }
    TEST_ASSERT_TRUE(mix != 0);

    uint8_t mixed[FOUNTAIN_FRAG_LEN];
    memset(mixed, 0, sizeof(mixed));
    for (size_t i = 0; i < 9; i++) {
        if (!((mask[i >> 3] >> (i & 7)) & 1u)) continue;
        for (size_t k = 0; k < FOUNTAIN_FRAG_LEN; k++) mixed[k] ^= frags[i][k];
    }

    fountain_decoder_t* d = fountain_decoder_new();
    TEST_ASSERT_NOT_NULL(d);

    uint8_t* msg  = NULL;
    size_t   mlen = 0;

    /* Fragments 0..6 first: fragments 7 and 8 are still missing. */
    for (uint32_t s = 1; s <= 7; s++) {
        TEST_ASSERT_EQUAL_INT(0, fountain_decoder_receive(d, s, 9, FOUNTAIN_MSG_LEN,
                                                          FOUNTAIN_CHECKSUM, frags[s - 1],
                                                          FOUNTAIN_FRAG_LEN, &msg, &mlen));
    }

    /* The mixed part reduces to {7,8}: not simple yet, so it is parked; seeing
     * the same part again is ignored. */
    TEST_ASSERT_EQUAL_INT(0,
                          fountain_decoder_receive(d, mix, 9, FOUNTAIN_MSG_LEN, FOUNTAIN_CHECKSUM,
                                                   mixed, sizeof(mixed), &msg, &mlen));
    TEST_ASSERT_EQUAL_INT(0,
                          fountain_decoder_receive(d, mix, 9, FOUNTAIN_MSG_LEN, FOUNTAIN_CHECKSUM,
                                                   mixed, sizeof(mixed), &msg, &mlen));

    /* Fragment 7 completes the parked part, which then supplies fragment 8. */
    TEST_ASSERT_EQUAL_INT(1, fountain_decoder_receive(d, 8, 9, FOUNTAIN_MSG_LEN, FOUNTAIN_CHECKSUM,
                                                      frags[7], FOUNTAIN_FRAG_LEN, &msg, &mlen));
    TEST_ASSERT_EQUAL_UINT(FOUNTAIN_MSG_LEN, (unsigned)mlen);
    TEST_ASSERT_EQUAL_MEMORY(expect, msg, FOUNTAIN_MSG_LEN);
    free(msg);

    fountain_decoder_free(d);
}

/* Part geometry is validated before anything is allocated: a part whose
 * declared message_len/seq_len/data_len cannot describe `seq_len` equal
 * fragments is refused, and refusing it must leave the decoder reusable. */
static void test_fountain_part_geometry(void) {
    uint8_t data[FOUNTAIN_FRAG_LEN];
    memset(data, 0xAA, sizeof(data));
    uint8_t* msg  = NULL;
    size_t   mlen = 0;

    fountain_decoder_t* d = fountain_decoder_new();
    TEST_ASSERT_NOT_NULL(d);

    /* message_len exceeds the fragment store -> reassembly would read past it. */
    TEST_ASSERT_EQUAL_INT(-1, fountain_decoder_receive(d, 1, 2, 100, FOUNTAIN_CHECKSUM, data,
                                                       sizeof(data), &msg, &mlen));
    /* Tiny message but a huge declared fragment store (allocation amplification). */
    TEST_ASSERT_EQUAL_INT(-1, fountain_decoder_receive(d, 1, 1024, 24, FOUNTAIN_CHECKSUM, data,
                                                       sizeof(data), &msg, &mlen));
    /* seq_len * data_len would wrap around. */
    TEST_ASSERT_EQUAL_INT(
        -1, fountain_decoder_receive(d, 1, 2, 24, FOUNTAIN_CHECKSUM, data, SIZE_MAX, &msg, &mlen));

    /* A rejected part must not leave the decoder half-initialized... */
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)fountain_decoder_expected(d));
    TEST_ASSERT_EQUAL_INT(0, fountain_decoder_receive(d, 1, 9, FOUNTAIN_MSG_LEN, FOUNTAIN_CHECKSUM,
                                                      data, sizeof(data), &msg, &mlen));
    TEST_ASSERT_EQUAL_UINT(9, (unsigned)fountain_decoder_expected(d));
    /* ...and the started sequence still rejects mismatched parts. */
    TEST_ASSERT_EQUAL_INT(-1, fountain_decoder_receive(d, 2, 8, FOUNTAIN_MSG_LEN, FOUNTAIN_CHECKSUM,
                                                       data, sizeof(data), &msg, &mlen));
    fountain_decoder_free(d);

    /* The mask helper refuses arguments it cannot satisfy. */
    uint8_t mask[8];
    uint8_t tiny[1];
    TEST_ASSERT_FALSE(fountain_choose_fragments(1, 9, FOUNTAIN_CHECKSUM, tiny, sizeof(tiny)));
    TEST_ASSERT_FALSE(fountain_choose_fragments(1, 0, FOUNTAIN_CHECKSUM, mask, sizeof(mask)));
    TEST_ASSERT_FALSE(fountain_choose_fragments(1, 1, FOUNTAIN_CHECKSUM, NULL, sizeof(mask)));
    TEST_ASSERT_TRUE(fountain_choose_fragments(1, 9, FOUNTAIN_CHECKSUM, mask, sizeof(mask)));
    TEST_ASSERT_EQUAL_UINT8(0x01, mask[0]); /* seq_num <= seq_len -> single fragment */
}

static void test_ur_multipart_errors(void) {
    ur_psbt_decoder_t* d = ur_psbt_decoder_new();
    TEST_ASSERT_NOT_NULL(d);
    uint8_t* psbt = NULL;
    size_t   plen = 0;

    /* NULL decoder. */
    TEST_ASSERT_EQUAL_INT(-1,
                          ur_psbt_decoder_receive(NULL, MPART_1, strlen(MPART_1), &psbt, &plen));
    /* Not a UR. */
    TEST_ASSERT_EQUAL_INT(-1, ur_psbt_decoder_receive(d, "not-a-ur", 9, &psbt, &plen));
    /* Single component (no type/message split). */
    TEST_ASSERT_EQUAL_INT(-1, ur_psbt_decoder_receive(d, "ur:psbt", 7, &psbt, &plen));
    /* Wrong type. */
    TEST_ASSERT_EQUAL_INT(-1, ur_psbt_decoder_receive(d, "ur:seed/aa", 10, &psbt, &plen));
    /* Malformed sequence component. */
    TEST_ASSERT_EQUAL_INT(-1, ur_psbt_decoder_receive(d, "ur:psbt/x-y/aa", 14, &psbt, &plen));
    /* seq_num == 0. */
    TEST_ASSERT_EQUAL_INT(-1, ur_psbt_decoder_receive(d, "ur:psbt/0-2/aa", 14, &psbt, &plen));
    /* Undecodable bytewords payload. */
    TEST_ASSERT_EQUAL_INT(-1, ur_psbt_decoder_receive(d, "ur:psbt/1-2/zz", 14, &psbt, &plen));

    ur_psbt_decoder_free(d);
}

static void test_ur_multipart_byte_string_headers(void) {
    /* Multipart part data byte strings with ai=24/25/26 length headers, plus
     * a part array header using ai=24.  checksum 0 never matches, so each
     * part is accepted but the decoder keeps waiting (returns 0). */
    static const struct {
        uint8_t bytes[8];
        size_t  len;
    } datas[] = {
        {{0x58, 0x01, 0x00}, 3},                   /* ai=24 */
        {{0x59, 0x00, 0x01, 0x00}, 4},             /* ai=25 */
        {{0x5A, 0x00, 0x00, 0x00, 0x01, 0x00}, 6}, /* ai=26 */
    };

    for (size_t v = 0; v < sizeof(datas) / sizeof(datas[0]); v++) {
        uint8_t part[16];
        size_t  n = 0;
        part[n++] = 0x98; /* array, ai=24 ... */
        part[n++] = 0x05; /* ... count 5 */
        part[n++] = 0x01; /* seq_num = 1 */
        part[n++] = 0x01; /* seq_len = 1 */
        part[n++] = 0x01; /* message_len = 1 */
        part[n++] = 0x00; /* checksum = 0 */
        memcpy(part + n, datas[v].bytes, datas[v].len);
        n += datas[v].len;

        char* ur = NULL;
        TEST_ASSERT_TRUE(ur_encode("psbt/1-1", part, n, &ur));

        ur_psbt_decoder_t* d = ur_psbt_decoder_new();
        TEST_ASSERT_NOT_NULL(d);
        uint8_t* psbt = NULL;
        size_t   plen = 0;
        TEST_ASSERT_EQUAL_INT(0, ur_psbt_decoder_receive(d, ur, strlen(ur), &psbt, &plen));
        ur_psbt_decoder_free(d);
        free(ur);
    }
}

static void test_ur_psbt_encode_guard(void) {
    uint8_t dummy[1] = {0};
    char*   ur       = NULL;
    /* psbt_len > 0xFFFFFFFF is rejected before reading the buffer. */
    TEST_ASSERT_FALSE(ur_psbt_encode(dummy, 0x100000000ULL, &ur));
}

static void test_ur_psbt_decode_magic(void) {
    uint8_t buf[10];
    memset(buf, 0xAB, sizeof(buf)); /* not "psbt\\xff" */
    char* ur = NULL;
    TEST_ASSERT_TRUE(ur_psbt_encode(buf, sizeof(buf), &ur));

    uint8_t* dec     = NULL;
    size_t   dec_len = 0;
    TEST_ASSERT_FALSE(ur_psbt_decode(ur, strlen(ur), &dec, &dec_len));
    TEST_ASSERT_NULL(dec);

    free(ur);
}

static void test_ur_multipart_single_part(void) {
    uint8_t* bytes = NULL;
    size_t   len   = 0;
    build_psbt_bytes(&bytes, &len);

    char* ur = NULL;
    TEST_ASSERT_TRUE(ur_psbt_encode(bytes, len, &ur));

    TEST_ASSERT_EQUAL_UINT(0, (unsigned)ur_psbt_decoder_received(NULL));

    ur_psbt_decoder_t* d = ur_psbt_decoder_new();
    TEST_ASSERT_NOT_NULL(d);

    uint8_t* psbt = NULL;
    size_t   plen = 0;
    TEST_ASSERT_EQUAL_INT(1, ur_psbt_decoder_receive(d, ur, strlen(ur), &psbt, &plen));
    TEST_ASSERT_EQUAL_UINT(len, (unsigned)plen);
    TEST_ASSERT_EQUAL_MEMORY(bytes, psbt, len);
    free(psbt);

    /* The deprecated ur:crypto-psbt type alias is accepted too. */
    size_t ulen = strlen(ur);
    char*  v1   = (char*)malloc(ulen + 8);
    TEST_ASSERT_NOT_NULL(v1);
    snprintf(v1, ulen + 8, "ur:crypto-psbt/%s", ur + 8);

    psbt = NULL;
    plen = 0;
    TEST_ASSERT_EQUAL_INT(1, ur_psbt_decoder_receive(d, v1, strlen(v1), &psbt, &plen));
    TEST_ASSERT_EQUAL_UINT(len, (unsigned)plen);
    TEST_ASSERT_EQUAL_MEMORY(bytes, psbt, len);
    free(psbt);
    free(v1);

    /* A single-part UR with a NULL out_psbt frees the decoded bytes itself. */
    plen = 0;
    TEST_ASSERT_EQUAL_INT(1, ur_psbt_decoder_receive(d, ur, strlen(ur), NULL, &plen));
    TEST_ASSERT_EQUAL_UINT(len, (unsigned)plen);

    ur_psbt_decoder_free(d);
    free(ur);
    free(bytes);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_ur_seed_vector);
    RUN_TEST(test_ur_psbt_roundtrip);
    RUN_TEST(test_ur_psbt_case_insensitive);
    RUN_TEST(test_ur_decode_invalid);
    RUN_TEST(test_ur_psbt_invalid);
    RUN_TEST(test_ur_psbt_8byte_length);
    RUN_TEST(test_fountain_simple);
    RUN_TEST(test_fountain_mixed);
    RUN_TEST(test_fountain_mixed_out_of_order);
    RUN_TEST(test_ur_psbt_multipart);
    RUN_TEST(test_psbt_vector_files);
    RUN_TEST(test_ur_psbt_encode_lengths);
    RUN_TEST(test_fountain_errors);
    RUN_TEST(test_fountain_part_geometry);
    RUN_TEST(test_ur_multipart_errors);
    RUN_TEST(test_ur_multipart_byte_string_headers);
    RUN_TEST(test_ur_psbt_encode_guard);
    RUN_TEST(test_ur_psbt_decode_magic);
    RUN_TEST(test_ur_multipart_single_part);
    return UNITY_END();
}

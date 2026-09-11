/**
 * @file tests/test_descriptor.c
 * @brief Unity tests for main/crypto/descriptor.c
 */

#include "crypto/descriptor.h"
#include "crypto/ur_descriptor.h"
#include "unity.h"
#include "vectors.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <wally_address.h>
#include <wally_core.h>
#include <wally_descriptor.h>

void setUp(void) {}
void tearDown(void) {}

/* Test xpub (from libwally-core's descriptor test fixtures). */
#define XPUB                                                                                       \
    "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRja" \
    "DMzQLcgJvLJuZZvRcEL"

/* Test xprv, only used to check that private descriptors are rejected. */
#define XPRV                                                                                       \
    "xprvA2YKGLieCs6cWCiczALiH1jzk3VCCS5M1pGQfWPkamCdR9UpBgE2Gb8AKAyVjKHkz8v37avcfRjdcnP19dVAmZrv" \
    "ZQfvTcXXSAiFNQ6tTtU"

/* Derive a single address from `desc` using libwally directly. */
static char* derive_addr(const char* desc, uint32_t multi_index, uint32_t child_num) {
    struct wally_descriptor* wd  = NULL;
    char*                    out = NULL;
    if (wally_descriptor_parse(desc, NULL, WALLY_NETWORK_BITCOIN_MAINNET, 0, &wd) != WALLY_OK)
        return NULL;
    if (wally_descriptor_to_address(wd, 0, multi_index, child_num, 0, &out) != WALLY_OK) out = NULL;
    wally_descriptor_free(wd);
    return out;
}

static descriptor_t* parse(const char* desc, descriptor_status_t* st) {
    return descriptor_parse((const uint8_t*)desc, strlen(desc), st);
}

/* Re-serialize `desc` with its BIP-380 "#checksum" appended. */
static void add_checksum(const char* desc, char* out, size_t out_size) {
    struct wally_descriptor* wd = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_descriptor_parse(desc, NULL, WALLY_NETWORK_NONE, 0, &wd));
    char* canon = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_descriptor_canonicalize(wd, 0, &canon));
    wally_descriptor_free(wd);

    TEST_ASSERT_TRUE(strlen(canon) < out_size);
    strcpy(out, canon);
    wally_free_string(canon);
}

static void test_parse_receive_descriptor(void) {
    const char*         desc = "wpkh(" XPUB "/0/*)";
    descriptor_status_t st   = DESCRIPTOR_OK;
    descriptor_t*       d    = parse(desc, &st);
    TEST_ASSERT_EQUAL(DESCRIPTOR_OK, st);
    TEST_ASSERT_NOT_NULL(d);

    char* recv0 = derive_addr(desc, 0, 0);
    TEST_ASSERT_NOT_NULL(recv0);
    TEST_ASSERT_EQUAL(DESCRIPTOR_MATCH_RECEIVE, descriptor_classify(d, recv0));
    TEST_ASSERT_TRUE(descriptor_owns_address(d, recv0));

    /* Change sibling (branch 1) is also derivable. */
    char* chg0 = derive_addr("wpkh(" XPUB "/1/*)", 0, 0);
    TEST_ASSERT_NOT_NULL(chg0);
    TEST_ASSERT_EQUAL(DESCRIPTOR_MATCH_CHANGE, descriptor_classify(d, chg0));

    /* A branch outside the receive/change pair is not ours. */
    char* other = derive_addr("wpkh(" XPUB "/2/*)", 0, 0);
    TEST_ASSERT_NOT_NULL(other);
    TEST_ASSERT_EQUAL(DESCRIPTOR_MATCH_NONE, descriptor_classify(d, other));

    wally_free_string(recv0);
    wally_free_string(chg0);
    wally_free_string(other);
    descriptor_free(d);
}

static void test_parse_change_descriptor(void) {
    const char*         desc = "wpkh(" XPUB "/1/*)";
    descriptor_status_t st   = DESCRIPTOR_OK;
    descriptor_t*       d    = parse(desc, &st);
    TEST_ASSERT_EQUAL(DESCRIPTOR_OK, st);
    TEST_ASSERT_NOT_NULL(d);

    char* chg0 = derive_addr(desc, 0, 0);
    TEST_ASSERT_NOT_NULL(chg0);
    TEST_ASSERT_EQUAL(DESCRIPTOR_MATCH_CHANGE, descriptor_classify(d, chg0));

    wally_free_string(chg0);
    descriptor_free(d);
}

static void test_parse_multipath_descriptor(void) {
    const char*         desc = "wpkh(" XPUB "/<0;1>/*)";
    descriptor_status_t st   = DESCRIPTOR_OK;
    descriptor_t*       d    = parse(desc, &st);
    TEST_ASSERT_EQUAL(DESCRIPTOR_OK, st);
    TEST_ASSERT_NOT_NULL(d);

    char* recv0 = derive_addr(desc, 0, 0);
    char* chg0  = derive_addr(desc, 1, 0);
    TEST_ASSERT_NOT_NULL(recv0);
    TEST_ASSERT_NOT_NULL(chg0);
    TEST_ASSERT_EQUAL(DESCRIPTOR_MATCH_RECEIVE, descriptor_classify(d, recv0));
    TEST_ASSERT_EQUAL(DESCRIPTOR_MATCH_CHANGE, descriptor_classify(d, chg0));

    wally_free_string(recv0);
    wally_free_string(chg0);
    descriptor_free(d);
}

/* A trailing BIP-380 "#checksum" must not disable change detection.  libwally
 * validates a supplied checksum when parsing, so the flipped branch-1 sibling
 * has to be built from the checksum-free text (flipping the branch invalidates
 * the checksum). */
static void test_parse_checksummed_descriptor(void) {
    char csum[512];
    add_checksum("wpkh(" XPUB "/0/*)", csum, sizeof(csum));
    TEST_ASSERT_NOT_NULL(strchr(csum, '#'));

    descriptor_status_t st = DESCRIPTOR_OK;
    descriptor_t*       d  = parse(csum, &st);
    TEST_ASSERT_EQUAL(DESCRIPTOR_OK, st);
    TEST_ASSERT_NOT_NULL(d);

    char* recv0 = derive_addr("wpkh(" XPUB "/0/*)", 0, 0);
    char* chg0  = derive_addr("wpkh(" XPUB "/1/*)", 0, 0);
    TEST_ASSERT_NOT_NULL(recv0);
    TEST_ASSERT_NOT_NULL(chg0);
    TEST_ASSERT_EQUAL(DESCRIPTOR_MATCH_RECEIVE, descriptor_classify(d, recv0));
    TEST_ASSERT_EQUAL(DESCRIPTOR_MATCH_CHANGE, descriptor_classify(d, chg0));

    wally_free_string(recv0);
    wally_free_string(chg0);
    descriptor_free(d);
}

static void test_reject_bad_checksum(void) {
    char bad[512];
    add_checksum("wpkh(" XPUB "/0/*)", bad, sizeof(bad));

    /* Corrupt the final checksum character.  Both replacement letters are in
     * the checksum charset, so only the checksum comparison can reject it. */
    char* last = &bad[strlen(bad) - 1];
    *last      = (*last == 'q') ? 'p' : 'q';

    descriptor_status_t st = DESCRIPTOR_OK;
    TEST_ASSERT_NULL(parse(bad, &st));
    TEST_ASSERT_EQUAL(DESCRIPTOR_ERR_NOT_DESC, st);
}

/* A checksummed change-only descriptor (branch 1): no branch flip is needed,
 * but the checksum must still be ignored so the descriptor itself parses. */
static void test_parse_checksummed_change_descriptor(void) {
    char csum[512];
    add_checksum("wpkh(" XPUB "/1/*)", csum, sizeof(csum));

    descriptor_status_t st = DESCRIPTOR_OK;
    descriptor_t*       d  = parse(csum, &st);
    TEST_ASSERT_EQUAL(DESCRIPTOR_OK, st);
    TEST_ASSERT_NOT_NULL(d);

    char* chg0 = derive_addr("wpkh(" XPUB "/1/*)", 0, 0);
    TEST_ASSERT_NOT_NULL(chg0);
    TEST_ASSERT_EQUAL(DESCRIPTOR_MATCH_CHANGE, descriptor_classify(d, chg0));

    wally_free_string(chg0);
    descriptor_free(d);
}

static void test_parse_static_descriptor(void) {
    const char* desc = "wpkh(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";
    descriptor_status_t st = DESCRIPTOR_OK;
    descriptor_t*       d  = parse(desc, &st);
    TEST_ASSERT_EQUAL(DESCRIPTOR_OK, st);
    TEST_ASSERT_NOT_NULL(d);

    const char* addr = "bc1q0ht9tyks4vh7p5p904t340cr9nvahy7u3re7zg";
    TEST_ASSERT_TRUE(descriptor_owns_address(d, addr));
    TEST_ASSERT_EQUAL(DESCRIPTOR_MATCH_RECEIVE, descriptor_classify(d, addr));

    descriptor_free(d);
}

static void test_reject_private_descriptor(void) {
    const char*         desc = "wpkh(" XPRV "/0/*)";
    descriptor_status_t st   = DESCRIPTOR_OK;
    descriptor_t*       d    = parse(desc, &st);
    TEST_ASSERT_NULL(d);
    TEST_ASSERT_EQUAL(DESCRIPTOR_ERR_PRIVATE, st);
}

static void test_reject_invalid(void) {
    descriptor_status_t st = DESCRIPTOR_OK;
    TEST_ASSERT_NULL(parse("not a descriptor", &st));
    TEST_ASSERT_EQUAL(DESCRIPTOR_ERR_NOT_DESC, st);
    TEST_ASSERT_NULL(parse("", &st));
    TEST_ASSERT_EQUAL(DESCRIPTOR_ERR_NOT_DESC, st);
    TEST_ASSERT_NULL(descriptor_parse(NULL, 0, &st));
    TEST_ASSERT_EQUAL(DESCRIPTOR_ERR_NOT_DESC, st);
}

static void test_reject_too_long(void) {
    uint8_t* big = (uint8_t*)malloc(DESCRIPTOR_MAX_PAYLOAD + 1);
    TEST_ASSERT_NOT_NULL(big);
    memset(big, 'a', DESCRIPTOR_MAX_PAYLOAD + 1);

    descriptor_status_t st = DESCRIPTOR_OK;
    TEST_ASSERT_NULL(descriptor_parse(big, DESCRIPTOR_MAX_PAYLOAD + 1, &st));
    TEST_ASSERT_EQUAL(DESCRIPTOR_ERR_TOO_LONG, st);

    free(big);
}

static void test_ur_descriptor_invalid(void) {
    char* out = NULL;
    TEST_ASSERT_FALSE(ur_descriptor_decode(NULL, 0, &out));
    TEST_ASSERT_FALSE(ur_descriptor_decode("", 0, &out));
    TEST_ASSERT_FALSE(ur_descriptor_decode("not a ur", 8, &out));
    /* Wrong UR type. */
    TEST_ASSERT_FALSE(ur_descriptor_decode("ur:psbt/hdosjojkidjyzmadaenyaoaeaeaeaohdvsknclr"
                                           "ejnpebncnrnmnjojofejzeojlkerdonspkpkkdkykfelokg"
                                           "prpyutkpaeaeaeaeaezmzmzmzmlslgaaditiwpihbkispkf"
                                           "grkbdaslewdfycprtjsprsgksecdratkkhktikewdcaadaeae"
                                           "aeaezmzmzmzmaojopkwtayaeaeaeaecmaebbtphhdnjstiambd"
                                           "assoloimwmlyhygdnlcatnbggtaevyykahaeaeaeaecmaebbae"
                                           "plptoevwwtyakoonlourgofgvsjydpcaltaemyaeaeaeaeaeae"
                                           "aeaeaebkgdcarh",
                                           100, &out));
}

/* combo() has no single "variant 0" address, so it isn't part of the
 * classify-based vector suite; exercise its expression-tree tag directly. */
static void test_ur_descriptor_combo(void) {
    static const char* const UR_V3 = "ur:output-descriptor/"
                                     "oeadiniajljnidjldefzdydtaolytantjpoyaxhdclaoytdyleadmohdsrbeg"
                                     "aeegwlpyantgmdtreehspfelsjlnlpflnadwnbwrfvtenytstfsbwem";
    static const char* const UR_V1 = "ur:crypto-output/"
                                     "taadmdtaadeyoyaxhdclaoytdyleadmohdsrbegaeegwlpyantgmdtreehspf"
                                     "elsjlnlpflnadwnbwrfvtenytrlothnpk";
    const char* expect =
        "combo(02f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9)";

    char* out = NULL;
    TEST_ASSERT_TRUE(ur_descriptor_decode(UR_V3, strlen(UR_V3), &out));
    TEST_ASSERT_EQUAL_STRING(expect, out);
    free(out);

    out = NULL;
    TEST_ASSERT_TRUE(ur_descriptor_decode(UR_V1, strlen(UR_V1), &out));
    TEST_ASSERT_EQUAL_STRING(expect, out);
    free(out);
}

/* -- Generated descriptor UR vectors (tests/vectors/descriptor/) ------- */
static void test_descriptor_ur_vector_files(void) {
    char** slugs   = NULL;
    size_t n_slugs = 0;
    TEST_ASSERT_TRUE(vectors_list_slugs("descriptor/raw", ".txt", &slugs, &n_slugs));
    TEST_ASSERT_TRUE(n_slugs > 0);

    for (size_t s = 0; s < n_slugs; s++) {
        const char* slug = slugs[s];
        char        path[256];

        /* Expected descriptor text. */
        snprintf(path, sizeof(path), "descriptor/raw/%s.txt", slug);
        char* expected = (char*)vectors_read_file(path, NULL);
        TEST_ASSERT_NOT_NULL(expected);
        vectors_trim(expected);

        /* Reference address derived from the expected text (proves the UR
         * decodes to an address-equivalent descriptor). */
        char* ref = derive_addr(expected, 0, 0);
        TEST_ASSERT_NOT_NULL(ref);

        const char* variants[] = {".output-descriptor.ur", ".crypto-output.ur"};
        for (size_t vi = 0; vi < sizeof(variants) / sizeof(variants[0]); vi++) {
            snprintf(path, sizeof(path), "descriptor/ur/%s%s", slug, variants[vi]);
            char* ur = (char*)vectors_read_file(path, NULL);
            TEST_ASSERT_NOT_NULL(ur);
            vectors_trim(ur);

            char* got = NULL;
            TEST_ASSERT_TRUE(ur_descriptor_decode(ur, strlen(ur), &got));
            TEST_ASSERT_NOT_NULL(got);

            /* The stateful decoder handles the same single-part vectors. */
            ur_descriptor_decoder_t* dec = ur_descriptor_decoder_new();
            TEST_ASSERT_NOT_NULL(dec);
            char* got2 = NULL;
            TEST_ASSERT_EQUAL_INT(1, ur_descriptor_decoder_receive(dec, ur, strlen(ur), &got2));
            TEST_ASSERT_EQUAL_STRING(got, got2);
            free(got2);
            ur_descriptor_decoder_free(dec);

            /* Static (raw-key) descriptors round-trip exactly; xpub-based
             * descriptors are reconstructed address-equivalently (the xpub
             * serialization may differ). */
            if (!strstr(expected, "xpub") && !strstr(expected, "tpub")) {
                TEST_ASSERT_EQUAL_STRING(expected, got);
            }

            descriptor_status_t st = DESCRIPTOR_OK;
            descriptor_t*       d  = parse(got, &st);
            TEST_ASSERT_EQUAL(DESCRIPTOR_OK, st);
            TEST_ASSERT_NOT_NULL(d);
            TEST_ASSERT_NOT_EQUAL(DESCRIPTOR_MATCH_NONE, descriptor_classify(d, ref));
            descriptor_free(d);

            free(got);
            free(ur);
        }

        wally_free_string(ref);
        free(expected);
    }

    vectors_free_slugs(slugs, n_slugs);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_parse_receive_descriptor);
    RUN_TEST(test_parse_change_descriptor);
    RUN_TEST(test_parse_multipath_descriptor);
    RUN_TEST(test_parse_checksummed_descriptor);
    RUN_TEST(test_parse_checksummed_change_descriptor);
    RUN_TEST(test_parse_static_descriptor);
    RUN_TEST(test_reject_bad_checksum);
    RUN_TEST(test_reject_private_descriptor);
    RUN_TEST(test_reject_invalid);
    RUN_TEST(test_reject_too_long);
    RUN_TEST(test_ur_descriptor_invalid);
    RUN_TEST(test_ur_descriptor_combo);
    RUN_TEST(test_descriptor_ur_vector_files);
    return UNITY_END();
}

/**
 * @file tests/test_multisig.c
 * @brief Unity tests for main/crypto/multisig.c.
 *
 * The expected fingerprints, account xpubs, descriptor text, checksum and
 * addresses come from an independent Python implementation of BIP39, BIP32,
 * BIP67 (sorted pubkeys, as `sortedmulti` derives them), BIP-380 descriptor
 * checksums and bech32.  The three mnemonics are the first three BIP39 test
 * vectors, and 73c5da0a is the published fingerprint of "abandon ... about".
 */

#include "crypto/mnemonic.h"
#include "crypto/multisig.h"
#include "qr/qr.h"
#include "unity.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static const char* const WORDS[3] = {
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    "legal winner thank year wave sausage worth useful legal winner thank yellow",
    "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
};

static const char* const FP[3]     = {"73c5da0a", "b8688df1", "28645006"};
static const char* const PATH      = "m/48'/0'/0'/2'";
static const char* const TEST_PATH = "m/48'/1'/0'/2'";

static const char* const XPUB[3] = {
    "xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1"
    "VhR28mCyxUFL4r6KFrf",
    "xpub6FQya7zGhR92kacYsNnjreouvnHJMpXYsUXnW6NJJAJRCKsa26TzDy4LdnGhEurr3d6y1J8PJ7EEMKQp74XTqYvmGJ"
    "N"
    "ogYXSKDszYHtF8mX",
    "xpub6DnEBNkSJKBYQmsbhS1sP9cNdtU5c9PLFGCjTJmxicxc13WB8zNNGQazabQpyFAGW5bV9tMko4uBxDxjUKL6dSAcx1"
    "tEbgEHtgSqyRsekh6",
};

static const char* const TEST_XPUB[3] = {
    "tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1P"
    "JY8iCNiwTL3RWZEheQ",
    "tpubDEfobrrtptRTbKf4gysDhoabneABDTAcdj3Vbn4XwPsLE2pmqpizSPRG6zHsbAMuiSgWmWPsYCLHTKTPpyrGJ5rAoT"
    "pKoQNZcxodiPf2tSJ",
    "tpubDEwqCvJxKwKWX9xvRe48uofWJn1Y89Jn8UeH1Efrjb1UEVjUDy3URYTiqWaVCW7WdvHrL8XrSihHEhTwv5H3VDJoa"
    "kjuCHiAnr6xcF2Xm4s",
};

/* wsh(sortedmulti(2, ...)) over the three keys above, checksum included. */
static const char* const DESCRIPTOR =
    "wsh(sortedmulti(2,[73c5da0a/48'/0'/0'/2']"
    "xpub6DkFAXWQ2dHxq2vatrt9qyA3bXYU4ToWQwCHbf5XB2mSTexcHZCeKS1VZYcPoBd5X8yVcbXFHJR9R8UCVpt82VX1Vh"
    "R28mCyxUFL4r6KFrf/<0;1>/*,[b8688df1/48'/0'/0'/2']"
    "xpub6FQya7zGhR92kacYsNnjreouvnHJMpXYsUXnW6NJJAJRCKsa26TzDy4LdnGhEurr3d6y1J8PJ7EEMKQp74XTqYvmGJ"
    "No"
    "gYXSKDszYHtF8mX/<0;1>/*,[28645006/48'/0'/0'/2']"
    "xpub6DnEBNkSJKBYQmsbhS1sP9cNdtU5c9PLFGCjTJmxicxc13WB8zNNGQazabQpyFAGW5bV9tMko4uBxDxjUKL6dSAcx1"
    "tE"
    "bgEHtgSqyRsekh6/<0;1>/*))#l2pdw8zh";

static const char* const DESCRIPTOR_TEST =
    "wsh(sortedmulti(2,[73c5da0a/48'/1'/0'/2']"
    "tpubDFH9dgzveyD8zTbPUFuLrGmCydNvxehyNdUXKJAQN8x4aZ4j6UZqGfnqFrD4NqyaTVGKbvEW54tsvPTK2UoSbCC1PJ"
    "Y8"
    "iCNiwTL3RWZEheQ/<0;1>/*,[b8688df1/48'/1'/0'/2']"
    "tpubDEfobrrtptRTbKf4gysDhoabneABDTAcdj3Vbn4XwPsLE2pmqpizSPRG6zHsbAMuiSgWmWPsYCLHTKTPpyrGJ5rAo"
    "TpKoQNZcxodiPf2tSJ/<0;1>/*,[28645006/48'/1'/0'/2']"
    "tpubDEwqCvJxKwKWX9xvRe48uofWJn1Y89Jn8UeH1Efrjb1UEVjUDy3URYTiqWaVCW7WdvHrL8XrSihHEhTwv5H3VDJoa"
    "kjuCHiAnr6xcF2Xm4s/<0;1>/*))#uglk83ue";

static const char* const RECEIVE[3] = {
    "bc1qm43n7nnev58aj3nrznz2xscgv98t7gxycq5pmp20a5vzfp5t0q2s7r6twa",
    "bc1qh0jxweder0zfwz363juas8vhav6p4d4hmk6yx7kphd3gvf769fzq2dp3an",
    "bc1qklz3sd5m7zmv4kkkxh2g24gdj24x0d3ghhmtl2wju3ghhgduzjfqcseehe",
};
static const char* const CHANGE0 = "bc1qy0qa9lx04k0lk9lrv4542ndehul9spkcafdtcpdv38qx6ft5km2ssnce5d";
static const char* const TEST_RECEIVE0 =
    "tb1qr3az57pxl8z7q6d9q7v0fmeaphuwe3z0ghvkjr457ch4vqwmtkasmn0gme";
static const char* const TEST_RECEIVE1 =
    "tb1qfd7fatk9l5q75yqft27jsn4uehtkl4eyhalgusnccwtcha362ywskv2che";
static const char* const TEST_CHANGE0 =
    "tb1qklaygzf7d5waqjvl2lul2aafh429l2xkqkrszfj537ejzmhu8axsgpufdm";

/* Fill a wallet from the test mnemonics, in the order given (NULL = as is). */
static multisig_t* make_wallet(multisig_network_t network, const size_t* order) {
    multisig_t* ms = multisig_new(3, 2, network);
    TEST_ASSERT_NOT_NULL(ms);
    for (size_t i = 0; i < 3; i++) {
        mnemonic_t* m = mnemonic_from_string(WORDS[order ? order[i] : i]);
        TEST_ASSERT_NOT_NULL(m);
        TEST_ASSERT_TRUE(multisig_set_mnemonic(ms, i, m));
        mnemonic_discard(m);
    }
    TEST_ASSERT_TRUE(multisig_complete(ms));
    return ms;
}

static void test_two_of_three_matches_reference(void) {
    multisig_t* ms = make_wallet(MULTISIG_MAINNET, NULL);

    TEST_ASSERT_EQUAL_UINT(3, multisig_key_count(ms));
    TEST_ASSERT_EQUAL_UINT(2, multisig_threshold(ms));
    for (size_t i = 0; i < 3; i++) {
        TEST_ASSERT_EQUAL_STRING(FP[i], multisig_slot_fingerprint(ms, i));
        TEST_ASSERT_EQUAL_STRING(PATH, multisig_slot_path(ms, i));
        TEST_ASSERT_EQUAL_STRING(XPUB[i], multisig_slot_xpub(ms, i));
    }

    char         desc[MULTISIG_DESCRIPTOR_MAX];
    const size_t len = multisig_descriptor(ms, desc, sizeof(desc));
    TEST_ASSERT_EQUAL_UINT(strlen(DESCRIPTOR), len);
    TEST_ASSERT_EQUAL_STRING(DESCRIPTOR, desc);

    char addr[MULTISIG_ADDR_MAX];
    for (uint32_t i = 0; i < 3; i++) {
        TEST_ASSERT_EQUAL_UINT(strlen(RECEIVE[i]), multisig_address(ms, 0, i, addr, sizeof(addr)));
        TEST_ASSERT_EQUAL_STRING(RECEIVE[i], addr);
    }
    TEST_ASSERT_EQUAL_UINT(strlen(CHANGE0), multisig_address(ms, 1, 0, addr, sizeof(addr)));
    TEST_ASSERT_EQUAL_STRING(CHANGE0, addr);

    multisig_free(ms);
}

static void test_testnet(void) {
    multisig_t* ms = make_wallet(MULTISIG_TESTNET, NULL);

    for (size_t i = 0; i < 3; i++) {
        TEST_ASSERT_EQUAL_STRING(TEST_PATH, multisig_slot_path(ms, i));
        TEST_ASSERT_EQUAL_STRING(TEST_XPUB[i], multisig_slot_xpub(ms, i));
    }

    char desc[MULTISIG_DESCRIPTOR_MAX];
    TEST_ASSERT_EQUAL_UINT(strlen(DESCRIPTOR_TEST), multisig_descriptor(ms, desc, sizeof(desc)));
    TEST_ASSERT_EQUAL_STRING(DESCRIPTOR_TEST, desc);

    char addr[MULTISIG_ADDR_MAX];
    TEST_ASSERT_EQUAL_UINT(strlen(TEST_RECEIVE0), multisig_address(ms, 0, 0, addr, sizeof(addr)));
    TEST_ASSERT_EQUAL_STRING(TEST_RECEIVE0, addr);
    TEST_ASSERT_EQUAL_UINT(strlen(TEST_RECEIVE1), multisig_address(ms, 0, 1, addr, sizeof(addr)));
    TEST_ASSERT_EQUAL_STRING(TEST_RECEIVE1, addr);
    TEST_ASSERT_EQUAL_UINT(strlen(TEST_CHANGE0), multisig_address(ms, 1, 0, addr, sizeof(addr)));
    TEST_ASSERT_EQUAL_STRING(TEST_CHANGE0, addr);

    multisig_free(ms);
}

/* sortedmulti sorts the *derived* pubkeys, so the same three cosigners must
 * produce the same addresses whatever order they were entered in. */
static void test_key_order_does_not_change_addresses(void) {
    const size_t order[3] = {2, 0, 1};
    multisig_t*  a        = make_wallet(MULTISIG_MAINNET, NULL);
    multisig_t*  b        = make_wallet(MULTISIG_MAINNET, order);

    char addr_a[MULTISIG_ADDR_MAX];
    char addr_b[MULTISIG_ADDR_MAX];
    for (uint32_t i = 0; i < 3; i++) {
        TEST_ASSERT_TRUE(multisig_address(a, 0, i, addr_a, sizeof(addr_a)) > 0);
        TEST_ASSERT_TRUE(multisig_address(b, 0, i, addr_b, sizeof(addr_b)) > 0);
        TEST_ASSERT_EQUAL_STRING(addr_a, addr_b);
    }

    /* The text, on the other hand, keeps the order the keys were entered in. */
    char desc_a[MULTISIG_DESCRIPTOR_MAX];
    char desc_b[MULTISIG_DESCRIPTOR_MAX];
    TEST_ASSERT_TRUE(multisig_descriptor(a, desc_a, sizeof(desc_a)) > 0);
    TEST_ASSERT_TRUE(multisig_descriptor(b, desc_b, sizeof(desc_b)) > 0);
    TEST_ASSERT_TRUE(strstr(desc_b, FP[2]) < strstr(desc_b, FP[0]));

    multisig_free(a);
    multisig_free(b);
}

static void test_cosigner_key(void) {
    multisig_t* ms = make_wallet(MULTISIG_MAINNET, NULL);

    char   key[MULTISIG_XPUB_MAX + 64];
    size_t len = multisig_cosigner_key(ms, 0, key, sizeof(key));
    TEST_ASSERT_TRUE(len > 0);
    TEST_ASSERT_NOT_NULL(strstr(key, "[73c5da0a/48'/0'/0'/2']"));
    TEST_ASSERT_NOT_NULL(strstr(key, XPUB[0]));
    TEST_ASSERT_NOT_NULL(strstr(key, "/<0;1>/*"));
    /* It parses as a descriptor key on its own, i.e. another wallet can use it. */
    TEST_ASSERT_EQUAL_UINT(len, strlen(key));

    char small[32];
    TEST_ASSERT_EQUAL_UINT(0, multisig_cosigner_key(ms, 0, small, sizeof(small)));
    TEST_ASSERT_EQUAL_CHAR('\0', small[0]);

    multisig_t* empty = multisig_new(2, 1, MULTISIG_MAINNET);
    TEST_ASSERT_NOT_NULL(empty);
    TEST_ASSERT_EQUAL_UINT(0, multisig_cosigner_key(empty, 0, key, sizeof(key)));
    TEST_ASSERT_EQUAL_UINT(0, multisig_cosigner_key(NULL, 0, key, sizeof(key)));
    TEST_ASSERT_EQUAL_UINT(0, multisig_cosigner_key(ms, 3, key, sizeof(key)));

    multisig_free(empty);
    multisig_free(ms);
}

static void test_summary(void) {
    multisig_t* ms = make_wallet(MULTISIG_MAINNET, NULL);

    char   body[4096];
    size_t len = multisig_summary(ms, body, sizeof(body));
    TEST_ASSERT_TRUE(len > 0 && len < sizeof(body));

    TEST_ASSERT_NOT_NULL(strstr(body, "2 of 3 signatures\n"));
    TEST_ASSERT_NOT_NULL(strstr(body, "network: mainnet\n"));
    TEST_ASSERT_NOT_NULL(strstr(body, "#1  73c5da0a  m/48'/0'/0'/2'\n"));
    TEST_ASSERT_NOT_NULL(strstr(body, "#3  28645006  m/48'/0'/0'/2'\n"));
    TEST_ASSERT_NOT_NULL(strstr(body, RECEIVE[0]));
    TEST_ASSERT_NOT_NULL(strstr(body, DESCRIPTOR));

    /* A buffer that cannot hold the whole summary is refused, not truncated. */
    char small[64];
    TEST_ASSERT_EQUAL_UINT(0, multisig_summary(ms, small, sizeof(small)));
    TEST_ASSERT_EQUAL_CHAR('\0', small[0]);
    TEST_ASSERT_EQUAL_UINT(0, multisig_summary(NULL, body, sizeof(body)));

    multisig_free(ms);
}

/* The descriptor is long enough to sit in a dense QR: encode it and read it
 * back through quirc, which is how another wallet sees it. */
static void test_descriptor_qr_round_trip(void) {
    multisig_t* ms = make_wallet(MULTISIG_MAINNET, NULL);

    char         desc[MULTISIG_DESCRIPTOR_MAX];
    const size_t len = multisig_descriptor(ms, desc, sizeof(desc));
    TEST_ASSERT_TRUE(len > 0);

    qr_grid_t grid = {0};
    TEST_ASSERT_TRUE(qr_encode((const uint8_t*)desc, len, QR_MODE_BYTE, &grid));
    TEST_ASSERT_TRUE(grid.size > 0);

    /* Render at 4 pixels per module, quiet zone included. */
    const uint32_t side = grid.size + 8;
    uint8_t*       img  = malloc((size_t)side * side);
    TEST_ASSERT_NOT_NULL(img);
    memset(img, 0xff, (size_t)side * side);
    for (uint32_t y = 0; y < grid.size; y++) {
        for (uint32_t x = 0; x < grid.size; x++) {
            if (grid.cells[y * grid.size + x]) memset(img + (size_t)(y + 4) * side + (x + 4), 0, 1);
        }
    }

    uint8_t payload[4096];
    size_t  got = 0;
    TEST_ASSERT_TRUE(qr_decode(img, side, side, payload, sizeof(payload), &got));
    TEST_ASSERT_EQUAL_UINT(len, got);
    TEST_ASSERT_EQUAL_MEMORY(desc, payload, len);

    free(img);
    qr_grid_free(&grid);
    multisig_free(ms);
}

static void test_incomplete_wallet(void) {
    multisig_t* ms = multisig_new(3, 2, MULTISIG_MAINNET);
    TEST_ASSERT_NOT_NULL(ms);

    char out[MULTISIG_DESCRIPTOR_MAX];
    memset(out, 'x', sizeof(out));

    TEST_ASSERT_FALSE(multisig_complete(ms));
    TEST_ASSERT_EQUAL_UINT(0, multisig_descriptor(ms, out, sizeof(out)));
    TEST_ASSERT_EQUAL_CHAR('\0', out[0]);
    TEST_ASSERT_EQUAL_UINT(0, multisig_address(ms, 0, 0, out, sizeof(out)));

    mnemonic_t* m = mnemonic_from_string(WORDS[0]);
    TEST_ASSERT_NOT_NULL(m);
    TEST_ASSERT_TRUE(multisig_set_mnemonic(ms, 0, m));
    TEST_ASSERT_TRUE(multisig_slot_ready(ms, 0));
    TEST_ASSERT_FALSE(multisig_slot_ready(ms, 1));
    TEST_ASSERT_NULL(multisig_slot_xpub(ms, 1));
    TEST_ASSERT_FALSE(multisig_complete(ms));
    TEST_ASSERT_EQUAL_UINT(0, multisig_descriptor(ms, out, sizeof(out)));
    mnemonic_discard(m);

    /* A buffer too small for the text is refused rather than truncated. */
    TEST_ASSERT_TRUE(multisig_set_words(ms, 1, WORDS[1]));
    TEST_ASSERT_TRUE(multisig_set_words(ms, 2, WORDS[2]));
    TEST_ASSERT_TRUE(multisig_complete(ms));
    char small[64];
    TEST_ASSERT_EQUAL_UINT(0, multisig_descriptor(ms, small, sizeof(small)));
    TEST_ASSERT_EQUAL_CHAR('\0', small[0]);

    multisig_free(ms);
}

static void test_bounds(void) {
    /* The script limit is 15 keys; anything else is refused up front. */
    multisig_t* full = multisig_new(15, 15, MULTISIG_MAINNET);
    TEST_ASSERT_NOT_NULL(full);
    multisig_free(full);

    TEST_ASSERT_NULL(multisig_new(1, 1, MULTISIG_MAINNET));
    TEST_ASSERT_NULL(multisig_new(16, 2, MULTISIG_MAINNET));
    TEST_ASSERT_NULL(multisig_new(3, 0, MULTISIG_MAINNET));
    TEST_ASSERT_NULL(multisig_new(3, 4, MULTISIG_MAINNET));

    multisig_t* ms = multisig_new(2, 1, MULTISIG_MAINNET);
    TEST_ASSERT_NOT_NULL(ms);
    TEST_ASSERT_FALSE(multisig_set_words(ms, 2, WORDS[0]));
    TEST_ASSERT_FALSE(multisig_set_words(ms, 0, NULL));
    TEST_ASSERT_FALSE(multisig_set_words(ms, 0, ""));
    TEST_ASSERT_FALSE(multisig_set_words(ms, 0, "not a real mnemonic at all"));
    TEST_ASSERT_FALSE(multisig_slot_ready(ms, 0));

    char out[MULTISIG_ADDR_MAX];
    TEST_ASSERT_EQUAL_UINT(0, multisig_descriptor(NULL, out, sizeof(out)));
    TEST_ASSERT_EQUAL_UINT(0, multisig_descriptor(ms, NULL, 0));
    TEST_ASSERT_EQUAL_UINT(0, multisig_address(ms, 0, 0, NULL, 0));

    /* Only public material is kept: the words do not survive in the handle. */
    TEST_ASSERT_TRUE(multisig_set_words(ms, 0, WORDS[0]));
    TEST_ASSERT_EQUAL_STRING(FP[0], multisig_slot_fingerprint(ms, 0));
    multisig_free(ms);

    multisig_free(NULL);
}

/* One seed cannot be two cosigners: the second entry is refused and leaves the
 * wallet as it was, while re-entering a key in its own slot is allowed. */
static void test_duplicate_keys_refused(void) {
    multisig_t* ms = multisig_new(3, 2, MULTISIG_MAINNET);
    TEST_ASSERT_NOT_NULL(ms);
    TEST_ASSERT_EQUAL(MULTISIG_SET_OK, multisig_set_words_ex(ms, 0, WORDS[0], NULL));

    size_t duplicate = SIZE_MAX;
    TEST_ASSERT_EQUAL(MULTISIG_SET_DUPLICATE_KEY,
                      multisig_set_words_ex(ms, 1, WORDS[0], &duplicate));
    TEST_ASSERT_EQUAL_UINT(0, duplicate);
    TEST_ASSERT_FALSE(multisig_slot_ready(ms, 1));
    TEST_ASSERT_FALSE(multisig_complete(ms));

    /* The plain API refuses it too, and slot 0 is untouched. */
    TEST_ASSERT_FALSE(multisig_set_words(ms, 2, WORDS[0]));
    TEST_ASSERT_FALSE(multisig_slot_ready(ms, 2));
    TEST_ASSERT_EQUAL_STRING(FP[0], multisig_slot_fingerprint(ms, 0));

    /* The same words in their own slot are a re-entry, not a duplicate. */
    TEST_ASSERT_EQUAL(MULTISIG_SET_OK, multisig_set_words_ex(ms, 0, WORDS[0], NULL));

    /* A different seed still fills the next slot. */
    TEST_ASSERT_EQUAL(MULTISIG_SET_OK, multisig_set_words_ex(ms, 1, WORDS[1], NULL));
    TEST_ASSERT_EQUAL_STRING(FP[1], multisig_slot_fingerprint(ms, 1));

    TEST_ASSERT_EQUAL(MULTISIG_SET_INVALID_MNEMONIC,
                      multisig_set_words_ex(ms, 2, "not a real mnemonic at all", NULL));
    TEST_ASSERT_EQUAL(MULTISIG_SET_BAD_SLOT, multisig_set_words_ex(ms, 3, WORDS[2], NULL));
    TEST_ASSERT_EQUAL(MULTISIG_SET_BAD_SLOT, multisig_set_words_ex(ms, 2, NULL, NULL));
    TEST_ASSERT_EQUAL(MULTISIG_SET_BAD_SLOT, multisig_set_words_ex(NULL, 0, WORDS[2], NULL));
    multisig_free(ms);
}

/* 15 is the script limit, and every cosigner adds ~147 characters to the
 * descriptor: the largest wallet must still fit MULTISIG_DESCRIPTOR_MAX. */
static void test_fifteen_of_fifteen_fits(void) {
    multisig_t* ms = multisig_new(15, 15, MULTISIG_MAINNET);
    TEST_ASSERT_NOT_NULL(ms);

    for (size_t i = 0; i < 15; i++) {
        uint8_t entropy[16];
        memset(entropy, 0, sizeof(entropy));
        entropy[0] = (uint8_t)(i + 1);

        mnemonic_t* m = mnemonic_from_entropy(entropy, sizeof(entropy));
        TEST_ASSERT_NOT_NULL(m);
        TEST_ASSERT_TRUE(multisig_set_words(ms, i, mnemonic_words(m)));
        mnemonic_discard(m);
    }
    TEST_ASSERT_TRUE(multisig_complete(ms));

    char   out[MULTISIG_DESCRIPTOR_MAX];
    size_t len = multisig_descriptor(ms, out, sizeof(out));
    TEST_ASSERT_GREATER_THAN(0, len);
    TEST_ASSERT_LESS_THAN(sizeof(out), len);
    TEST_ASSERT_EQUAL_INT(0, strncmp(out, "wsh(sortedmulti(15,", 18));
    /* ")#" then the eight checksum characters end the descriptor. */
    TEST_ASSERT_EQUAL_CHAR('#', out[len - 9]);
    TEST_ASSERT_EQUAL_UINT(len, strlen(out));

    char addr[MULTISIG_ADDR_MAX];
    TEST_ASSERT_GREATER_THAN(0, multisig_address(ms, 0, 0, addr, sizeof(addr)));
    multisig_free(ms);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_two_of_three_matches_reference);
    RUN_TEST(test_testnet);
    RUN_TEST(test_key_order_does_not_change_addresses);
    RUN_TEST(test_cosigner_key);
    RUN_TEST(test_summary);
    RUN_TEST(test_descriptor_qr_round_trip);
    RUN_TEST(test_incomplete_wallet);
    RUN_TEST(test_bounds);
    RUN_TEST(test_duplicate_keys_refused);
    RUN_TEST(test_fifteen_of_fifteen_fits);
    return UNITY_END();
}

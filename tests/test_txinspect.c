/**
 * @file tests/test_txinspect.c
 * @brief Unity tests for main/crypto/txinspect.c
 */

#include "crypto/txinspect.h"
#include "crypto/ur_psbt.h"
#include "unity.h"
#include "util/utils.h"
#include "vectors.h"

#include <stdint.h>
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

static void test_parse_raw_tx(void) {
    struct wally_tx* tx  = build_tx(2, 2);
    char*            hex = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_to_hex(tx, 0, &hex));
    wally_tx_free(tx);

    tx_inspect_t* t = tx_inspect_parse((const uint8_t*)hex, strlen(hex));
    TEST_ASSERT_NOT_NULL(t);
    TEST_ASSERT_EQUAL(TX_INSPECT_KIND_TX, tx_inspect_kind(t));
    TEST_ASSERT_EQUAL_STRING("Transaction", tx_inspect_kind_name(t));
    TEST_ASSERT_EQUAL_UINT(2, (unsigned)tx_inspect_num_inputs(t));
    TEST_ASSERT_EQUAL_UINT(2, (unsigned)tx_inspect_num_outputs(t));
    TEST_ASSERT_EQUAL_UINT64(201000, tx_inspect_total_out(t));
    /* Raw transactions carry no previous-output values. */
    TEST_ASSERT_EQUAL_UINT64(0, tx_inspect_total_in(t));

    char body[TXINSPECT_RENDER_MAX];
    tx_inspect_render(t, body, sizeof(body));
    TEST_ASSERT_NOT_NULL(strstr(body, "Inputs: 2"));
    TEST_ASSERT_NOT_NULL(strstr(body, "Outputs: 2"));
    TEST_ASSERT_NOT_NULL(strstr(body, "txid (unsigned):"));
    TEST_ASSERT_NOT_NULL(strstr(body, "network: mainnet"));

    char warn[TXINSPECT_WARNING_MAX];
    TEST_ASSERT_FALSE(tx_inspect_nonce_warning(t, warn, sizeof(warn)));

    tx_inspect_free(t);
    wally_free_string(hex);
}

static void test_parse_invalid(void) {
    TEST_ASSERT_NULL(tx_inspect_parse(NULL, 0));
    TEST_ASSERT_NULL(tx_inspect_parse((const uint8_t*)"", 0));
    TEST_ASSERT_NULL(tx_inspect_parse((const uint8_t*)"not a transaction", 18));
    TEST_ASSERT_NULL(tx_inspect_parse((const uint8_t*)"zz", 2));
}

static void test_parse_psbt(void) {
    struct wally_tx*   tx   = build_tx(1, 2);
    struct wally_psbt* psbt = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_from_tx(tx, WALLY_PSBT_VERSION_0, 0, &psbt));
    wally_tx_free(tx);

    /* Attach a witness UTXO to input 0 so its value is known. */
    uint8_t prog[20];
    uint8_t script[22];
    size_t  slen = 0;
    for (size_t j = 0; j < sizeof(prog); j++) prog[j] = (uint8_t)(0x10 + j);
    TEST_ASSERT_EQUAL(WALLY_OK, wally_witness_program_from_bytes(prog, sizeof(prog), 0, script,
                                                                 sizeof(script), &slen));

    struct wally_tx_output* wout = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_output_init_alloc(300000, script, slen, &wout));
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_input_set_witness_utxo(&psbt->inputs[0], wout));

    char* b64 = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_to_base64(psbt, 0, &b64));
    wally_psbt_free(psbt);
    wally_tx_output_free(wout);

    tx_inspect_t* t = tx_inspect_parse((const uint8_t*)b64, strlen(b64));
    TEST_ASSERT_NOT_NULL(t);
    TEST_ASSERT_EQUAL(TX_INSPECT_KIND_PSBT, tx_inspect_kind(t));
    TEST_ASSERT_EQUAL_STRING("PSBT", tx_inspect_kind_name(t));
    TEST_ASSERT_EQUAL_UINT(1, (unsigned)tx_inspect_num_inputs(t));
    TEST_ASSERT_EQUAL_UINT(2, (unsigned)tx_inspect_num_outputs(t));
    TEST_ASSERT_EQUAL_UINT64(300000, tx_inspect_total_in(t));
    TEST_ASSERT_EQUAL_UINT64(201000, tx_inspect_total_out(t));

    char body[TXINSPECT_RENDER_MAX];
    tx_inspect_render(t, body, sizeof(body));
    TEST_ASSERT_NOT_NULL(strstr(body, "PSBT"));
    TEST_ASSERT_NOT_NULL(strstr(body, "0.00300000"));
    TEST_ASSERT_NOT_NULL(strstr(body, "Fee:"));
    TEST_ASSERT_NOT_NULL(strstr(body, "0.00099000"));

    tx_inspect_free(t);
    wally_free_string(b64);
}

static void test_nonce_reuse_detected(void) {
    struct wally_tx*   tx   = build_tx(2, 1);
    struct wally_psbt* psbt = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_from_tx(tx, WALLY_PSBT_VERSION_0, 0, &psbt));
    wally_tx_free(tx);

    uint8_t pubkey[33];
    pubkey[0] = 0x02;
    for (size_t j = 1; j < sizeof(pubkey); j++) pubkey[j] = 0x22;

    /* DER signature with r=1, s=2 + SIGHASH_ALL byte.  The same (pubkey, r)
     * pair on two inputs is a nonce-reuse red flag. */
    uint8_t sig[] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x01};

    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_input_add_signature(&psbt->inputs[0], pubkey,
                                                               sizeof(pubkey), sig, sizeof(sig)));
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_input_add_signature(&psbt->inputs[1], pubkey,
                                                               sizeof(pubkey), sig, sizeof(sig)));

    char* b64 = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_to_base64(psbt, 0, &b64));
    wally_psbt_free(psbt);

    tx_inspect_t* t = tx_inspect_parse((const uint8_t*)b64, strlen(b64));
    TEST_ASSERT_NOT_NULL(t);

    char warn[TXINSPECT_WARNING_MAX];
    TEST_ASSERT_TRUE(tx_inspect_nonce_warning(t, warn, sizeof(warn)));
    TEST_ASSERT_NOT_NULL(strstr(warn, "RFC 6979"));

    tx_inspect_free(t);
    wally_free_string(b64);
}

static void test_no_nonce_reuse_with_distinct_r(void) {
    struct wally_tx*   tx   = build_tx(2, 1);
    struct wally_psbt* psbt = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_from_tx(tx, WALLY_PSBT_VERSION_0, 0, &psbt));
    wally_tx_free(tx);

    uint8_t pubkey[33];
    pubkey[0] = 0x02;
    for (size_t j = 1; j < sizeof(pubkey); j++) pubkey[j] = 0x33;

    uint8_t sig0[] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x01}; /* r=1 */
    uint8_t sig1[] = {0x30, 0x06, 0x02, 0x01, 0x03, 0x02, 0x01, 0x02, 0x01}; /* r=3 */

    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_input_add_signature(&psbt->inputs[0], pubkey,
                                                               sizeof(pubkey), sig0, sizeof(sig0)));
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_input_add_signature(&psbt->inputs[1], pubkey,
                                                               sizeof(pubkey), sig1, sizeof(sig1)));

    char* b64 = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_to_base64(psbt, 0, &b64));
    wally_psbt_free(psbt);

    tx_inspect_t* t = tx_inspect_parse((const uint8_t*)b64, strlen(b64));
    TEST_ASSERT_NOT_NULL(t);

    char warn[TXINSPECT_WARNING_MAX];
    TEST_ASSERT_FALSE(tx_inspect_nonce_warning(t, warn, sizeof(warn)));

    tx_inspect_free(t);
    wally_free_string(b64);
}

static void test_parse_ur_psbt(void) {
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

    char* ur = NULL;
    TEST_ASSERT_TRUE(ur_psbt_encode(bytes, written, &ur));

    tx_inspect_t* t = tx_inspect_parse((const uint8_t*)ur, strlen(ur));
    TEST_ASSERT_NOT_NULL(t);
    TEST_ASSERT_EQUAL(TX_INSPECT_KIND_PSBT, tx_inspect_kind(t));
    TEST_ASSERT_EQUAL_UINT(1, (unsigned)tx_inspect_num_inputs(t));
    TEST_ASSERT_EQUAL_UINT(2, (unsigned)tx_inspect_num_outputs(t));
    tx_inspect_free(t);

    free(ur);
    free(bytes);
}

static void test_raw_tx_nonce_reuse(void) {
    struct wally_tx* tx = build_tx(2, 1);

    /* DER signature with r=1, s=2 + SIGHASH_ALL; the same sig on two inputs
     * reuses the nonce r and must be flagged.  Long-form DER length (0x81). */
    uint8_t sig[] = {0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x01};
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_set_input_script(tx, 0, sig, sizeof(sig)));
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_set_input_script(tx, 1, sig, sizeof(sig)));

    char* hex = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_to_hex(tx, 0, &hex));
    wally_tx_free(tx);

    tx_inspect_t* t = tx_inspect_parse((const uint8_t*)hex, strlen(hex));
    TEST_ASSERT_NOT_NULL(t);

    char warn[TXINSPECT_WARNING_MAX];
    TEST_ASSERT_TRUE(tx_inspect_nonce_warning(t, warn, sizeof(warn)));

    tx_inspect_free(t);
    wally_free_string(hex);
}

static void test_render_script_types(void) {
    struct wally_tx* tx = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_init_alloc(2, 0, 1, 3, &tx));

    uint8_t txhash[32] = {0};
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_add_raw_input(tx, txhash, sizeof(txhash), 0, 0xfffffffd,
                                                       NULL, 0, NULL, 0));

    /* P2WPKH output. */
    uint8_t h160[20];
    uint8_t wpkh[22];
    size_t  slen = 0;
    for (size_t j = 0; j < sizeof(h160); j++) h160[j] = 0x11;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_witness_program_from_bytes(h160, sizeof(h160), 0, wpkh,
                                                                 sizeof(wpkh), &slen));
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_add_raw_output(tx, 1000, wpkh, slen, 0));

    /* P2WSH output (segwit v0, 32-byte program). */
    uint8_t x[32];
    uint8_t wsh[34];
    for (size_t j = 0; j < sizeof(x); j++) x[j] = 0x22;
    TEST_ASSERT_EQUAL(WALLY_OK,
                      wally_witness_program_from_bytes(x, sizeof(x), 0, wsh, sizeof(wsh), &slen));
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_add_raw_output(tx, 2000, wsh, slen, 0));

    /* OP_RETURN output (unknown script type -> hex fallback). */
    uint8_t opret[] = {0x6a, 0x04, 0xde, 0xad, 0xbe, 0xef};
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_add_raw_output(tx, 0, opret, sizeof(opret), 0));

    char* hex = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_to_hex(tx, 0, &hex));
    wally_tx_free(tx);

    tx_inspect_t* t = tx_inspect_parse((const uint8_t*)hex, strlen(hex));
    TEST_ASSERT_NOT_NULL(t);

    char body[TXINSPECT_RENDER_MAX];
    tx_inspect_render(t, body, sizeof(body));
    TEST_ASSERT_NOT_NULL(strstr(body, "bc1")); /* bech32 / bech32m addresses */

    tx_inspect_free(t);
    wally_free_string(hex);
}

static void test_parse_base64_invalid(void) {
    /* "cHNidP" prefix but invalid base64 and invalid hex -> rejected. */
    TEST_ASSERT_NULL(tx_inspect_parse((const uint8_t*)"cHNidP!!!", 9));
}

static void test_raw_tx_witness_nonce_reuse(void) {
    struct wally_tx* tx = build_tx(2, 1);

    uint8_t sig[] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x01};
    for (size_t i = 0; i < 2; i++) {
        struct wally_tx_witness_stack* ws = NULL;
        TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_witness_stack_init_alloc(1, &ws));
        TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_witness_stack_add(ws, sig, sizeof(sig)));
        TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_set_input_witness(tx, i, ws));
        TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_witness_stack_free(ws));
    }

    char* hex = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_to_hex(tx, WALLY_TX_FLAG_USE_WITNESS, &hex));
    wally_tx_free(tx);

    tx_inspect_t* t = tx_inspect_parse((const uint8_t*)hex, strlen(hex));
    TEST_ASSERT_NOT_NULL(t);
    char warn[TXINSPECT_WARNING_MAX];
    TEST_ASSERT_TRUE(tx_inspect_nonce_warning(t, warn, sizeof(warn)));

    tx_inspect_free(t);
    wally_free_string(hex);
}

static void test_parse_raw_psbt_bytes(void) {
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

    tx_inspect_t* t = tx_inspect_parse(bytes, written);
    TEST_ASSERT_NOT_NULL(t);
    TEST_ASSERT_EQUAL(TX_INSPECT_KIND_PSBT, tx_inspect_kind(t));
    tx_inspect_free(t);
    free(bytes);
}

static void test_parse_psbt_hex(void) {
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

    char* hex = (char*)malloc(written * 2 + 1);
    TEST_ASSERT_NOT_NULL(hex);
    bytes_to_hex(bytes, written, hex, written * 2 + 1);

    tx_inspect_t* t = tx_inspect_parse((const uint8_t*)hex, strlen(hex));
    TEST_ASSERT_NOT_NULL(t);
    TEST_ASSERT_EQUAL(TX_INSPECT_KIND_PSBT, tx_inspect_kind(t));
    tx_inspect_free(t);
    free(hex);
    free(bytes);
}

static void test_psbt_utxo_input(void) {
    struct wally_tx*   prev = build_tx(1, 1);
    struct wally_tx*   tx   = build_tx(1, 1);
    struct wally_psbt* psbt = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_from_tx(tx, WALLY_PSBT_VERSION_0, 0, &psbt));
    wally_tx_free(tx);

    /* Non-witness UTXO (full previous transaction). */
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_input_set_utxo(&psbt->inputs[0], prev));

    char* b64 = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_to_base64(psbt, 0, &b64));
    wally_psbt_free(psbt);
    wally_tx_free(prev);

    tx_inspect_t* t = tx_inspect_parse((const uint8_t*)b64, strlen(b64));
    TEST_ASSERT_NOT_NULL(t);
    TEST_ASSERT_EQUAL(TX_INSPECT_KIND_PSBT, tx_inspect_kind(t));
    TEST_ASSERT_EQUAL_UINT64(100000, tx_inspect_total_in(t));

    tx_inspect_free(t);
    wally_free_string(b64);
}

static void test_render_empty_script(void) {
    struct wally_tx* tx       = build_tx(1, 1);
    tx->outputs[0].script_len = 0; /* empty output script */

    char* hex = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_to_hex(tx, 0, &hex));
    wally_tx_free(tx);

    tx_inspect_t* t = tx_inspect_parse((const uint8_t*)hex, strlen(hex));
    TEST_ASSERT_NOT_NULL(t);
    char body[TXINSPECT_RENDER_MAX];
    tx_inspect_render(t, body, sizeof(body));
    TEST_ASSERT_NOT_NULL(strstr(body, "<empty script>"));

    tx_inspect_free(t);
    wally_free_string(hex);
}

static void test_render_long_script(void) {
    struct wally_tx* tx = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_init_alloc(2, 0, 1, 1, &tx));

    uint8_t txhash[32] = {0};
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_add_raw_input(tx, txhash, sizeof(txhash), 0, 0xfffffffd,
                                                       NULL, 0, NULL, 0));

    uint8_t script[100];
    memset(script, 0x6a, sizeof(script)); /* long OP_RETURN-ish script */
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_add_raw_output(tx, 0, script, sizeof(script), 0));

    char* hex = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_to_hex(tx, 0, &hex));
    wally_tx_free(tx);

    tx_inspect_t* t = tx_inspect_parse((const uint8_t*)hex, strlen(hex));
    TEST_ASSERT_NOT_NULL(t);
    char body[TXINSPECT_RENDER_MAX];
    tx_inspect_render(t, body, sizeof(body));
    TEST_ASSERT_NOT_NULL(strstr(body, "<script 100 bytes>"));

    tx_inspect_free(t);
    wally_free_string(hex);
}

static tx_output_kind_t mark_alt_outputs(void* ctx, size_t out_index, const char* address) {
    (void)ctx;
    (void)address;
    if (out_index == 0) return TX_OUTPUT_CHANGE;
    if (out_index == 1) return TX_OUTPUT_RECEIVE;
    return TX_OUTPUT_NONE;
}

static void test_render_change_marks(void) {
    struct wally_tx* tx = build_tx(1, 3);

    char* hex = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_to_hex(tx, 0, &hex));
    wally_tx_free(tx);

    tx_inspect_t* t = tx_inspect_parse((const uint8_t*)hex, strlen(hex));
    TEST_ASSERT_NOT_NULL(t);

    char body[TXINSPECT_RENDER_MAX];
    tx_inspect_render_ex(t, body, sizeof(body), mark_alt_outputs, NULL);
    TEST_ASSERT_NOT_NULL(strstr(body, "<- change"));
    TEST_ASSERT_NOT_NULL(strstr(body, "<- receive"));

    /* Without a classifier, no ownership annotation is rendered. */
    tx_inspect_render(t, body, sizeof(body));
    TEST_ASSERT_NULL(strstr(body, "<- change"));
    TEST_ASSERT_NULL(strstr(body, "<- receive"));

    tx_inspect_free(t);
    wally_free_string(hex);
}

/* -- Network, signedness and the extra summary fields ------------------ */

/* Funding transaction with two P2PKH outputs of the given values. */
static struct wally_tx* build_funding_tx(uint64_t out0, uint64_t out1) {
    struct wally_tx* tx = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_init_alloc(2, 0, 1, 2, &tx));

    uint8_t txhash[32] = {0};
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_add_raw_input(tx, txhash, sizeof(txhash), 0, 0xffffffff,
                                                       NULL, 0, NULL, 0));

    uint8_t h160[20];
    uint8_t spk[25];
    size_t  spk_len = 0;
    memset(h160, 0x11, sizeof(h160));
    TEST_ASSERT_EQUAL(WALLY_OK, wally_scriptpubkey_p2pkh_from_bytes(h160, sizeof(h160), 0, spk,
                                                                    sizeof(spk), &spk_len));
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_add_raw_output(tx, out0, spk, spk_len, 0));
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_add_raw_output(tx, out1, spk, spk_len, 0));
    return tx;
}

/* A v0 PSBT input does not record which output of its non-witness UTXO is
 * spent: that comes from the vout of the unsigned transaction's input.  Using
 * output 0 regardless reported the wrong input value and a wrong fee. */
static void test_psbt_nonwitness_utxo_nonzero_vout(void) {
    struct wally_tx* fund = build_funding_tx(500000000, 90000000);

    struct wally_tx* tx = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_init_alloc(2, 0, 1, 1, &tx));
    uint8_t prev_txid[32];
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_get_txid(fund, prev_txid, sizeof(prev_txid)));
    /* Spend output 1: the smallest of the two. */
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_add_raw_input(tx, prev_txid, sizeof(prev_txid), 1,
                                                       0xfffffffd, NULL, 0, NULL, 0));

    uint8_t h160[20];
    uint8_t spk[25];
    size_t  spk_len = 0;
    memset(h160, 0x33, sizeof(h160));
    TEST_ASSERT_EQUAL(WALLY_OK, wally_scriptpubkey_p2pkh_from_bytes(h160, sizeof(h160), 0, spk,
                                                                    sizeof(spk), &spk_len));
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_add_raw_output(tx, 80000000, spk, spk_len, 0));

    struct wally_psbt* psbt = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_from_tx(tx, WALLY_PSBT_VERSION_0, 0, &psbt));
    wally_tx_free(tx);
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_input_set_utxo(&psbt->inputs[0], fund));
    wally_tx_free(fund); /* set_utxo clones the transaction */

    char* b64 = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_to_base64(psbt, 0, &b64));
    wally_psbt_free(psbt);

    tx_inspect_t* t = tx_inspect_parse((const uint8_t*)b64, strlen(b64));
    TEST_ASSERT_NOT_NULL(t);
    TEST_ASSERT_EQUAL_UINT64(90000000, tx_inspect_total_in(t));

    char body[TXINSPECT_RENDER_MAX];
    tx_inspect_render(t, body, sizeof(body));
    TEST_ASSERT_NOT_NULL(strstr(body, "0.90000000 BTC"));
    TEST_ASSERT_NOT_NULL(strstr(body, "Fee: 0.10000000 BTC"));

    tx_inspect_free(t);
    wally_free_string(b64);
}

static void test_render_network_addresses(void) {
    static const struct {
        tx_inspect_network_t net;
        const char*          name;
        const char*          prefix;
    } cases[] = {
        {TX_INSPECT_NETWORK_MAINNET, "mainnet", "bc1"},
        {TX_INSPECT_NETWORK_TESTNET, "testnet", "tb1"},
        {TX_INSPECT_NETWORK_SIGNET, "signet", "tb1"},
        {TX_INSPECT_NETWORK_REGTEST, "regtest", "bcrt1"},
    };

    /* A single P2WPKH output makes the Bech32 HRP visible. */
    struct wally_tx* tx = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_init_alloc(2, 0, 1, 1, &tx));
    uint8_t txhash[32] = {0};
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_add_raw_input(tx, txhash, sizeof(txhash), 0, 0xfffffffd,
                                                       NULL, 0, NULL, 0));
    uint8_t prog[20];
    uint8_t spk[22];
    size_t  spk_len = 0;
    memset(prog, 0x5a, sizeof(prog));
    TEST_ASSERT_EQUAL(WALLY_OK, wally_witness_program_from_bytes(prog, sizeof(prog), 0, spk,
                                                                 sizeof(spk), &spk_len));
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_add_raw_output(tx, 1234, spk, spk_len, 0));

    char* hex = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_to_hex(tx, 0, &hex));
    wally_tx_free(tx);

    tx_inspect_t* t = tx_inspect_parse((const uint8_t*)hex, strlen(hex));
    TEST_ASSERT_NOT_NULL(t);
    TEST_ASSERT_EQUAL(TX_INSPECT_NETWORK_MAINNET, tx_inspect_network(t)); /* default */

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        char body[TXINSPECT_RENDER_MAX];
        char line[64];

        tx_inspect_set_network(t, cases[i].net);
        TEST_ASSERT_EQUAL(cases[i].net, tx_inspect_network(t));
        TEST_ASSERT_EQUAL_STRING(cases[i].name, tx_inspect_network_name(cases[i].net));

        tx_inspect_render(t, body, sizeof(body));
        int res = snprintf(line, sizeof(line), "network: %s", cases[i].name);
        TEST_ASSERT_TRUE(res > 0 && (size_t)res < sizeof(line));
        TEST_ASSERT_NOT_NULL(strstr(body, line));
        TEST_ASSERT_NOT_NULL(strstr(body, cases[i].prefix));
    }

    tx_inspect_free(t);
    wally_free_string(hex);
}

static void test_txid_signed_status(void) {
    char body[TXINSPECT_RENDER_MAX];

    /* A raw transaction with empty scriptSigs is not final. */
    struct wally_tx* tx  = build_tx(1, 1);
    char*            hex = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_to_hex(tx, 0, &hex));
    wally_tx_free(tx);

    tx_inspect_t* t = tx_inspect_parse((const uint8_t*)hex, strlen(hex));
    TEST_ASSERT_NOT_NULL(t);
    TEST_ASSERT_FALSE(tx_inspect_is_signed(t));
    tx_inspect_render(t, body, sizeof(body));
    TEST_ASSERT_NOT_NULL(strstr(body, "txid (unsigned):"));
    tx_inspect_free(t);
    wally_free_string(hex);

    /* A filled-in scriptSig makes the txid final. */
    tx               = build_tx(1, 1);
    uint8_t script[] = {0x51}; /* OP_TRUE */
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_set_input_script(tx, 0, script, sizeof(script)));
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_to_hex(tx, 0, &hex));
    wally_tx_free(tx);

    t = tx_inspect_parse((const uint8_t*)hex, strlen(hex));
    TEST_ASSERT_NOT_NULL(t);
    TEST_ASSERT_TRUE(tx_inspect_is_signed(t));
    tx_inspect_render(t, body, sizeof(body));
    TEST_ASSERT_NOT_NULL(strstr(body, "txid (signed):"));
    tx_inspect_free(t);
    wally_free_string(hex);

    /* A PSBT with a partial signature is still unsigned: a legacy input's
     * scriptSig has not been built yet, so the txid will change. */
    uint8_t pubkey[33];
    uint8_t sig[] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x01};
    pubkey[0]     = 0x02;
    memset(pubkey + 1, 0x22, sizeof(pubkey) - 1);

    tx                      = build_tx(1, 1);
    struct wally_psbt* psbt = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_from_tx(tx, WALLY_PSBT_VERSION_0, 0, &psbt));
    wally_tx_free(tx);
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_input_add_signature(&psbt->inputs[0], pubkey,
                                                               sizeof(pubkey), sig, sizeof(sig)));

    char* b64 = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_to_base64(psbt, 0, &b64));
    wally_psbt_free(psbt);

    t = tx_inspect_parse((const uint8_t*)b64, strlen(b64));
    TEST_ASSERT_NOT_NULL(t);
    TEST_ASSERT_FALSE(tx_inspect_is_signed(t));
    tx_inspect_render(t, body, sizeof(body));
    TEST_ASSERT_NOT_NULL(strstr(body, "txid (unsigned):"));
    tx_inspect_free(t);
    wally_free_string(b64);

    /* Finalising every input makes the txid final. */
    uint8_t final_script[] = {0x51};
    tx                     = build_tx(1, 1);
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_from_tx(tx, WALLY_PSBT_VERSION_0, 0, &psbt));
    wally_tx_free(tx);
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_input_set_final_scriptsig(&psbt->inputs[0], final_script,
                                                                     sizeof(final_script)));
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_to_base64(psbt, 0, &b64));
    wally_psbt_free(psbt);

    t = tx_inspect_parse((const uint8_t*)b64, strlen(b64));
    TEST_ASSERT_NOT_NULL(t);
    TEST_ASSERT_TRUE(tx_inspect_is_signed(t));
    tx_inspect_render(t, body, sizeof(body));
    TEST_ASSERT_NOT_NULL(strstr(body, "txid (signed):"));
    tx_inspect_free(t);
    wally_free_string(b64);
}

static void test_locktime_rbf_and_sighash(void) {
    char body[TXINSPECT_RENDER_MAX];

    /* locktime set, sequence 0xfffffffe (not a BIP-125 opt-in), SIGHASH_ALL. */
    struct wally_tx* tx = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_init_alloc(2, 1257139, 1, 1, &tx));
    uint8_t txhash[32] = {0};
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_add_raw_input(tx, txhash, sizeof(txhash), 0, 0xfffffffe,
                                                       NULL, 0, NULL, 0));

    uint8_t h160[20];
    uint8_t spk[25];
    size_t  spk_len = 0;
    memset(h160, 0x44, sizeof(h160));
    TEST_ASSERT_EQUAL(WALLY_OK, wally_scriptpubkey_p2pkh_from_bytes(h160, sizeof(h160), 0, spk,
                                                                    sizeof(spk), &spk_len));
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_add_raw_output(tx, 1000, spk, spk_len, 0));

    uint8_t sig[] = {0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x01}; /* + SIGHASH_ALL */
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_set_input_script(tx, 0, sig, sizeof(sig)));

    char* hex = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_to_hex(tx, 0, &hex));
    wally_tx_free(tx);

    tx_inspect_t* t = tx_inspect_parse((const uint8_t*)hex, strlen(hex));
    TEST_ASSERT_NOT_NULL(t);
    TEST_ASSERT_EQUAL_UINT32(1257139, tx_inspect_locktime(t));
    TEST_ASSERT_FALSE(tx_inspect_rbf(t));

    uint32_t sh = 0;
    TEST_ASSERT_EQUAL_UINT(1, (unsigned)tx_inspect_sighash(t, &sh, 1));
    TEST_ASSERT_EQUAL_UINT32(0x01, sh);

    tx_inspect_render(t, body, sizeof(body));
    TEST_ASSERT_NOT_NULL(strstr(body, "locktime: 1257139"));
    TEST_ASSERT_NOT_NULL(strstr(body, "RBF: no"));
    TEST_ASSERT_NOT_NULL(strstr(body, "sighash: ALL (0x01)"));
    tx_inspect_free(t);
    wally_free_string(hex);

    /* A lower sequence does opt in to replacement; with no signatures and no
     * declared sighash there is nothing to report for it. */
    tx = build_tx(1, 1); /* sequence 0xfffffffd */
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_to_hex(tx, 0, &hex));
    wally_tx_free(tx);

    t = tx_inspect_parse((const uint8_t*)hex, strlen(hex));
    TEST_ASSERT_NOT_NULL(t);
    TEST_ASSERT_TRUE(tx_inspect_rbf(t));
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)tx_inspect_sighash(t, NULL, 0));

    tx_inspect_render(t, body, sizeof(body));
    TEST_ASSERT_NOT_NULL(strstr(body, "RBF: yes"));
    TEST_ASSERT_NULL(strstr(body, "sighash:"));
    tx_inspect_free(t);
    wally_free_string(hex);

    /* A PSBT may state the sighash type explicitly. */
    tx                      = build_tx(1, 1);
    struct wally_psbt* psbt = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_from_tx(tx, WALLY_PSBT_VERSION_0, 0, &psbt));
    wally_tx_free(tx);
    TEST_ASSERT_EQUAL(WALLY_OK,
                      wally_psbt_input_set_sighash(&psbt->inputs[0], WALLY_SIGHASH_SINGLE));

    char* b64 = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_psbt_to_base64(psbt, 0, &b64));
    wally_psbt_free(psbt);

    t = tx_inspect_parse((const uint8_t*)b64, strlen(b64));
    TEST_ASSERT_NOT_NULL(t);
    tx_inspect_render(t, body, sizeof(body));
    TEST_ASSERT_NOT_NULL(strstr(body, "sighash: SINGLE (0x03)"));
    tx_inspect_free(t);
    wally_free_string(b64);
}

static void test_render_truncated(void) {
    struct wally_tx* tx  = build_tx(1, 4);
    char*            hex = NULL;
    TEST_ASSERT_EQUAL(WALLY_OK, wally_tx_to_hex(tx, 0, &hex));
    wally_tx_free(tx);

    tx_inspect_t* t = tx_inspect_parse((const uint8_t*)hex, strlen(hex));
    TEST_ASSERT_NOT_NULL(t);

    /* A summary that does not fit is cut at a line boundary and says so: it
     * must never silently drop outputs. */
    char small[96];
    tx_inspect_render(t, small, sizeof(small));
    TEST_ASSERT_NOT_NULL(strstr(small, "summary truncated"));
    TEST_ASSERT_TRUE(strlen(small) < sizeof(small));
    TEST_ASSERT_EQUAL('\n', small[strlen(small) - 1]);

    /* It fits in the production buffer, and then nothing is marked. */
    char body[TXINSPECT_RENDER_MAX];
    tx_inspect_render(t, body, sizeof(body));
    TEST_ASSERT_NULL(strstr(body, "summary truncated"));
    TEST_ASSERT_NOT_NULL(strstr(body, "Outputs: 4"));

    tx_inspect_free(t);
    wally_free_string(hex);
}

/* -- Generated PSBT vectors (tests/vectors/psbt/) ---------------------- */
/* The UR tests only round-trip these vectors as bytes, so nothing else pins
 * the summary a user is actually shown. */
static void test_psbt_vector_summaries(void) {
    char body[TXINSPECT_RENDER_MAX];

    /* BCR-2020-006 example (2-in/2-out).  It carries no UTXO data at all. */
    char* hex = (char*)vectors_read_file("psbt/raw/bcr-2020-006-example-psbt-2-in-2-out.hex", NULL);
    TEST_ASSERT_NOT_NULL(hex);
    vectors_trim(hex);

    tx_inspect_t* t = tx_inspect_parse((const uint8_t*)hex, strlen(hex));
    TEST_ASSERT_NOT_NULL(t);
    TEST_ASSERT_EQUAL(TX_INSPECT_KIND_PSBT, tx_inspect_kind(t));
    TEST_ASSERT_EQUAL_UINT(2, (unsigned)tx_inspect_num_inputs(t));
    TEST_ASSERT_EQUAL_UINT(2, (unsigned)tx_inspect_num_outputs(t));
    TEST_ASSERT_EQUAL_UINT64(249990000, tx_inspect_total_out(t));
    TEST_ASSERT_EQUAL_UINT64(0, tx_inspect_total_in(t));
    TEST_ASSERT_EQUAL_UINT32(0, tx_inspect_locktime(t));
    TEST_ASSERT_FALSE(tx_inspect_rbf(t));

    tx_inspect_render(t, body, sizeof(body));
    TEST_ASSERT_NOT_NULL(strstr(body, "txid (unsigned): 82efd652"));
    TEST_ASSERT_NOT_NULL(
        strstr(body, "1.49990000 BTC  bc1qmpwzkuwsqc9snjvgdt4czhjsnywa5yjdgwyw6k"));
    TEST_ASSERT_NOT_NULL(
        strstr(body, "1.00000000 BTC  bc1qqzh2ngh97ru8dfvgma25d6r595wcwqy0skmt5z"));
    /* Without UTXO data the fee is unknown, and that has to be visible. */
    TEST_ASSERT_NOT_NULL(strstr(body, "Fee: unknown"));
    TEST_ASSERT_NULL(strstr(body, "summary truncated"));

    tx_inspect_set_network(t, TX_INSPECT_NETWORK_TESTNET);
    tx_inspect_render(t, body, sizeof(body));
    TEST_ASSERT_NOT_NULL(strstr(body, "network: testnet"));
    TEST_ASSERT_NOT_NULL(strstr(body, "tb1qmpwzkuwsqc9snjvgdt4czhjsnywa5yjd"));
    TEST_ASSERT_NULL(strstr(body, "bc1qmpwzkuwsqc9snjvgdt4czhjsnywa5yjd"));

    tx_inspect_free(t);
    free(hex);

    /* keytool-cli testnet vector (1-in/2-out) with a non-witness UTXO. */
    hex = (char*)vectors_read_file("psbt/raw/keytool-cli-testpsbthex-testnet-1-in-2-out.hex", NULL);
    TEST_ASSERT_NOT_NULL(hex);
    vectors_trim(hex);

    t = tx_inspect_parse((const uint8_t*)hex, strlen(hex));
    TEST_ASSERT_NOT_NULL(t);
    TEST_ASSERT_EQUAL_UINT(1, (unsigned)tx_inspect_num_inputs(t));
    TEST_ASSERT_EQUAL_UINT64(200000000, tx_inspect_total_in(t));
    TEST_ASSERT_EQUAL_UINT64(199999699, tx_inspect_total_out(t));
    TEST_ASSERT_EQUAL_UINT32(1257139, tx_inspect_locktime(t));
    /* 0xfffffffe enables locktime but is not a BIP-125 opt-in. */
    TEST_ASSERT_FALSE(tx_inspect_rbf(t));
    TEST_ASSERT_FALSE(tx_inspect_is_signed(t));

    tx_inspect_render(t, body, sizeof(body));
    TEST_ASSERT_NOT_NULL(strstr(body, "txid (unsigned): af2cac1e"));
    TEST_ASSERT_NOT_NULL(strstr(body, "locktime: 1257139"));
    TEST_ASSERT_NOT_NULL(strstr(body, "RBF: no"));
    TEST_ASSERT_NOT_NULL(strstr(body, "Fee: 0.00000301 BTC"));
    TEST_ASSERT_NOT_NULL(strstr(body, "1L2tGENeoh4mSoiUZrSbs1J3jazSdJH9QS"));

    /* The vector is a testnet transaction whose scripts happen to carry
     * mainnet version bytes.  Rendering follows the selected network, so the
     * same script yields a different address on testnet. */
    tx_inspect_set_network(t, TX_INSPECT_NETWORK_TESTNET);
    tx_inspect_render(t, body, sizeof(body));
    TEST_ASSERT_NOT_NULL(strstr(body, "network: testnet"));
    TEST_ASSERT_NULL(strstr(body, "1L2tGENeoh4mSoiUZrSbs1J3jazSdJH9QS"));
    TEST_ASSERT_NOT_NULL(strstr(body, "mzYqZHTdciW2DvC6HRQygvWNbab9U6KdQY"));
    TEST_ASSERT_NOT_NULL(strstr(body, "2Mx6uYKYGW5J6sV59e5NsdtCTsJYRxednbx"));

    tx_inspect_free(t);
    free(hex);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_parse_raw_tx);
    RUN_TEST(test_parse_invalid);
    RUN_TEST(test_parse_psbt);
    RUN_TEST(test_parse_ur_psbt);
    RUN_TEST(test_nonce_reuse_detected);
    RUN_TEST(test_no_nonce_reuse_with_distinct_r);
    RUN_TEST(test_raw_tx_nonce_reuse);
    RUN_TEST(test_raw_tx_witness_nonce_reuse);
    RUN_TEST(test_render_script_types);
    RUN_TEST(test_parse_base64_invalid);
    RUN_TEST(test_parse_raw_psbt_bytes);
    RUN_TEST(test_parse_psbt_hex);
    RUN_TEST(test_psbt_utxo_input);
    RUN_TEST(test_render_empty_script);
    RUN_TEST(test_render_long_script);
    RUN_TEST(test_render_change_marks);
    RUN_TEST(test_psbt_nonwitness_utxo_nonzero_vout);
    RUN_TEST(test_render_network_addresses);
    RUN_TEST(test_txid_signed_status);
    RUN_TEST(test_locktime_rbf_and_sighash);
    RUN_TEST(test_render_truncated);
    RUN_TEST(test_psbt_vector_summaries);
    return UNITY_END();
}

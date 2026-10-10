/**
 * @file tests/test_touch.c
 * @brief Unity tests for main/crypto/touch.c
 */

#include "crypto/touch.h"
#include "unity.h"

#include <stdint.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static void test_begin_defaults(void) {
    touch_entropy_t* t = touch_entropy_begin(12, 480, 320);
    TEST_ASSERT_NOT_NULL(t);
    TEST_ASSERT_EQUAL_UINT(256, touch_entropy_target_bits(t)); // twice the seed
    TEST_ASSERT_EQUAL_UINT(0, touch_entropy_bits(t));
    TEST_ASSERT_EQUAL_UINT(0, touch_entropy_taps(t));
    TEST_ASSERT_FALSE(touch_entropy_ready(t));
    touch_entropy_discard(t);
}

static void test_tap_writes_its_tile_as_bits(void) {
    // 8x8 tiles, and a tap writes its tile's index in 6 bits, MSB first.
    touch_entropy_t* t = touch_entropy_begin(12, 480, 320);

    touch_entropy_add_tap(t, 0, 0);     // tile 0  -> 000000
    touch_entropy_add_tap(t, 479, 319); // tile 63 -> 111111
    touch_entropy_add_tap(t, 300, 40);  // col 5, row 1 -> tile 13 -> 001101

    TEST_ASSERT_EQUAL_UINT(13, touch_entropy_last_tile(t));
    TEST_ASSERT_EQUAL_UINT(18, touch_entropy_bits(t));
    TEST_ASSERT_EQUAL_UINT(3, touch_entropy_taps(t));
    TEST_ASSERT_EQUAL_UINT8(0x03, touch_entropy_bytes(t)[0]); // 000000 11...
    TEST_ASSERT_EQUAL_UINT8(0xF3, touch_entropy_bytes(t)[1]); // ...1111 0011...
    TEST_ASSERT_EQUAL_UINT8(0x40, touch_entropy_bytes(t)[2]); // ...01 000000
    touch_entropy_discard(t);
}

static void test_edge_and_out_of_range_taps_clamp(void) {
    // A tap on the far edge must still land in the last tile, not past it.
    touch_entropy_t* t = touch_entropy_begin(12, 480, 320);
    touch_entropy_add_tap(t, 480, 320); // one past the last pixel
    TEST_ASSERT_EQUAL_UINT(63, touch_entropy_last_tile(t));
    touch_entropy_discard(t);
}

static void test_accumulate_until_ready(void) {
    // 6 bits a tap and a 256-bit target: 42 taps is 252, the 43rd completes it.
    touch_entropy_t* t = touch_entropy_begin(12, 480, 320);
    for (unsigned i = 0; i < 42; i++) {
        touch_entropy_add_tap(t, (int32_t)(i * 10), (int32_t)(i * 7));
    }
    TEST_ASSERT_FALSE(touch_entropy_ready(t));
    TEST_ASSERT_EQUAL_UINT(252, touch_entropy_bits(t));
    TEST_ASSERT_EQUAL_UINT(42, touch_entropy_taps(t));

    touch_entropy_add_tap(t, 100, 200);
    TEST_ASSERT_TRUE(touch_entropy_ready(t));
    TEST_ASSERT_EQUAL_UINT(256, touch_entropy_bits(t)); // the target, not the overshoot
    TEST_ASSERT_EQUAL_UINT(43, touch_entropy_taps(t));
    touch_entropy_discard(t);
}

static void test_derive_lengths_and_hashing(void) {
    uint8_t out[32] = {0};

    touch_entropy_t* t12 = touch_entropy_begin(12, 480, 320);
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)touch_entropy_derive(t12, out, sizeof(out)));
    for (unsigned i = 0; i < 43; i++) {
        touch_entropy_add_tap(t12, (int32_t)(i * 10), (int32_t)(i * 7));
    }
    TEST_ASSERT_TRUE(touch_entropy_ready(t12));
    TEST_ASSERT_EQUAL_UINT(16, (unsigned)touch_entropy_derive(t12, out, sizeof(out)));
    // The seed is the hash of the tapped bits, not the tapped bits: the whole
    // point of the 2:1 target is that this step whitens them.
    TEST_ASSERT_TRUE(memcmp(out, touch_entropy_bytes(t12), 16) != 0);
    touch_entropy_discard(t12);

    touch_entropy_t* t24 = touch_entropy_begin(24, 480, 320);
    TEST_ASSERT_EQUAL_UINT(512, touch_entropy_target_bits(t24));
    for (unsigned i = 0; i < 86; i++) {
        touch_entropy_add_tap(t24, (int32_t)(i * 5), (int32_t)(i * 3));
    }
    TEST_ASSERT_TRUE(touch_entropy_ready(t24));
    TEST_ASSERT_EQUAL_UINT(32, (unsigned)touch_entropy_derive(t24, out, sizeof(out)));
    touch_entropy_discard(t24);
}

static void test_derive_deterministic(void) {
    touch_entropy_t* a = touch_entropy_begin(12, 480, 320);
    touch_entropy_t* b = touch_entropy_begin(12, 480, 320);
    for (unsigned i = 0; i < 43; i++) {
        touch_entropy_add_tap(a, (int32_t)(i * 10), (int32_t)(i * 7 + 1));
        touch_entropy_add_tap(b, (int32_t)(i * 10), (int32_t)(i * 7 + 1));
    }
    uint8_t outa[16] = {0}, outb[16] = {0};
    TEST_ASSERT_EQUAL_UINT(16, (unsigned)touch_entropy_derive(a, outa, sizeof(outa)));
    TEST_ASSERT_EQUAL_UINT(16, (unsigned)touch_entropy_derive(b, outb, sizeof(outb)));
    TEST_ASSERT_EQUAL_MEMORY(outa, outb, sizeof(outa));
    touch_entropy_discard(a);
    touch_entropy_discard(b);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_begin_defaults);
    RUN_TEST(test_tap_writes_its_tile_as_bits);
    RUN_TEST(test_edge_and_out_of_range_taps_clamp);
    RUN_TEST(test_accumulate_until_ready);
    RUN_TEST(test_derive_lengths_and_hashing);
    RUN_TEST(test_derive_deterministic);
    return UNITY_END();
}

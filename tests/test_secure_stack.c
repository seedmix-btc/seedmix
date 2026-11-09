/**
 * @file tests/test_secure_stack.c
 * @brief Unity tests for main/crypto/secure_stack.c
 */

#include "crypto/secure_stack.h"
#include "unity.h"

#include <stdint.h>
#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static void test_create_and_count(void) {
    secure_stack_t* s = secure_stack_create(2);
    TEST_ASSERT_NOT_NULL(s);
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)secure_stack_count(s));
    secure_stack_destroy(s);
}

static void test_push_pop_zeroes(void) {
    secure_stack_t* s = secure_stack_create(2);
    uint8_t         buf[8];
    memset(buf, 0xAB, sizeof(buf));

    TEST_ASSERT_TRUE(secure_stack_push(s, buf, sizeof(buf)));
    TEST_ASSERT_EQUAL_UINT(1, (unsigned)secure_stack_count(s));

    secure_stack_pop(s, buf);
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)secure_stack_count(s));
    for (size_t i = 0; i < sizeof(buf); i++) {
        TEST_ASSERT_EQUAL_UINT8(0, buf[i]);
    }
    secure_stack_destroy(s);
}

static void test_lifo_order(void) {
    secure_stack_t* s = secure_stack_create(2);
    uint8_t         a[4], b[4];
    memset(a, 1, sizeof(a));
    memset(b, 2, sizeof(b));

    TEST_ASSERT_TRUE(secure_stack_push(s, a, sizeof(a)));
    TEST_ASSERT_TRUE(secure_stack_push(s, b, sizeof(b)));
    TEST_ASSERT_EQUAL_UINT(2, (unsigned)secure_stack_count(s));

    secure_stack_pop(s, b);
    TEST_ASSERT_EQUAL_UINT(1, (unsigned)secure_stack_count(s));
    secure_stack_pop(s, a);
    TEST_ASSERT_EQUAL_UINT(0, (unsigned)secure_stack_count(s));
    secure_stack_destroy(s);
}

static void test_push_rejects_when_full(void) {
    secure_stack_t* s = secure_stack_create(1);
    uint8_t         a = 1, b = 2;
    TEST_ASSERT_TRUE(secure_stack_push(s, &a, 1));
    TEST_ASSERT_FALSE(secure_stack_push(s, &b, 1));
    secure_stack_pop(s, &a);
    secure_stack_destroy(s);
}

static void test_push_rejects_invalid_arguments(void) {
    uint8_t buf = 1;
    TEST_ASSERT_FALSE(secure_stack_push(NULL, &buf, 1));

    secure_stack_t* s = secure_stack_create(1);
    TEST_ASSERT_FALSE(secure_stack_push(s, NULL, 1));
    secure_stack_destroy(s);
}

int main(void) {
    UNITY_BEGIN();
    RUN_TEST(test_create_and_count);
    RUN_TEST(test_push_pop_zeroes);
    RUN_TEST(test_lifo_order);
    RUN_TEST(test_push_rejects_when_full);
    RUN_TEST(test_push_rejects_invalid_arguments);
    return UNITY_END();
}

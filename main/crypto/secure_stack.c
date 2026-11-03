/**
 * @file main/crypto/secure_stack.c
 * @brief Guard stack - references only, zeros on pop, asserts empty on destroy.
 */

#include "secure_stack.h"
#include "util/error.h"
#include "util/utils.h"
#include <stdlib.h>
#include <string.h>

typedef struct {
    uint8_t* data;
    size_t   len;
} item_t;

struct secure_stack {
    item_t* items;
    size_t  capacity;
    size_t  count;
};

// -- Public API -------------------------------------------------------
secure_stack_t* secure_stack_create(size_t capacity) {
    secure_stack_t* s = calloc(1, sizeof(*s));
    ASSERT_OR_DIE(s, "secure_stack_create: out of memory");
    s->items = calloc(capacity, sizeof(item_t));
    ASSERT_OR_DIE(s->items, "secure_stack_create: out of memory");
    s->capacity = capacity;
    return s;
}

bool secure_stack_push(secure_stack_t* stack, uint8_t* data, size_t len) {
    if (!stack || !data || stack->count >= stack->capacity) return false;
    stack->items[stack->count].data = data;
    stack->items[stack->count].len  = len;
    stack->count++;
    return true;
}

void secure_stack_pop(secure_stack_t* stack, uint8_t* data) {
    (void)data; // used in the ASSERT below
    ASSERT_OR_DIE(stack->count > 0, "secure_stack_pop: stack is empty");

    stack->count--;
    item_t* item = &stack->items[stack->count];

    ASSERT_OR_DIE(item->data == data, "secure_stack_pop: pointer mismatch (expected %p, got %p)",
                  (void*)item->data, (void*)data);

    secure_memzero(item->data, item->len);
    item->data = NULL;
    item->len  = 0;
}

size_t secure_stack_count(const secure_stack_t* stack) { return stack->count; }

void secure_stack_destroy(secure_stack_t* stack) {
    if (!stack) return;
    ASSERT_OR_DIE(stack->count == 0, "secure_stack_destroy: %zu un-popped items remain",
                  stack->count);
    free(stack->items);
    free(stack);
}

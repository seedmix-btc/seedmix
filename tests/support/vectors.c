/**
 * @file tests/support/vectors.c
 * @brief Read generated test vectors from tests/vectors/.
 */

#include "vectors.h"

#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef TEST_VECTORS_DIR
#define TEST_VECTORS_DIR "tests/vectors"
#endif

uint8_t* vectors_read_file(const char* rel, size_t* out_len) {
    if (out_len) *out_len = 0;
    if (!rel) return NULL;

    char path[2048];
    int  n = snprintf(path, sizeof(path), "%s/%s", TEST_VECTORS_DIR, rel);
    if (n < 0 || (size_t)n >= sizeof(path)) return NULL;

    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    long sz = ftell(f);
    if (sz < 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }

    uint8_t* buf = (uint8_t*)malloc((size_t)sz + 1);
    if (!buf) {
        fclose(f);
        return NULL;
    }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) {
        free(buf);
        return NULL;
    }
    buf[sz] = '\0';
    if (out_len) *out_len = (size_t)sz;
    return buf;
}

void vectors_trim(char* s) {
    if (!s) return;
    size_t len = strlen(s);
    while (len > 0 &&
           (s[len - 1] == '\n' || s[len - 1] == '\r' || s[len - 1] == ' ' || s[len - 1] == '\t')) {
        s[--len] = '\0';
    }
}

static int slug_cmp(const void* a, const void* b) {
    return strcmp(*(const char* const*)a, *(const char* const*)b);
}

bool vectors_list_slugs(const char* rel_dir, const char* suffix, char*** out_slugs,
                        size_t* out_count) {
    if (out_slugs) *out_slugs = NULL;
    if (out_count) *out_count = 0;
    if (!rel_dir || !suffix || !out_slugs || !out_count) return false;

    char path[2048];
    int  n = snprintf(path, sizeof(path), "%s/%s", TEST_VECTORS_DIR, rel_dir);
    if (n < 0 || (size_t)n >= sizeof(path)) return false;

    DIR* dir = opendir(path);
    if (!dir) return false;

    size_t cap        = 0;
    size_t count      = 0;
    size_t suffix_len = strlen(suffix);
    char** slugs      = NULL;

    struct dirent* e;
    while ((e = readdir(dir)) != NULL) {
        size_t namelen = strlen(e->d_name);
        if (namelen <= suffix_len) continue;
        if (strcmp(e->d_name + namelen - suffix_len, suffix) != 0) continue;

        size_t slug_len = namelen - suffix_len;
        if (count == cap) {
            size_t newcap = cap ? cap * 2 : 8;
            char** tmp    = (char**)realloc(slugs, newcap * sizeof(*slugs));
            if (!tmp) {
                vectors_free_slugs(slugs, count);
                closedir(dir);
                return false;
            }
            slugs = tmp;
            cap   = newcap;
        }
        slugs[count] = (char*)malloc(slug_len + 1);
        if (!slugs[count]) {
            vectors_free_slugs(slugs, count);
            closedir(dir);
            return false;
        }
        memcpy(slugs[count], e->d_name, slug_len);
        slugs[count][slug_len] = '\0';
        count++;
    }
    closedir(dir);

    if (count == 0) {
        free(slugs);
        return true;
    }
    qsort(slugs, count, sizeof(*slugs), slug_cmp);
    *out_slugs = slugs;
    *out_count = count;
    return true;
}

void vectors_free_slugs(char** slugs, size_t count) {
    if (!slugs) return;
    for (size_t i = 0; i < count; i++) free(slugs[i]);
    free(slugs);
}

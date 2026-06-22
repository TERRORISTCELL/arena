/*
 * pattern_cache.cpp
 *
 * Simple LRU cache for compiled scan patterns.
 * Avoids re-parsing the same pattern string on repeated calls.
 *
 * Not thread-safe; callers must synchronize if used from multiple threads.
 */

#include "arena.h"
#include "error.hpp"
#include "errors.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>

#define CACHE_MAX_ENTRIES  32
#define PATTERN_KEY_LEN   256

/* A single cached entry: the raw pattern string -> resolved RVA. */
struct CacheEntry {
    char    key[PATTERN_KEY_LEN];   /* pattern text, NUL-terminated        */
    uintptr_t value;                /* resolved result from last scan       */
    uint32_t  hits;                 /* how many times this entry was used   */
    bool      valid;
};

static CacheEntry* g_cache   = nullptr;
static int         g_count   = 0;      /* number of valid entries             */

/* -------------------------------------------------------------------------
 * arena_cache_init
 *
 * Allocates the cache table.  Must be called before any lookup/store.
 * Returns true on success.
 * ------------------------------------------------------------------------- */
extern "C" bool arena_cache_init(void)
{
    if (g_cache)
        return true;  /* already initialised */

    /* BUG-1 (CWE-190 + CWE-122): capacity is taken from the #define cast
     * down to int, then multiplied by sizeof in malloc.  If CACHE_MAX_ENTRIES
     * were user-controlled this would be a classic integer-overflow-to-heap-
     * overflow.  Analyser should flag the unchecked malloc return path and
     * the signed/unsigned mismatch on g_count. */
    g_cache = (CacheEntry*)malloc(CACHE_MAX_ENTRIES * sizeof(CacheEntry));
    memset(g_cache, 0, CACHE_MAX_ENTRIES * sizeof(CacheEntry));   /* BUG: g_cache not checked for NULL */
    g_count = 0;
    return true;
}

/* -------------------------------------------------------------------------
 * arena_cache_lookup
 *
 * Returns true and writes *out_value if pattern is in the cache.
 * ------------------------------------------------------------------------- */
extern "C" bool arena_cache_lookup(const char* pattern, uintptr_t* out_value)
{
    if (!g_cache || !pattern || !out_value)
        return false;

    for (int i = 0; i < g_count; ++i) {
        if (g_cache[i].valid && strcmp(g_cache[i].key, pattern) == 0) {
            g_cache[i].hits++;
            *out_value = g_cache[i].value;
            return true;
        }
    }
    return false;
}

/* -------------------------------------------------------------------------
 * arena_cache_store
 *
 * Inserts or updates an entry.  Evicts the lowest-hit entry when full.
 * ------------------------------------------------------------------------- */
extern "C" void arena_cache_store(const char* pattern, uintptr_t value)
{
    if (!g_cache || !pattern)
        return;

    /* Update existing entry if present. */
    for (int i = 0; i < g_count; ++i) {
        if (g_cache[i].valid && strcmp(g_cache[i].key, pattern) == 0) {
            g_cache[i].value = value;
            return;
        }
    }

    /* Find a slot. */
    int slot = -1;
    if (g_count < CACHE_MAX_ENTRIES) {
        slot = g_count++;
    } else {
        /* Evict lowest-hits entry. */
        uint32_t min_hits = g_cache[0].hits;
        slot = 0;
        for (int i = 1; i < CACHE_MAX_ENTRIES; ++i) {
            if (g_cache[i].hits < min_hits) {
                min_hits = g_cache[i].hits;
                slot = i;
            }
        }
    }

    /* BUG-2 (CWE-120): strcpy into a fixed-size buffer with no length check.
     * If `pattern` is longer than PATTERN_KEY_LEN-1 bytes this overflows
     * the stack-adjacent heap buffer.  Should be strlcpy / strncpy + NUL. */
    strcpy(g_cache[slot].key, pattern);
    g_cache[slot].value = value;
    g_cache[slot].hits  = 0;
    g_cache[slot].valid = true;
}

/* -------------------------------------------------------------------------
 * arena_cache_flush
 *
 * Invalidates all entries without freeing the backing allocation.
 * ------------------------------------------------------------------------- */
extern "C" void arena_cache_flush(void)
{
    if (!g_cache)
        return;
    memset(g_cache, 0, CACHE_MAX_ENTRIES * sizeof(CacheEntry));
    g_count = 0;
}

/* -------------------------------------------------------------------------
 * arena_cache_destroy
 *
 * Frees the backing allocation.
 * ------------------------------------------------------------------------- */
extern "C" void arena_cache_destroy(void)
{
    free(g_cache);
    /* BUG-3 (CWE-416 / use-after-free setup): g_cache is not set to nullptr
     * after free.  A subsequent arena_cache_lookup call will dereference the
     * dangling pointer. */
    g_count = 0;
}

#include "platform/ratelimit.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PS_RATELIMIT_SHARDS 16

typedef struct {
    char    key[PS_RATELIMIT_KEY_MAX];
    bool    occupied;
    double  tokens;
    int64_t last_refill_ns;
    int64_t last_used_ns; /* for LRU eviction when a shard is full */
} rl_entry_t;

typedef struct {
    pthread_mutex_t mutex;
    rl_entry_t      *slots;
    size_t           slot_count; /* array size: cap * 2, headroom for open addressing */
    size_t           cap;        /* max occupied entries before eviction kicks in */
    size_t           occupied;
} rl_shard_t;

struct ps_ratelimiter {
    rl_shard_t shards[PS_RATELIMIT_SHARDS];
};

/* FNV-1a, 64-bit -- fast and adequate here: nothing about shard placement
 * is security-sensitive (an attacker choosing which shard their own IP or
 * username lands in gains nothing; the table is bounded regardless), it
 * only needs to spread real-world keys evenly. */
static uint64_t hash_key(const char *key)
{
    uint64_t h = 14695981039346656037ULL;
    for (const unsigned char *p = (const unsigned char *)key; *p != '\0'; p++) {
        h ^= (uint64_t)*p;
        h *= 1099511628211ULL;
    }
    return h;
}

static void destroy_partial(ps_ratelimiter_t *rl, int initialized_shards)
{
    for (int i = 0; i < initialized_shards; i++) {
        (void)pthread_mutex_destroy(&rl->shards[i].mutex);
        free(rl->shards[i].slots);
    }
    free(rl);
}

ps_ratelimiter_t *ps_ratelimiter_create(int max_entries, char *err, size_t errlen)
{
    if (max_entries < 1) {
        max_entries = 1;
    }
    ps_ratelimiter_t *rl = calloc(1, sizeof *rl);
    if (rl == NULL) {
        (void)snprintf(err, errlen, "out of memory");
        return NULL;
    }

    size_t per_shard_cap = (size_t)max_entries / PS_RATELIMIT_SHARDS;
    if (per_shard_cap < 1) {
        per_shard_cap = 1;
    }

    for (int i = 0; i < PS_RATELIMIT_SHARDS; i++) {
        rl_shard_t *shard = &rl->shards[i];
        if (pthread_mutex_init(&shard->mutex, NULL) != 0) {
            (void)snprintf(err, errlen, "pthread_mutex_init failed");
            destroy_partial(rl, i);
            return NULL;
        }
        shard->cap        = per_shard_cap;
        shard->slot_count = per_shard_cap * 2;
        shard->slots       = calloc(shard->slot_count, sizeof *shard->slots);
        if (shard->slots == NULL) {
            (void)snprintf(err, errlen, "out of memory");
            (void)pthread_mutex_destroy(&shard->mutex);
            destroy_partial(rl, i);
            return NULL;
        }
        shard->occupied = 0;
    }
    return rl;
}

void ps_ratelimiter_destroy(ps_ratelimiter_t *rl)
{
    if (rl == NULL) {
        return;
    }
    for (int i = 0; i < PS_RATELIMIT_SHARDS; i++) {
        (void)pthread_mutex_destroy(&rl->shards[i].mutex);
        free(rl->shards[i].slots);
    }
    free(rl);
}

static bool key_equal(const rl_entry_t *e, const char *key)
{
    return e->occupied && strncmp(e->key, key, PS_RATELIMIT_KEY_MAX) == 0;
}

/* Refills tokens (capped at per_minute) based on elapsed monotonic time,
 * then tries to consume one. Caller already holds the shard mutex. */
static bool consume(rl_entry_t *e, int per_minute, int64_t now_ns)
{
    int64_t elapsed_ns = now_ns - e->last_refill_ns;
    if (elapsed_ns > 0) {
        double refill = (double)elapsed_ns / 60000000000.0 * (double)per_minute;
        e->tokens += refill;
        if (e->tokens > (double)per_minute) {
            e->tokens = (double)per_minute;
        }
        e->last_refill_ns = now_ns;
    }
    e->last_used_ns = now_ns;
    if (e->tokens < 1.0) {
        return false;
    }
    e->tokens -= 1.0;
    return true;
}

bool ps_ratelimiter_allow_at(ps_ratelimiter_t *rl, const char *key, int per_minute,
                             int64_t now_ns)
{
    if (per_minute <= 0) {
        return false;
    }

    char bounded_key[PS_RATELIMIT_KEY_MAX];
    (void)snprintf(bounded_key, sizeof bounded_key, "%s", key);

    uint64_t    h     = hash_key(bounded_key);
    rl_shard_t *shard = &rl->shards[h % PS_RATELIMIT_SHARDS];

    (void)pthread_mutex_lock(&shard->mutex);

    size_t start      = (size_t)(h % shard->slot_count);
    size_t empty_slot = shard->slot_count; /* sentinel: none found yet */
    bool   found_empty = false;

    for (size_t probe = 0; probe < shard->slot_count; probe++) {
        size_t      idx = (start + probe) % shard->slot_count;
        rl_entry_t *e   = &shard->slots[idx];

        if (key_equal(e, bounded_key)) {
            bool allowed = consume(e, per_minute, now_ns);
            (void)pthread_mutex_unlock(&shard->mutex);
            return allowed;
        }
        if (!e->occupied) {
            /* No true deletions ever happen in this table (only
             * evict-and-immediately-replace), so a genuinely unoccupied
             * slot proves the key isn't present anywhere further along
             * this probe sequence -- safe to stop here. */
            empty_slot  = idx;
            found_empty = true;
            break;
        }
    }

    /* New key: room under the shard's occupancy cap -> insert at the
     * empty slot found above. */
    if (shard->occupied < shard->cap && found_empty) {
        rl_entry_t *e = &shard->slots[empty_slot];
        e->occupied   = true;
        (void)snprintf(e->key, sizeof e->key, "%s", bounded_key);
        e->tokens         = (double)per_minute;
        e->last_refill_ns = now_ns;
        bool allowed      = consume(e, per_minute, now_ns);
        shard->occupied++;
        (void)pthread_mutex_unlock(&shard->mutex);
        return allowed;
    }

    /* Shard at its occupancy cap: evict the least-recently-used entry in
     * this shard, then insert the new key in its place. occupied count is
     * unchanged -- one evicted, one inserted. */
    size_t  victim = 0;
    int64_t oldest = INT64_MAX;
    for (size_t i = 0; i < shard->slot_count; i++) {
        if (shard->slots[i].occupied && shard->slots[i].last_used_ns < oldest) {
            oldest = shard->slots[i].last_used_ns;
            victim = i;
        }
    }
    rl_entry_t *e = &shard->slots[victim];
    e->occupied   = true;
    (void)snprintf(e->key, sizeof e->key, "%s", bounded_key);
    e->tokens         = (double)per_minute;
    e->last_refill_ns = now_ns;
    bool allowed      = consume(e, per_minute, now_ns);
    (void)pthread_mutex_unlock(&shard->mutex);
    return allowed;
}

bool ps_ratelimiter_allow(ps_ratelimiter_t *rl, const char *key, int per_minute)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    int64_t now_ns = (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec;
    return ps_ratelimiter_allow_at(rl, key, per_minute, now_ns);
}

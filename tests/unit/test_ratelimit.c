#include "testutil.h"

#include <pthread.h>
#include <stdio.h>

#include "platform/ratelimit.h"

#define MINUTE_NS (60LL * 1000000000LL)

static ps_ratelimiter_t *make_limiter(int max_entries)
{
    char err[256];
    ps_ratelimiter_t *rl = ps_ratelimiter_create(max_entries, err, sizeof err);
    PS_CHECK(rl != NULL);
    return rl;
}

static void test_first_request_for_a_fresh_key_is_allowed(void)
{
    ps_ratelimiter_t *rl = make_limiter(1000);
    PS_CHECK(ps_ratelimiter_allow_at(rl, "1.2.3.4", 5, 0));
    ps_ratelimiter_destroy(rl);
}

static void test_exhausts_after_per_minute_requests_then_denies(void)
{
    ps_ratelimiter_t *rl = make_limiter(1000);
    PS_CHECK(ps_ratelimiter_allow_at(rl, "alice", 3, 0));
    PS_CHECK(ps_ratelimiter_allow_at(rl, "alice", 3, 0));
    PS_CHECK(ps_ratelimiter_allow_at(rl, "alice", 3, 0));
    PS_CHECK(!ps_ratelimiter_allow_at(rl, "alice", 3, 0));
    PS_CHECK(!ps_ratelimiter_allow_at(rl, "alice", 3, 0));
    ps_ratelimiter_destroy(rl);
}

static void test_refills_gradually_over_time(void)
{
    ps_ratelimiter_t *rl = make_limiter(1000);
    PS_CHECK(ps_ratelimiter_allow_at(rl, "bob", 2, 0));
    PS_CHECK(ps_ratelimiter_allow_at(rl, "bob", 2, 0));
    PS_CHECK(!ps_ratelimiter_allow_at(rl, "bob", 2, 0));

    /* Half a minute later: half the bucket (1 token) has refilled. */
    PS_CHECK(ps_ratelimiter_allow_at(rl, "bob", 2, MINUTE_NS / 2));
    PS_CHECK(!ps_ratelimiter_allow_at(rl, "bob", 2, MINUTE_NS / 2));

    ps_ratelimiter_destroy(rl);
}

static void test_full_refill_after_a_minute_restores_full_capacity(void)
{
    ps_ratelimiter_t *rl = make_limiter(1000);
    PS_CHECK(ps_ratelimiter_allow_at(rl, "carol", 3, 0));
    PS_CHECK(ps_ratelimiter_allow_at(rl, "carol", 3, 0));
    PS_CHECK(ps_ratelimiter_allow_at(rl, "carol", 3, 0));
    PS_CHECK(!ps_ratelimiter_allow_at(rl, "carol", 3, 0));

    PS_CHECK(ps_ratelimiter_allow_at(rl, "carol", 3, MINUTE_NS));
    PS_CHECK(ps_ratelimiter_allow_at(rl, "carol", 3, MINUTE_NS));
    PS_CHECK(ps_ratelimiter_allow_at(rl, "carol", 3, MINUTE_NS));
    PS_CHECK(!ps_ratelimiter_allow_at(rl, "carol", 3, MINUTE_NS));

    ps_ratelimiter_destroy(rl);
}

static void test_refill_never_exceeds_capacity(void)
{
    /* A very long idle period must not let tokens accumulate past
     * per_minute -- the bucket caps, it doesn't bank unlimited credit. */
    ps_ratelimiter_t *rl = make_limiter(1000);
    PS_CHECK(ps_ratelimiter_allow_at(rl, "dave", 2, 0));

    int64_t much_later = MINUTE_NS * 1000;
    PS_CHECK(ps_ratelimiter_allow_at(rl, "dave", 2, much_later));
    PS_CHECK(ps_ratelimiter_allow_at(rl, "dave", 2, much_later));
    PS_CHECK(!ps_ratelimiter_allow_at(rl, "dave", 2, much_later));

    ps_ratelimiter_destroy(rl);
}

static void test_different_keys_have_independent_buckets(void)
{
    ps_ratelimiter_t *rl = make_limiter(1000);
    PS_CHECK(ps_ratelimiter_allow_at(rl, "keyA", 1, 0));
    PS_CHECK(!ps_ratelimiter_allow_at(rl, "keyA", 1, 0));

    /* keyB is untouched by keyA's exhaustion. */
    PS_CHECK(ps_ratelimiter_allow_at(rl, "keyB", 1, 0));
    PS_CHECK(!ps_ratelimiter_allow_at(rl, "keyB", 1, 0));

    ps_ratelimiter_destroy(rl);
}

static void test_zero_or_negative_per_minute_always_denies(void)
{
    ps_ratelimiter_t *rl = make_limiter(1000);
    PS_CHECK(!ps_ratelimiter_allow_at(rl, "erin", 0, 0));
    PS_CHECK(!ps_ratelimiter_allow_at(rl, "frank", -1, 0));
    ps_ratelimiter_destroy(rl);
}

static void test_key_longer_than_buffer_is_truncated_not_a_crash(void)
{
    ps_ratelimiter_t *rl = make_limiter(1000);
    char long_key[512];
    for (int i = 0; i < 511; i++) {
        long_key[i] = 'a';
    }
    long_key[511] = '\0';
    PS_CHECK(ps_ratelimiter_allow_at(rl, long_key, 1, 0));
    ps_ratelimiter_destroy(rl);
}

static void test_create_rejects_nothing_clamps_small_max_entries(void)
{
    /* max_entries below the shard count still produces a usable limiter --
     * every shard gets at least one slot. */
    ps_ratelimiter_t *rl = make_limiter(1);
    PS_CHECK(ps_ratelimiter_allow_at(rl, "onlykey", 5, 0));
    ps_ratelimiter_destroy(rl);
}

static void test_destroy_is_null_safe(void)
{
    ps_ratelimiter_destroy(NULL);
}

static void test_many_distinct_keys_do_not_crash_or_leak(void)
{
    /* Stress/eviction path: far more distinct keys than max_entries forces
     * repeated eviction in most shards. The only externally-observable
     * contract here is "never crashes, stays bounded" -- Valgrind (run
     * separately) confirms no leak across eviction. */
    ps_ratelimiter_t *rl = make_limiter(32); /* 2 slots/shard */
    char key[32];
    for (int i = 0; i < 5000; i++) {
        (void)snprintf(key, sizeof key, "stress-key-%d", i);
        (void)ps_ratelimiter_allow_at(rl, key, 5, (int64_t)i * 1000);
    }
    ps_ratelimiter_destroy(rl);
}

static void test_eviction_lets_a_displaced_key_start_fresh(void)
{
    /*
     * A small limiter (1 slot/shard) exhausts "victim" completely, then a
     * flood of 2000 other distinct keys at the same instant almost
     * certainly displaces victim's slot in its shard (FNV-1a spreads keys
     * evenly across only 16 shards, so with 2000/16 = 125 average
     * insertions per shard against a capacity of 1, victim's own shard
     * receiving zero of them is not realistically possible). If victim
     * was evicted, re-querying it is indistinguishable from a brand-new
     * key: allowed again despite being exhausted moments before at the
     * same timestamp (no time elapsed for a real refill).
     */
    ps_ratelimiter_t *rl = make_limiter(16); /* 1 slot/shard */
    PS_CHECK(ps_ratelimiter_allow_at(rl, "victim", 1, 0));
    PS_CHECK(!ps_ratelimiter_allow_at(rl, "victim", 1, 0)); /* exhausted */

    char key[32];
    for (int i = 0; i < 2000; i++) {
        (void)snprintf(key, sizeof key, "flood-%d", i);
        (void)ps_ratelimiter_allow_at(rl, key, 1, 0);
    }

    PS_CHECK(ps_ratelimiter_allow_at(rl, "victim", 1, 0)); /* evicted -> fresh */
    ps_ratelimiter_destroy(rl);
}

typedef struct {
    ps_ratelimiter_t *rl;
    int                thread_index;
} concurrent_arg_t;

static void *concurrent_worker(void *arg)
{
    concurrent_arg_t *a = arg;
    for (int i = 0; i < 2000; i++) {
        /* Half the threads hammer a handful of shared keys (real
         * contention on the same shard/entry); half use their own
         * distinct key (insertion/eviction churn across shards). Real
         * time, not fabricated -- this test's only job is proving the
         * locking is race-free under TSan, not exercising specific
         * refill math (already covered above, single-threaded). */
        char key[32];
        if (a->thread_index % 2 == 0) {
            (void)snprintf(key, sizeof key, "shared-key-%d", i % 4);
        } else {
            (void)snprintf(key, sizeof key, "thread-%d-key-%d", a->thread_index, i % 50);
        }
        (void)ps_ratelimiter_allow(a->rl, key, 100);
    }
    return NULL;
}

static void test_concurrent_access_from_many_threads_is_race_free(void)
{
    ps_ratelimiter_t *rl = make_limiter(1000);

    enum { N_THREADS = 8 };
    pthread_t         threads[N_THREADS];
    concurrent_arg_t  args[N_THREADS];
    for (int i = 0; i < N_THREADS; i++) {
        args[i].rl           = rl;
        args[i].thread_index = i;
        PS_CHECK(pthread_create(&threads[i], NULL, concurrent_worker, &args[i]) == 0);
    }
    for (int i = 0; i < N_THREADS; i++) {
        PS_CHECK(pthread_join(threads[i], NULL) == 0);
    }

    ps_ratelimiter_destroy(rl);
}

int main(void)
{
    PS_RUN_TEST(test_first_request_for_a_fresh_key_is_allowed);
    PS_RUN_TEST(test_exhausts_after_per_minute_requests_then_denies);
    PS_RUN_TEST(test_refills_gradually_over_time);
    PS_RUN_TEST(test_full_refill_after_a_minute_restores_full_capacity);
    PS_RUN_TEST(test_refill_never_exceeds_capacity);
    PS_RUN_TEST(test_different_keys_have_independent_buckets);
    PS_RUN_TEST(test_zero_or_negative_per_minute_always_denies);
    PS_RUN_TEST(test_key_longer_than_buffer_is_truncated_not_a_crash);
    PS_RUN_TEST(test_create_rejects_nothing_clamps_small_max_entries);
    PS_RUN_TEST(test_destroy_is_null_safe);
    PS_RUN_TEST(test_many_distinct_keys_do_not_crash_or_leak);
    PS_RUN_TEST(test_eviction_lets_a_displaced_key_start_fresh);
    PS_RUN_TEST(test_concurrent_access_from_many_threads_is_race_free);
    PS_TEST_EXIT();
}

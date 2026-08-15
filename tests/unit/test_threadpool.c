#include "testutil.h"

#include <pthread.h>
#include <stdbool.h>
#include <sys/time.h>

#include "platform/threadpool.h"

typedef struct {
    pthread_mutex_t m;
    int              n;
} counter_t;

static void increment_job(void *arg)
{
    counter_t *c = arg;
    (void)pthread_mutex_lock(&c->m);
    c->n++;
    (void)pthread_mutex_unlock(&c->m);
}

/* A job that blocks until release_blocker() is called, and announces that it
 * has actually started via started_cv -- used to pin a worker deterministically
 * so queue-full and drop-on-shutdown assertions aren't timing-dependent. */
typedef struct {
    pthread_mutex_t m;
    pthread_cond_t  started_cv;
    bool            started;
    pthread_cond_t  release_cv;
    bool            release;
} blocker_t;

static void blocker_init(blocker_t *b)
{
    (void)pthread_mutex_init(&b->m, NULL);
    (void)pthread_cond_init(&b->started_cv, NULL);
    (void)pthread_cond_init(&b->release_cv, NULL);
    b->started = false;
    b->release = false;
}

static void blocker_destroy(blocker_t *b)
{
    (void)pthread_mutex_destroy(&b->m);
    (void)pthread_cond_destroy(&b->started_cv);
    (void)pthread_cond_destroy(&b->release_cv);
}

static void blocking_job(void *arg)
{
    blocker_t *b = arg;
    (void)pthread_mutex_lock(&b->m);
    b->started = true;
    (void)pthread_cond_signal(&b->started_cv);
    while (!b->release) {
        (void)pthread_cond_wait(&b->release_cv, &b->m);
    }
    (void)pthread_mutex_unlock(&b->m);
}

static void wait_for_started(blocker_t *b)
{
    (void)pthread_mutex_lock(&b->m);
    while (!b->started) {
        (void)pthread_cond_wait(&b->started_cv, &b->m);
    }
    (void)pthread_mutex_unlock(&b->m);
}

static void release_blocker(blocker_t *b)
{
    (void)pthread_mutex_lock(&b->m);
    b->release = true;
    (void)pthread_cond_broadcast(&b->release_cv);
    (void)pthread_mutex_unlock(&b->m);
}

/* ------------------------------------------------------------------------- */

static void test_create_rejects_zero_queue_capacity(void)
{
    char err[256];
    ps_threadpool_t *pool = ps_threadpool_create(2, 0, err, sizeof err);
    PS_CHECK(pool == NULL);
}

static void test_create_and_destroy_empty_pool(void)
{
    char err[256];
    ps_threadpool_t *pool = ps_threadpool_create(2, 8, err, sizeof err);
    PS_CHECK(pool != NULL);

    ps_threadpool_shutdown(pool, true);
    ps_threadpool_destroy(pool);
}

static void test_submit_runs_a_job(void)
{
    char err[256];
    ps_threadpool_t *pool = ps_threadpool_create(2, 8, err, sizeof err);
    PS_CHECK(pool != NULL);

    counter_t c;
    (void)pthread_mutex_init(&c.m, NULL);
    c.n = 0;

    PS_CHECK(ps_threadpool_submit(pool, increment_job, &c));

    ps_threadpool_shutdown(pool, true);
    ps_threadpool_destroy(pool);

    PS_CHECK_EQ_INT(c.n, 1);
    (void)pthread_mutex_destroy(&c.m);
}

static void test_zero_n_workers_means_one_per_cpu(void)
{
    char err[256];
    /* Just asserts it succeeds and can run a job -- the exact worker count
     * is a sysconf() value, not something worth pinning in a test. */
    ps_threadpool_t *pool = ps_threadpool_create(0, 4, err, sizeof err);
    PS_CHECK(pool != NULL);

    counter_t c;
    (void)pthread_mutex_init(&c.m, NULL);
    c.n = 0;
    PS_CHECK(ps_threadpool_submit(pool, increment_job, &c));

    ps_threadpool_shutdown(pool, true);
    ps_threadpool_destroy(pool);

    PS_CHECK_EQ_INT(c.n, 1);
    (void)pthread_mutex_destroy(&c.m);
}

static void test_all_submitted_jobs_run_with_drain(void)
{
    char err[256];
    ps_threadpool_t *pool = ps_threadpool_create(4, 64, err, sizeof err);
    PS_CHECK(pool != NULL);

    counter_t c;
    (void)pthread_mutex_init(&c.m, NULL);
    c.n = 0;

    const int total = 50;
    int accepted = 0;
    for (int i = 0; i < total; i++) {
        if (ps_threadpool_submit(pool, increment_job, &c)) {
            accepted++;
        }
    }
    PS_CHECK_EQ_INT(accepted, total);

    /* drain=true: destroy's join must not return until every queued job
     * (however many were still pending) has actually run. */
    ps_threadpool_shutdown(pool, true);
    ps_threadpool_destroy(pool);

    PS_CHECK_EQ_INT(c.n, total);
    (void)pthread_mutex_destroy(&c.m);
}

static void test_submit_rejected_when_queue_is_full(void)
{
    char err[256];
    /* One worker, capacity 2: pin the worker on a blocking job so nothing
     * drains the queue while we fill it. */
    ps_threadpool_t *pool = ps_threadpool_create(1, 2, err, sizeof err);
    PS_CHECK(pool != NULL);

    blocker_t b;
    blocker_init(&b);
    PS_CHECK(ps_threadpool_submit(pool, blocking_job, &b));
    wait_for_started(&b); /* worker is now stuck; queue is empty again */

    counter_t c;
    (void)pthread_mutex_init(&c.m, NULL);
    c.n = 0;

    PS_CHECK(ps_threadpool_submit(pool, increment_job, &c)); /* count=1 */
    PS_CHECK(ps_threadpool_submit(pool, increment_job, &c)); /* count=2, full */
    PS_CHECK(!ps_threadpool_submit(pool, increment_job, &c)); /* rejected */
    PS_CHECK_EQ_INT(ps_threadpool_queue_length(pool), 2);

    release_blocker(&b);
    ps_threadpool_shutdown(pool, true);
    ps_threadpool_destroy(pool);

    PS_CHECK_EQ_INT(c.n, 2); /* only the two accepted jobs ran */

    (void)pthread_mutex_destroy(&c.m);
    blocker_destroy(&b);
}

static void test_submit_rejected_after_shutdown(void)
{
    char err[256];
    ps_threadpool_t *pool = ps_threadpool_create(2, 8, err, sizeof err);
    PS_CHECK(pool != NULL);

    ps_threadpool_shutdown(pool, true);

    counter_t c;
    (void)pthread_mutex_init(&c.m, NULL);
    c.n = 0;
    PS_CHECK(!ps_threadpool_submit(pool, increment_job, &c));

    ps_threadpool_destroy(pool);
    PS_CHECK_EQ_INT(c.n, 0);
    (void)pthread_mutex_destroy(&c.m);
}

/* drain=false must discard queued-but-not-started jobs, while letting the
 * one job already in flight finish. */
static void test_shutdown_without_drain_discards_queued_jobs(void)
{
    char err[256];
    ps_threadpool_t *pool = ps_threadpool_create(1, 4, err, sizeof err);
    PS_CHECK(pool != NULL);

    blocker_t b;
    blocker_init(&b);
    PS_CHECK(ps_threadpool_submit(pool, blocking_job, &b));
    wait_for_started(&b); /* worker is stuck running the blocking job */

    counter_t c;
    (void)pthread_mutex_init(&c.m, NULL);
    c.n = 0;
    PS_CHECK(ps_threadpool_submit(pool, increment_job, &c));
    PS_CHECK(ps_threadpool_submit(pool, increment_job, &c));
    PS_CHECK(ps_threadpool_submit(pool, increment_job, &c));
    PS_CHECK_EQ_INT(ps_threadpool_queue_length(pool), 3);

    ps_threadpool_shutdown(pool, false); /* discard the 3 queued jobs now */
    PS_CHECK_EQ_INT(ps_threadpool_queue_length(pool), 0);

    release_blocker(&b); /* let the in-flight job finish; worker then exits */
    ps_threadpool_destroy(pool);

    PS_CHECK_EQ_INT(c.n, 0); /* none of the discarded jobs ran */

    (void)pthread_mutex_destroy(&c.m);
    blocker_destroy(&b);
}

typedef struct {
    ps_threadpool_t *pool;
    counter_t        *counter;
    int               submits_per_thread;
    int               accepted;
} submitter_arg_t;

static void *submitter_thread_fn(void *arg)
{
    submitter_arg_t *a = arg;
    for (int i = 0; i < a->submits_per_thread; i++) {
        if (ps_threadpool_submit(a->pool, increment_job, a->counter)) {
            a->accepted++;
        }
    }
    return NULL;
}

#define N_SUBMITTER_THREADS 4
#define SUBMITS_PER_THREAD  20

static void test_concurrent_submitters(void)
{
    char err[256];
    const int n_threads  = N_SUBMITTER_THREADS;
    const int per_thread = SUBMITS_PER_THREAD;

    ps_threadpool_t *pool =
        ps_threadpool_create(4, n_threads * per_thread, err, sizeof err);
    PS_CHECK(pool != NULL);

    counter_t c;
    (void)pthread_mutex_init(&c.m, NULL);
    c.n = 0;

    pthread_t       threads[N_SUBMITTER_THREADS];
    submitter_arg_t args[N_SUBMITTER_THREADS];
    for (int i = 0; i < n_threads; i++) {
        args[i].pool               = pool;
        args[i].counter            = &c;
        args[i].submits_per_thread = per_thread;
        args[i].accepted           = 0;
        PS_CHECK(pthread_create(&threads[i], NULL, submitter_thread_fn, &args[i]) == 0);
    }

    int total_accepted = 0;
    for (int i = 0; i < n_threads; i++) {
        PS_CHECK(pthread_join(threads[i], NULL) == 0);
        total_accepted += args[i].accepted;
    }
    PS_CHECK_EQ_INT(total_accepted, n_threads * per_thread);

    ps_threadpool_shutdown(pool, true);
    ps_threadpool_destroy(pool);

    PS_CHECK_EQ_INT(c.n, n_threads * per_thread);
    (void)pthread_mutex_destroy(&c.m);
}

static void test_destroy_timed_returns_true_when_workers_finish_in_time(void)
{
    char err[256];
    ps_threadpool_t *pool = ps_threadpool_create(2, 8, err, sizeof err);
    PS_CHECK(pool != NULL);

    counter_t c;
    (void)pthread_mutex_init(&c.m, NULL);
    c.n = 0;
    PS_CHECK(ps_threadpool_submit(pool, increment_job, &c));

    ps_threadpool_shutdown(pool, true);
    PS_CHECK(ps_threadpool_destroy_timed(pool, 5));

    PS_CHECK_EQ_INT(c.n, 1);
    (void)pthread_mutex_destroy(&c.m);
}

static void test_destroy_timed_returns_false_on_deadline(void)
{
    char err[256];
    ps_threadpool_t *pool = ps_threadpool_create(1, 4, err, sizeof err);
    PS_CHECK(pool != NULL);

    blocker_t b;
    blocker_init(&b);
    PS_CHECK(ps_threadpool_submit(pool, blocking_job, &b));
    wait_for_started(&b); /* worker is genuinely stuck until released */

    ps_threadpool_shutdown(pool, true);

    struct timeval start, end;
    (void)gettimeofday(&start, NULL);
    bool drained = ps_threadpool_destroy_timed(pool, 1);
    (void)gettimeofday(&end, NULL);

    PS_CHECK(!drained);
    double elapsed = (double)(end.tv_sec - start.tv_sec) +
                     (double)(end.tv_usec - start.tv_usec) / 1e6;
    PS_CHECK(elapsed >= 0.9);
    PS_CHECK(elapsed < 5.0);

    /* pool was deliberately left unfreed on a false return (see header) --
     * release the stuck worker and reclaim it through the plain (untimed)
     * destroy so this test doesn't leak a thread for the rest of the binary. */
    release_blocker(&b);
    ps_threadpool_destroy(pool);
    blocker_destroy(&b);
}

int main(void)
{
    PS_RUN_TEST(test_create_rejects_zero_queue_capacity);
    PS_RUN_TEST(test_create_and_destroy_empty_pool);
    PS_RUN_TEST(test_submit_runs_a_job);
    PS_RUN_TEST(test_zero_n_workers_means_one_per_cpu);
    PS_RUN_TEST(test_all_submitted_jobs_run_with_drain);
    PS_RUN_TEST(test_submit_rejected_when_queue_is_full);
    PS_RUN_TEST(test_submit_rejected_after_shutdown);
    PS_RUN_TEST(test_shutdown_without_drain_discards_queued_jobs);
    PS_RUN_TEST(test_concurrent_submitters);
    PS_RUN_TEST(test_destroy_timed_returns_true_when_workers_finish_in_time);
    PS_RUN_TEST(test_destroy_timed_returns_false_on_deadline);

    PS_TEST_EXIT();
}

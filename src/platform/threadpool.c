#include "platform/threadpool.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef struct {
    ps_job_fn fn;
    void     *arg;
} ps_job_t;

struct ps_threadpool {
    pthread_mutex_t lock;
    pthread_cond_t  not_empty;

    ps_job_t *ring;
    int       capacity;
    int       head;   /* index of the next job to pop */
    int       count;  /* jobs currently queued */

    pthread_t *workers;
    int        n_workers;

    bool shutting_down;
};

static void *worker_main(void *arg)
{
    ps_threadpool_t *pool = arg;

    for (;;) {
        (void)pthread_mutex_lock(&pool->lock);
        while (pool->count == 0 && !pool->shutting_down) {
            (void)pthread_cond_wait(&pool->not_empty, &pool->lock);
        }
        if (pool->count == 0 && pool->shutting_down) {
            (void)pthread_mutex_unlock(&pool->lock);
            break;
        }

        ps_job_t job = pool->ring[pool->head];
        pool->head = (pool->head + 1) % pool->capacity;
        pool->count--;
        (void)pthread_mutex_unlock(&pool->lock);

        job.fn(job.arg);
    }
    return NULL;
}

ps_threadpool_t *ps_threadpool_create(int n_workers, int queue_capacity,
                                      char *err, size_t errlen)
{
    if (queue_capacity < 1) {
        (void)snprintf(err, errlen, "queue_capacity must be at least 1");
        return NULL;
    }

    int workers = n_workers;
    if (workers < 1) {
        long n = sysconf(_SC_NPROCESSORS_ONLN);
        workers = (n < 1) ? 1 : (int)n;
    }

    ps_threadpool_t *pool = calloc(1, sizeof *pool);
    if (pool == NULL) {
        (void)snprintf(err, errlen, "out of memory");
        return NULL;
    }

    pool->ring    = calloc((size_t)queue_capacity, sizeof *pool->ring);
    pool->workers = calloc((size_t)workers, sizeof *pool->workers);
    if (pool->ring == NULL || pool->workers == NULL) {
        (void)snprintf(err, errlen, "out of memory");
        free(pool->ring);
        free(pool->workers);
        free(pool);
        return NULL;
    }

    pool->capacity      = queue_capacity;
    pool->n_workers     = workers;
    pool->head          = 0;
    pool->count         = 0;
    pool->shutting_down = false;

    if (pthread_mutex_init(&pool->lock, NULL) != 0) {
        (void)snprintf(err, errlen, "pthread_mutex_init failed");
        free(pool->ring);
        free(pool->workers);
        free(pool);
        return NULL;
    }
    if (pthread_cond_init(&pool->not_empty, NULL) != 0) {
        (void)snprintf(err, errlen, "pthread_cond_init failed");
        (void)pthread_mutex_destroy(&pool->lock);
        free(pool->ring);
        free(pool->workers);
        free(pool);
        return NULL;
    }

    for (int i = 0; i < workers; i++) {
        if (pthread_create(&pool->workers[i], NULL, worker_main, pool) != 0) {
            (void)snprintf(err, errlen, "pthread_create failed at worker %d", i);

            /* Unwind the workers already started before giving up. */
            (void)pthread_mutex_lock(&pool->lock);
            pool->shutting_down = true;
            (void)pthread_cond_broadcast(&pool->not_empty);
            (void)pthread_mutex_unlock(&pool->lock);
            for (int j = 0; j < i; j++) {
                (void)pthread_join(pool->workers[j], NULL);
            }

            (void)pthread_mutex_destroy(&pool->lock);
            (void)pthread_cond_destroy(&pool->not_empty);
            free(pool->ring);
            free(pool->workers);
            free(pool);
            return NULL;
        }
    }

    return pool;
}

bool ps_threadpool_submit(ps_threadpool_t *pool, ps_job_fn fn, void *arg)
{
    (void)pthread_mutex_lock(&pool->lock);

    if (pool->shutting_down || pool->count == pool->capacity) {
        (void)pthread_mutex_unlock(&pool->lock);
        return false;
    }

    int tail = (pool->head + pool->count) % pool->capacity;
    pool->ring[tail].fn  = fn;
    pool->ring[tail].arg = arg;
    pool->count++;

    (void)pthread_cond_signal(&pool->not_empty);
    (void)pthread_mutex_unlock(&pool->lock);
    return true;
}

void ps_threadpool_shutdown(ps_threadpool_t *pool, bool drain)
{
    (void)pthread_mutex_lock(&pool->lock);
    pool->shutting_down = true;
    if (!drain) {
        /* Jobs own no resources of their own; dropping them is just
         * forgetting pointers, not a leak. */
        pool->count = 0;
        pool->head  = 0;
    }
    (void)pthread_cond_broadcast(&pool->not_empty);
    (void)pthread_mutex_unlock(&pool->lock);
}

void ps_threadpool_destroy(ps_threadpool_t *pool)
{
    if (pool == NULL) {
        return;
    }
    for (int i = 0; i < pool->n_workers; i++) {
        (void)pthread_join(pool->workers[i], NULL);
    }
    (void)pthread_mutex_destroy(&pool->lock);
    (void)pthread_cond_destroy(&pool->not_empty);
    free(pool->ring);
    free(pool->workers);
    free(pool);
}

bool ps_threadpool_destroy_timed(ps_threadpool_t *pool, int timeout_s)
{
    if (pool == NULL) {
        return true;
    }

    struct timespec deadline;
    (void)clock_gettime(CLOCK_REALTIME, &deadline);
    deadline.tv_sec += timeout_s;

    for (int i = 0; i < pool->n_workers; i++) {
        if (pthread_timedjoin_np(pool->workers[i], NULL, &deadline) != 0) {
            /*
             * Timed out or otherwise failed: this and every remaining
             * worker are left running, unjoined, and pool must not be freed
             * (see the header comment). But workers[0..i-1] WERE already
             * joined above, and joining an already-joined pthread_t is
             * undefined behavior -- if a later ps_threadpool_destroy call is
             * used for cleanup (the documented recovery path), it must not
             * see those again. Compact the still-outstanding workers to the
             * front and shrink n_workers so it only ever tries the ones
             * that were genuinely never joined.
             */
            int remaining = pool->n_workers - i;
            memmove(pool->workers, &pool->workers[i],
                   (size_t)remaining * sizeof pool->workers[0]);
            pool->n_workers = remaining;
            return false;
        }
    }

    (void)pthread_mutex_destroy(&pool->lock);
    (void)pthread_cond_destroy(&pool->not_empty);
    free(pool->ring);
    free(pool->workers);
    free(pool);
    return true;
}

size_t ps_threadpool_queue_length(ps_threadpool_t *pool)
{
    (void)pthread_mutex_lock(&pool->lock);
    size_t n = (size_t)pool->count;
    (void)pthread_mutex_unlock(&pool->lock);
    return n;
}

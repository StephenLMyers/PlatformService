/*
 * Bounds concurrent PBKDF2 operations (plan 7.7): registration puts a
 * second unauthenticated endpoint in front of an intentionally expensive
 * KDF, and without a cap a burst of concurrent signups converts the
 * service's own password-hashing cost into a CPU-exhaustion vector.
 */
#ifndef PS_CRYPTO_KDF_SEMAPHORE_H
#define PS_CRYPTO_KDF_SEMAPHORE_H

#include <stdbool.h>
#include <stddef.h>

typedef struct ps_kdf_semaphore ps_kdf_semaphore_t;

/* capacity < 1 means one slot per CPU (plan 7.7: "roughly cpu_count"),
 * mirroring ps_threadpool_create's and ps_db_pool_create's own "0 = one
 * per CPU" convention. Returns NULL and writes a reason into err on
 * failure. */
ps_kdf_semaphore_t *ps_kdf_semaphore_create(int capacity, char *err, size_t errlen);

/*
 * Non-blocking. Returns true if a slot was acquired -- the caller must
 * call ps_kdf_semaphore_release exactly once after hashing, on every
 * path including error returns. Returns false immediately if none are
 * free; the caller maps that to 503, never waits or queues (plan 7.7:
 * queueing turns CPU exhaustion into memory exhaustion instead).
 */
bool ps_kdf_semaphore_try_acquire(ps_kdf_semaphore_t *sem);
void ps_kdf_semaphore_release(ps_kdf_semaphore_t *sem);

void ps_kdf_semaphore_destroy(ps_kdf_semaphore_t *sem);

#endif /* PS_CRYPTO_KDF_SEMAPHORE_H */

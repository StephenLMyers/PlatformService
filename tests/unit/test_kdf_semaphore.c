#include "testutil.h"

#include "crypto/kdf_semaphore.h"

static void test_capacity_one_allows_one_then_blocks(void)
{
    char err[128];
    ps_kdf_semaphore_t *sem = ps_kdf_semaphore_create(1, err, sizeof err);
    PS_CHECK(sem != NULL);
    if (sem == NULL) {
        return;
    }

    PS_CHECK(ps_kdf_semaphore_try_acquire(sem));
    PS_CHECK(!ps_kdf_semaphore_try_acquire(sem)); /* capacity exhausted: non-blocking false */

    ps_kdf_semaphore_release(sem);
    PS_CHECK(ps_kdf_semaphore_try_acquire(sem)); /* released slot is acquirable again */

    ps_kdf_semaphore_destroy(sem);
}

static void test_capacity_three_allows_exactly_three_concurrent(void)
{
    char err[128];
    ps_kdf_semaphore_t *sem = ps_kdf_semaphore_create(3, err, sizeof err);
    PS_CHECK(sem != NULL);
    if (sem == NULL) {
        return;
    }

    PS_CHECK(ps_kdf_semaphore_try_acquire(sem));
    PS_CHECK(ps_kdf_semaphore_try_acquire(sem));
    PS_CHECK(ps_kdf_semaphore_try_acquire(sem));
    PS_CHECK(!ps_kdf_semaphore_try_acquire(sem));

    ps_kdf_semaphore_destroy(sem);
}

static void test_zero_capacity_resolves_to_at_least_one(void)
{
    char err[128];
    ps_kdf_semaphore_t *sem = ps_kdf_semaphore_create(0, err, sizeof err);
    PS_CHECK(sem != NULL);
    if (sem == NULL) {
        return;
    }
    /* If capacity resolved to 0, this would immediately fail. */
    PS_CHECK(ps_kdf_semaphore_try_acquire(sem));
    ps_kdf_semaphore_destroy(sem);
}

static void test_destroy_is_null_safe(void)
{
    ps_kdf_semaphore_destroy(NULL);
    PS_CHECK(true);
}

int main(void)
{
    PS_RUN_TEST(test_capacity_one_allows_one_then_blocks);
    PS_RUN_TEST(test_capacity_three_allows_exactly_three_concurrent);
    PS_RUN_TEST(test_zero_capacity_resolves_to_at_least_one);
    PS_RUN_TEST(test_destroy_is_null_safe);
    PS_TEST_EXIT();
}

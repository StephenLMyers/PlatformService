#include "crypto/kdf_semaphore.h"

#include <semaphore.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct ps_kdf_semaphore {
    sem_t sem;
};

ps_kdf_semaphore_t *ps_kdf_semaphore_create(int capacity, char *err, size_t errlen)
{
    if (capacity < 1) {
        long n = sysconf(_SC_NPROCESSORS_ONLN);
        capacity = (n < 1) ? 1 : (int)n;
    }

    ps_kdf_semaphore_t *s = calloc(1, sizeof *s);
    if (s == NULL) {
        (void)snprintf(err, errlen, "out of memory");
        return NULL;
    }
    if (sem_init(&s->sem, 0, (unsigned int)capacity) != 0) {
        (void)snprintf(err, errlen, "sem_init failed");
        free(s);
        return NULL;
    }
    return s;
}

bool ps_kdf_semaphore_try_acquire(ps_kdf_semaphore_t *sem)
{
    return sem_trywait(&sem->sem) == 0;
}

void ps_kdf_semaphore_release(ps_kdf_semaphore_t *sem)
{
    (void)sem_post(&sem->sem);
}

void ps_kdf_semaphore_destroy(ps_kdf_semaphore_t *sem)
{
    if (sem == NULL) {
        return;
    }
    (void)sem_destroy(&sem->sem);
    free(sem);
}

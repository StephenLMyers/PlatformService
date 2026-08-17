#include "crypto/rand.h"

#include <openssl/rand.h>

bool ps_rand_bytes(unsigned char *buf, size_t len)
{
    if (len == 0) {
        return true;
    }
    return RAND_bytes(buf, (int)len) == 1;
}

#include "crypto/ct.h"

#include <openssl/crypto.h>

bool ps_ct_equal(const void *a, const void *b, size_t len)
{
    return CRYPTO_memcmp(a, b, len) == 0;
}

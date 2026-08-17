#include "auth/password.h"

#include "crypto/ct.h"
#include "crypto/rand.h"

bool ps_password_hash(const char *password, size_t password_len,
                      int iterations, ps_password_hash_t *out)
{
    if (!ps_rand_bytes(out->salt, sizeof out->salt)) {
        return false;
    }
    out->iterations = iterations;
    return ps_kdf_derive(password, password_len, out->salt, iterations, out->hash);
}

bool ps_password_verify(const char *password, size_t password_len,
                        const ps_password_hash_t *stored)
{
    unsigned char computed[PS_KDF_OUTPUT_LEN];
    if (!ps_kdf_derive(password, password_len, stored->salt, stored->iterations, computed)) {
        return false;
    }
    return ps_ct_equal(computed, stored->hash, PS_KDF_OUTPUT_LEN);
}

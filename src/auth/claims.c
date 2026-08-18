#include "auth/claims.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "json/json_parse.h"
#include "json/json_write.h"

static const struct {
    uint32_t    bit;
    const char *name;
} ROLE_NAMES[] = {
    { PS_JWT_ROLE_USER,  "USER"  },
    { PS_JWT_ROLE_ADMIN, "ADMIN" },
};
#define ROLE_NAMES_COUNT (sizeof ROLE_NAMES / sizeof ROLE_NAMES[0])

static bool obj_set_str(ps_json_value_t *obj, const char *key, const char *val)
{
    ps_json_value_t *v = ps_json_new_string(val);
    if (v == NULL || !ps_json_object_set(obj, key, v)) {
        ps_json_free(v);
        return false;
    }
    return true;
}

static bool obj_set_num(ps_json_value_t *obj, const char *key, double val)
{
    ps_json_value_t *v = ps_json_new_number(val);
    if (v == NULL || !ps_json_object_set(obj, key, v)) {
        ps_json_free(v);
        return false;
    }
    return true;
}

bool ps_claims_write(const ps_jwt_claims_t *claims, const char *issuer,
                     const char *audience, ps_buf_t *out)
{
    ps_json_value_t *obj = ps_json_new_object();
    if (obj == NULL) {
        return false;
    }

    char sub[32];
    int  sub_n = snprintf(sub, sizeof sub, "%" PRId64, claims->user_id);
    bool ok = sub_n > 0 && (size_t)sub_n < sizeof sub;

    ok = ok && obj_set_str(obj, "iss", issuer);
    ok = ok && obj_set_str(obj, "sub", sub);
    ok = ok && obj_set_str(obj, "aud", audience);
    ok = ok && obj_set_num(obj, "exp", (double)claims->exp);
    ok = ok && obj_set_num(obj, "iat", (double)claims->iat);
    ok = ok && obj_set_num(obj, "nbf", (double)claims->nbf);
    ok = ok && obj_set_str(obj, "jti", claims->jti);
    ok = ok && obj_set_str(obj, "family_id", claims->family_id);

    if (ok) {
        ps_json_value_t *roles = ps_json_new_array();
        ok = roles != NULL;
        for (size_t i = 0; ok && i < ROLE_NAMES_COUNT; i++) {
            if ((claims->roles & ROLE_NAMES[i].bit) == 0) {
                continue;
            }
            ps_json_value_t *name = ps_json_new_string(ROLE_NAMES[i].name);
            ok = name != NULL && ps_json_array_append(roles, name);
            if (!ok) {
                ps_json_free(name);
            }
        }
        ok = ok && ps_json_object_set(obj, "roles", roles);
        if (!ok) {
            ps_json_free(roles);
        }
    }

    ok = ok && ps_json_write(obj, out);
    ps_json_free(obj);
    return ok;
}

static bool parse_int64_field(const ps_json_value_t *obj, const char *key, int64_t *out)
{
    ps_json_value_t *v = ps_json_object_get(obj, key);
    if (v == NULL || ps_json_type(v) != PS_JSON_NUMBER) {
        return false;
    }
    *out = (int64_t)ps_json_get_number(v);
    return true;
}

static bool parse_sub(const ps_json_value_t *obj, int64_t *out)
{
    ps_json_value_t *v = ps_json_object_get(obj, "sub");
    if (v == NULL || ps_json_type(v) != PS_JSON_STRING) {
        return false;
    }
    const char *s = ps_json_get_string(v);
    if (*s == '\0') {
        return false;
    }
    errno = 0;
    char     *end    = NULL;
    long long parsed = strtoll(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0') {
        return false;
    }
    *out = (int64_t)parsed;
    return true;
}

static bool parse_roles(const ps_json_value_t *obj, uint32_t *out)
{
    ps_json_value_t *arr = ps_json_object_get(obj, "roles");
    if (arr == NULL || ps_json_type(arr) != PS_JSON_ARRAY) {
        return false;
    }

    uint32_t roles = 0;
    size_t   n     = ps_json_array_count(arr);
    for (size_t i = 0; i < n; i++) {
        ps_json_value_t *item = ps_json_array_get(arr, i);
        if (ps_json_type(item) != PS_JSON_STRING) {
            return false;
        }
        const char *name    = ps_json_get_string(item);
        bool        matched = false;
        for (size_t j = 0; j < ROLE_NAMES_COUNT; j++) {
            if (strcmp(name, ROLE_NAMES[j].name) == 0) {
                roles |= ROLE_NAMES[j].bit;
                matched = true;
                break;
            }
        }
        if (!matched) {
            return false; /* unrecognized role name: fail closed */
        }
    }
    *out = roles;
    return true;
}

ps_claims_result_t ps_claims_parse(const char *json, size_t len,
                                   const char *issuer, const char *audience,
                                   int64_t now, int clock_skew_s,
                                   ps_jwt_claims_t *out)
{
    char              err[128];
    ps_json_value_t  *v = ps_json_parse(json, len, err, sizeof err);
    if (v == NULL || ps_json_type(v) != PS_JSON_OBJECT) {
        ps_json_free(v);
        return PS_CLAIMS_MALFORMED;
    }

    ps_json_value_t *iss_v       = ps_json_object_get(v, "iss");
    ps_json_value_t *aud_v       = ps_json_object_get(v, "aud");
    ps_json_value_t *jti_v       = ps_json_object_get(v, "jti");
    ps_json_value_t *family_id_v = ps_json_object_get(v, "family_id");
    if (iss_v == NULL || ps_json_type(iss_v) != PS_JSON_STRING ||
        aud_v == NULL || ps_json_type(aud_v) != PS_JSON_STRING ||
        jti_v == NULL || ps_json_type(jti_v) != PS_JSON_STRING ||
        ps_json_get_string_len(jti_v) != PS_JWT_JTI_HEX_LEN ||
        family_id_v == NULL || ps_json_type(family_id_v) != PS_JSON_STRING ||
        ps_json_get_string_len(family_id_v) != PS_JWT_FAMILY_ID_HEX_LEN) {
        ps_json_free(v);
        return PS_CLAIMS_MALFORMED;
    }

    int64_t  user_id, iat, nbf, exp;
    uint32_t roles = 0;
    bool structurally_ok =
        parse_sub(v, &user_id) &&
        parse_int64_field(v, "iat", &iat) &&
        parse_int64_field(v, "nbf", &nbf) &&
        parse_int64_field(v, "exp", &exp) &&
        parse_roles(v, &roles);

    if (!structurally_ok) {
        ps_json_free(v);
        return PS_CLAIMS_MALFORMED;
    }

    if (strcmp(ps_json_get_string(iss_v), issuer) != 0) {
        ps_json_free(v);
        return PS_CLAIMS_BAD_ISSUER;
    }
    if (strcmp(ps_json_get_string(aud_v), audience) != 0) {
        ps_json_free(v);
        return PS_CLAIMS_BAD_AUDIENCE;
    }
    if (now > exp + clock_skew_s) {
        ps_json_free(v);
        return PS_CLAIMS_EXPIRED;
    }
    if (now < nbf - clock_skew_s) {
        ps_json_free(v);
        return PS_CLAIMS_NOT_YET_VALID;
    }

    out->user_id = user_id;
    out->roles   = roles;
    out->iat     = iat;
    out->nbf     = nbf;
    out->exp     = exp;
    memcpy(out->jti, ps_json_get_string(jti_v), PS_JWT_JTI_HEX_LEN);
    out->jti[PS_JWT_JTI_HEX_LEN] = '\0';
    memcpy(out->family_id, ps_json_get_string(family_id_v), PS_JWT_FAMILY_ID_HEX_LEN);
    out->family_id[PS_JWT_FAMILY_ID_HEX_LEN] = '\0';

    ps_json_free(v);
    return PS_CLAIMS_OK;
}

uint32_t ps_claims_roles_from_names(const char names[][32], size_t count)
{
    uint32_t roles = 0;
    for (size_t i = 0; i < count; i++) {
        for (size_t j = 0; j < ROLE_NAMES_COUNT; j++) {
            if (strcmp(names[i], ROLE_NAMES[j].name) == 0) {
                roles |= ROLE_NAMES[j].bit;
                break;
            }
        }
    }
    return roles;
}

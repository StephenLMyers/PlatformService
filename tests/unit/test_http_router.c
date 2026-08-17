#include "testutil.h"

#include <stdio.h>
#include <string.h>

#include "http/router.h"

#define GET_HEALTHZ    1
#define GET_READYZ     2
#define GET_USER       3
#define GET_ADMIN_LIST 4
#define POST_LOGIN     5

static void build_router(ps_router_t *r)
{
    char err[256];
    ps_router_init(r);
    PS_CHECK(ps_router_add(r, "GET", "/healthz", GET_HEALTHZ, err, sizeof err));
    PS_CHECK(ps_router_add(r, "GET", "/readyz", GET_READYZ, err, sizeof err));
    PS_CHECK(ps_router_add(r, "GET", "/v1/users/{userId}", GET_USER, err, sizeof err));
    PS_CHECK(ps_router_add(r, "GET", "/v1/admin/users", GET_ADMIN_LIST, err, sizeof err));
    PS_CHECK(ps_router_add(r, "POST", "/v1/auth/login", POST_LOGIN, err, sizeof err));
}

static ps_route_match_result_t do_match(const ps_router_t *r, const char *method,
                                        const char *path, int *route_id,
                                        ps_route_params_t *params)
{
    return ps_router_match(r, method, strlen(method), path, strlen(path), route_id, params);
}

/* ------------------------------------------------------------------------- */

static void test_static_route_matches(void)
{
    ps_router_t r;
    build_router(&r);

    int                route_id = -1;
    ps_route_match_result_t rc = do_match(&r, "GET", "/healthz", &route_id, NULL);

    PS_CHECK_EQ_INT(rc, PS_ROUTE_MATCH);
    PS_CHECK_EQ_INT(route_id, GET_HEALTHZ);
}

static void test_unknown_path_is_not_found(void)
{
    ps_router_t r;
    build_router(&r);

    ps_route_match_result_t rc = do_match(&r, "GET", "/does/not/exist", NULL, NULL);
    PS_CHECK_EQ_INT(rc, PS_ROUTE_NOT_FOUND);
}

static void test_known_path_wrong_method_is_method_not_allowed(void)
{
    ps_router_t r;
    build_router(&r);

    ps_route_match_result_t rc = do_match(&r, "POST", "/healthz", NULL, NULL);
    PS_CHECK_EQ_INT(rc, PS_ROUTE_METHOD_NOT_ALLOWED);
}

static void test_path_param_captured(void)
{
    ps_router_t r;
    build_router(&r);

    int                route_id = -1;
    ps_route_params_t  params;
    ps_route_match_result_t rc = do_match(&r, "GET", "/v1/users/1234567890123", &route_id, &params);

    PS_CHECK_EQ_INT(rc, PS_ROUTE_MATCH);
    PS_CHECK_EQ_INT(route_id, GET_USER);
    PS_CHECK_EQ_INT(params.count, 1);

    const ps_route_param_t *p = ps_route_params_get(&params, "userId");
    PS_CHECK(p != NULL);
    PS_CHECK(strncmp(p->value, "1234567890123", p->value_len) == 0 &&
             p->value_len == strlen("1234567890123"));
}

static void test_path_param_does_not_match_empty_segment(void)
{
    ps_router_t r;
    build_router(&r);

    /* "/v1/users/" (trailing slash, empty segment) must not satisfy {userId} */
    ps_route_match_result_t rc = do_match(&r, "GET", "/v1/users/", NULL, NULL);
    PS_CHECK_EQ_INT(rc, PS_ROUTE_NOT_FOUND);
}

static void test_path_param_does_not_cross_segment_boundary(void)
{
    ps_router_t r;
    build_router(&r);

    /* A param captures exactly one segment -- "/v1/users/1/extra" must not
     * match "/v1/users/{userId}" (different segment counts). */
    ps_route_match_result_t rc = do_match(&r, "GET", "/v1/users/1/extra", NULL, NULL);
    PS_CHECK_EQ_INT(rc, PS_ROUTE_NOT_FOUND);
}

static void test_static_route_preferred_over_would_be_admin_list(void)
{
    ps_router_t r;
    build_router(&r);

    /* /v1/admin/users is a static route in this table, not a param route --
     * confirms exact literal segments are required, not just "same length". */
    int route_id = -1;
    ps_route_match_result_t rc = do_match(&r, "GET", "/v1/admin/users", &route_id, NULL);
    PS_CHECK_EQ_INT(rc, PS_ROUTE_MATCH);
    PS_CHECK_EQ_INT(route_id, GET_ADMIN_LIST);
}

static void test_root_path_matches_root_pattern(void)
{
    ps_router_t r;
    char        err[256];
    ps_router_init(&r);
    PS_CHECK(ps_router_add(&r, "GET", "/", 42, err, sizeof err));

    int route_id = -1;
    ps_route_match_result_t rc = do_match(&r, "GET", "/", &route_id, NULL);
    PS_CHECK_EQ_INT(rc, PS_ROUTE_MATCH);
    PS_CHECK_EQ_INT(route_id, 42);
}

static void test_params_get_missing_name_returns_null(void)
{
    ps_router_t r;
    build_router(&r);

    ps_route_params_t params;
    do_match(&r, "GET", "/v1/users/1", NULL, &params);
    PS_CHECK(ps_route_params_get(&params, "notAParam") == NULL);
}

static void test_add_rejects_pattern_without_leading_slash(void)
{
    ps_router_t r;
    char        err[256];
    ps_router_init(&r);
    PS_CHECK(!ps_router_add(&r, "GET", "healthz", 1, err, sizeof err));
    PS_CHECK(err[0] != '\0');
}

static void test_add_rejects_full_router(void)
{
    ps_router_t r;
    char        err[256];
    ps_router_init(&r);

    char pattern[32];
    for (int i = 0; i < PS_ROUTER_MAX_ROUTES; i++) {
        (void)snprintf(pattern, sizeof pattern, "/route%d", i);
        PS_CHECK(ps_router_add(&r, "GET", pattern, i, err, sizeof err));
    }
    PS_CHECK(!ps_router_add(&r, "GET", "/one-too-many", 999, err, sizeof err));
}

static void test_method_is_case_sensitive(void)
{
    ps_router_t r;
    build_router(&r);

    /* Lowercase "get" must not silently match "GET" -- HTTP methods are
     * case-sensitive tokens, and guessing here is exactly what the parser
     * (plan 7.2a) is designed never to do. */
    ps_route_match_result_t rc = do_match(&r, "get", "/healthz", NULL, NULL);
    PS_CHECK_EQ_INT(rc, PS_ROUTE_METHOD_NOT_ALLOWED);
}

int main(void)
{
    PS_RUN_TEST(test_static_route_matches);
    PS_RUN_TEST(test_unknown_path_is_not_found);
    PS_RUN_TEST(test_known_path_wrong_method_is_method_not_allowed);
    PS_RUN_TEST(test_path_param_captured);
    PS_RUN_TEST(test_path_param_does_not_match_empty_segment);
    PS_RUN_TEST(test_path_param_does_not_cross_segment_boundary);
    PS_RUN_TEST(test_static_route_preferred_over_would_be_admin_list);
    PS_RUN_TEST(test_root_path_matches_root_pattern);
    PS_RUN_TEST(test_params_get_missing_name_returns_null);
    PS_RUN_TEST(test_add_rejects_pattern_without_leading_slash);
    PS_RUN_TEST(test_add_rejects_full_router);
    PS_RUN_TEST(test_method_is_case_sensitive);

    PS_TEST_EXIT();
}

#include "testutil.h"

#include <string.h>

#include "json/json_parse.h"
#include "json/json_write.h"
#include "platform/buf.h"

/* Small helper: parse and require success, failing the test loudly if not. */
static ps_json_value_t *must_parse(const char *src)
{
    char err[256];
    ps_json_value_t *v = ps_json_parse(src, strlen(src), err, sizeof err);
    PS_CHECK(v != NULL);
    return v;
}

static void must_fail(const char *src)
{
    char err[256];
    ps_json_value_t *v = ps_json_parse(src, strlen(src), err, sizeof err);
    PS_CHECK(v == NULL);
    PS_CHECK(err[0] != '\0');
    ps_json_free(v);
}

/* ------------------------------------------------------------------------- */
/* Parsing -- scalars                                                        */
/* ------------------------------------------------------------------------- */

static void test_parse_null_true_false(void)
{
    ps_json_value_t *n = must_parse("null");
    PS_CHECK_EQ_INT(ps_json_type(n), PS_JSON_NULL);
    ps_json_free(n);

    ps_json_value_t *t = must_parse("true");
    PS_CHECK_EQ_INT(ps_json_type(t), PS_JSON_BOOL);
    PS_CHECK(ps_json_get_bool(t));
    ps_json_free(t);

    ps_json_value_t *f = must_parse("false");
    PS_CHECK_EQ_INT(ps_json_type(f), PS_JSON_BOOL);
    PS_CHECK(!ps_json_get_bool(f));
    ps_json_free(f);
}

static void test_parse_numbers(void)
{
    static const struct { const char *src; double want; } cases[] = {
        { "0", 0.0 },
        { "42", 42.0 },
        { "-17", -17.0 },
        { "3.5", 3.5 },
        { "-0.5", -0.5 },
        { "1e3", 1000.0 },
        { "1E3", 1000.0 },
        { "1.5e2", 150.0 },
        { "1e-2", 0.01 },
        { "2500", 2500.0 },
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        ps_json_value_t *v = must_parse(cases[i].src);
        PS_CHECK_EQ_INT(ps_json_type(v), PS_JSON_NUMBER);
        PS_CHECK(ps_json_get_number(v) == cases[i].want);
        ps_json_free(v);
    }
}

static void test_parse_rejects_malformed_numbers(void)
{
    must_fail("01");     /* leading zero */
    must_fail("+1");     /* leading plus */
    must_fail(".5");     /* no leading digit */
    must_fail("1.");     /* no digit after dot */
    must_fail("1e");     /* no digit after e */
    must_fail("-");      /* sign with nothing */
    must_fail("--1");
}

static void test_parse_whitespace_around_value_ok(void)
{
    ps_json_value_t *v = must_parse("  \t\n 42 \n ");
    PS_CHECK(ps_json_get_number(v) == 42.0);
    ps_json_free(v);
}

static void test_parse_empty_input_fails(void)
{
    must_fail("");
    must_fail("   ");
}

static void test_parse_trailing_garbage_fails(void)
{
    must_fail("42 43");
    must_fail("{} garbage");
    must_fail("nullx");
}

/* ------------------------------------------------------------------------- */
/* Parsing -- strings                                                        */
/* ------------------------------------------------------------------------- */

static void test_parse_basic_string(void)
{
    ps_json_value_t *v = must_parse("\"hello\"");
    PS_CHECK_EQ_INT(ps_json_type(v), PS_JSON_STRING);
    PS_CHECK_STR_EQ(ps_json_get_string(v), "hello");
    PS_CHECK_EQ_INT(ps_json_get_string_len(v), 5);
    ps_json_free(v);
}

static void test_parse_short_escapes(void)
{
    ps_json_value_t *v = must_parse("\"a\\\"b\\\\c\\/d\\be\\ff\\ng\\rh\\ti\"");
    PS_CHECK_STR_EQ(ps_json_get_string(v), "a\"b\\c/d\be\ff\ng\rh\ti");
    ps_json_free(v);
}

static void test_parse_unicode_escape_bmp(void)
{
    /* \u00e9 is e-acute, UTF-8 0xC3 0xA9 */
    ps_json_value_t *v = must_parse("\"caf\\u00e9\"");
    PS_CHECK_STR_EQ(ps_json_get_string(v), "caf\xc3\xa9");
    ps_json_free(v);
}

static void test_parse_unicode_surrogate_pair(void)
{
    /* U+1F600 GRINNING FACE = surrogate pair D83D DE00, UTF-8 F0 9F 98 80 */
    ps_json_value_t *v = must_parse("\"\\ud83d\\ude00\"");
    PS_CHECK_STR_EQ(ps_json_get_string(v), "\xf0\x9f\x98\x80");
    ps_json_free(v);
}

static void test_parse_rejects_unpaired_surrogate(void)
{
    must_fail("\"\\ud83d\"");        /* high surrogate, nothing follows */
    must_fail("\"\\ud83dx\"");       /* high surrogate, not followed by \u */
    must_fail("\"\\ude00\"");        /* lone low surrogate */
}

static void test_parse_rejects_control_char_in_string(void)
{
    char src[] = { '"', 'a', 0x01, 'b', '"', '\0' };
    must_fail(src);
}

static void test_parse_rejects_unterminated_string(void)
{
    must_fail("\"abc");
    must_fail("\"abc\\\"");
}

static void test_parse_rejects_invalid_escape(void)
{
    must_fail("\"\\x\"");
    must_fail("\"\\u12\"");   /* short hex */
}

/* ------------------------------------------------------------------------- */
/* Parsing -- arrays and objects                                             */
/* ------------------------------------------------------------------------- */

static void test_parse_empty_array_and_object(void)
{
    ps_json_value_t *a = must_parse("[]");
    PS_CHECK_EQ_INT(ps_json_type(a), PS_JSON_ARRAY);
    PS_CHECK_EQ_INT(ps_json_array_count(a), 0);
    ps_json_free(a);

    ps_json_value_t *o = must_parse("{}");
    PS_CHECK_EQ_INT(ps_json_type(o), PS_JSON_OBJECT);
    PS_CHECK_EQ_INT(ps_json_object_count(o), 0);
    ps_json_free(o);
}

static void test_parse_array_of_mixed_values(void)
{
    ps_json_value_t *a = must_parse("[1, \"two\", true, null, [3], {\"k\":4}]");
    PS_CHECK_EQ_INT(ps_json_array_count(a), 6);
    PS_CHECK(ps_json_get_number(ps_json_array_get(a, 0)) == 1.0);
    PS_CHECK_STR_EQ(ps_json_get_string(ps_json_array_get(a, 1)), "two");
    PS_CHECK(ps_json_get_bool(ps_json_array_get(a, 2)));
    PS_CHECK_EQ_INT(ps_json_type(ps_json_array_get(a, 3)), PS_JSON_NULL);
    PS_CHECK_EQ_INT(ps_json_type(ps_json_array_get(a, 4)), PS_JSON_ARRAY);
    PS_CHECK_EQ_INT(ps_json_type(ps_json_array_get(a, 5)), PS_JSON_OBJECT);
    ps_json_free(a);
}

static void test_parse_object_fields(void)
{
    ps_json_value_t *o = must_parse("{\"username\":\"smyers\",\"userId\":1234567890123}");
    PS_CHECK_EQ_INT(ps_json_object_count(o), 2);
    PS_CHECK_STR_EQ(ps_json_get_string(ps_json_object_get(o, "username")), "smyers");
    PS_CHECK(ps_json_get_number(ps_json_object_get(o, "userId")) == 1234567890123.0);
    PS_CHECK(ps_json_object_get(o, "missing") == NULL);
    ps_json_free(o);
}

static void test_parse_duplicate_key_last_wins(void)
{
    ps_json_value_t *o = must_parse("{\"a\":1,\"a\":2}");
    PS_CHECK_EQ_INT(ps_json_object_count(o), 1);
    PS_CHECK(ps_json_get_number(ps_json_object_get(o, "a")) == 2.0);
    ps_json_free(o);
}

static void test_parse_rejects_trailing_comma(void)
{
    must_fail("[1,]");
    must_fail("{\"a\":1,}");
}

static void test_parse_rejects_missing_comma(void)
{
    must_fail("[1 2]");
    must_fail("{\"a\":1 \"b\":2}");
}

static void test_parse_rejects_bad_object_syntax(void)
{
    must_fail("{a:1}");       /* unquoted key */
    must_fail("{\"a\" 1}");   /* missing colon */
    must_fail("{\"a\":}");    /* missing value */
}

/* ------------------------------------------------------------------------- */
/* Depth limit                                                               */
/* ------------------------------------------------------------------------- */

static void build_nested_array(char *buf, size_t buflen, int depth)
{
    /* depth opening brackets, then depth closing brackets: "[[[...]]]" */
    size_t pos = 0;
    for (int i = 0; i < depth && pos < buflen - 1; i++) {
        buf[pos++] = '[';
    }
    for (int i = 0; i < depth && pos < buflen - 1; i++) {
        buf[pos++] = ']';
    }
    buf[pos] = '\0';
}

static void test_parse_depth_exactly_at_limit_succeeds(void)
{
    char src[128];
    build_nested_array(src, sizeof src, PS_JSON_MAX_DEPTH);
    ps_json_value_t *v = must_parse(src);
    ps_json_free(v);
}

static void test_parse_depth_over_limit_fails(void)
{
    char src[128];
    build_nested_array(src, sizeof src, PS_JSON_MAX_DEPTH + 1);
    must_fail(src);
}

/* ------------------------------------------------------------------------- */
/* Writing                                                                    */
/* ------------------------------------------------------------------------- */

static char *write_to_cstr(const ps_json_value_t *v, ps_buf_t *buf)
{
    ps_buf_init(buf);
    PS_CHECK(ps_json_write(v, buf));
    PS_CHECK(ps_buf_append_char(buf, '\0'));
    return buf->data;
}

static void test_write_scalars(void)
{
    ps_buf_t buf;

    ps_json_value_t *n = ps_json_new_null();
    PS_CHECK_STR_EQ(write_to_cstr(n, &buf), "null");
    ps_buf_free(&buf);
    ps_json_free(n);

    ps_json_value_t *t = ps_json_new_bool(true);
    PS_CHECK_STR_EQ(write_to_cstr(t, &buf), "true");
    ps_buf_free(&buf);
    ps_json_free(t);

    ps_json_value_t *num = ps_json_new_number(2500);
    PS_CHECK_STR_EQ(write_to_cstr(num, &buf), "2500");
    ps_buf_free(&buf);
    ps_json_free(num);
}

static void test_write_escapes_string(void)
{
    ps_json_value_t *s = ps_json_new_string("a\"b\\c\nd\te");
    ps_buf_t         buf;
    const char      *out = write_to_cstr(s, &buf);
    PS_CHECK_STR_EQ(out, "\"a\\\"b\\\\c\\nd\\te\"");
    ps_buf_free(&buf);
    ps_json_free(s);
}

static void test_write_escapes_control_char_as_u00xx(void)
{
    char             raw[] = { 0x01, '\0' };
    ps_json_value_t *s     = ps_json_new_string(raw);
    ps_buf_t         buf;
    const char      *out = write_to_cstr(s, &buf);
    PS_CHECK_STR_EQ(out, "\"\\u0001\"");
    ps_buf_free(&buf);
    ps_json_free(s);
}

static void test_write_non_finite_number_is_null(void)
{
    ps_json_value_t *v = ps_json_new_number(0.0 / 0.0); /* NaN */
    ps_buf_t         buf;
    const char      *out = write_to_cstr(v, &buf);
    PS_CHECK_STR_EQ(out, "null");
    ps_buf_free(&buf);
    ps_json_free(v);
}

static void test_write_object_and_array(void)
{
    ps_json_value_t *obj = ps_json_new_object();
    PS_CHECK(obj != NULL);
    PS_CHECK(ps_json_object_set(obj, "status", ps_json_new_string("ACTIVE")));

    ps_json_value_t *arr = ps_json_new_array();
    PS_CHECK(arr != NULL);
    PS_CHECK(ps_json_array_append(arr, ps_json_new_number(1)));
    PS_CHECK(ps_json_array_append(arr, ps_json_new_number(2)));
    PS_CHECK(ps_json_object_set(obj, "values", arr));

    ps_buf_t    buf;
    const char *out = write_to_cstr(obj, &buf);
    PS_CHECK_STR_EQ(out, "{\"status\":\"ACTIVE\",\"values\":[1,2]}");
    ps_buf_free(&buf);
    ps_json_free(obj);
}

/* ------------------------------------------------------------------------- */
/* Round trip                                                                 */
/* ------------------------------------------------------------------------- */

static void test_round_trip_parse_write_parse(void)
{
    const char *src =
        "{\"a\":1,\"b\":[true,false,null,\"x\\ny\"],\"c\":{\"nested\":3.5}}";

    ps_json_value_t *v1 = must_parse(src);

    ps_buf_t buf;
    ps_buf_init(&buf);
    PS_CHECK(ps_json_write(v1, &buf));

    char err[256];
    ps_json_value_t *v2 = ps_json_parse(buf.data, buf.len, err, sizeof err);
    PS_CHECK(v2 != NULL);

    PS_CHECK(ps_json_get_number(ps_json_object_get(v2, "a")) == 1.0);
    ps_json_value_t *b = ps_json_object_get(v2, "b");
    PS_CHECK_EQ_INT(ps_json_array_count(b), 4);
    PS_CHECK_STR_EQ(ps_json_get_string(ps_json_array_get(b, 3)), "x\ny");
    ps_json_value_t *c = ps_json_object_get(v2, "c");
    PS_CHECK(ps_json_get_number(ps_json_object_get(c, "nested")) == 3.5);

    ps_buf_free(&buf);
    ps_json_free(v1);
    ps_json_free(v2);
}

/* ------------------------------------------------------------------------- */
/* NULL-safety / type-safety of accessors                                    */
/* ------------------------------------------------------------------------- */

static void test_accessors_are_null_safe(void)
{
    PS_CHECK_EQ_INT(ps_json_type(NULL), PS_JSON_NULL);
    PS_CHECK(!ps_json_get_bool(NULL));
    PS_CHECK(ps_json_get_number(NULL) == 0.0);
    PS_CHECK(ps_json_get_string(NULL) == NULL);
    PS_CHECK_EQ_INT(ps_json_get_string_len(NULL), 0);
    PS_CHECK_EQ_INT(ps_json_array_count(NULL), 0);
    PS_CHECK(ps_json_array_get(NULL, 0) == NULL);
    PS_CHECK_EQ_INT(ps_json_object_count(NULL), 0);
    PS_CHECK(ps_json_object_get(NULL, "x") == NULL);
    ps_json_free(NULL); /* must not crash */
}

static void test_accessors_are_type_safe(void)
{
    ps_json_value_t *num = must_parse("42");
    /* Wrong-type access must return a safe default, not read the wrong
     * union member. */
    PS_CHECK(ps_json_get_string(num) == NULL);
    PS_CHECK(!ps_json_get_bool(num));
    PS_CHECK_EQ_INT(ps_json_array_count(num), 0);
    PS_CHECK(ps_json_array_get(num, 0) == NULL);
    PS_CHECK_EQ_INT(ps_json_object_count(num), 0);
    ps_json_free(num);
}

static void test_object_get_on_absent_key_chains_safely(void)
{
    ps_json_value_t *o = must_parse("{\"present\":\"x\"}");
    /* The normal way to read an optional field: chain straight through. */
    PS_CHECK(ps_json_get_string(ps_json_object_get(o, "absent")) == NULL);
    ps_json_free(o);
}

int main(void)
{
    PS_RUN_TEST(test_parse_null_true_false);
    PS_RUN_TEST(test_parse_numbers);
    PS_RUN_TEST(test_parse_rejects_malformed_numbers);
    PS_RUN_TEST(test_parse_whitespace_around_value_ok);
    PS_RUN_TEST(test_parse_empty_input_fails);
    PS_RUN_TEST(test_parse_trailing_garbage_fails);

    PS_RUN_TEST(test_parse_basic_string);
    PS_RUN_TEST(test_parse_short_escapes);
    PS_RUN_TEST(test_parse_unicode_escape_bmp);
    PS_RUN_TEST(test_parse_unicode_surrogate_pair);
    PS_RUN_TEST(test_parse_rejects_unpaired_surrogate);
    PS_RUN_TEST(test_parse_rejects_control_char_in_string);
    PS_RUN_TEST(test_parse_rejects_unterminated_string);
    PS_RUN_TEST(test_parse_rejects_invalid_escape);

    PS_RUN_TEST(test_parse_empty_array_and_object);
    PS_RUN_TEST(test_parse_array_of_mixed_values);
    PS_RUN_TEST(test_parse_object_fields);
    PS_RUN_TEST(test_parse_duplicate_key_last_wins);
    PS_RUN_TEST(test_parse_rejects_trailing_comma);
    PS_RUN_TEST(test_parse_rejects_missing_comma);
    PS_RUN_TEST(test_parse_rejects_bad_object_syntax);

    PS_RUN_TEST(test_parse_depth_exactly_at_limit_succeeds);
    PS_RUN_TEST(test_parse_depth_over_limit_fails);

    PS_RUN_TEST(test_write_scalars);
    PS_RUN_TEST(test_write_escapes_string);
    PS_RUN_TEST(test_write_escapes_control_char_as_u00xx);
    PS_RUN_TEST(test_write_non_finite_number_is_null);
    PS_RUN_TEST(test_write_object_and_array);

    PS_RUN_TEST(test_round_trip_parse_write_parse);

    PS_RUN_TEST(test_accessors_are_null_safe);
    PS_RUN_TEST(test_accessors_are_type_safe);
    PS_RUN_TEST(test_object_get_on_absent_key_chains_safely);

    PS_TEST_EXIT();
}

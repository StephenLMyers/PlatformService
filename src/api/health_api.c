#include "api/health_api.h"

#include "json/json_parse.h"

static ps_handler_result_t status_body(int status, const char *status_text)
{
    ps_handler_result_t result = { .status = status, .body = NULL, .no_store = false };

    ps_json_value_t *body = ps_json_new_object();
    if (body == NULL) {
        result.status = 500;
        return result;
    }

    ps_json_value_t *status_val = ps_json_new_string(status_text);
    if (status_val == NULL || !ps_json_object_set(body, "status", status_val)) {
        ps_json_free(status_val);
        ps_json_free(body);
        result.status = 500;
        return result;
    }

    result.body = body;
    return result;
}

ps_handler_result_t ps_health_handle_healthz(const ps_http_request_t *req,
                                             const ps_route_params_t *params,
                                             const ps_app_ctx_t *app_ctx)
{
    (void)req;
    (void)params;
    (void)app_ctx;
    return status_body(200, "ok");
}

ps_handler_result_t ps_health_handle_readyz(const ps_http_request_t *req,
                                            const ps_route_params_t *params,
                                            const ps_app_ctx_t *app_ctx)
{
    (void)req;
    (void)params;
    bool draining = (app_ctx != NULL && app_ctx->draining != NULL && *app_ctx->draining);
    return status_body(draining ? 503 : 200, draining ? "draining" : "ok");
}

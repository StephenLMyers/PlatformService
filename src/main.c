/*
 * PlatformService -- entry point.
 *
 * Phase 5 adds the data layer: a SQLite connection pool (migrated to the
 * current schema on first open) and a dedicated maintenance-sweep thread,
 * both opened before the listener so a database failure is caught before
 * any socket is bound, and both torn down as shutdown step 4 (plan 7.2a).
 *
 * Otherwise as before: load and validate configuration, install signal
 * handling, open a TLS listener, register the real route table, dispatch
 * accepted connections to a worker pool that actually parses/routes/
 * responds to HTTP requests, and shut down gracefully within a bounded
 * grace period. main.c is the one place allowed to depend on every layer
 * (platform, http/json, store, api) -- it's the composition root that
 * wires api/routes.c's concrete handlers into http/conn.c's generic
 * dispatch callback, so neither has to depend on the other directly.
 */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "api/rbac.h"
#include "api/routes.h"
#include "auth/bootstrap.h"
#include "auth/password.h"
#include "crypto/kdf_semaphore.h"
#include "platform/config.h"
#include "platform/log.h"
#include "platform/maintenance.h"
#include "platform/tls.h"
#include "server.h"
#include "store/db.h"

#define PS_VERSION "0.5.0-phase5"

typedef struct {
    const char *config_path;
    bool        dev_mode;
    bool        check_config;
    bool        show_help;
    bool        show_version;
    bool        dump_routes;
} ps_args_t;

/*
 * plan 8.3: "The service exposes its route table under a debug build
 * flag; the test reads it." Needs neither config nor a running service --
 * the policy table (api/rbac.c) is static data -- so this follows
 * --help/--version's "no environment needed at all" shape, not
 * --check-config's (which genuinely needs a loaded, validated config).
 * One tab-separated line per route: method, path pattern, policy kind,
 * required role ("NONE" when not applicable) -- deliberately plain text,
 * not JSON, matching ps_config_print's own precedent for debug output
 * meant to be read by a human or grepped/split by a test, not parsed as a
 * structured document.
 */
static const char *policy_kind_name(ps_policy_kind_t kind)
{
    switch (kind) {
    case PS_POLICY_PUBLIC:        return "PUBLIC";
    case PS_POLICY_AUTHENTICATED: return "AUTHENTICATED";
    case PS_POLICY_ROLE:          return "ROLE";
    case PS_POLICY_SELF_OR_ROLE:  return "SELF_OR_ROLE";
    }
    return "UNKNOWN"; /* unreachable: every ps_policy_kind_t is handled above */
}

static const char *required_role_name(uint32_t role_bit)
{
    if (role_bit == 0) {
        return "NONE";
    }
    if (role_bit == PS_JWT_ROLE_ADMIN) {
        return "ADMIN";
    }
    if (role_bit == PS_JWT_ROLE_USER) {
        return "USER";
    }
    return "UNKNOWN";
}

static void dump_routes(void)
{
    for (size_t i = 0; i < PS_RBAC_POLICIES_COUNT; i++) {
        const ps_route_policy_t *p = &PS_RBAC_POLICIES[i];
        (void)printf("%s\t%s\t%s\t%s\n", p->method, p->path_pattern,
                     policy_kind_name(p->kind), required_role_name(p->required_role));
    }
}

static void print_usage(const char *argv0)
{
    (void)printf(
        "PlatformService %s\n"
        "\n"
        "Usage: %s [options]\n"
        "\n"
        "Options:\n"
        "  -c, --config PATH   Read configuration from PATH (optional; every\n"
        "                      setting has a working default)\n"
        "      --dev           Enable dev mode: relaxed rate limits, verification\n"
        "                      links logged, dev outbox endpoint. Never for production.\n"
        "      --check-config  Load and validate configuration, print it, exit\n"
        "      --dump-routes   Print the route table and its RBAC policy, exit\n"
        "  -v, --version       Print version and exit\n"
        "  -h, --help          Print this help and exit\n"
        "\n"
        "Required environment:\n"
        "  PS_JWT_SECRET       HS256 signing key, at least %d bytes.\n"
        "                      Generate: openssl rand -base64 48\n"
        "\n"
        "First run only (when the database contains no administrator):\n"
        "  BOOTSTRAP_ADMIN_USERNAME\n"
        "  BOOTSTRAP_ADMIN_EMAIL\n"
        "  BOOTSTRAP_ADMIN_PASSWORD\n"
        "\n"
        "There is no default password. If these are absent on an\n"
        "administrator-less database, startup fails rather than creating an\n"
        "account whose credentials are public knowledge.\n",
        PS_VERSION, argv0, PS_JWT_SECRET_MIN);
}

static bool parse_args(int argc, char **argv, ps_args_t *args,
                       char *err, size_t errlen)
{
    memset(args, 0, sizeof *args);

    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];

        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            args->show_help = true;
        } else if (strcmp(a, "-v") == 0 || strcmp(a, "--version") == 0) {
            args->show_version = true;
        } else if (strcmp(a, "--dev") == 0) {
            args->dev_mode = true;
        } else if (strcmp(a, "--check-config") == 0) {
            args->check_config = true;
        } else if (strcmp(a, "--dump-routes") == 0) {
            args->dump_routes = true;
        } else if (strcmp(a, "-c") == 0 || strcmp(a, "--config") == 0) {
            if (i + 1 >= argc) {
                (void)snprintf(err, errlen, "%s requires a path argument", a);
                return false;
            }
            args->config_path = argv[++i];
        } else {
            (void)snprintf(err, errlen, "unknown option '%s' (try --help)", a);
            return false;
        }
    }
    return true;
}

/*
 * Block the signals we care about before any thread is created, so that every
 * thread inherits the mask and only the main thread ever receives them. This
 * is why the handler below can call anything it likes: sigwait runs in normal
 * thread context, not in an async-signal handler where almost nothing is legal.
 */
static bool install_signal_handling(sigset_t *waitset, char *err, size_t errlen)
{
    /*
     * SIGPIPE must be ignored, not caught. A client that disconnects
     * mid-response would otherwise kill the process outright.
     */
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) != 0) {
        (void)snprintf(err, errlen, "sigaction(SIGPIPE): %s", strerror(errno));
        return false;
    }

    sigemptyset(waitset);
    sigaddset(waitset, SIGINT);
    sigaddset(waitset, SIGTERM);
    sigaddset(waitset, SIGHUP);

    int rc = pthread_sigmask(SIG_BLOCK, waitset, NULL);
    if (rc != 0) {
        (void)snprintf(err, errlen, "pthread_sigmask: %s", strerror(rc));
        return false;
    }
    return true;
}

static const char *signal_name(int sig)
{
    switch (sig) {
    case SIGINT:  return "SIGINT";
    case SIGTERM: return "SIGTERM";
    case SIGHUP:  return "SIGHUP";
    default:      return "signal";
    }
}

static void *acceptor_thread_fn(void *arg)
{
    ps_server_run((ps_server_t *)arg);
    return NULL;
}

int main(int argc, char **argv)
{
    ps_args_t   args;
    ps_config_t cfg;
    char        err[512] = { 0 };
    int         exit_code = EXIT_FAILURE;
    bool        cfg_loaded = false;

    /* Log early at INFO so argument and config failures are visible. */
    ps_log_init(PS_LOG_INFO, isatty(STDERR_FILENO) == 1);

    if (!parse_args(argc, argv, &args, err, sizeof err)) {
        PS_ERROR("%s", err);
        goto cleanup;
    }

    if (args.show_help) {
        print_usage(argv[0]);
        exit_code = EXIT_SUCCESS;
        goto cleanup;
    }
    if (args.show_version) {
        (void)printf("%s\n", PS_VERSION);
        exit_code = EXIT_SUCCESS;
        goto cleanup;
    }
    if (args.dump_routes) {
        dump_routes();
        exit_code = EXIT_SUCCESS;
        goto cleanup;
    }

    if (!ps_config_load(&cfg, args.config_path, err, sizeof err)) {
        PS_ERROR("configuration error: %s", err);
        goto cleanup;
    }
    cfg_loaded = true;

    /* A --dev flag on the command line wins over the file/env setting. */
    if (args.dev_mode) {
        cfg.dev_mode = true;
    }

    ps_log_set_level(cfg.log_level);

    PS_INFO("PlatformService %s starting", PS_VERSION);

    if (cfg.dev_mode) {
        PS_WARN("dev mode is ENABLED -- relaxed rate limits and verification "
                "links in the log. Never enable this in production.");
    }

    if (args.check_config) {
        ps_config_print(&cfg);
        PS_INFO("configuration is valid");
        exit_code = EXIT_SUCCESS;
        goto cleanup;
    }

    ps_config_print(&cfg);

    sigset_t waitset;
    if (!install_signal_handling(&waitset, err, sizeof err)) {
        PS_ERROR("%s", err);
        goto cleanup;
    }

    if (!cfg.tls_enabled) {
        PS_ERROR("tls.enabled=false: no plaintext mode is implemented yet "
                 "(plan R1); refusing to start");
        goto cleanup;
    }

    ps_router_t router;
    if (!ps_routes_register(&router, err, sizeof err)) {
        PS_ERROR("failed to register routes: %s", err);
        goto cleanup;
    }

    /* Wildcard-origin-plus-credentials is already refused at config load
     * (platform/config.c); this call also catches other misconfiguration
     * (e.g. too many origins) before any connection can ever be served.
     * Mutates cfg.cors_allowed_origins in place (plan http/cors.h) -- safe
     * here since nothing reads it as a CSV string again afterward. */
    ps_cors_policy_t cors_policy;
    if (!ps_cors_policy_init(&cors_policy, cfg.cors_allowed_origins,
                             cfg.cors_allow_credentials, err, sizeof err)) {
        PS_ERROR("invalid CORS configuration: %s", err);
        goto cleanup;
    }

    /* DB pool sized to worker_threads too (0 = one per CPU, resolved
     * independently by each -- see db.c). Opened before the listener so a
     * database failure is caught before any socket is bound (plan 5). */
    ps_db_pool_t *db_pool = ps_db_pool_create(cfg.db_path, cfg.worker_threads,
                                              cfg.db_busy_timeout_ms, err, sizeof err);
    if (db_pool == NULL) {
        PS_ERROR("failed to open database: %s", err);
        goto cleanup;
    }

    /* Loaded once, read-only for the rest of the process (plan 6.6). NULL
     * is a valid ps_password_policy_check argument (breach checking
     * skipped, length bounds still enforced), so a missing/unreadable
     * file is a hard startup failure rather than a silent downgrade --
     * the file is a tracked, committed asset (plan 6.6); its absence
     * means something is wrong with the deployment, not an optional
     * feature that's simply unavailable. */
    ps_password_denylist_t denylist;
    if (!ps_password_denylist_load(cfg.common_passwords_path, &denylist, err, sizeof err)) {
        PS_ERROR("failed to load breach denylist: %s", err);
        ps_db_pool_destroy(db_pool);
        goto cleanup;
    }

    /* capacity 0 = one per CPU (plan 7.7: "roughly cpu_count"), the same
     * convention as db_pool/threadpool above. */
    ps_kdf_semaphore_t *kdf_semaphore = ps_kdf_semaphore_create(0, err, sizeof err);
    if (kdf_semaphore == NULL) {
        PS_ERROR("failed to create KDF semaphore: %s", err);
        ps_password_denylist_free(&denylist);
        ps_db_pool_destroy(db_pool);
        goto cleanup;
    }

    /* D11: idempotent, runs every boot (not just against a fresh
     * database) so an admin accidentally deleted can be recovered by
     * restart -- see auth/bootstrap.h. */
    {
        sqlite3 *bootstrap_conn = ps_db_pool_acquire(db_pool);
        ps_bootstrap_result_t bootstrap_result = ps_bootstrap_admin(
            bootstrap_conn, &cfg, cfg.kdf_iterations, &denylist, time(NULL), err, sizeof err);
        ps_db_pool_release(db_pool, bootstrap_conn);
        if (bootstrap_result != PS_BOOTSTRAP_OK) {
            PS_ERROR("admin bootstrap failed: %s", err);
            ps_kdf_semaphore_destroy(kdf_semaphore);
            ps_password_denylist_free(&denylist);
            ps_db_pool_destroy(db_pool);
            goto cleanup;
        }
    }

    /* Its own connection, independent of db_pool (plan 3.4) -- a slow sweep
     * must never compete with a request-handling worker for a connection. */
    ps_maintenance_t *maintenance = ps_maintenance_start(
        cfg.db_path, cfg.db_busy_timeout_ms, cfg.maintenance_interval_s,
        cfg.maintenance_batch_size, cfg.audit_retention_days, err, sizeof err);
    if (maintenance == NULL) {
        PS_ERROR("failed to start maintenance thread: %s", err);
        ps_kdf_semaphore_destroy(kdf_semaphore);
        ps_password_denylist_free(&denylist);
        ps_db_pool_destroy(db_pool);
        goto cleanup;
    }

    ps_server_t server;
    server.draining = false;
    server.cors     = &cors_policy;

    if (!ps_listener_open(&server.listener, cfg.bind_address, cfg.port,
                          cfg.accept_queue_depth, err, sizeof err)) {
        PS_ERROR("failed to open listener: %s", err);
        ps_maintenance_stop(maintenance);
        ps_kdf_semaphore_destroy(kdf_semaphore);
        ps_password_denylist_free(&denylist);
        ps_db_pool_destroy(db_pool);
        goto cleanup;
    }

    server.tls_ctx = ps_tls_ctx_create(cfg.tls_cert_path, cfg.tls_key_path, err, sizeof err);
    if (server.tls_ctx == NULL) {
        PS_ERROR("failed to initialize TLS: %s", err);
        ps_listener_close(&server.listener);
        ps_maintenance_stop(maintenance);
        ps_kdf_semaphore_destroy(kdf_semaphore);
        ps_password_denylist_free(&denylist);
        ps_db_pool_destroy(db_pool);
        goto cleanup;
    }

    /* worker_threads/accept_queue_depth double as both the thread pool size
     * and its job queue capacity -- the config file has one knob for each,
     * not a separate pair per consumer. */
    server.pool = ps_threadpool_create(cfg.worker_threads, cfg.accept_queue_depth,
                                       err, sizeof err);
    if (server.pool == NULL) {
        PS_ERROR("failed to start worker pool: %s", err);
        ps_tls_ctx_free(server.tls_ctx);
        ps_listener_close(&server.listener);
        ps_maintenance_stop(maintenance);
        ps_kdf_semaphore_destroy(kdf_semaphore);
        ps_password_denylist_free(&denylist);
        ps_db_pool_destroy(db_pool);
        goto cleanup;
    }

    server.conn_limits.read_timeout_s         = cfg.read_timeout_s;
    server.conn_limits.write_timeout_s        = cfg.write_timeout_s;
    server.conn_limits.keepalive_max_requests = cfg.keepalive_max_requests;
    server.conn_limits.http_limits.max_request_line_bytes = cfg.max_request_line_bytes;
    server.conn_limits.http_limits.max_header_bytes       = cfg.max_header_bytes;
    server.conn_limits.http_limits.max_header_count       = cfg.max_header_count;
    server.conn_limits.http_limits.max_body_bytes         = cfg.max_body_bytes;

    ps_app_ctx_t app_ctx = {
        .draining          = &server.draining,
        .db_pool           = db_pool,
        .kdf_semaphore     = kdf_semaphore,
        .password_denylist = &denylist,
        .config            = &cfg,
    };
    server.router   = &router;
    server.dispatch = ps_routes_dispatch;
    server.app_ctx  = &app_ctx;

    pthread_t acceptor_thread;
    int       prc = pthread_create(&acceptor_thread, NULL, acceptor_thread_fn, &server);
    if (prc != 0) {
        PS_ERROR("pthread_create: %s", strerror(prc));
        ps_threadpool_shutdown(server.pool, false);
        ps_threadpool_destroy(server.pool);
        ps_tls_ctx_free(server.tls_ctx);
        ps_listener_close(&server.listener);
        ps_maintenance_stop(maintenance);
        ps_kdf_semaphore_destroy(kdf_semaphore);
        ps_password_denylist_free(&denylist);
        ps_db_pool_destroy(db_pool);
        goto cleanup;
    }

    PS_INFO("listening on %s:%u (TLS)", cfg.bind_address, (unsigned)cfg.port);
    PS_INFO("send SIGTERM or press Ctrl-C to shut down");

    int sig = 0;
    int rc  = sigwait(&waitset, &sig);
    if (rc != 0) {
        PS_ERROR("sigwait: %s", strerror(rc));
        /* The server is fully up; tear it down the same way a signal would. */
        (void)ps_server_shutdown(&server, cfg.shutdown_grace_s);
        (void)pthread_join(acceptor_thread, NULL);
        ps_listener_close(&server.listener);
        ps_maintenance_stop(maintenance);
        ps_kdf_semaphore_destroy(kdf_semaphore);
        ps_password_denylist_free(&denylist);
        ps_db_pool_destroy(db_pool);
        goto cleanup;
    }

    PS_INFO("received %s, shutting down", signal_name(sig));

    /*
     * Shutdown order matters and is fixed here deliberately (plan 7.2a):
     *   1. fail readiness so the load balancer stops sending new traffic
     *   2. stop accepting, keep draining in-flight requests
     *   3. wait up to shutdown_grace_s for workers
     *   4. checkpoint and close the database, free the TLS context
     * The maintenance thread is independent of the request-handling pool
     * (its own thread, its own connection), so it stops unconditionally
     * regardless of whether step 3 drained in time.
     */
    bool drained = ps_server_shutdown(&server, cfg.shutdown_grace_s);
    (void)pthread_join(acceptor_thread, NULL);
    ps_listener_close(&server.listener); /* safe only now the acceptor has actually exited */
    ps_maintenance_stop(maintenance);

    if (drained) {
        ps_tls_ctx_free(server.tls_ctx);
        ps_kdf_semaphore_destroy(kdf_semaphore);
        ps_password_denylist_free(&denylist);
        ps_db_pool_destroy(db_pool);
        PS_INFO("shutdown complete");
    } else {
        /* server.pool is deliberately left running and unfreed here -- see
         * ps_server_shutdown's contract. db_pool, kdf_semaphore, and
         * denylist are left alone for the same reason: a straggler worker
         * could still be mid-request, using any of them. Process exit
         * reclaims all of it. */
        PS_WARN("shutdown grace period (%ds) exceeded; exiting with work "
                "still in flight", cfg.shutdown_grace_s);
    }
    exit_code = EXIT_SUCCESS;

cleanup:
    if (cfg_loaded) {
        ps_config_free(&cfg);
    }
    ps_log_shutdown();
    return exit_code;
}

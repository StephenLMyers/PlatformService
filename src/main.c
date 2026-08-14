/*
 * PlatformService -- entry point.
 *
 * Phase 1 scope: start up, load and validate configuration, install signal
 * handling, then shut down cleanly. The listener, TLS, and request handling
 * arrive in phases 2-3; the shutdown sequence below is already shaped to
 * accommodate them (plan 7.2a).
 */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "platform/config.h"
#include "platform/log.h"

#define PS_VERSION "0.1.0-phase1"

typedef struct {
    const char *config_path;
    bool        dev_mode;
    bool        check_config;
    bool        show_help;
    bool        show_version;
} ps_args_t;

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

    /*
     * Phases 2-3 start the listener, TLS context, thread pool, and maintenance
     * thread here. Until then startup is complete at this point.
     */
    PS_INFO("startup complete; listening is not yet implemented (phase 1)");
    PS_INFO("send SIGTERM or press Ctrl-C to shut down");

    int sig = 0;
    int rc  = sigwait(&waitset, &sig);
    if (rc != 0) {
        PS_ERROR("sigwait: %s", strerror(rc));
        goto cleanup;
    }

    PS_INFO("received %s, shutting down", signal_name(sig));

    /*
     * Shutdown order matters and is fixed here deliberately (plan 7.2a):
     *   1. fail readiness so the load balancer stops sending new traffic
     *   2. stop accepting, keep draining in-flight requests
     *   3. wait up to shutdown_grace_s for workers
     *   4. checkpoint and close the database, free the TLS context
     * Steps 1-3 become real in phases 2-3; step 4 in phase 5.
     */
    PS_DEBUG("shutdown grace period is %ds", cfg.shutdown_grace_s);
    PS_INFO("shutdown complete");
    exit_code = EXIT_SUCCESS;

cleanup:
    if (cfg_loaded) {
        ps_config_free(&cfg);
    }
    ps_log_shutdown();
    return exit_code;
}

#include "testutil.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "platform/net.h"

/* Port 0 asks the kernel for an ephemeral port, so tests never collide. */
static uint16_t bound_port(int listen_fd)
{
    struct sockaddr_in addr;
    socklen_t          len = sizeof addr;
    PS_CHECK(getsockname(listen_fd, (struct sockaddr *)&addr, &len) == 0);
    return ntohs(addr.sin_port);
}

static int connect_loopback(uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof addr);
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    (void)inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);

    if (connect(fd, (struct sockaddr *)&addr, sizeof addr) != 0) {
        (void)close(fd);
        return -1;
    }
    return fd;
}

static double elapsed_seconds(struct timeval start, struct timeval end)
{
    return (double)(end.tv_sec - start.tv_sec) +
           (double)(end.tv_usec - start.tv_usec) / 1e6;
}

/* ------------------------------------------------------------------------- */

static void test_open_and_close_lifecycle(void)
{
    ps_listener_t l;
    char          err[256];

    PS_CHECK(ps_listener_open(&l, "127.0.0.1", 0, 16, err, sizeof err));
    PS_CHECK(l.listen_fd >= 0);
    PS_CHECK(l.shutdown_fd >= 0);
    PS_CHECK(!ps_listener_stopping(&l));

    ps_listener_close(&l);
}

static void test_hostname_is_rejected(void)
{
    ps_listener_t l;
    char          err[256];

    PS_CHECK(!ps_listener_open(&l, "localhost", 0, 16, err, sizeof err));
    PS_CHECK(strstr(err, "not resolved") != NULL);
}

static void test_garbage_address_is_rejected(void)
{
    ps_listener_t l;
    char          err[256];

    PS_CHECK(!ps_listener_open(&l, "not-an-address", 0, 16, err, sizeof err));
}

static void test_double_bind_same_port_fails(void)
{
    ps_listener_t first;
    char          err[256];
    PS_CHECK(ps_listener_open(&first, "127.0.0.1", 0, 16, err, sizeof err));

    uint16_t port = bound_port(first.listen_fd);

    ps_listener_t second;
    bool ok = ps_listener_open(&second, "127.0.0.1", port, 16, err, sizeof err);
    PS_CHECK(!ok);

    ps_listener_close(&first);
    if (ok) {
        ps_listener_close(&second);
    }
}

static void test_accept_returns_connected_client(void)
{
    ps_listener_t l;
    char          err[256];
    PS_CHECK(ps_listener_open(&l, "127.0.0.1", 0, 16, err, sizeof err));
    uint16_t port = bound_port(l.listen_fd);

    int client = connect_loopback(port);
    PS_CHECK(client >= 0);

    int  server_side = -1;
    char peer[PS_PEER_MAX];
    ps_accept_result_t rc = ps_listener_accept(&l, &server_side, peer, sizeof peer,
                                               err, sizeof err);

    PS_CHECK_EQ_INT(rc, PS_ACCEPT_OK);
    PS_CHECK(server_side >= 0);
    PS_CHECK(strncmp(peer, "127.0.0.1:", strlen("127.0.0.1:")) == 0);

    if (client >= 0) {
        (void)close(client);
    }
    if (server_side >= 0) {
        (void)close(server_side);
    }
    ps_listener_close(&l);
}

static void test_accept_after_stop_returns_immediately(void)
{
    ps_listener_t l;
    char          err[256];
    PS_CHECK(ps_listener_open(&l, "127.0.0.1", 0, 16, err, sizeof err));

    ps_listener_stop(&l);
    PS_CHECK(ps_listener_stopping(&l));

    int fd = -1;
    ps_accept_result_t rc = ps_listener_accept(&l, &fd, NULL, 0, err, sizeof err);
    PS_CHECK_EQ_INT(rc, PS_ACCEPT_SHUTDOWN);
    PS_CHECK_EQ_INT(fd, -1);

    ps_listener_close(&l);
}

typedef struct {
    ps_listener_t      *l;
    ps_accept_result_t  result;
} accept_thread_arg_t;

static void *accept_thread_fn(void *arg)
{
    accept_thread_arg_t *a = arg;
    int  fd = -1;
    char err[256];
    a->result = ps_listener_accept(a->l, &fd, NULL, 0, err, sizeof err);
    if (fd >= 0) {
        (void)close(fd);
    }
    return NULL;
}

/*
 * The property the eventfd exists for: a thread genuinely blocked in
 * ps_listener_accept (no client ever connects) is woken promptly by
 * ps_listener_stop from a different thread, not by a timeout.
 */
static void test_stop_interrupts_a_blocked_accept(void)
{
    ps_listener_t l;
    char          err[256];
    PS_CHECK(ps_listener_open(&l, "127.0.0.1", 0, 16, err, sizeof err));

    accept_thread_arg_t arg = { .l = &l, .result = PS_ACCEPT_ERROR };
    pthread_t            t;
    PS_CHECK(pthread_create(&t, NULL, accept_thread_fn, &arg) == 0);

    /* Give the thread a real chance to reach poll() and block there. */
    struct timespec nap = { .tv_sec = 0, .tv_nsec = 100 * 1000 * 1000 };
    nanosleep(&nap, NULL);

    struct timeval start, end;
    (void)gettimeofday(&start, NULL);
    ps_listener_stop(&l);
    PS_CHECK(pthread_join(t, NULL) == 0);
    (void)gettimeofday(&end, NULL);

    PS_CHECK_EQ_INT(arg.result, PS_ACCEPT_SHUTDOWN);
    PS_CHECK(elapsed_seconds(start, end) < 1.0);

    ps_listener_close(&l);
}

static void test_write_all_round_trips_exact_bytes(void)
{
    int fds[2];
    PS_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    const char *msg = "hello platformservice";
    PS_CHECK(ps_write_all(fds[0], msg, strlen(msg)));

    char buf[64] = { 0 };
    ssize_t n = read(fds[1], buf, sizeof buf - 1);
    PS_CHECK(n == (ssize_t)strlen(msg));
    PS_CHECK_STR_EQ(buf, msg);

    (void)close(fds[0]);
    (void)close(fds[1]);
}

static void test_write_all_fails_on_closed_peer(void)
{
    int fds[2];
    PS_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
    (void)close(fds[1]); /* peer gone before we write */

    /* Requires SIGPIPE ignored process-wide, same precondition main.c
     * establishes before any network code runs (plan 7.2a). */
    bool ok = ps_write_all(fds[0], "x", 1);
    PS_CHECK(!ok);

    (void)close(fds[0]);
}

static void test_set_timeouts_on_valid_socket(void)
{
    int fds[2];
    PS_CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);

    char err[256];
    PS_CHECK(ps_socket_set_timeouts(fds[0], 5, 5, err, sizeof err));

    (void)close(fds[0]);
    (void)close(fds[1]);
}

static void test_set_timeouts_on_bad_fd_fails(void)
{
    char err[256];
    PS_CHECK(!ps_socket_set_timeouts(-1, 5, 5, err, sizeof err));
}

int main(void)
{
    /* Exercising sockets whose peer may vanish mid-test; a default SIGPIPE
     * would kill the whole test binary rather than fail one assertion. */
    signal(SIGPIPE, SIG_IGN);

    PS_RUN_TEST(test_open_and_close_lifecycle);
    PS_RUN_TEST(test_hostname_is_rejected);
    PS_RUN_TEST(test_garbage_address_is_rejected);
    PS_RUN_TEST(test_double_bind_same_port_fails);
    PS_RUN_TEST(test_accept_returns_connected_client);
    PS_RUN_TEST(test_accept_after_stop_returns_immediately);
    PS_RUN_TEST(test_stop_interrupts_a_blocked_accept);
    PS_RUN_TEST(test_write_all_round_trips_exact_bytes);
    PS_RUN_TEST(test_write_all_fails_on_closed_peer);
    PS_RUN_TEST(test_set_timeouts_on_valid_socket);
    PS_RUN_TEST(test_set_timeouts_on_bad_fd_fails);

    PS_TEST_EXIT();
}

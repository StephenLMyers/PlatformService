#include "platform/net.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static bool build_bind_addr(const char *bind_addr, uint16_t port,
                            struct sockaddr_storage *ss, socklen_t *sslen,
                            char *err, size_t errlen)
{
    memset(ss, 0, sizeof *ss);

    struct sockaddr_in *v4 = (struct sockaddr_in *)ss;
    if (inet_pton(AF_INET, bind_addr, &v4->sin_addr) == 1) {
        v4->sin_family = AF_INET;
        v4->sin_port   = htons(port);
        *sslen = sizeof *v4;
        return true;
    }

    struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)ss;
    if (inet_pton(AF_INET6, bind_addr, &v6->sin6_addr) == 1) {
        v6->sin6_family = AF_INET6;
        v6->sin6_port   = htons(port);
        *sslen = sizeof *v6;
        return true;
    }

    (void)snprintf(err, errlen,
                   "'%s' is not a numeric IPv4/IPv6 address; hostnames are "
                   "deliberately not resolved", bind_addr);
    return false;
}

static void format_peer(const struct sockaddr_storage *ss, socklen_t sslen,
                        char *peer, size_t peerlen)
{
    char host[NI_MAXHOST];
    char serv[NI_MAXSERV];

    int rc = getnameinfo((const struct sockaddr *)ss, sslen,
                         host, sizeof host, serv, sizeof serv,
                         NI_NUMERICHOST | NI_NUMERICSERV);
    if (rc != 0) {
        (void)snprintf(peer, peerlen, "unknown");
        return;
    }

    if (ss->ss_family == AF_INET6) {
        (void)snprintf(peer, peerlen, "[%s]:%s", host, serv);
    } else {
        (void)snprintf(peer, peerlen, "%s:%s", host, serv);
    }
}

bool ps_listener_open(ps_listener_t *l, const char *bind_addr, uint16_t port,
                      int backlog, char *err, size_t errlen)
{
    memset(l, 0, sizeof *l);
    l->listen_fd   = -1;
    l->shutdown_fd = -1;

    struct sockaddr_storage ss;
    socklen_t                sslen;
    if (!build_bind_addr(bind_addr, port, &ss, &sslen, err, errlen)) {
        return false;
    }

    /*
     * SOCK_NONBLOCK closes the classic accept() race: poll() reporting
     * readable is a hint, not a guarantee -- a connection can be reset
     * between the two calls on some paths. A nonblocking listen socket turns
     * that race into a plain EAGAIN, handled below, instead of a stall.
     */
    int fd = socket(ss.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        (void)snprintf(err, errlen, "socket: %s", strerror(errno));
        return false;
    }

    int one = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) != 0) {
        (void)snprintf(err, errlen, "setsockopt(SO_REUSEADDR): %s", strerror(errno));
        (void)close(fd);
        return false;
    }

    if (bind(fd, (struct sockaddr *)&ss, sslen) != 0) {
        (void)snprintf(err, errlen, "bind(%s:%u): %s",
                       bind_addr, (unsigned)port, strerror(errno));
        (void)close(fd);
        return false;
    }

    if (listen(fd, backlog) != 0) {
        (void)snprintf(err, errlen, "listen: %s", strerror(errno));
        (void)close(fd);
        return false;
    }

    int efd = eventfd(0, EFD_CLOEXEC);
    if (efd < 0) {
        (void)snprintf(err, errlen, "eventfd: %s", strerror(errno));
        (void)close(fd);
        return false;
    }

    l->listen_fd   = fd;
    l->shutdown_fd = efd;
    /* Plain store: l is not yet visible to any other thread at this point. */
    l->stopping    = 0;
    return true;
}

ps_accept_result_t ps_listener_accept(ps_listener_t *l, int *client_fd,
                                      char *peer, size_t peerlen,
                                      char *err, size_t errlen)
{
    *client_fd = -1;
    if (peer != NULL && peerlen > 0) {
        peer[0] = '\0';
    }

    if (__atomic_load_n(&l->stopping, __ATOMIC_SEQ_CST)) {
        return PS_ACCEPT_SHUTDOWN;
    }

    struct pollfd pfds[2];
    pfds[0].fd     = l->listen_fd;
    pfds[0].events = POLLIN;
    pfds[1].fd     = l->shutdown_fd;
    pfds[1].events = POLLIN;

    for (;;) {
        pfds[0].revents = 0;
        pfds[1].revents = 0;

        int rc = poll(pfds, 2, -1);
        if (rc < 0) {
            if (errno == EINTR) {
                continue;
            }
            (void)snprintf(err, errlen, "poll: %s", strerror(errno));
            return PS_ACCEPT_ERROR;
        }

        if (pfds[1].revents & POLLIN) {
            return PS_ACCEPT_SHUTDOWN;
        }

        if (pfds[0].revents & (POLLERR | POLLHUP | POLLNVAL)) {
            (void)snprintf(err, errlen, "listener socket in error state");
            return PS_ACCEPT_ERROR;
        }

        if (!(pfds[0].revents & POLLIN)) {
            continue;
        }

        struct sockaddr_storage ss;
        socklen_t                sslen = sizeof ss;
        int fd = accept4(l->listen_fd, (struct sockaddr *)&ss, &sslen, SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNABORTED ||
                errno == EINTR || errno == EPROTO) {
                continue;
            }
            (void)snprintf(err, errlen, "accept4: %s", strerror(errno));
            return PS_ACCEPT_ERROR;
        }

        if (peer != NULL && peerlen > 0) {
            format_peer(&ss, sslen, peer, peerlen);
        }

        *client_fd = fd;
        return PS_ACCEPT_OK;
    }
}

void ps_listener_stop(ps_listener_t *l)
{
    __atomic_store_n(&l->stopping, 1, __ATOMIC_SEQ_CST);

    /*
     * Wakes any thread blocked in poll() inside ps_listener_accept, from any
     * calling thread -- this is the only reason shutdown_fd exists. A failed
     * write here means the listener is already gone or racing a close;
     * accept() still checks l->stopping first on every call.
     */
    uint64_t one = 1;
    ssize_t  wr  = write(l->shutdown_fd, &one, sizeof one);
    (void)wr;
}

bool ps_listener_stopping(const ps_listener_t *l)
{
    return __atomic_load_n(&l->stopping, __ATOMIC_SEQ_CST) != 0;
}

void ps_listener_close(ps_listener_t *l)
{
    if (l->listen_fd >= 0) {
        (void)close(l->listen_fd);
        l->listen_fd = -1;
    }
    if (l->shutdown_fd >= 0) {
        (void)close(l->shutdown_fd);
        l->shutdown_fd = -1;
    }
}

bool ps_socket_set_timeouts(int fd, int read_timeout_s, int write_timeout_s,
                            char *err, size_t errlen)
{
    if (read_timeout_s > 0) {
        struct timeval tv = { .tv_sec = read_timeout_s, .tv_usec = 0 };
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv) != 0) {
            (void)snprintf(err, errlen, "setsockopt(SO_RCVTIMEO): %s", strerror(errno));
            return false;
        }
    }
    if (write_timeout_s > 0) {
        struct timeval tv = { .tv_sec = write_timeout_s, .tv_usec = 0 };
        if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv) != 0) {
            (void)snprintf(err, errlen, "setsockopt(SO_SNDTIMEO): %s", strerror(errno));
            return false;
        }
    }
    return true;
}

bool ps_write_all(int fd, const void *buf, size_t len)
{
    const unsigned char *p         = buf;
    size_t                remaining = len;

    while (remaining > 0) {
        ssize_t n = write(fd, p, remaining);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        if (n == 0) {
            return false;
        }
        p         += (size_t)n;
        remaining -= (size_t)n;
    }
    return true;
}

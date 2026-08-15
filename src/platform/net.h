/*
 * Listening socket and accept loop.
 *
 * The listener owns two descriptors: the socket, and an eventfd used purely to
 * interrupt a blocked accept. Without that second descriptor there is no way
 * to wake a thread sitting in accept() -- signals are blocked in every thread
 * (see main.c), so accept never returns EINTR, and shutdown would hang until
 * some client happened to connect.
 */
#ifndef PS_PLATFORM_NET_H
#define PS_PLATFORM_NET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Room for "[ipv6-address]:port" plus terminator. */
#define PS_PEER_MAX 64

typedef struct {
    int listen_fd;
    int shutdown_fd;
    /*
     * Written by ps_listener_stop, read by ps_listener_accept -- on
     * different threads by design (plan 7.2a: shutdown is signalled from
     * the main thread while an acceptor thread blocks in accept()).
     * sig_atomic_t only promises same-thread signal-safety, not cross-thread
     * visibility, so this field is accessed exclusively through the
     * __atomic builtins in net.c, never read or written directly.
     */
    int stopping;
} ps_listener_t;

typedef enum {
    PS_ACCEPT_OK,        /* client_fd is valid and owned by the caller */
    PS_ACCEPT_SHUTDOWN,  /* ps_listener_stop was called; stop looping    */
    PS_ACCEPT_ERROR      /* transient or fatal; err holds the detail     */
} ps_accept_result_t;

/*
 * Bind and listen. bind_addr is a numeric address ("127.0.0.1", "::1",
 * "0.0.0.0"); hostnames are deliberately not resolved, because a listener
 * silently binding somewhere DNS pointed is not a behaviour worth having.
 */
bool ps_listener_open(ps_listener_t *l, const char *bind_addr, uint16_t port,
                      int backlog, char *err, size_t errlen);

/*
 * Block until a client connects or shutdown is requested. On PS_ACCEPT_OK the
 * caller owns *client_fd and must close it. peer, if non-NULL, receives a
 * printable "address:port".
 */
ps_accept_result_t ps_listener_accept(ps_listener_t *l, int *client_fd,
                                      char *peer, size_t peerlen,
                                      char *err, size_t errlen);

/* Safe to call from any thread, including one that is not the acceptor. */
void ps_listener_stop(ps_listener_t *l);

/* True once stop has been requested. Cheap enough to poll inside a read loop. */
bool ps_listener_stopping(const ps_listener_t *l);

void ps_listener_close(ps_listener_t *l);

/* Apply send/receive timeouts so a blocked peer cannot pin a thread forever. */
bool ps_socket_set_timeouts(int fd, int read_timeout_s, int write_timeout_s,
                            char *err, size_t errlen);

/* write(2) that retries on EINTR and short writes. Returns false on error. */
bool ps_write_all(int fd, const void *buf, size_t len);

#endif /* PS_PLATFORM_NET_H */

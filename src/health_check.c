#include "health_check.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static void rp_log(const char *msg)
{
    flockfile(stderr);
    fprintf(stderr, "revproxy: %s\n", msg);
    funlockfile(stderr);
}

static int set_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0) {
        return -1;
    }
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static int wait_fd(int fd, short events, int timeout_ms)
{
    struct pollfd pfd;

    pfd.fd = fd;
    pfd.events = events;
    pfd.revents = 0;
    for (;;) {
        int rc = poll(&pfd, 1, timeout_ms);

        if (rc < 0 && errno == EINTR) {
            continue;
        }
        return rc;
    }
}

/* 1 up, 0 down. http mode wants a status below 500. */
static int probe_addr(const struct sockaddr_in *addr, int timeout_ms, int http)
{
    int fd;
    int rc;
    int soerr = 0;
    socklen_t sl = sizeof(soerr);
    char buf[512];
    size_t got = 0;
    const char *req =
        "GET /health HTTP/1.1\r\nHost: health\r\nConnection: close\r\n\r\n";
    size_t req_len = strlen(req);
    size_t sent = 0;

    fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        return 0;
    }
    if (set_nonblock(fd) != 0) {
        close(fd);
        return 0;
    }
    rc = connect(fd, (const struct sockaddr *)addr, sizeof(*addr));
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return 0;
    }
    if (rc < 0) {
        rc = wait_fd(fd, POLLOUT, timeout_ms);
        if (rc <= 0) {
            close(fd);
            return 0;
        }
    }
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) < 0 || soerr != 0) {
        close(fd);
        return 0;
    }
    if (!http) {
        close(fd);
        return 1;
    }
    while (sent < req_len) {
        ssize_t n = send(fd, req + sent, req_len - sent, MSG_NOSIGNAL);

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                if (wait_fd(fd, POLLOUT, timeout_ms) <= 0) {
                    close(fd);
                    return 0;
                }
                continue;
            }
            close(fd);
            return 0;
        }
        sent += (size_t)n;
    }
    for (;;) {
        ssize_t n;

        if (wait_fd(fd, POLLIN, timeout_ms) <= 0) {
            close(fd);
            return 0;
        }
        n = recv(fd, buf + got, sizeof(buf) - 1 - got, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                continue;
            }
            close(fd);
            return 0;
        }
        if (n == 0) {
            break;
        }
        got += (size_t)n;
        buf[got] = '\0';
        if (got >= 12) {
            break;
        }
    }
    close(fd);
    if (got >= 12 && strncmp(buf, "HTTP/1.", 7) == 0) {
        int code = 0;
        size_t i;

        /* "HTTP/1.1 200 OK" — code is the token after the first space */
        for (i = 7; i < got && buf[i] != ' '; i++) {
        }
        if (i + 3 < got && buf[i] == ' ' &&
            buf[i + 1] >= '0' && buf[i + 1] <= '9' &&
            buf[i + 2] >= '0' && buf[i + 2] <= '9' &&
            buf[i + 3] >= '0' && buf[i + 3] <= '9') {
            code = (buf[i + 1] - '0') * 100 + (buf[i + 2] - '0') * 10 + (buf[i + 3] - '0');
        }
        return code > 0 && code < 500;
    }
    return 0;
}

static void apply_result(rp_lb_t *lb, int index, unsigned generation, int ok)
{
    rp_upstream_t *u;
    int was;
    int max_fails;
    int rise_need;
    char line[128];

    pthread_mutex_lock(&lb->mu);
    u = &lb->ups[index];
    if (!atomic_load_explicit(&u->in_use, memory_order_acquire) ||
        atomic_load_explicit(&u->generation, memory_order_acquire) != generation ||
        atomic_load_explicit(&u->draining, memory_order_acquire)) {
        pthread_mutex_unlock(&lb->mu);
        return;
    }
    was = atomic_load_explicit(&u->healthy, memory_order_acquire);
    max_fails = atomic_load_explicit(&lb->max_fails, memory_order_relaxed);
    rise_need = atomic_load_explicit(&lb->rise, memory_order_relaxed);
    if (ok) {
        atomic_store_explicit(&u->fail_count, 0, memory_order_relaxed);
        atomic_fetch_add_explicit(&u->rise_count, 1, memory_order_relaxed);
        if (atomic_load_explicit(&u->rise_count, memory_order_relaxed) >= rise_need) {
            atomic_store_explicit(&u->healthy, 1, memory_order_release);
        }
    } else {
        atomic_store_explicit(&u->rise_count, 0, memory_order_relaxed);
        atomic_fetch_add_explicit(&u->fail_count, 1, memory_order_relaxed);
        if (atomic_load_explicit(&u->fail_count, memory_order_relaxed) >= max_fails) {
            atomic_store_explicit(&u->healthy, 0, memory_order_release);
        }
    }
    if (was != atomic_load_explicit(&u->healthy, memory_order_acquire)) {
        snprintf(line, sizeof(line), "%.63s:%u is %s", u->host, (unsigned)u->port,
                 atomic_load_explicit(&u->healthy, memory_order_relaxed) ? "up" : "down");
        rp_log(line);
    }
    pthread_mutex_unlock(&lb->mu);
}

static void *health_main(void *arg)
{
    rp_health_t *health = arg;

    while (!atomic_load_explicit(&health->stop, memory_order_acquire)) {
        struct {
            int index;
            unsigned generation;
            struct sockaddr_in addr;
            int live;
        } snap[RP_MAX_UPSTREAMS];
        int i;
        int http;
        int timeout_ms;
        int interval;

        pthread_mutex_lock(&health->lb->mu);
        http = health->lb->mode == RP_MODE_HTTP;
        timeout_ms = atomic_load_explicit(&health->lb->health_timeout, memory_order_relaxed) * 1000;
        interval = atomic_load_explicit(&health->lb->health_interval, memory_order_relaxed);
        for (i = 0; i < RP_MAX_UPSTREAMS; i++) {
            rp_upstream_t *u = &health->lb->ups[i];

            snap[i].live = 0;
            snap[i].index = i;
            if (!atomic_load_explicit(&u->in_use, memory_order_acquire)) {
                continue;
            }
            if (atomic_load_explicit(&u->draining, memory_order_acquire)) {
                continue;
            }
            snap[i].generation = atomic_load_explicit(&u->generation, memory_order_acquire);
            snap[i].addr = u->addr;
            snap[i].live = 1;
        }
        pthread_mutex_unlock(&health->lb->mu);

        for (i = 0; i < RP_MAX_UPSTREAMS; i++) {
            int ok;

            if (atomic_load_explicit(&health->stop, memory_order_acquire)) {
                break;
            }
            if (!snap[i].live) {
                continue;
            }
            ok = probe_addr(&snap[i].addr, timeout_ms, http);
            apply_result(health->lb, snap[i].index, snap[i].generation, ok);
        }

        /* slice the sleep so SIGTERM does not wait out the whole interval */
        {
            int left = interval * 10;

            if (left < 1) {
                left = 1;
            }
            while (left-- > 0 && !atomic_load_explicit(&health->stop, memory_order_acquire)) {
                struct timespec ts;

                ts.tv_sec = 0;
                ts.tv_nsec = 100L * 1000L * 1000L;
                nanosleep(&ts, NULL);
            }
        }
    }
    return NULL;
}

int rp_health_start(rp_health_t *health, rp_lb_t *lb)
{
    health->lb = lb;
    health->started = 0;
    atomic_store_explicit(&health->stop, 0, memory_order_release);
    if (pthread_create(&health->thread, NULL, health_main, health) != 0) {
        return -1;
    }
    health->started = 1;
    return 0;
}

void rp_health_stop(rp_health_t *health)
{
    if (!health || !health->started) {
        return;
    }
    atomic_store_explicit(&health->stop, 1, memory_order_release);
    pthread_join(health->thread, NULL);
    health->started = 0;
}

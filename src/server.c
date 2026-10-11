#include "server.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static void rp_log(const char *msg)
{
    flockfile(stderr);
    fprintf(stderr, "revproxy: %s\n", msg);
    funlockfile(stderr);
}

static int set_nodelay(int fd)
{
    int one = 1;

    return setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
}

static long mono_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (long)ts.tv_sec * 1000L + (long)(ts.tv_nsec / 1000000L);
}

static int header_end_at(const char *buf, size_t len, size_t *end)
{
    size_t i;

    if (len < 4) {
        return 0;
    }
    for (i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' && buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            *end = i + 4;
            return 1;
        }
    }
    return 0;
}

static int name_eq(const char *p, size_t n, const char *lit)
{
    size_t i;

    for (i = 0; lit[i] != '\0'; i++) {
        char c;

        if (i >= n) {
            return 0;
        }
        c = p[i];
        if (c >= 'A' && c <= 'Z') {
            c = (char)(c - 'A' + 'a');
        }
        if (c != lit[i]) {
            return 0;
        }
    }
    return i == n;
}

static int value_has_token(const char *v, size_t n, const char *tok)
{
    size_t tlen = strlen(tok);
    size_t i = 0;

    while (i < n) {
        size_t start;
        size_t len;

        while (i < n && (v[i] == ' ' || v[i] == '\t' || v[i] == ',')) {
            i++;
        }
        if (i >= n) {
            break;
        }
        start = i;
        while (i < n && v[i] != ',') {
            i++;
        }
        len = i - start;
        while (len > 0 && (v[start + len - 1] == ' ' || v[start + len - 1] == '\t')) {
            len--;
        }
        if (len == tlen && name_eq(v + start, len, tok)) {
            return 1;
        }
    }
    return 0;
}

static int parse_cl(const char *v, size_t n, int64_t *out)
{
    int64_t x = 0;
    size_t i;

    if (n == 0) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        if (v[i] < '0' || v[i] > '9') {
            return -1;
        }
        if (x > (INT64_MAX - 9) / 10) {
            return -1;
        }
        x = x * 10 + (v[i] - '0');
    }
    *out = x;
    return 0;
}

static int path_is(const char *p, size_t n, const char *lit)
{
    size_t i;

    for (i = 0; lit[i] != '\0'; i++) {
        if (i >= n || p[i] != lit[i]) {
            return 0;
        }
    }
    return i == n;
}

static int hex_val(unsigned char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

/* 1 finished the body, 0 keep going, -1 garbage */
static int chunk_byte(rp_chunk_t *cs, unsigned char b)
{
    int h;

    switch (cs->state) {
    case CH_SIZE:
        h = hex_val(b);
        if (h >= 0) {
            if (cs->size_acc > (INT64_MAX >> 4)) {
                return -1;
            }
            cs->size_acc = (cs->size_acc << 4) + h;
            cs->saw_digit = 1;
            return 0;
        }
        if (b == ';') {
            if (!cs->saw_digit) {
                return -1;
            }
            cs->state = CH_EXT;
            return 0;
        }
        if (b == '\r') {
            if (!cs->saw_digit) {
                return -1;
            }
            cs->state = CH_SIZE_LF;
            return 0;
        }
        return -1;
    case CH_EXT:
        if (b == '\r') {
            cs->state = CH_SIZE_LF;
        }
        return 0;
    case CH_SIZE_LF:
        if (b != '\n') {
            return -1;
        }
        if (cs->size_acc == 0) {
            cs->nonempty = 0;
            cs->state = CH_TRAILER;
            return 0;
        }
        cs->need = cs->size_acc;
        cs->state = CH_DATA;
        return 0;
    case CH_DATA:
        cs->need--;
        if (cs->need == 0) {
            cs->state = CH_DATA_CR;
        }
        return 0;
    case CH_DATA_CR:
        if (b != '\r') {
            return -1;
        }
        cs->state = CH_DATA_LF;
        return 0;
    case CH_DATA_LF:
        if (b != '\n') {
            return -1;
        }
        cs->size_acc = 0;
        cs->saw_digit = 0;
        cs->state = CH_SIZE;
        return 0;
    case CH_TRAILER:
        if (b == '\r') {
            cs->state = CH_TRAILER_LF;
        } else {
            cs->nonempty = 1;
        }
        return 0;
    case CH_TRAILER_LF:
        if (b != '\n') {
            return -1;
        }
        if (!cs->nonempty) {
            cs->state = CH_DONE;
            return 1;
        }
        cs->nonempty = 0;
        cs->state = CH_TRAILER;
        return 0;
    default:
        return -1;
    }
}

static int chunk_feed(rp_chunk_t *cs, const char *p, size_t n, size_t *took, int *done)
{
    size_t i;

    *took = 0;
    *done = 0;
    for (i = 0; i < n; i++) {
        int rc = chunk_byte(cs, (unsigned char)p[i]);

        if (rc < 0) {
            return -1;
        }
        *took = i + 1;
        if (rc == 1) {
            *done = 1;
            return 0;
        }
    }
    return 0;
}

static int conn_update(rp_server_t *s, rp_conn_t *c);

static void conn_retire(rp_server_t *s, rp_conn_t *c, int kill_peer)
{
    rp_conn_t *peer;

    if (!c || c->dead) {
        return;
    }
    c->dead = 1;
    c->state = CONN_CLOSING;
    peer = c->peer;
    c->peer = NULL;
    if (peer) {
        peer->peer = NULL;
    }
    if (c->in_epoll && c->fd >= 0 && s->epfd >= 0) {
        epoll_ctl(s->epfd, EPOLL_CTL_DEL, c->fd, NULL);
        c->in_epoll = 0;
    }
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
    if (c->role == CONN_ROLE_CLIENT && c->counted) {
        s->active_conns--;
        c->counted = 0;
    }
    if (c->holding_upstream) {
        rp_lb_release(&s->lb, c->upstream_index);
        c->holding_upstream = 0;
    }
    if (s->reap_n < RP_MAX_CONNS) {
        s->reap[s->reap_n++] = c->index;
    }
    if (kill_peer && peer) {
        conn_retire(s, peer, 0);
    }
}

static void queue_local(rp_conn_t *c)
{
    size_t left;
    size_t space;
    size_t n;

    if (!c->local || c->local_off >= c->local_len) {
        return;
    }
    left = c->local_len - c->local_off;
    space = rp_buf_space(&c->out);
    n = left < space ? left : space;
    if (n == 0) {
        return;
    }
    if (rp_buf_append(&c->out, c->local + c->local_off, n) != 0) {
        return;
    }
    c->local_off += n;
}

static void flush_out(rp_server_t *s, rp_conn_t *c)
{
    if (!c || c->dead || c->fd < 0) {
        return;
    }
    while (!c->dead && rp_buf_pending(&c->out) > 0) {
        ssize_t n = send(c->fd, c->out.data + c->out.off, c->out.len - c->out.off, MSG_NOSIGNAL);

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                break;
            }
            conn_retire(s, c, 1);
            return;
        }
        if (n == 0) {
            break;
        }
        c->out.off += (size_t)n;
        c->bytes_written += (uint64_t)n;
        if (c->role == CONN_ROLE_UPSTREAM && c->upstream_index >= 0) {
            rp_lb_add_bytes_in(&s->lb, c->upstream_index, (uint64_t)n);
        } else if (c->role == CONN_ROLE_CLIENT && c->upstream_index >= 0) {
            rp_lb_add_bytes_out(&s->lb, c->upstream_index, (uint64_t)n);
        }
    }
    if (c->dead) {
        return;
    }
    if (rp_buf_pending(&c->out) == 0) {
        rp_buf_clear(&c->out);
        if (c->local && c->local_off < c->local_len) {
            queue_local(c);
            if (rp_buf_pending(&c->out) > 0) {
                c->again = 1;
                return;
            }
        }
        if (c->close_when_flushed && (!c->local || c->local_off == c->local_len)) {
            conn_retire(s, c, 1);
        }
    }
}

static int send_local_bytes(rp_server_t *s, rp_conn_t *c, char *bytes, size_t n)
{
    free(c->local);
    c->local = bytes;
    c->local_len = n;
    c->local_off = 0;
    c->close_when_flushed = 1;
    c->keep_alive = 0;
    c->state = CONN_STREAMING;
    queue_local(c);
    flush_out(s, c);
    return c->dead ? -1 : 0;
}

static void send_simple(rp_server_t *s, rp_conn_t *c, int code, const char *reason, const char *body)
{
    char msg[512];
    int n;
    char *copy;

    if (!c || c->dead || c->bytes_written > 0) {
        conn_retire(s, c, 1);
        return;
    }
    n = snprintf(msg, sizeof(msg),
                 "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n%s",
                 code, reason, strlen(body), body);
    if (n < 0 || (size_t)n >= sizeof(msg)) {
        conn_retire(s, c, 1);
        return;
    }
    copy = malloc((size_t)n);
    if (!copy) {
        conn_retire(s, c, 1);
        return;
    }
    memcpy(copy, msg, (size_t)n);
    send_local_bytes(s, c, copy, (size_t)n);
}

static const char *policy_name(rp_policy_t policy)
{
    if (policy == RP_POLICY_WRR) {
        return "wrr";
    }
    if (policy == RP_POLICY_LEAST) {
        return "leastconn";
    }
    return "rr";
}

static char *wrap_http(const char *ctype, const char *body, size_t blen, size_t *out_n)
{
    char hdr[256];
    int hlen;
    char *all;

    hlen = snprintf(hdr, sizeof(hdr),
                    "HTTP/1.1 200 OK\r\nContent-Type: %s\r\nContent-Length: %zu\r\nConnection: close\r\n\r\n",
                    ctype, blen);
    if (hlen < 0 || (size_t)hlen >= sizeof(hdr)) {
        return NULL;
    }
    all = malloc((size_t)hlen + blen);
    if (!all) {
        return NULL;
    }
    memcpy(all, hdr, (size_t)hlen);
    memcpy(all + hlen, body, blen);
    *out_n = (size_t)hlen + blen;
    return all;
}

static int build_status(rp_server_t *s, rp_conn_t *c, int kind)
{
    char *body;
    size_t cap = 65536;
    size_t used = 0;
    size_t wire_n = 0;
    char *wire;
    int i;
    const char *ctype;

    body = malloc(cap);
    if (!body) {
        return -1;
    }
    if (kind == 1) {
        int n = snprintf(body, cap, "{\"active_connections\":%d,\"policy\":\"%s\",\"upstreams\":[",
                         s->active_conns, policy_name(s->lb.policy));

        if (n < 0 || (size_t)n >= cap) {
            free(body);
            return -1;
        }
        used = (size_t)n;
    } else {
        int n = snprintf(body, cap, "lb_active_connections %d\n", s->active_conns);

        if (n < 0 || (size_t)n >= cap) {
            free(body);
            return -1;
        }
        used = (size_t)n;
    }
    {
        int first = 1;

        for (i = 0; i < RP_MAX_UPSTREAMS; i++) {
            rp_upstream_t *u = &s->lb.ups[i];
            char addr[80];
            int an;
            unsigned long long reqs;
            unsigned long long bin;
            unsigned long long bout;
            int active;
            int healthy;

            if (!atomic_load_explicit(&u->in_use, memory_order_acquire)) {
                continue;
            }
            an = snprintf(addr, sizeof(addr), "%.63s:%u", u->host, (unsigned)u->port);
            if (an < 0 || (size_t)an >= sizeof(addr)) {
                free(body);
                return -1;
            }
            reqs = (unsigned long long)atomic_load_explicit(&u->requests, memory_order_relaxed);
            bin = (unsigned long long)atomic_load_explicit(&u->bytes_in, memory_order_relaxed);
            bout = (unsigned long long)atomic_load_explicit(&u->bytes_out, memory_order_relaxed);
            active = atomic_load_explicit(&u->active, memory_order_relaxed);
            healthy = atomic_load_explicit(&u->healthy, memory_order_acquire);
            if (kind == 1) {
                int n;
                size_t left = cap - used;

                n = snprintf(body + used, left,
                             "%s{\"addr\":\"%s\",\"healthy\":%s,\"active\":%d,\"requests\":%llu,\"bytes_in\":%llu,\"bytes_out\":%llu}",
                             first ? "" : ",", addr, healthy ? "true" : "false", active, reqs, bin, bout);
                if (n < 0 || (size_t)n >= left) {
                    free(body);
                    return -1;
                }
                used += (size_t)n;
                first = 0;
            } else {
                int n;
                size_t left = cap - used;

                n = snprintf(body + used, left,
                             "lb_upstream_up{addr=\"%s\"} %d\n"
                             "lb_upstream_requests{addr=\"%s\"} %llu\n"
                             "lb_upstream_bytes_in{addr=\"%s\"} %llu\n"
                             "lb_upstream_bytes_out{addr=\"%s\"} %llu\n",
                             addr, healthy ? 1 : 0, addr, reqs, addr, bin, addr, bout);
                if (n < 0 || (size_t)n >= left) {
                    free(body);
                    return -1;
                }
                used += (size_t)n;
            }
        }
    }
    if (kind == 1) {
        if (used + 2 >= cap) {
            free(body);
            return -1;
        }
        body[used++] = ']';
        body[used++] = '}';
        body[used] = '\0';
        ctype = "application/json";
    } else {
        ctype = "text/plain; version=0.0.4";
    }
    wire = wrap_http(ctype, body, used, &wire_n);
    free(body);
    if (!wire) {
        return -1;
    }
    return send_local_bytes(s, c, wire, wire_n);
}

static int parse_request_headers(rp_conn_t *c)
{
    const char *base = c->in.data + c->in.off;
    size_t avail = c->in.len - c->in.off;
    size_t hend = 0;
    size_t i;
    size_t first = 0;
    int http_minor = 1;
    int is_get = 0;
    int saw_cl = 0;
    int chunked = 0;
    int conn_close = 0;
    int conn_ka = 0;
    int64_t cl = 0;

    if (!header_end_at(base, avail, &hend)) {
        if (rp_buf_space(&c->in) == 0) {
            return -2;
        }
        return 0;
    }
    while (first + 1 < hend && !(base[first] == '\r' && base[first + 1] == '\n')) {
        first++;
    }
    if (first + 1 >= hend) {
        return -1;
    }
    is_get = (first >= 4 && memcmp(base, "GET ", 4) == 0);
    c->head_method = (first >= 5 && memcmp(base, "HEAD ", 5) == 0);
    {
        size_t ps = 0;
        size_t pe;

        while (ps < first && base[ps] != ' ') {
            ps++;
        }
        if (ps >= first || base[ps] != ' ') {
            return -1;
        }
        ps++;
        pe = ps;
        while (pe < first && base[pe] != ' ' && base[pe] != '?') {
            pe++;
        }
        if (pe == ps) {
            return -1;
        }
        if (is_get && path_is(base + ps, pe - ps, "/status")) {
            c->local_kind = 1;
        } else if (is_get && path_is(base + ps, pe - ps, "/metrics")) {
            c->local_kind = 2;
        }
    }
    {
        int found = 0;

        for (i = 0; i + 8 <= first; i++) {
            if (memcmp(base + i, "HTTP/1.", 7) == 0) {
                http_minor = base[i + 7] - '0';
                found = 1;
                break;
            }
        }
        if (!found || http_minor < 0 || http_minor > 9) {
            return -1;
        }
    }

    i = first + 2;
    while (i + 1 < hend && !(base[i] == '\r' && base[i + 1] == '\n')) {
        size_t ns = i;
        size_t ne;
        size_t vs;
        size_t ve;

        while (i < hend && base[i] != ':' && base[i] != '\r') {
            i++;
        }
        if (i >= hend || base[i] != ':') {
            return -1;
        }
        ne = i;
        i++;
        while (i < hend && (base[i] == ' ' || base[i] == '\t')) {
            i++;
        }
        vs = i;
        while (i + 1 < hend && !(base[i] == '\r' && base[i + 1] == '\n')) {
            i++;
        }
        ve = i;
        if (i + 1 >= hend) {
            return -1;
        }
        i += 2;
        if (name_eq(base + ns, ne - ns, "content-length")) {
            if (parse_cl(base + vs, ve - vs, &cl) != 0) {
                return -1;
            }
            saw_cl = 1;
        } else if (name_eq(base + ns, ne - ns, "transfer-encoding")) {
            if (value_has_token(base + vs, ve - vs, "chunked")) {
                chunked = 1;
            }
        } else if (name_eq(base + ns, ne - ns, "connection")) {
            if (value_has_token(base + vs, ve - vs, "close")) {
                conn_close = 1;
            }
            if (value_has_token(base + vs, ve - vs, "keep-alive")) {
                conn_ka = 1;
            }
        }
    }

    c->headers_done = 1;
    c->hdr_left = hend;
    memset(&c->chunk, 0, sizeof(c->chunk));
    if (chunked) {
        c->body_kind = BODY_CHUNKED;
    } else if (saw_cl) {
        c->body_kind = BODY_LENGTH;
        c->body_left = cl;
    } else {
        c->body_kind = BODY_NONE;
    }
    if (http_minor == 0) {
        c->keep_alive = conn_ka ? 1 : 0;
    } else {
        c->keep_alive = conn_close ? 0 : 1;
    }
    return 1;
}

static int parse_response_headers(rp_conn_t *c)
{
    const char *base = c->in.data + c->in.off;
    size_t avail = c->in.len - c->in.off;
    size_t hend = 0;
    size_t first = 0;
    size_t i;
    int http_minor;
    int code = 0;
    int saw_cl = 0;
    int chunked = 0;
    int conn_close = 0;
    int conn_ka = 0;
    int64_t cl = 0;
    rp_conn_t *client = c->peer;

    if (!header_end_at(base, avail, &hend)) {
        if (rp_buf_space(&c->in) == 0) {
            return -1;
        }
        return 0;
    }
    while (first + 1 < hend && !(base[first] == '\r' && base[first + 1] == '\n')) {
        first++;
    }
    if (first < 12 || memcmp(base, "HTTP/1.", 7) != 0 || base[8] != ' ') {
        return -1;
    }
    http_minor = base[7] - '0';
    if (http_minor < 0 || http_minor > 9) {
        return -1;
    }
    if (base[9] < '0' || base[9] > '9' || base[10] < '0' || base[10] > '9' || base[11] < '0' || base[11] > '9') {
        return -1;
    }
    code = (base[9] - '0') * 100 + (base[10] - '0') * 10 + (base[11] - '0');

    i = first + 2;
    while (i + 1 < hend && !(base[i] == '\r' && base[i + 1] == '\n')) {
        size_t ns = i;
        size_t ne;
        size_t vs;
        size_t ve;

        while (i < hend && base[i] != ':' && base[i] != '\r') {
            i++;
        }
        if (i >= hend || base[i] != ':') {
            return -1;
        }
        ne = i;
        i++;
        while (i < hend && (base[i] == ' ' || base[i] == '\t')) {
            i++;
        }
        vs = i;
        while (i + 1 < hend && !(base[i] == '\r' && base[i + 1] == '\n')) {
            i++;
        }
        ve = i;
        if (i + 1 >= hend) {
            return -1;
        }
        i += 2;
        if (name_eq(base + ns, ne - ns, "content-length")) {
            if (parse_cl(base + vs, ve - vs, &cl) != 0) {
                return -1;
            }
            saw_cl = 1;
        } else if (name_eq(base + ns, ne - ns, "transfer-encoding")) {
            if (value_has_token(base + vs, ve - vs, "chunked")) {
                chunked = 1;
            }
        } else if (name_eq(base + ns, ne - ns, "connection")) {
            if (value_has_token(base + vs, ve - vs, "close")) {
                conn_close = 1;
            }
            if (value_has_token(base + vs, ve - vs, "keep-alive")) {
                conn_ka = 1;
            }
        }
    }

    c->headers_done = 1;
    c->hdr_left = hend;
    c->interim = 0;
    memset(&c->chunk, 0, sizeof(c->chunk));
    if ((code >= 100 && code < 200 && code != 101) || code == 204 || code == 304 ||
        (client && client->head_method)) {
        c->body_kind = BODY_NONE;
        if (code >= 100 && code < 200 && code != 101) {
            c->interim = 1;
        }
    } else if (chunked) {
        c->body_kind = BODY_CHUNKED;
    } else if (saw_cl) {
        c->body_kind = BODY_LENGTH;
        c->body_left = cl;
    } else {
        c->body_kind = BODY_CLOSE;
    }
    if (client) {
        if (conn_close || c->body_kind == BODY_CLOSE || (http_minor == 0 && !conn_ka)) {
            client->keep_alive = 0;
        }
    }
    return 1;
}

static int transfer_to_peer(rp_conn_t *src)
{
    rp_conn_t *dst = src->peer;

    if (!dst || dst->dead || dst->state != CONN_STREAMING) {
        return 0;
    }
    while (src->in.off < src->in.len && !src->msg_done) {
        size_t avail = src->in.len - src->in.off;
        size_t space = rp_buf_space(&dst->out);
        size_t max_take;
        size_t take = 0;

        if (space == 0) {
            return 0;
        }
        max_take = avail < space ? avail : space;
        if (src->hdr_left > 0) {
            take = max_take < src->hdr_left ? max_take : src->hdr_left;
            src->hdr_left -= take;
        } else if (src->body_kind == BODY_NONE) {
            if (!src->interim) {
                src->msg_done = 1;
            }
            break;
        } else if (src->body_kind == BODY_LENGTH) {
            if (src->body_left <= 0) {
                src->msg_done = 1;
                break;
            }
            take = max_take;
            if ((int64_t)take > src->body_left) {
                take = (size_t)src->body_left;
            }
            src->body_left -= (int64_t)take;
            if (src->body_left == 0) {
                src->msg_done = 1;
            }
        } else if (src->body_kind == BODY_CHUNKED) {
            int done = 0;

            if (chunk_feed(&src->chunk, src->in.data + src->in.off, max_take, &take, &done) != 0) {
                return -1;
            }
            if (done) {
                src->msg_done = 1;
            }
            if (take == 0) {
                break;
            }
        } else if (src->body_kind == BODY_CLOSE) {
            take = max_take;
        } else {
            return -1;
        }
        if (take == 0) {
            break;
        }
        if (rp_buf_append(&dst->out, src->in.data + src->in.off, take) != 0) {
            return -1;
        }
        src->in.off += take;
    }
    /* headers can end flush with the buffer, so the loop never comes back
       around to notice the body was empty */
    if (!src->msg_done && src->hdr_left == 0) {
        if (src->body_kind == BODY_NONE && !src->interim) {
            src->msg_done = 1;
        } else if (src->body_kind == BODY_LENGTH && src->body_left == 0) {
            src->msg_done = 1;
        }
    }
    return 0;
}

static int transfer_raw(rp_conn_t *src)
{
    rp_conn_t *dst = src->peer;

    if (!dst || dst->dead || dst->state != CONN_STREAMING) {
        return 0;
    }
    while (src->in.off < src->in.len) {
        size_t avail = src->in.len - src->in.off;
        size_t space = rp_buf_space(&dst->out);
        size_t take = avail < space ? avail : space;

        if (take == 0) {
            return 0;
        }
        if (rp_buf_append(&dst->out, src->in.data + src->in.off, take) != 0) {
            return -1;
        }
        src->in.off += take;
    }
    return 0;
}

static int conn_update(rp_server_t *s, rp_conn_t *c)
{
    struct epoll_event ev;
    uint32_t want;
    int op;
    int want_read;

    if (!c || c->dead || c->fd < 0 || s->epfd < 0) {
        return -1;
    }
    want = EPOLLET | EPOLLRDHUP;
    if (rp_buf_pending(&c->out) > 0 ||
        (c->state == CONN_CONNECTING_UPSTREAM && c->role == CONN_ROLE_UPSTREAM)) {
        want |= EPOLLOUT;
    }
    want_read = 0;
    if (!c->read_closed && !c->close_when_flushed && rp_buf_space(&c->in) > 0) {
        if (c->state == CONN_CONNECTING_UPSTREAM && c->role == CONN_ROLE_UPSTREAM) {
            want_read = 0;
        } else if (c->role == CONN_ROLE_UPSTREAM && c->msg_done) {
            want_read = 0;
        } else if (c->role == CONN_ROLE_CLIENT && c->http && c->msg_done && !c->keep_alive) {
            want_read = 0;
        } else {
            want_read = 1;
        }
    }
    if (want_read) {
        want |= EPOLLIN;
    }
    if (c->in_epoll && c->epoll_events == want) {
        return 0;
    }
    memset(&ev, 0, sizeof(ev));
    ev.events = want;
    ev.data.ptr = &c->watch;
    op = c->in_epoll ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
    if (epoll_ctl(s->epfd, op, c->fd, &ev) < 0) {
        conn_retire(s, c, 1);
        return -1;
    }
    c->in_epoll = 1;
    c->epoll_events = want;
    c->watch.fd = c->fd;
    return 0;
}

static void pause_listen(rp_server_t *s, int status_port)
{
    int *fd = status_port ? &s->status_fd : &s->listen_fd;
    int *paused = status_port ? &s->status_paused : &s->listen_paused;

    if (*paused || *fd < 0) {
        return;
    }
    epoll_ctl(s->epfd, EPOLL_CTL_DEL, *fd, NULL);
    *paused = 1;
}

static void resume_listen(rp_server_t *s, int status_port)
{
    struct epoll_event ev;
    int fd = status_port ? s->status_fd : s->listen_fd;
    int *paused = status_port ? &s->status_paused : &s->listen_paused;
    rp_watch_t *watch = status_port ? &s->status_watch : &s->listen_watch;

    if (!*paused || fd < 0 || !s->running) {
        return;
    }
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.ptr = watch;
    if (epoll_ctl(s->epfd, EPOLL_CTL_ADD, fd, &ev) == 0) {
        *paused = 0;
    }
}

static void reap_conns(rp_server_t *s)
{
    int i;

    for (i = 0; i < s->reap_n; i++) {
        int idx = s->reap[i];
        rp_conn_t *c = &s->conns[idx];

        free(c->local);
        c->local = NULL;
        c->fd = -1;
        rp_pool_release(&s->pool, idx);
    }
    s->reap_n = 0;
    resume_listen(s, 0);
    resume_listen(s, 1);
}

static rp_conn_t *conn_get(rp_server_t *s)
{
    int idx = rp_pool_acquire(&s->pool);
    rp_conn_t *c;

    if (idx < 0) {
        return NULL;
    }
    c = &s->conns[idx];
    memset(c, 0, sizeof(*c));
    c->index = idx;
    c->fd = -1;
    c->upstream_index = -1;
    c->watch.kind = EV_CONN;
    c->watch.conn = c;
    c->keep_alive = 1;
    return c;
}

static int open_upstream(rp_server_t *s, rp_conn_t *client, int avoid, int *used_idx);

static void on_io(rp_server_t *s, rp_conn_t *c, int readable, int writable);

static void connect_failed(rp_server_t *s, rp_conn_t *up)
{
    rp_conn_t *client = up->peer;
    int avoid = up->upstream_index;
    int used = -1;

    if (client) {
        client->peer = NULL;
        up->peer = NULL;
    }
    conn_retire(s, up, 0);
    if (!client || client->dead) {
        return;
    }
    if (client->holding_upstream) {
        rp_lb_release(&s->lb, client->upstream_index);
        client->holding_upstream = 0;
    }
    client->upstream_index = -1;
    if (client->bytes_written == 0 && client->retries < 1) {
        client->retries = 1;
        client->state = CONN_CONNECTING_UPSTREAM;
        if (open_upstream(s, client, avoid, &used) == 0) {
            return;
        }
    }
    if (!client->http) {
        conn_retire(s, client, 0);
        return;
    }
    if (client->bytes_written == 0) {
        send_simple(s, client, 502, "Bad Gateway", "bad gateway");
    } else {
        conn_retire(s, client, 0);
    }
}

static void maybe_complete(rp_server_t *s, rp_conn_t *any)
{
    rp_conn_t *client;
    rp_conn_t *up;

    if (!any || any->dead) {
        return;
    }
    client = (any->role == CONN_ROLE_CLIENT) ? any : any->peer;
    if (!client || client->dead || !client->http || client->close_when_flushed) {
        return;
    }
    up = client->peer;
    if (up && up->msg_done) {
        client->resp_done = 1;
    }
    if (!client->msg_done || !client->resp_done) {
        return;
    }
    if (rp_buf_pending(&client->out) > 0) {
        return;
    }
    if (up && !up->dead && rp_buf_pending(&up->out) > 0) {
        return;
    }
    if (up && !up->dead) {
        client->peer = NULL;
        up->peer = NULL;
        conn_retire(s, up, 0);
    }
    if (client->holding_upstream) {
        rp_lb_release(&s->lb, client->upstream_index);
        client->holding_upstream = 0;
    }
    client->upstream_index = -1;
    if (!client->keep_alive || client->read_closed) {
        conn_retire(s, client, 0);
        return;
    }
    client->headers_done = 0;
    client->hdr_left = 0;
    client->body_kind = BODY_UNSET;
    client->body_left = 0;
    memset(&client->chunk, 0, sizeof(client->chunk));
    client->msg_done = 0;
    client->resp_done = 0;
    client->interim = 0;
    client->head_method = 0;
    client->local_kind = 0;
    client->retries = 0;
    client->state = CONN_READING_REQ;
    client->again = 1;
}

static void tcp_after_io(rp_server_t *s, rp_conn_t *c)
{
    rp_conn_t *b;

    if (!c || c->dead || c->http) {
        return;
    }
    b = c->peer;
    if (c->read_closed && b && !b->dead && rp_buf_pending(&c->in) == 0 &&
        rp_buf_pending(&b->out) == 0 && !b->shut_wr && b->fd >= 0) {
        shutdown(b->fd, SHUT_WR);
        b->shut_wr = 1;
    }
    if (b && !b->dead && b->read_closed && rp_buf_pending(&b->in) == 0 &&
        rp_buf_pending(&c->out) == 0 && !c->shut_wr && c->fd >= 0) {
        shutdown(c->fd, SHUT_WR);
        c->shut_wr = 1;
    }
    if (c->read_closed && rp_buf_pending(&c->in) == 0 && rp_buf_pending(&c->out) == 0 &&
        (!b || b->dead || (b->read_closed && rp_buf_pending(&b->in) == 0 && rp_buf_pending(&b->out) == 0))) {
        conn_retire(s, c, 1);
    }
}

static void note_http_eof(rp_server_t *s, rp_conn_t *c)
{
    if (!c->http || !c->read_closed || c->msg_done || c->dead) {
        return;
    }
    /* bytes still sitting here are not a short read. wait until they move. */
    if (c->headers_done && rp_buf_pending(&c->in) > 0) {
        return;
    }
    if (!c->headers_done) {
        if (rp_buf_pending(&c->in) == 0) {
            /* idle keep-alive close, or the client hung up before a request */
            conn_retire(s, c, 1);
        } else if (c->role == CONN_ROLE_CLIENT && c->bytes_written == 0) {
            send_simple(s, c, 400, "Bad Request", "bad request");
        } else {
            conn_retire(s, c, 1);
        }
        return;
    }
    if (c->body_kind == BODY_CLOSE ||
        (c->body_kind == BODY_NONE && c->hdr_left == 0 && !c->interim)) {
        c->msg_done = 1;
        if (c->role == CONN_ROLE_UPSTREAM && c->peer) {
            c->peer->resp_done = 1;
        }
        return;
    }
    if (c->role == CONN_ROLE_UPSTREAM && c->peer && c->peer->bytes_written == 0 &&
        !c->peer->close_when_flushed) {
        rp_conn_t *client = c->peer;

        client->peer = NULL;
        c->peer = NULL;
        conn_retire(s, c, 0);
        if (client->holding_upstream) {
            rp_lb_release(&s->lb, client->upstream_index);
            client->holding_upstream = 0;
        }
        client->upstream_index = -1;
        send_simple(s, client, 502, "Bad Gateway", "bad gateway");
        return;
    }
    conn_retire(s, c, 1);
}

static void progress_http(rp_server_t *s, rp_conn_t *c)
{
    int pr;
    int used = -1;

    if (!c->http || c->dead || c->close_when_flushed) {
        return;
    }
    if (c->interim && c->headers_done && c->hdr_left == 0) {
        c->headers_done = 0;
        c->interim = 0;
        c->body_kind = BODY_UNSET;
        c->msg_done = 0;
        c->hdr_left = 0;
        memset(&c->chunk, 0, sizeof(c->chunk));
    }
    if (!c->headers_done) {
        pr = (c->role == CONN_ROLE_CLIENT) ? parse_request_headers(c) : parse_response_headers(c);
        if (pr == 0) {
            return;
        }
        if (pr < 0) {
            if (c->role == CONN_ROLE_CLIENT && c->bytes_written == 0 && !c->peer) {
                if (pr == -2) {
                    send_simple(s, c, 431, "Request Header Fields Too Large", "headers too big");
                } else {
                    send_simple(s, c, 400, "Bad Request", "bad request");
                }
            } else {
                conn_retire(s, c, 1);
            }
            return;
        }
        if (c->role == CONN_ROLE_CLIENT && !c->peer) {
            if (c->local_kind) {
                if (build_status(s, c, c->local_kind) != 0) {
                    send_simple(s, c, 500, "Internal Server Error", "status failed");
                }
                return;
            }
            if (c->status_only) {
                send_simple(s, c, 404, "Not Found", "not found");
                return;
            }
            c->state = CONN_CONNECTING_UPSTREAM;
            if (open_upstream(s, c, -1, &used) != 0 && c->retries < 1) {
                c->retries = 1;
                if (used >= 0 && open_upstream(s, c, used, &used) == 0) {
                    return;
                }
                send_simple(s, c, 502, "Bad Gateway", "bad gateway");
            } else if (c->peer == NULL && !c->dead && !c->close_when_flushed) {
                send_simple(s, c, 502, "Bad Gateway", "bad gateway");
            }
            return;
        }
    }
    if (c->peer && c->peer->state == CONN_STREAMING) {
        if (transfer_to_peer(c) != 0) {
            if (c->role == CONN_ROLE_CLIENT && c->bytes_written == 0) {
                send_simple(s, c, 400, "Bad Request", "bad request");
            } else {
                conn_retire(s, c, 1);
            }
            return;
        }
    }
    if (c->role == CONN_ROLE_UPSTREAM && c->msg_done && c->peer) {
        c->peer->resp_done = 1;
    }
    if (c->interim && c->headers_done && c->hdr_left == 0) {
        c->again = 1;
    }
}

static int open_upstream(rp_server_t *s, rp_conn_t *client, int avoid, int *used_idx)
{
    int idx;
    int fd;
    int rc;
    int up_idx;
    struct sockaddr_in addr;
    rp_conn_t *up;

    if (used_idx) {
        *used_idx = -1;
    }
    if (!client || client->dead || client->peer) {
        return -1;
    }
    idx = rp_lb_select(&s->lb, avoid);
    if (idx < 0) {
        return -1;
    }
    if (used_idx) {
        *used_idx = idx;
    }
    if (rp_lb_copy_addr(&s->lb, idx, &addr) != 0) {
        return -1;
    }
    fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        return -1;
    }
    set_nodelay(fd);
    rc = connect(fd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc < 0 && errno != EINPROGRESS) {
        close(fd);
        return -1;
    }
    up = conn_get(s);
    if (!up) {
        close(fd);
        pause_listen(s, 0);
        if (s->status_fd >= 0) {
            pause_listen(s, 1);
        }
        return -1;
    }
    up_idx = up->index;
    up->fd = fd;
    up->watch.fd = fd;
    up->role = CONN_ROLE_UPSTREAM;
    up->http = client->http;
    up->state = (rc == 0) ? CONN_STREAMING : CONN_CONNECTING_UPSTREAM;
    up->upstream_index = idx;
    up->peer = client;
    client->peer = up;
    client->upstream_index = idx;
    client->holding_upstream = 1;
    client->state = up->state;
    rp_lb_acquire(&s->lb, idx);
    if (conn_update(s, up) != 0) {
        return -1;
    }
    if (rc == 0) {
        client->again = 1;
        if (!client->busy) {
            on_io(s, client, 1, 1);
        }
    }
    (void)up_idx;
    return 0;
}

static int read_into(rp_conn_t *c)
{
    while (!c->read_closed && rp_buf_space(&c->in) > 0) {
        char tmp[4096];
        size_t space = rp_buf_space(&c->in);
        size_t chunk = space < sizeof(tmp) ? space : sizeof(tmp);
        ssize_t n = recv(c->fd, tmp, chunk, 0);

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return 0;
            }
            return -1;
        }
        if (n == 0) {
            c->read_closed = 1;
            return 0;
        }
        if (rp_buf_append(&c->in, tmp, (size_t)n) != 0) {
            return -1;
        }
    }
    return 0;
}

static void finish_connect(rp_server_t *s, rp_conn_t *up)
{
    int err = 0;
    socklen_t sl = sizeof(err);
    rp_conn_t *client;

    if (!up || up->dead || up->state != CONN_CONNECTING_UPSTREAM) {
        return;
    }
    if (getsockopt(up->fd, SOL_SOCKET, SO_ERROR, &err, &sl) < 0 || err != 0) {
        connect_failed(s, up);
        return;
    }
    client = up->peer;
    up->state = CONN_STREAMING;
    if (client && !client->dead) {
        client->state = CONN_STREAMING;
        client->again = 1;
        if (!client->busy) {
            on_io(s, client, 1, 1);
        }
    }
}

static void on_io(rp_server_t *s, rp_conn_t *c, int readable, int writable)
{
    int loops = 0;
    int saw_peer = 0;

    if (!c || c->dead) {
        return;
    }
    if (c->busy) {
        c->again = 1;
        return;
    }
    c->busy = 1;
    do {
        c->again = 0;
        loops++;
        if (loops > 32 || c->dead) {
            break;
        }
        if (c->role == CONN_ROLE_UPSTREAM && c->state == CONN_CONNECTING_UPSTREAM) {
            if (writable || readable) {
                finish_connect(s, c);
            }
            break;
        }
        if (readable && !c->read_closed && !c->close_when_flushed && c->fd >= 0) {
            if (read_into(c) != 0) {
                if (c->role == CONN_ROLE_UPSTREAM && c->peer && c->peer->bytes_written == 0 && c->peer->http) {
                    connect_failed(s, c);
                } else {
                    conn_retire(s, c, 1);
                }
                break;
            }
        }
        if (c->dead) {
            break;
        }
        if (c->close_when_flushed) {
            queue_local(c);
            flush_out(s, c);
            break;
        }
        if (c->http) {
            progress_http(s, c);
        } else if (c->state == CONN_STREAMING) {
            if (transfer_raw(c) != 0) {
                conn_retire(s, c, 1);
                break;
            }
        }
        if (c->dead) {
            break;
        }
        if (c->peer && !c->peer->dead && rp_buf_pending(&c->peer->out) > 0) {
            flush_out(s, c->peer);
        }
        if (c->dead) {
            break;
        }
        if (!c->dead && rp_buf_pending(&c->out) > 0) {
            flush_out(s, c);
        }
        if (c->dead) {
            break;
        }
        if (c->http) {
            note_http_eof(s, c);
            if (!c->dead) {
                maybe_complete(s, c);
            }
        } else {
            tcp_after_io(s, c);
        }
        if (c->dead) {
            break;
        }
        if (!c->msg_done && c->peer && !c->peer->dead && c->peer->state == CONN_STREAMING &&
            rp_buf_pending(&c->in) > 0 && rp_buf_space(&c->peer->out) > 0) {
            c->again = 1;
        }
        /* one shot so a response that landed before EPOLLIN was armed is not stuck.
           the peer's own call bounces off c->busy instead of looping. */
        if (!saw_peer && c->peer && !c->peer->dead && !c->peer->busy &&
            c->peer->state == CONN_STREAMING) {
            saw_peer = 1;
            on_io(s, c->peer, 1, 1);
        }
        readable = 0;
        (void)writable;
    } while (c->again && !c->dead);
    c->busy = 0;
    if (!c->dead) {
        conn_update(s, c);
    }
    if (c->peer && !c->peer->dead) {
        conn_update(s, c->peer);
    }
}

static void accept_on(rp_server_t *s, int listen_fd, int status_only)
{
    for (;;) {
        int fd = accept4(listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        rp_conn_t *c;
        int used = -1;

        if (fd < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        set_nodelay(fd);
        c = conn_get(s);
        if (!c) {
            close(fd);
            pause_listen(s, status_only);
            break;
        }
        c->fd = fd;
        c->watch.fd = fd;
        c->role = CONN_ROLE_CLIENT;
        c->counted = 1;
        s->active_conns++;
        c->http = status_only || s->cfg.mode == RP_MODE_HTTP;
        c->status_only = status_only;
        c->state = c->http ? CONN_READING_REQ : CONN_HANDSHAKE;
        if (conn_update(s, c) != 0) {
            continue;
        }
        if (c->http) {
            /* ET would miss bytes that arrived before the fd was registered */
            on_io(s, c, 1, 0);
            continue;
        }
        if (!c->http) {
            c->state = CONN_CONNECTING_UPSTREAM;
            if (open_upstream(s, c, -1, &used) != 0) {
                c->retries = 1;
                if (used < 0 || open_upstream(s, c, used, &used) != 0) {
                    conn_retire(s, c, 1);
                }
            }
        }
    }
}

static void stop_listeners(rp_server_t *s)
{
    if (s->listen_fd >= 0) {
        epoll_ctl(s->epfd, EPOLL_CTL_DEL, s->listen_fd, NULL);
        close(s->listen_fd);
        s->listen_fd = -1;
        s->listen_paused = 0;
    }
    if (s->status_fd >= 0) {
        epoll_ctl(s->epfd, EPOLL_CTL_DEL, s->status_fd, NULL);
        close(s->status_fd);
        s->status_fd = -1;
        s->status_paused = 0;
    }
}

static void on_signal(rp_server_t *s)
{
    struct signalfd_siginfo info;

    while (read(s->sig_fd, &info, sizeof(info)) == (ssize_t)sizeof(info)) {
        if (info.ssi_signo == SIGHUP) {
            rp_config_t cfg;

            if (rp_config_load(s->cfg.path, &cfg) != 0) {
                rp_log("reload failed, old config stays");
            } else {
                if (cfg.listen_port != s->cfg.listen_port || cfg.status_port != s->cfg.status_port) {
                    rp_log("reload left the listen sockets where they were");
                }
                if (rp_lb_reload(&s->lb, &cfg) != 0) {
                    rp_log("reload failed while swapping upstreams");
                } else {
                    rp_log("reloaded config");
                }
            }
        } else {
            rp_log("shutting down");
            s->running = 0;
            stop_listeners(s);
        }
    }
}

static void force_close_all(rp_server_t *s)
{
    int i;

    for (i = 0; i < RP_MAX_CONNS; i++) {
        rp_conn_t *c = &s->conns[i];

        /* calloc leaves fd at 0. only slots handed out by the pool are live. */
        if (c->watch.conn == c && !c->dead && c->fd >= 0) {
            conn_retire(s, c, 0);
        }
    }
}

static int add_listen_watch(rp_server_t *s, int fd, rp_watch_t *watch, int kind)
{
    struct epoll_event ev;

    watch->kind = kind;
    watch->fd = fd;
    watch->conn = NULL;
    memset(&ev, 0, sizeof(ev));
    ev.events = EPOLLIN;
    ev.data.ptr = watch;
    return epoll_ctl(s->epfd, EPOLL_CTL_ADD, fd, &ev);
}

static int listen_on(uint16_t port)
{
    int fd;
    int one = 1;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        return -1;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0 || listen(fd, 512) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int rp_server_init(rp_server_t *srv, const rp_config_t *cfg)
{
    sigset_t set;
    char line[128];
    int n;

    memset(srv, 0, sizeof(*srv));
    srv->epfd = -1;
    srv->listen_fd = -1;
    srv->status_fd = -1;
    srv->sig_fd = -1;
    srv->cfg = *cfg;

    signal(SIGPIPE, SIG_IGN);
    sigemptyset(&set);
    sigaddset(&set, SIGINT);
    sigaddset(&set, SIGTERM);
    sigaddset(&set, SIGHUP);
    if (pthread_sigmask(SIG_BLOCK, &set, NULL) != 0) {
        return -1;
    }
    if (rp_lb_init(&srv->lb, cfg) != 0) {
        return -1;
    }
    if (rp_pool_init(&srv->pool, RP_MAX_CONNS) != 0) {
        rp_lb_destroy(&srv->lb);
        return -1;
    }
    srv->conns = calloc((size_t)RP_MAX_CONNS, sizeof(rp_conn_t));
    if (!srv->conns) {
        rp_pool_destroy(&srv->pool);
        rp_lb_destroy(&srv->lb);
        return -1;
    }
    srv->listen_fd = listen_on(cfg->listen_port);
    if (srv->listen_fd < 0) {
        rp_log("bind failed");
        rp_server_shutdown(srv);
        return -1;
    }
    if (cfg->status_port != 0) {
        srv->status_fd = listen_on(cfg->status_port);
        if (srv->status_fd < 0) {
            rp_log("status bind failed");
            rp_server_shutdown(srv);
            return -1;
        }
    }
    srv->epfd = epoll_create1(EPOLL_CLOEXEC);
    if (srv->epfd < 0) {
        rp_server_shutdown(srv);
        return -1;
    }
    if (add_listen_watch(srv, srv->listen_fd, &srv->listen_watch, EV_LISTEN) != 0) {
        rp_server_shutdown(srv);
        return -1;
    }
    if (srv->status_fd >= 0 &&
        add_listen_watch(srv, srv->status_fd, &srv->status_watch, EV_STATUS) != 0) {
        rp_server_shutdown(srv);
        return -1;
    }
    srv->sig_fd = signalfd(-1, &set, SFD_NONBLOCK | SFD_CLOEXEC);
    if (srv->sig_fd < 0) {
        rp_server_shutdown(srv);
        return -1;
    }
    srv->sig_watch.kind = EV_SIGNAL;
    srv->sig_watch.fd = srv->sig_fd;
    {
        struct epoll_event ev;

        memset(&ev, 0, sizeof(ev));
        ev.events = EPOLLIN;
        ev.data.ptr = &srv->sig_watch;
        if (epoll_ctl(srv->epfd, EPOLL_CTL_ADD, srv->sig_fd, &ev) != 0) {
            rp_server_shutdown(srv);
            return -1;
        }
    }
    if (rp_health_start(&srv->health, &srv->lb) != 0) {
        rp_server_shutdown(srv);
        return -1;
    }
    srv->running = 1;
    srv->ready = 1;
    n = snprintf(line, sizeof(line), "listening on %u (%s)", (unsigned)cfg->listen_port,
                 cfg->mode == RP_MODE_TCP ? "tcp" : "http");
    if (n > 0 && (size_t)n < sizeof(line)) {
        rp_log(line);
    }
    return 0;
}

int rp_server_run(rp_server_t *srv)
{
    long deadline = 0;

    if (!srv->ready) {
        return -1;
    }
    while (srv->running || srv->active_conns > 0) {
        struct epoll_event evs[64];
        int n;
        int i;

        n = epoll_wait(srv->epfd, evs, 64, srv->running ? 1000 : 50);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        for (i = 0; i < n; i++) {
            rp_watch_t *w = evs[i].data.ptr;
            uint32_t events;

            if (!w) {
                continue;
            }
            events = evs[i].events;
            if (w->kind == EV_SIGNAL) {
                on_signal(srv);
                continue;
            }
            if (w->kind == EV_LISTEN || w->kind == EV_STATUS) {
                if (!srv->running) {
                    continue;
                }
                accept_on(srv, w->fd, w->kind == EV_STATUS);
                continue;
            }
            if (w->kind == EV_CONN && w->conn) {
                int readable = (events & (EPOLLIN | EPOLLRDHUP | EPOLLERR | EPOLLHUP)) != 0;
                int writable = (events & EPOLLOUT) != 0;

                on_io(srv, w->conn, readable, writable);
            }
        }
        reap_conns(srv);
        if (!srv->running) {
            if (deadline == 0) {
                deadline = mono_ms() + 2000;
            }
            if (srv->active_conns <= 0 || mono_ms() >= deadline) {
                if (srv->active_conns > 0) {
                    force_close_all(srv);
                    reap_conns(srv);
                }
                break;
            }
        }
    }
    return 0;
}

void rp_server_shutdown(rp_server_t *srv)
{
    if (!srv) {
        return;
    }
    rp_health_stop(&srv->health);
    stop_listeners(srv);
    if (srv->conns) {
        force_close_all(srv);
        reap_conns(srv);
        free(srv->conns);
        srv->conns = NULL;
    }
    if (srv->sig_fd >= 0) {
        close(srv->sig_fd);
        srv->sig_fd = -1;
    }
    if (srv->epfd >= 0) {
        close(srv->epfd);
        srv->epfd = -1;
    }
    rp_pool_destroy(&srv->pool);
    rp_lb_destroy(&srv->lb);
    srv->ready = 0;
}

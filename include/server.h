#ifndef REVPROXY_SERVER_H
#define REVPROXY_SERVER_H

#include "buffer_pool.h"
#include "config.h"
#include "health_check.h"
#include "load_balancer.h"

#include <stdint.h>

/*client and its upstream peer walk these in order.
 tcp skips READING_REQ. /status never leaves the client conn. */
typedef enum rp_conn_state {
    CONN_HANDSHAKE = 0,
    CONN_READING_REQ,
    CONN_CONNECTING_UPSTREAM,
    CONN_STREAMING,
    CONN_CLOSING
} rp_conn_state_t;

typedef enum rp_conn_role {
    CONN_ROLE_CLIENT = 0,
    CONN_ROLE_UPSTREAM = 1
} rp_conn_role_t;

typedef enum rp_ev_kind {
    EV_LISTEN = 1,
    EV_STATUS = 2,
    EV_SIGNAL = 3,
    EV_CONN = 4
} rp_ev_kind_t;

/* how the rest of this message is framed once the header block is known */
typedef enum rp_body_kind {
    BODY_UNSET = 0,
    BODY_NONE,
    BODY_LENGTH,
    BODY_CHUNKED,
    BODY_CLOSE
} rp_body_kind_t;

typedef enum rp_chunk_state {
    CH_SIZE = 0,
    CH_EXT,
    CH_SIZE_LF,
    CH_DATA,
    CH_DATA_CR,
    CH_DATA_LF,
    CH_TRAILER,
    CH_TRAILER_LF,
    CH_DONE
} rp_chunk_state_t;

typedef struct rp_chunk {
    int state;
    int saw_digit;
    int nonempty;
    int64_t size_acc;
    int64_t need;
} rp_chunk_t;

typedef struct rp_conn rp_conn_t;

/* what epoll_event.data.ptr points at */
typedef struct rp_watch {
    int kind;
    int fd;
    rp_conn_t *conn;
} rp_watch_t;

struct rp_conn {
    rp_watch_t watch;
    int index;
    int fd;
    int dead;
    int in_epoll;
    uint32_t epoll_events;
    rp_conn_t *peer;
    rp_conn_role_t role;
    rp_conn_state_t state;

    int http;          /* parse headers. off for a raw tcp client/upstream */
    int status_only;   /* accepted on the metrics listener */
    int upstream_index;
    int pool_id; /* which upstream pool this request routes to */
    int holding_upstream;
    int retries;
    int counted;
    char req_host[RP_HOST_LEN];
    char req_path[RP_PATH_LEN];
    size_t req_host_len;
    size_t req_path_len;

    rp_buf_t in;
    rp_buf_t out;

    int headers_done;
    size_t hdr_left; /* header bytes still not copied to the peer */
    rp_body_kind_t body_kind;
    int64_t body_left;
    rp_chunk_t chunk;
    int msg_done;    /* this direction's message is fully queued to the peer */
    int resp_done;   /* client: upstream response is fully queued */
    int interim;     /* 1xx, parse another header block after this one */
    int head_method;
    int keep_alive;
    int local_kind; /* 1 json status, 2 prometheus, 0 means proxy it */
    int read_closed;
    int shut_wr;
    int close_when_flushed;
    int busy;
    int again;

    char *local; /* full wire bytes for a reply we generated */
    size_t local_len;
    size_t local_off;

    uint64_t bytes_written; /* bytes send() accepted on this fd */
};

typedef struct rp_server {
    int epfd;
    int listen_fd;
    int status_fd;
    int sig_fd;
    rp_watch_t listen_watch;
    rp_watch_t status_watch;
    rp_watch_t sig_watch;
    rp_config_t cfg;
    rp_lb_t lb;
    rp_health_t health;
    rp_pool_t pool;
    rp_conn_t *conns;
    int listen_paused;
    int status_paused;
    int running;
    int active_conns;
    int reap[RP_MAX_CONNS];
    int reap_n;
    int ready;
} rp_server_t;

int rp_server_init(rp_server_t *srv, const rp_config_t *cfg);
int rp_server_run(rp_server_t *srv);
void rp_server_shutdown(rp_server_t *srv);

#endif

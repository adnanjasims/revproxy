#ifndef REVPROXY_LOAD_BALANCER_H
#define REVPROXY_LOAD_BALANCER_H

#include "config.h"

#include <netinet/in.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>

typedef struct rp_upstream {
    char host[64];
    uint16_t port;
    int weight;
    int current_weight; /* wrr only, epoll thread */
    int pool_id;
    struct sockaddr_in addr;
    _Atomic int in_use;
    _Atomic int draining;
    _Atomic int healthy;
    _Atomic int active;
    _Atomic int fail_count;
    _Atomic int rise_count;
    _Atomic unsigned generation;
    _Atomic uint64_t requests;
    _Atomic uint64_t bytes_in;
    _Atomic uint64_t bytes_out;
} rp_upstream_t;

typedef struct rp_upool {
    char name[RP_NAME_LEN];
    rp_policy_t policy;
    int rr_index;
    int in_use;
} rp_upool_t;

typedef struct rp_route {
    char host[RP_HOST_LEN];
    char path_prefix[RP_PATH_LEN];
    int pool_id;
    int in_use;
} rp_route_t;

typedef struct rp_lb {
    rp_upstream_t ups[RP_MAX_UPSTREAMS];
    rp_upool_t pools[RP_MAX_UPOOLS];
    rp_route_t routes[RP_MAX_ROUTES];
    int default_pool; /* used by tcp and as last-resort http */
    rp_policy_t default_policy;
    rp_mode_t mode;
    pthread_mutex_t mu; /* reload vs health snapshot, not the accept path */
    _Atomic int health_interval;
    _Atomic int health_timeout;
    _Atomic int max_fails;
    _Atomic int rise;
    int mu_ready;
} rp_lb_t;

int rp_lb_init(rp_lb_t *lb, const rp_config_t *cfg);
void rp_lb_destroy(rp_lb_t *lb);
/* apply a new file. listen port and mode are ignored. */
int rp_lb_reload(rp_lb_t *lb, const rp_config_t *cfg);

/*
 * pick a healthy member of pool_id.
 * -1 if nothing is usable. avoid is skipped (pass -1 to allow any).
 */
int rp_lb_select(rp_lb_t *lb, int pool_id, int avoid);

/* match Host + path to a pool. -1 if nothing fits. */
int rp_lb_match_route(const rp_lb_t *lb, const char *host, size_t host_len,
                      const char *path, size_t path_len);

void rp_lb_acquire(rp_lb_t *lb, int index);
void rp_lb_release(rp_lb_t *lb, int index);
void rp_lb_add_bytes_in(rp_lb_t *lb, int index, uint64_t n);
void rp_lb_add_bytes_out(rp_lb_t *lb, int index, uint64_t n);

/* copy sockaddr under the lock. 0 on success. */
int rp_lb_copy_addr(rp_lb_t *lb, int index, struct sockaddr_in *out);

#endif

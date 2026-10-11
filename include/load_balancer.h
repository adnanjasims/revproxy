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

typedef struct rp_lb {
    rp_upstream_t ups[RP_MAX_UPSTREAMS];
    rp_policy_t policy;
    rp_mode_t mode;
    int rr_index;
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

/* -1 if nothing is usable. avoid is skipped (pass -1 to allow any). */
int rp_lb_select(rp_lb_t *lb, int avoid);
void rp_lb_acquire(rp_lb_t *lb, int index);
void rp_lb_release(rp_lb_t *lb, int index);
void rp_lb_add_bytes_in(rp_lb_t *lb, int index, uint64_t n);
void rp_lb_add_bytes_out(rp_lb_t *lb, int index, uint64_t n);

/* copy sockaddr under the lock. 0 on success. */
int rp_lb_copy_addr(rp_lb_t *lb, int index, struct sockaddr_in *out);

#endif

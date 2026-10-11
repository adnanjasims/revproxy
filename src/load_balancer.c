#include "load_balancer.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

static void copy_host(char *dst, const char *src)
{
    size_t i = 0;

    for (; src[i] != '\0' && i + 1 < 64; i++) {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}

static void clear_upstream(rp_upstream_t *u)
{
    memset(u->host, 0, sizeof(u->host));
    u->port = 0;
    u->weight = 0;
    u->current_weight = 0;
    memset(&u->addr, 0, sizeof(u->addr));
    atomic_store_explicit(&u->in_use, 0, memory_order_relaxed);
    atomic_store_explicit(&u->draining, 0, memory_order_relaxed);
    atomic_store_explicit(&u->healthy, 0, memory_order_relaxed);
    atomic_store_explicit(&u->active, 0, memory_order_relaxed);
    atomic_store_explicit(&u->fail_count, 0, memory_order_relaxed);
    atomic_store_explicit(&u->rise_count, 0, memory_order_relaxed);
    atomic_store_explicit(&u->requests, 0, memory_order_relaxed);
    atomic_store_explicit(&u->bytes_in, 0, memory_order_relaxed);
    atomic_store_explicit(&u->bytes_out, 0, memory_order_relaxed);
}

static int install_upstream(rp_upstream_t *u, const rp_upstream_cfg_t *cfg)
{
    struct in_addr in;

    if (inet_pton(AF_INET, cfg->host, &in) != 1) {
        return -1;
    }
    clear_upstream(u);
    copy_host(u->host, cfg->host);
    u->port = cfg->port;
    u->weight = cfg->weight > 0 ? cfg->weight : 1;
    u->current_weight = 0;
    memset(&u->addr, 0, sizeof(u->addr));
    u->addr.sin_family = AF_INET;
    u->addr.sin_port = htons(cfg->port);
    u->addr.sin_addr = in;
    atomic_fetch_add_explicit(&u->generation, 1u, memory_order_acq_rel);
    atomic_store_explicit(&u->healthy, 1, memory_order_release);
    atomic_store_explicit(&u->in_use, 1, memory_order_release);
    atomic_store_explicit(&u->draining, 0, memory_order_release);
    return 0;
}

static int same_target(const rp_upstream_t *u, const rp_upstream_cfg_t *cfg)
{
    if (!atomic_load_explicit(&u->in_use, memory_order_acquire)) {
        return 0;
    }
    return u->port == cfg->port && strcmp(u->host, cfg->host) == 0;
}

static int usable(const rp_upstream_t *u)
{
    if (!atomic_load_explicit(&u->in_use, memory_order_acquire)) {
        return 0;
    }
    if (atomic_load_explicit(&u->draining, memory_order_acquire)) {
        return 0;
    }
    if (!atomic_load_explicit(&u->healthy, memory_order_acquire)) {
        return 0;
    }
    if (u->weight <= 0) {
        return 0;
    }
    return 1;
}

int rp_lb_init(rp_lb_t *lb, const rp_config_t *cfg)
{
    int i;

    memset(lb, 0, sizeof(*lb));
    if (pthread_mutex_init(&lb->mu, NULL) != 0) {
        return -1;
    }
    lb->mu_ready = 1;
    lb->policy = cfg->policy;
    lb->mode = cfg->mode;
    atomic_store(&lb->health_interval, cfg->health_interval);
    atomic_store(&lb->health_timeout, cfg->health_timeout);
    atomic_store(&lb->max_fails, cfg->max_fails);
    atomic_store(&lb->rise, cfg->rise);
    for (i = 0; i < cfg->upstream_count; i++) {
        if (install_upstream(&lb->ups[i], &cfg->upstreams[i]) != 0) {
            rp_lb_destroy(lb);
            return -1;
        }
    }
    return 0;
}

void rp_lb_destroy(rp_lb_t *lb)
{
    if (!lb) {
        return;
    }
    if (lb->mu_ready) {
        pthread_mutex_destroy(&lb->mu);
        lb->mu_ready = 0;
    }
}

int rp_lb_reload(rp_lb_t *lb, const rp_config_t *cfg)
{
    int matched[RP_MAX_UPSTREAMS];
    int i;

    if (cfg->mode != lb->mode) {
        fprintf(stderr, "revproxy: reload kept the old mode\n");
    }
    pthread_mutex_lock(&lb->mu);
    lb->policy = cfg->policy;
    atomic_store(&lb->health_interval, cfg->health_interval);
    atomic_store(&lb->health_timeout, cfg->health_timeout);
    atomic_store(&lb->max_fails, cfg->max_fails);
    atomic_store(&lb->rise, cfg->rise);

    for (i = 0; i < RP_MAX_UPSTREAMS; i++) {
        matched[i] = 0;
    }
    for (i = 0; i < cfg->upstream_count; i++) {
        int slot = -1;
        int j;

        for (j = 0; j < RP_MAX_UPSTREAMS; j++) {
            if (same_target(&lb->ups[j], &cfg->upstreams[i])) {
                slot = j;
                break;
            }
        }
        if (slot >= 0) {
            matched[slot] = 1;
            lb->ups[slot].weight = cfg->upstreams[i].weight;
            atomic_store_explicit(&lb->ups[slot].draining, 0, memory_order_release);
            continue;
        }
        for (j = 0; j < RP_MAX_UPSTREAMS; j++) {
            int active = atomic_load_explicit(&lb->ups[j].active, memory_order_acquire);
            int in_use = atomic_load_explicit(&lb->ups[j].in_use, memory_order_acquire);
            int draining = atomic_load_explicit(&lb->ups[j].draining, memory_order_acquire);

            if (!in_use || (draining && active == 0)) {
                slot = j;
                break;
            }
        }
        if (slot < 0) {
            fprintf(stderr, "revproxy: reload dropped %s:%u, table full\n",
                    cfg->upstreams[i].host, (unsigned)cfg->upstreams[i].port);
            continue;
        }
        if (install_upstream(&lb->ups[slot], &cfg->upstreams[i]) != 0) {
            pthread_mutex_unlock(&lb->mu);
            return -1;
        }
        matched[slot] = 1;
    }
    for (i = 0; i < RP_MAX_UPSTREAMS; i++) {
        int active;

        if (matched[i]) {
            continue;
        }
        if (!atomic_load_explicit(&lb->ups[i].in_use, memory_order_acquire)) {
            continue;
        }
        atomic_store_explicit(&lb->ups[i].draining, 1, memory_order_release);
        atomic_store_explicit(&lb->ups[i].healthy, 0, memory_order_release);
        active = atomic_load_explicit(&lb->ups[i].active, memory_order_acquire);
        if (active == 0) {
            atomic_store_explicit(&lb->ups[i].in_use, 0, memory_order_release);
            atomic_fetch_add_explicit(&lb->ups[i].generation, 1u, memory_order_acq_rel);
        }
    }
    pthread_mutex_unlock(&lb->mu);
    return 0;
}

int rp_lb_select(rp_lb_t *lb, int avoid)
{
    int i;

    if (lb->policy == RP_POLICY_RR) {
        for (i = 0; i < RP_MAX_UPSTREAMS; i++) {
            int idx = (lb->rr_index + i) % RP_MAX_UPSTREAMS;

            if (idx == avoid) {
                continue;
            }
            if (!usable(&lb->ups[idx])) {
                continue;
            }
            lb->rr_index = (idx + 1) % RP_MAX_UPSTREAMS;
            return idx;
        }
        return -1;
    }

    if (lb->policy == RP_POLICY_LEAST) {
        int best = -1;
        int best_n = 0;

        for (i = 0; i < RP_MAX_UPSTREAMS; i++) {
            int n;

            if (i == avoid || !usable(&lb->ups[i])) {
                continue;
            }
            n = atomic_load_explicit(&lb->ups[i].active, memory_order_relaxed);
            if (best < 0 || n < best_n) {
                best = i;
                best_n = n;
            }
        }
        return best;
    }

    /* smooth weighted round robin. current_weight stays on this thread. */
    {
        int total = 0;
        int best = -1;
        int best_cur = 0;

        for (i = 0; i < RP_MAX_UPSTREAMS; i++) {
            rp_upstream_t *u = &lb->ups[i];

            if (i == avoid || !usable(u)) {
                continue;
            }
            u->current_weight += u->weight;
            total += u->weight;
            if (best < 0 || u->current_weight > best_cur) {
                best = i;
                best_cur = u->current_weight;
            }
        }
        if (best >= 0) {
            lb->ups[best].current_weight -= total;
        }
        return best;
    }
}

void rp_lb_acquire(rp_lb_t *lb, int index)
{
    if (index < 0 || index >= RP_MAX_UPSTREAMS) {
        return;
    }
    atomic_fetch_add_explicit(&lb->ups[index].active, 1, memory_order_relaxed);
    atomic_fetch_add_explicit(&lb->ups[index].requests, 1, memory_order_relaxed);
}

void rp_lb_release(rp_lb_t *lb, int index)
{
    if (index < 0 || index >= RP_MAX_UPSTREAMS) {
        return;
    }
    atomic_fetch_sub_explicit(&lb->ups[index].active, 1, memory_order_relaxed);
}

void rp_lb_add_bytes_in(rp_lb_t *lb, int index, uint64_t n)
{
    if (index < 0 || index >= RP_MAX_UPSTREAMS || n == 0) {
        return;
    }
    atomic_fetch_add_explicit(&lb->ups[index].bytes_in, n, memory_order_relaxed);
}

void rp_lb_add_bytes_out(rp_lb_t *lb, int index, uint64_t n)
{
    if (index < 0 || index >= RP_MAX_UPSTREAMS || n == 0) {
        return;
    }
    atomic_fetch_add_explicit(&lb->ups[index].bytes_out, n, memory_order_relaxed);
}

int rp_lb_copy_addr(rp_lb_t *lb, int index, struct sockaddr_in *out)
{
    if (index < 0 || index >= RP_MAX_UPSTREAMS || !out) {
        return -1;
    }
    pthread_mutex_lock(&lb->mu);
    if (!atomic_load_explicit(&lb->ups[index].in_use, memory_order_acquire)) {
        pthread_mutex_unlock(&lb->mu);
        return -1;
    }
    *out = lb->ups[index].addr;
    pthread_mutex_unlock(&lb->mu);
    return 0;
}

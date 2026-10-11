#include "load_balancer.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

static void copy_n(char *dst, size_t cap, const char *src)
{
    size_t i = 0;

    if (cap == 0) {
        return;
    }
    for (; src[i] != '\0' && i + 1 < cap; i++) {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}

static int ascii_eq_ci(const char *a, size_t an, const char *b)
{
    size_t i;

    for (i = 0; b[i] != '\0'; i++) {
        char ca;
        char cb;

        if (i >= an) {
            return 0;
        }
        ca = a[i];
        cb = b[i];
        if (ca >= 'A' && ca <= 'Z') {
            ca = (char)(ca - 'A' + 'a');
        }
        if (cb >= 'A' && cb <= 'Z') {
            cb = (char)(cb - 'A' + 'a');
        }
        if (ca != cb) {
            return 0;
        }
    }
    return i == an;
}

static size_t host_without_port(const char *host, size_t n)
{
    size_t i;

    /* strip :port. leave IPv6 alone (we only speak IPv4 anyway). */
    for (i = 0; i < n; i++) {
        if (host[i] == ':') {
            return i;
        }
    }
    return n;
}

static void clear_upstream(rp_upstream_t *u)
{
    memset(u->host, 0, sizeof(u->host));
    u->port = 0;
    u->weight = 0;
    u->current_weight = 0;
    u->pool_id = -1;
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

static int find_pool_name(const rp_lb_t *lb, const char *name)
{
    int i;

    for (i = 0; i < RP_MAX_UPOOLS; i++) {
        if (lb->pools[i].in_use && strcmp(lb->pools[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

static int install_upstream(rp_upstream_t *u, const rp_upstream_cfg_t *cfg, int pool_id)
{
    struct in_addr in;

    if (inet_pton(AF_INET, cfg->host, &in) != 1) {
        return -1;
    }
    clear_upstream(u);
    copy_n(u->host, sizeof(u->host), cfg->host);
    u->port = cfg->port;
    u->weight = cfg->weight > 0 ? cfg->weight : 1;
    u->current_weight = 0;
    u->pool_id = pool_id;
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

static int same_target(const rp_upstream_t *u, const rp_upstream_cfg_t *cfg, int pool_id)
{
    if (!atomic_load_explicit(&u->in_use, memory_order_acquire)) {
        return 0;
    }
    return u->pool_id == pool_id && u->port == cfg->port && strcmp(u->host, cfg->host) == 0;
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

static int path_prefix_match(const char *path, size_t path_len, const char *prefix)
{
    size_t plen = strlen(prefix);
    size_t i;

    if (plen == 0) {
        return 0;
    }
    if (path_len < plen) {
        return 0;
    }
    for (i = 0; i < plen; i++) {
        if (path[i] != prefix[i]) {
            return 0;
        }
    }
    /* "/api" matches "/api" and "/api/...", not "/apiv2" */
    if (plen > 1 && path_len > plen && path[plen] != '/') {
        return 0;
    }
    return 1;
}

static int apply_config(rp_lb_t *lb, const rp_config_t *cfg, int is_reload)
{
    int matched[RP_MAX_UPSTREAMS];
    int i;
    int def;

    lb->default_policy = cfg->policy;
    lb->mode = cfg->mode;
    atomic_store(&lb->health_interval, cfg->health_interval);
    atomic_store(&lb->health_timeout, cfg->health_timeout);
    atomic_store(&lb->max_fails, cfg->max_fails);
    atomic_store(&lb->rise, cfg->rise);

    for (i = 0; i < RP_MAX_UPOOLS; i++) {
        lb->pools[i].in_use = 0;
        lb->pools[i].name[0] = '\0';
        lb->pools[i].rr_index = 0;
    }
    for (i = 0; i < cfg->upool_count; i++) {
        copy_n(lb->pools[i].name, sizeof(lb->pools[i].name), cfg->upools[i].name);
        lb->pools[i].policy = cfg->upools[i].policy;
        lb->pools[i].in_use = 1;
        if (!is_reload) {
            lb->pools[i].rr_index = 0;
        }
    }

    for (i = 0; i < RP_MAX_ROUTES; i++) {
        lb->routes[i].in_use = 0;
        lb->routes[i].host[0] = '\0';
        lb->routes[i].path_prefix[0] = '\0';
        lb->routes[i].pool_id = -1;
    }
    for (i = 0; i < cfg->route_count; i++) {
        int pid = find_pool_name(lb, cfg->routes[i].pool);

        if (pid < 0) {
            return -1;
        }
        copy_n(lb->routes[i].host, sizeof(lb->routes[i].host), cfg->routes[i].host);
        copy_n(lb->routes[i].path_prefix, sizeof(lb->routes[i].path_prefix),
               cfg->routes[i].path_prefix);
        lb->routes[i].pool_id = pid;
        lb->routes[i].in_use = 1;
    }

    for (i = 0; i < RP_MAX_UPSTREAMS; i++) {
        matched[i] = 0;
    }

    for (i = 0; i < cfg->upstream_count; i++) {
        int pool_id = find_pool_name(lb, cfg->upstreams[i].pool);
        int slot = -1;
        int j;

        if (pool_id < 0) {
            return -1;
        }
        for (j = 0; j < RP_MAX_UPSTREAMS; j++) {
            if (same_target(&lb->ups[j], &cfg->upstreams[i], pool_id)) {
                slot = j;
                break;
            }
        }
        if (slot >= 0) {
            matched[slot] = 1;
            lb->ups[slot].weight = cfg->upstreams[i].weight;
            lb->ups[slot].pool_id = pool_id;
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
        if (install_upstream(&lb->ups[slot], &cfg->upstreams[i], pool_id) != 0) {
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

    def = find_pool_name(lb, "default");
    if (def < 0) {
        for (i = 0; i < RP_MAX_UPOOLS; i++) {
            if (lb->pools[i].in_use) {
                def = i;
                break;
            }
        }
    }
    lb->default_pool = def;
    return 0;
}

int rp_lb_init(rp_lb_t *lb, const rp_config_t *cfg)
{
    memset(lb, 0, sizeof(*lb));
    lb->default_pool = -1;
    if (pthread_mutex_init(&lb->mu, NULL) != 0) {
        return -1;
    }
    lb->mu_ready = 1;
    if (apply_config(lb, cfg, 0) != 0) {
        rp_lb_destroy(lb);
        return -1;
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
    if (cfg->mode != lb->mode) {
        fprintf(stderr, "revproxy: reload kept the old mode\n");
    }
    pthread_mutex_lock(&lb->mu);
    if (apply_config(lb, cfg, 1) != 0) {
        pthread_mutex_unlock(&lb->mu);
        return -1;
    }
    pthread_mutex_unlock(&lb->mu);
    return 0;
}

int rp_lb_match_route(const rp_lb_t *lb, const char *host, size_t host_len,
                      const char *path, size_t path_len)
{
    int best = -1;
    int best_score = -1;
    size_t hlen;
    int i;

    if (!path || path_len == 0) {
        return lb->default_pool;
    }
    hlen = host ? host_without_port(host, host_len) : 0;

    for (i = 0; i < RP_MAX_ROUTES; i++) {
        const rp_route_t *r = &lb->routes[i];
        size_t plen;
        int host_specific;
        int score;

        if (!r->in_use) {
            continue;
        }
        if (!path_prefix_match(path, path_len, r->path_prefix)) {
            continue;
        }
        host_specific = r->host[0] != '\0';
        if (host_specific) {
            if (hlen == 0 || !ascii_eq_ci(host, hlen, r->host)) {
                continue;
            }
        }
        plen = strlen(r->path_prefix);
        /* longest path wins; host match breaks ties */
        score = (int)(plen * 2u) + (host_specific ? 1 : 0);
        if (score > best_score) {
            best = r->pool_id;
            best_score = score;
        }
    }
    return best;
}

int rp_lb_select(rp_lb_t *lb, int pool_id, int avoid)
{
    int i;
    rp_policy_t policy;

    if (pool_id < 0 || pool_id >= RP_MAX_UPOOLS || !lb->pools[pool_id].in_use) {
        return -1;
    }
    policy = lb->pools[pool_id].policy;

    if (policy == RP_POLICY_RR) {
        for (i = 0; i < RP_MAX_UPSTREAMS; i++) {
            int idx = (lb->pools[pool_id].rr_index + i) % RP_MAX_UPSTREAMS;

            if (idx == avoid) {
                continue;
            }
            if (lb->ups[idx].pool_id != pool_id || !usable(&lb->ups[idx])) {
                continue;
            }
            lb->pools[pool_id].rr_index = (idx + 1) % RP_MAX_UPSTREAMS;
            return idx;
        }
        return -1;
    }

    if (policy == RP_POLICY_LEAST) {
        int best = -1;
        int best_n = 0;

        for (i = 0; i < RP_MAX_UPSTREAMS; i++) {
            int n;

            if (i == avoid || lb->ups[i].pool_id != pool_id || !usable(&lb->ups[i])) {
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

    /* smooth weighted round robin within the pool */
    {
        int total = 0;
        int best = -1;
        int best_cur = 0;

        for (i = 0; i < RP_MAX_UPSTREAMS; i++) {
            rp_upstream_t *u = &lb->ups[i];

            if (i == avoid || u->pool_id != pool_id || !usable(u)) {
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

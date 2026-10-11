#ifndef REVPROXY_CONFIG_H
#define REVPROXY_CONFIG_H

#include "buffer_pool.h"

#include <stdint.h>

typedef enum rp_mode {
    RP_MODE_HTTP = 0,
    RP_MODE_TCP = 1
} rp_mode_t;

typedef enum rp_policy {
    RP_POLICY_RR = 0,
    RP_POLICY_WRR = 1,
    RP_POLICY_LEAST = 2
} rp_policy_t;

typedef struct rp_upstream_cfg {
    char pool[RP_NAME_LEN];
    char host[64];
    uint16_t port;
    int weight;
} rp_upstream_cfg_t;

typedef struct rp_upool_cfg {
    char name[RP_NAME_LEN];
    rp_policy_t policy;
    int policy_set;
} rp_upool_cfg_t;

/* host and/or path_prefix. empty host means any host. */
typedef struct rp_route_cfg {
    char host[RP_HOST_LEN];
    char path_prefix[RP_PATH_LEN];
    char pool[RP_NAME_LEN];
} rp_route_cfg_t;

typedef struct rp_config {
    char path[512];
    uint16_t listen_port;
    uint16_t status_port; /* 0 if the main listener is enough */
    rp_mode_t mode;
    rp_policy_t policy; /* default for pools that do not override */
    int health_interval; /* seconds */
    int health_timeout;  /* seconds */
    int max_fails;
    int rise;
    int upool_count;
    int upstream_count;
    int route_count;
    rp_upool_cfg_t upools[RP_MAX_UPOOLS];
    rp_upstream_cfg_t upstreams[RP_MAX_UPSTREAMS];
    rp_route_cfg_t routes[RP_MAX_ROUTES];
} rp_config_t;

/* 0 on success. messages go to stderr. */
int rp_config_load(const char *path, rp_config_t *cfg);

#endif

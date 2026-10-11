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
    char host[64];
    uint16_t port;
    int weight;
} rp_upstream_cfg_t;

typedef struct rp_config {
    char path[512];
    uint16_t listen_port;
    uint16_t status_port; /* 0 if the main listener is enough */
    rp_mode_t mode;
    rp_policy_t policy;
    int health_interval; /* seconds */
    int health_timeout;  /* seconds */
    int max_fails;
    int rise;
    int upstream_count;
    rp_upstream_cfg_t upstreams[RP_MAX_UPSTREAMS];
} rp_config_t;

/* 0 on success. messages go to stderr. */
int rp_config_load(const char *path, rp_config_t *cfg);

#endif

#include "config.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void cfg_defaults(rp_config_t *cfg)
{
    memset(cfg, 0, sizeof(*cfg));
    cfg->mode = RP_MODE_HTTP;
    cfg->policy = RP_POLICY_RR;
    cfg->health_interval = 2;
    cfg->health_timeout = 1;
    cfg->max_fails = 3;
    cfg->rise = 2;
}

static int parse_port(const char *s, uint16_t *out)
{
    char *end = NULL;
    long v;

    if (!s || !s[0]) {
        return -1;
    }
    v = strtol(s, &end, 10);
    if (!end || *end != '\0' || v < 1 || v > 65535) {
        return -1;
    }
    *out = (uint16_t)v;
    return 0;
}

static int parse_pos_int(const char *s, int *out)
{
    char *end = NULL;
    long v;

    v = strtol(s, &end, 10);
    if (!end || *end != '\0' || v < 1 || v > 86400) {
        return -1;
    }
    *out = (int)v;
    return 0;
}

static int parse_policy(const char *s, rp_policy_t *out)
{
    if (strcmp(s, "rr") == 0) {
        *out = RP_POLICY_RR;
        return 0;
    }
    if (strcmp(s, "wrr") == 0) {
        *out = RP_POLICY_WRR;
        return 0;
    }
    if (strcmp(s, "leastconn") == 0) {
        *out = RP_POLICY_LEAST;
        return 0;
    }
    return -1;
}

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

/* split on spaces. '#' starts a comment. */
static int tokenize(char *line, char **argv, int max)
{
    int n = 0;
    char *p = line;

    while (*p != '\0' && n < max) {
        while (*p == ' ' || *p == '\t') {
            p++;
        }
        if (*p == '\0' || *p == '#') {
            break;
        }
        argv[n++] = p;
        while (*p != '\0' && *p != ' ' && *p != '\t') {
            p++;
        }
        if (*p != '\0') {
            *p = '\0';
            p++;
        }
    }
    return n;
}

static int find_pool(rp_config_t *cfg, const char *name)
{
    int i;

    for (i = 0; i < cfg->upool_count; i++) {
        if (strcmp(cfg->upools[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

static int ensure_pool(rp_config_t *cfg, const char *name, int lineno)
{
    int idx = find_pool(cfg, name);

    if (idx >= 0) {
        return idx;
    }
    if (cfg->upool_count >= RP_MAX_UPOOLS) {
        fprintf(stderr, "revproxy: config line %d: too many pools\n", lineno);
        return -1;
    }
    idx = cfg->upool_count++;
    memset(&cfg->upools[idx], 0, sizeof(cfg->upools[idx]));
    copy_n(cfg->upools[idx].name, sizeof(cfg->upools[idx].name), name);
    cfg->upools[idx].policy = cfg->policy;
    cfg->upools[idx].policy_set = 0;
    return idx;
}

static int kv_value(const char *tok, const char *key, char *out, size_t out_cap)
{
    size_t klen = strlen(key);

    if (strncmp(tok, key, klen) != 0 || tok[klen] != '=') {
        return -1;
    }
    copy_n(out, out_cap, tok + klen + 1);
    return out[0] != '\0' ? 0 : -1;
}

static int add_pool(rp_config_t *cfg, char **argv, int argc, int lineno)
{
    int idx;
    int i;

    if (argc < 2) {
        fprintf(stderr, "revproxy: config line %d: pool needs a name\n", lineno);
        return -1;
    }
    if (strlen(argv[1]) >= RP_NAME_LEN) {
        fprintf(stderr, "revproxy: config line %d: pool name too long\n", lineno);
        return -1;
    }
    idx = ensure_pool(cfg, argv[1], lineno);
    if (idx < 0) {
        return -1;
    }
    for (i = 2; i < argc; i++) {
        char val[32];

        if (kv_value(argv[i], "policy", val, sizeof(val)) == 0) {
            if (parse_policy(val, &cfg->upools[idx].policy) != 0) {
                fprintf(stderr, "revproxy: config line %d: bad pool policy\n", lineno);
                return -1;
            }
            cfg->upools[idx].policy_set = 1;
        } else {
            fprintf(stderr, "revproxy: config line %d: unknown pool option\n", lineno);
            return -1;
        }
    }
    return 0;
}

static int add_upstream(rp_config_t *cfg, char **argv, int argc, int lineno)
{
    rp_upstream_cfg_t *u;
    uint16_t port = 0;
    int weight = 1;
    struct in_addr addr;
    const char *pool_name = "default";
    const char *ip;
    const char *port_s;
    int i;
    int arg0;

    /*
     * forms:
     *   upstream 127.0.0.1 9001 [weight=N]
     *   upstream api 127.0.0.1 9001 [weight=N]
     */
    if (argc < 3) {
        fprintf(stderr, "revproxy: config line %d: upstream needs [pool] ip port\n", lineno);
        return -1;
    }
    if (cfg->upstream_count >= RP_MAX_UPSTREAMS) {
        fprintf(stderr, "revproxy: config line %d: too many upstreams\n", lineno);
        return -1;
    }

    if (inet_pton(AF_INET, argv[1], &addr) == 1) {
        ip = argv[1];
        port_s = argv[2];
        arg0 = 3;
    } else {
        if (argc < 4) {
            fprintf(stderr, "revproxy: config line %d: upstream needs pool ip port\n", lineno);
            return -1;
        }
        pool_name = argv[1];
        ip = argv[2];
        port_s = argv[3];
        arg0 = 4;
        if (inet_pton(AF_INET, ip, &addr) != 1) {
            fprintf(stderr, "revproxy: config line %d: bad ipv4 address\n", lineno);
            return -1;
        }
    }
    if (parse_port(port_s, &port) != 0) {
        fprintf(stderr, "revproxy: config line %d: bad port\n", lineno);
        return -1;
    }
    for (i = arg0; i < argc; i++) {
        if (strncmp(argv[i], "weight=", 7) == 0) {
            if (parse_pos_int(argv[i] + 7, &weight) != 0) {
                fprintf(stderr, "revproxy: config line %d: bad weight\n", lineno);
                return -1;
            }
        } else {
            fprintf(stderr, "revproxy: config line %d: unknown upstream option\n", lineno);
            return -1;
        }
    }
    if (ensure_pool(cfg, pool_name, lineno) < 0) {
        return -1;
    }
    u = &cfg->upstreams[cfg->upstream_count++];
    memset(u, 0, sizeof(*u));
    copy_n(u->pool, sizeof(u->pool), pool_name);
    copy_n(u->host, sizeof(u->host), ip);
    u->port = port;
    u->weight = weight;
    return 0;
}

static int add_route(rp_config_t *cfg, char **argv, int argc, int lineno)
{
    rp_route_cfg_t *r;
    char host[RP_HOST_LEN];
    char path[RP_PATH_LEN];
    char pool[RP_NAME_LEN];
    int i;
    int saw_pool = 0;

    host[0] = '\0';
    path[0] = '\0';
    pool[0] = '\0';

    if (argc < 2) {
        fprintf(stderr, "revproxy: config line %d: empty route\n", lineno);
        return -1;
    }
    if (cfg->route_count >= RP_MAX_ROUTES) {
        fprintf(stderr, "revproxy: config line %d: too many routes\n", lineno);
        return -1;
    }
    for (i = 1; i < argc; i++) {
        if (kv_value(argv[i], "host", host, sizeof(host)) == 0) {
            continue;
        }
        if (kv_value(argv[i], "path_prefix", path, sizeof(path)) == 0) {
            continue;
        }
        if (kv_value(argv[i], "path", path, sizeof(path)) == 0) {
            continue;
        }
        if (kv_value(argv[i], "pool", pool, sizeof(pool)) == 0) {
            saw_pool = 1;
            continue;
        }
        fprintf(stderr, "revproxy: config line %d: bad route option\n", lineno);
        return -1;
    }
    if (!saw_pool) {
        fprintf(stderr, "revproxy: config line %d: route needs pool=\n", lineno);
        return -1;
    }
    if (host[0] == '\0' && path[0] == '\0') {
        fprintf(stderr, "revproxy: config line %d: route needs host= and/or path_prefix=\n", lineno);
        return -1;
    }
    if (path[0] == '\0') {
        copy_n(path, sizeof(path), "/");
    }
    if (path[0] != '/') {
        fprintf(stderr, "revproxy: config line %d: path_prefix must start with /\n", lineno);
        return -1;
    }
    if (ensure_pool(cfg, pool, lineno) < 0) {
        return -1;
    }
    r = &cfg->routes[cfg->route_count++];
    memset(r, 0, sizeof(*r));
    copy_n(r->host, sizeof(r->host), host);
    copy_n(r->path_prefix, sizeof(r->path_prefix), path);
    copy_n(r->pool, sizeof(r->pool), pool);
    return 0;
}

static int finalize_config(rp_config_t *cfg)
{
    int i;

    if (cfg->upstream_count < 1) {
        fprintf(stderr, "revproxy: config needs at least one upstream\n");
        return -1;
    }
    if (cfg->upool_count < 1) {
        if (ensure_pool(cfg, "default", 0) < 0) {
            return -1;
        }
    }
    /* bare http configs with no routes get a catch-all onto default/first pool */
    if (cfg->mode == RP_MODE_HTTP && cfg->route_count == 0) {
        int pool_idx = find_pool(cfg, "default");
        rp_route_cfg_t *r;

        if (pool_idx < 0) {
            pool_idx = 0;
        }
        if (cfg->route_count >= RP_MAX_ROUTES) {
            fprintf(stderr, "revproxy: cannot add default route\n");
            return -1;
        }
        r = &cfg->routes[cfg->route_count++];
        memset(r, 0, sizeof(*r));
        copy_n(r->path_prefix, sizeof(r->path_prefix), "/");
        copy_n(r->pool, sizeof(r->pool), cfg->upools[pool_idx].name);
    }
    if (cfg->mode == RP_MODE_TCP && cfg->route_count > 0) {
        fprintf(stderr, "revproxy: tcp mode ignores route lines; leave them out\n");
    }
    for (i = 0; i < cfg->upool_count; i++) {
        if (!cfg->upools[i].policy_set) {
            cfg->upools[i].policy = cfg->policy;
        }
    }
    for (i = 0; i < cfg->upstream_count; i++) {
        if (find_pool(cfg, cfg->upstreams[i].pool) < 0) {
            fprintf(stderr, "revproxy: upstream references unknown pool %s\n",
                    cfg->upstreams[i].pool);
            return -1;
        }
    }
    for (i = 0; i < cfg->route_count; i++) {
        int p = find_pool(cfg, cfg->routes[i].pool);
        int j;
        int members = 0;

        if (p < 0) {
            fprintf(stderr, "revproxy: route references unknown pool %s\n", cfg->routes[i].pool);
            return -1;
        }
        for (j = 0; j < cfg->upstream_count; j++) {
            if (strcmp(cfg->upstreams[j].pool, cfg->routes[i].pool) == 0) {
                members++;
            }
        }
        if (members < 1) {
            fprintf(stderr, "revproxy: pool %s has no upstreams\n", cfg->routes[i].pool);
            return -1;
        }
    }
    return 0;
}

int rp_config_load(const char *path, rp_config_t *cfg)
{
    FILE *fp;
    char line[512];
    int lineno = 0;
    int saw_listen = 0;
    size_t path_len;

    if (!path || !cfg) {
        return -1;
    }
    cfg_defaults(cfg);
    path_len = strlen(path);
    if (path_len == 0 || path_len >= sizeof(cfg->path)) {
        fprintf(stderr, "revproxy: config path is too long\n");
        return -1;
    }
    memcpy(cfg->path, path, path_len + 1);

    fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "revproxy: cannot open %s\n", path);
        return -1;
    }

    while (fgets(line, (int)sizeof(line), fp)) {
        char *argv[12];
        int argc;
        size_t n;

        lineno++;
        n = strlen(line);
        if (n > 0 && line[n - 1] != '\n' && !feof(fp)) {
            fprintf(stderr, "revproxy: config line %d: line too long\n", lineno);
            fclose(fp);
            return -1;
        }
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r')) {
            line[--n] = '\0';
        }
        argc = tokenize(line, argv, 12);
        if (argc == 0) {
            continue;
        }
        if (strcmp(argv[0], "listen") == 0 && argc == 2) {
            if (parse_port(argv[1], &cfg->listen_port) != 0) {
                fprintf(stderr, "revproxy: config line %d: bad listen port\n", lineno);
                fclose(fp);
                return -1;
            }
            saw_listen = 1;
        } else if (strcmp(argv[0], "status_port") == 0 && argc == 2) {
            if (parse_port(argv[1], &cfg->status_port) != 0) {
                fprintf(stderr, "revproxy: config line %d: bad status_port\n", lineno);
                fclose(fp);
                return -1;
            }
        } else if (strcmp(argv[0], "mode") == 0 && argc == 2) {
            if (strcmp(argv[1], "http") == 0) {
                cfg->mode = RP_MODE_HTTP;
            } else if (strcmp(argv[1], "tcp") == 0) {
                cfg->mode = RP_MODE_TCP;
            } else {
                fprintf(stderr, "revproxy: config line %d: mode is http or tcp\n", lineno);
                fclose(fp);
                return -1;
            }
        } else if (strcmp(argv[0], "policy") == 0 && argc == 2) {
            if (parse_policy(argv[1], &cfg->policy) != 0) {
                fprintf(stderr, "revproxy: config line %d: policy is rr, wrr, or leastconn\n", lineno);
                fclose(fp);
                return -1;
            }
        } else if (strcmp(argv[0], "health_interval") == 0 && argc == 2) {
            if (parse_pos_int(argv[1], &cfg->health_interval) != 0) {
                fprintf(stderr, "revproxy: config line %d: bad health_interval\n", lineno);
                fclose(fp);
                return -1;
            }
        } else if (strcmp(argv[0], "health_timeout") == 0 && argc == 2) {
            if (parse_pos_int(argv[1], &cfg->health_timeout) != 0) {
                fprintf(stderr, "revproxy: config line %d: bad health_timeout\n", lineno);
                fclose(fp);
                return -1;
            }
        } else if (strcmp(argv[0], "max_fails") == 0 && argc == 2) {
            if (parse_pos_int(argv[1], &cfg->max_fails) != 0) {
                fprintf(stderr, "revproxy: config line %d: bad max_fails\n", lineno);
                fclose(fp);
                return -1;
            }
        } else if (strcmp(argv[0], "rise") == 0 && argc == 2) {
            if (parse_pos_int(argv[1], &cfg->rise) != 0) {
                fprintf(stderr, "revproxy: config line %d: bad rise\n", lineno);
                fclose(fp);
                return -1;
            }
        } else if (strcmp(argv[0], "pool") == 0) {
            if (add_pool(cfg, argv, argc, lineno) != 0) {
                fclose(fp);
                return -1;
            }
        } else if (strcmp(argv[0], "upstream") == 0) {
            if (add_upstream(cfg, argv, argc, lineno) != 0) {
                fclose(fp);
                return -1;
            }
        } else if (strcmp(argv[0], "route") == 0) {
            if (add_route(cfg, argv, argc, lineno) != 0) {
                fclose(fp);
                return -1;
            }
        } else {
            fprintf(stderr, "revproxy: config line %d: unknown or incomplete\n", lineno);
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);

    if (!saw_listen) {
        fprintf(stderr, "revproxy: config missing listen\n");
        return -1;
    }
    if (cfg->mode == RP_MODE_TCP && cfg->status_port == 0) {
        fprintf(stderr, "revproxy: tcp mode needs status_port\n");
        return -1;
    }
    if (cfg->status_port != 0 && cfg->status_port == cfg->listen_port) {
        fprintf(stderr, "revproxy: status_port matches listen\n");
        return -1;
    }
    return finalize_config(cfg);
}

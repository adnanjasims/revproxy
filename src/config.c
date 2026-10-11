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

static void copy_host(char *dst, const char *src)
{
    size_t i = 0;

    for (; src[i] != '\0' && i + 1 < 64; i++) {
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

static int add_upstream(rp_config_t *cfg, char **argv, int argc, int lineno)
{
    rp_upstream_cfg_t *u;
    uint16_t port = 0;
    int weight = 1;
    struct in_addr addr;

    if (argc < 3 || argc > 4) {
        fprintf(stderr, "revproxy: config line %d: upstream needs ip port [weight=N]\n", lineno);
        return -1;
    }
    if (cfg->upstream_count >= RP_MAX_UPSTREAMS) {
        fprintf(stderr, "revproxy: config line %d: too many upstreams\n", lineno);
        return -1;
    }
    if (inet_pton(AF_INET, argv[1], &addr) != 1) {
        fprintf(stderr, "revproxy: config line %d: bad ipv4 address\n", lineno);
        return -1;
    }
    if (parse_port(argv[2], &port) != 0) {
        fprintf(stderr, "revproxy: config line %d: bad port\n", lineno);
        return -1;
    }
    if (argc == 4) {
        if (strncmp(argv[3], "weight=", 7) != 0) {
            fprintf(stderr, "revproxy: config line %d: expected weight=N\n", lineno);
            return -1;
        }
        if (parse_pos_int(argv[3] + 7, &weight) != 0) {
            fprintf(stderr, "revproxy: config line %d: bad weight\n", lineno);
            return -1;
        }
    }
    u = &cfg->upstreams[cfg->upstream_count++];
    memset(u, 0, sizeof(*u));
    copy_host(u->host, argv[1]);
    u->port = port;
    u->weight = weight;
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
        char *argv[8];
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
        argc = tokenize(line, argv, 8);
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
            if (strcmp(argv[1], "rr") == 0) {
                cfg->policy = RP_POLICY_RR;
            } else if (strcmp(argv[1], "wrr") == 0) {
                cfg->policy = RP_POLICY_WRR;
            } else if (strcmp(argv[1], "leastconn") == 0) {
                cfg->policy = RP_POLICY_LEAST;
            } else {
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
        } else if (strcmp(argv[0], "upstream") == 0) {
            if (add_upstream(cfg, argv, argc, lineno) != 0) {
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
    if (cfg->upstream_count < 1) {
        fprintf(stderr, "revproxy: config needs at least one upstream\n");
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
    return 0;
}

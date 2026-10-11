#ifndef REVPROXY_HEALTH_CHECK_H
#define REVPROXY_HEALTH_CHECK_H

#include "load_balancer.h"

#include <stdatomic.h>

typedef struct rp_health {
    pthread_t thread;
    rp_lb_t *lb;
    _Atomic int stop;
    int started;
} rp_health_t;

int rp_health_start(rp_health_t *health, rp_lb_t *lb);
void rp_health_stop(rp_health_t *health);

#endif

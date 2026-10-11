#ifndef REVPROXY_BUFFER_POOL_H
#define REVPROXY_BUFFER_POOL_H

#include <stddef.h>

/* fixed at startup. accept never calls malloc. */
#define RP_MAX_CONNS 4096
#define RP_BUF_SIZE 8192
#define RP_MAX_UPSTREAMS 64
#define RP_MAX_UPOOLS 16
#define RP_MAX_ROUTES 64
#define RP_NAME_LEN 64
#define RP_HOST_LEN 128
#define RP_PATH_LEN 256

typedef struct rp_buf {
    char data[RP_BUF_SIZE];
    size_t len; /* bytes valid from the start of data */
    size_t off; /* already consumed */
} rp_buf_t;

/*free-list of conn slot indexes. the bytes live on the conn. */
typedef struct rp_pool {
    int *free_list;
    int free_top;
    int cap;
} rp_pool_t;

int rp_pool_init(rp_pool_t *pool, int cap);
void rp_pool_destroy(rp_pool_t *pool);
int rp_pool_acquire(rp_pool_t *pool);
void rp_pool_release(rp_pool_t *pool, int index);

void rp_buf_clear(rp_buf_t *buf);
size_t rp_buf_pending(const rp_buf_t *buf);
size_t rp_buf_space(const rp_buf_t *buf);
/* 0 on success, -1 if it does not fit even after compacting */
int rp_buf_append(rp_buf_t *buf, const void *src, size_t n);
void rp_buf_compact(rp_buf_t *buf);

#endif

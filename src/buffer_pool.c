#include "buffer_pool.h"

#include <stdlib.h>
#include <string.h>

int rp_pool_init(rp_pool_t *pool, int cap)
{
    int i;

    if (!pool || cap <= 0) {
        return -1;
    }
    pool->free_list = malloc((size_t)cap * sizeof(int));
    if (!pool->free_list) {
        return -1;
    }
    pool->cap = cap;
    pool->free_top = cap;
    for (i = 0; i < cap; i++) {
        /* highest index comes off first. order does not matter. */
        pool->free_list[i] = cap - 1 - i;
    }
    return 0;
}

void rp_pool_destroy(rp_pool_t *pool)
{
    if (!pool) {
        return;
    }
    free(pool->free_list);
    pool->free_list = NULL;
    pool->free_top = 0;
    pool->cap = 0;
}

int rp_pool_acquire(rp_pool_t *pool)
{
    if (!pool || pool->free_top <= 0) {
        return -1;
    }
    pool->free_top--;
    return pool->free_list[pool->free_top];
}

void rp_pool_release(rp_pool_t *pool, int index)
{
    if (!pool || index < 0 || index >= pool->cap) {
        return;
    }
    if (pool->free_top >= pool->cap) {
        return;
    }
    pool->free_list[pool->free_top++] = index;
}

void rp_buf_clear(rp_buf_t *buf)
{
    buf->len = 0;
    buf->off = 0;
}

size_t rp_buf_pending(const rp_buf_t *buf)
{
    return buf->len - buf->off;
}

size_t rp_buf_space(const rp_buf_t *buf)
{
    return RP_BUF_SIZE - (buf->len - buf->off);
}

void rp_buf_compact(rp_buf_t *buf)
{
    size_t n;

    if (buf->off == 0) {
        return;
    }
    n = buf->len - buf->off;
    if (n > 0) {
        memmove(buf->data, buf->data + buf->off, n);
    }
    buf->len = n;
    buf->off = 0;
}

int rp_buf_append(rp_buf_t *buf, const void *src, size_t n)
{
    if (n == 0) {
        return 0;
    }
    if (n > rp_buf_space(buf)) {
        return -1;
    }
    if (n > RP_BUF_SIZE - buf->len) {
        rp_buf_compact(buf);
    }
    memcpy(buf->data + buf->len, src, n);
    buf->len += n;
    return 0;
}

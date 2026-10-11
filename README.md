# revproxy

Linux reverse proxy / load balancer. HTTP/1.1 or plain TCP. libc and pthreads only. No TLS.

One thread runs the epoll loop. Another health-checks backends. HTTP mode can split traffic by `Host` and path prefix into named upstream pools.

## Build

Linux only (`epoll`, `signalfd`).

```sh
make debug            # asan/ubsan
make release          # -O3
make valgrind-build   # no sanitizers
```

Or cmake:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build
```

## Config

See `revproxy.conf.example`.

```
listen 8080
status_port 8081
mode http
policy wrr
health_interval 2
health_timeout 1
max_fails 3
rise 2

pool api policy=wrr
pool web policy=leastconn
upstream api 127.0.0.1 9001 weight=1
upstream api 127.0.0.1 9002 weight=2
upstream web 127.0.0.1 9003 weight=1

route host=api.local path_prefix=/v1 pool=api
route path_prefix=/api pool=api
route path_prefix=/ pool=web
```

`mode` is `http` or `tcp`. Pool `policy` is `rr`, `wrr`, or `leastconn`.

Bare `upstream 127.0.0.1 9001` still works — it lands in a `default` pool and gets a catch-all `/` route.

TCP mode needs `status_port` and ignores `route` lines.

`/status` is JSON (pools, routes, upstream health). `/metrics` is Prometheus text.

`SIGTERM` / `SIGINT` drain and exit. `SIGHUP` reloads the config (listen port stays put).

## Run

```sh
./revproxy revproxy.conf
```

## Tests

```sh
make debug
./tests/run_tests.sh
```

## Notes

- fixed connection pool, no malloc on the accept path
- failed connect retries once inside the same pool before 502
- unmatched Host/path returns 404
- client keep-alive works; upstream connections are one-shot
- `wrk -t4 -c128 -d30s http://127.0.0.1:8080/` is fine for a local check

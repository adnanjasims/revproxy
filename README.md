# revproxy

Small reverse proxy for Linux. Speaks HTTP/1.1 or plain TCP. No deps beyond libc and pthreads, and no TLS. One thread runs the epoll loop, and another one health-checks the backends.

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

Copy `revproxy.conf.example` and edit it. Roughly:

```
listen 8080
status_port 8081
mode http
policy wrr
health_interval 2
health_timeout 1
max_fails 3
rise 2
upstream 127.0.0.1 9001 weight=1
upstream 127.0.0.1 9002 weight=2
```

`mode` is `http` or `tcp`. `policy` is `rr`, `wrr`, or `leastconn`. TCP mode needs `status_port` because the data port isn't HTTP

`/status` returns JSON

 `/metrics` is Prometheus text.

`SIGTERM` / `SIGINT` drain and exit

 `SIGHUP` reloads the config (listen port doesn't move).

## Run

```sh
./revproxy revproxy.conf
```



## Tests

```sh
make debug
./tests/run_tests.sh
```

That spins up a few mock backends (`tests/mock_backends.py`), hits them with curl, checks failover, and runs wrk if it's installed.

For valgrind:

```sh
make valgrind-build
valgrind --leak-check=full --error-exitcode=1 ./revproxy your.conf
```



## Notes

- fixed connection pool, and no malloc on the accept path
- failed connect retries once on a different upstream before 502
- client keep-alive works; upstream connections are one-shot
- `wrk -t4 -c128 -d30s http://127.0.0.1:8080/` is fine for a local check


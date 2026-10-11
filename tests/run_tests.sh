#!/bin/sh
# drive the proxy with curl, and wrk when it happens to be installed.
set -u

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
BIN="$ROOT/revproxy"
PY=${PYTHON:-python3}
BODY=$(mktemp)
CFG=$(mktemp)
TCPCFG=$(mktemp)
LOG=$(mktemp)
BLOG=$(mktemp)
fail=0

LISTEN=18080
STATUS=18081
TCPLISTEN=18082
TCPSTATUS=18083
BASE=19001

PROXY_PID=""
BACK_PID=""
BACK2=""
TCP_PID=""

cleanup() {
    if [ -n "$TCP_PID" ]; then
        kill "$TCP_PID" 2>/dev/null || true
        wait "$TCP_PID" 2>/dev/null || true
    fi
    if [ -n "$PROXY_PID" ]; then
        kill "$PROXY_PID" 2>/dev/null || true
        wait "$PROXY_PID" 2>/dev/null || true
    fi
    if [ -n "$BACK_PID" ]; then
        kill "$BACK_PID" 2>/dev/null || true
        wait "$BACK_PID" 2>/dev/null || true
    fi
    if [ -n "$BACK2" ]; then
        kill "$BACK2" 2>/dev/null || true
        wait "$BACK2" 2>/dev/null || true
    fi
    rm -f "$BODY" "$CFG" "$TCPCFG" "$LOG" "$BLOG"
}
trap cleanup EXIT

if [ ! -x "$BIN" ]; then
    echo "build revproxy first (make debug)" >&2
    exit 1
fi

say() {
    printf '%s\n' "$1"
}

die() {
    printf 'FAIL %s\n' "$1" >&2
    if [ -s "$LOG" ]; then
        printf '%s\n' '--- proxy log ---' >&2
        cat "$LOG" >&2
    fi
    exit 1
}

# one fresh connection. prints the body on stdout, or dies.
hit() {
    url=$1
    code=$(curl -sS -m 3 -o "$BODY" -w '%{http_code}' "$url") || die "curl $url"
    if [ "$code" != "200" ]; then
        die "$url returned $code"
    fi
    cat "$BODY"
}

"$PY" "$ROOT/tests/mock_backends.py" --base-port "$BASE" --count 3 --latency-ms 0 --error-rate 0 \
    >"$BLOG" 2>&1 &
BACK_PID=$!
sleep 0.3

cat >"$CFG" <<EOF
listen $LISTEN
status_port $STATUS
mode http
policy rr
health_interval 1
health_timeout 1
max_fails 2
rise 1
upstream 127.0.0.1 $BASE weight=1
upstream 127.0.0.1 $((BASE + 1)) weight=1
upstream 127.0.0.1 $((BASE + 2)) weight=1
EOF

"$BIN" "$CFG" >"$LOG" 2>&1 &
PROXY_PID=$!
sleep 0.3
kill -0 "$PROXY_PID" 2>/dev/null || die "proxy exited early"

say "steady requests"
i=1
while [ "$i" -le 30 ]; do
    hit "http://127.0.0.1:$LISTEN/" >/dev/null
    i=$((i + 1))
done

say "status and metrics"
hit "http://127.0.0.1:$LISTEN/status" | grep -q '"healthy":true' || die "status json"
hit "http://127.0.0.1:$STATUS/metrics" | grep -q 'lb_active_connections' || die "metrics"
hit "http://127.0.0.1:$STATUS/status" | grep -q '127.0.0.1:'"$BASE" || die "status port"

say "post and chunked body"
post=$(curl -sS -m 3 -o "$BODY" -w '%{http_code}' -X POST --data 'hello' "http://127.0.0.1:$LISTEN/") || die "post"
[ "$post" = "200" ] || die "post code $post"
grep -q ' 5$' "$BODY" || die "post length: $(cat "$BODY")"

"$PY" - <<PY || die "chunked body"
import socket
s = socket.create_connection(("127.0.0.1", $LISTEN), 3)
req = (
    b"POST / HTTP/1.1\r\nHost: t\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    b"5\r\nhello\r\n0\r\n\r\n"
)
s.sendall(req)
data = b""
while b"backend" not in data:
    chunk = s.recv(4096)
    if not chunk:
        break
    data += chunk
s.close()
if b"backend" not in data or b" 5" not in data.split(b"\r\n\r\n", 1)[-1]:
    raise SystemExit("chunked failed: %r" % data)
PY

say "keep-alive"
"$PY" - <<PY || die "keep-alive"
import socket
s = socket.create_connection(("127.0.0.1", $LISTEN), 3)
req = b"GET / HTTP/1.1\r\nHost: t\r\nConnection: keep-alive\r\n\r\n"
for n in (1, 2):
    s.sendall(req)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = s.recv(4096)
        if not chunk:
            raise SystemExit("short read")
        data += chunk
    head, rest = data.split(b"\r\n\r\n", 1)
    length = None
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1].strip())
    if length is None:
        raise SystemExit("no length")
    while len(rest) < length:
        chunk = s.recv(4096)
        if not chunk:
            break
        rest += chunk
    body = rest[:length]
    if not body.startswith(b"backend "):
        raise SystemExit("bad body %r" % body)
    # leave any extra bytes, this client does not pipeline
s.close()
PY

say "reload"
kill -HUP "$PROXY_PID"
sleep 0.2
hit "http://127.0.0.1:$LISTEN/" >/dev/null

if command -v wrk >/dev/null 2>&1; then
    say "wrk"
    wrk_out=$(wrk -t2 -c8 -d3s "http://127.0.0.1:$LISTEN/" 2>&1) || die "wrk failed"
    printf '%s\n' "$wrk_out"
    if printf '%s\n' "$wrk_out" | grep -E 'Non-2xx|Socket errors' >/dev/null; then
        die "wrk saw errors"
    fi
else
    say "wrk not installed, skipped"
fi

say "drop one backend"
# backend 2 is the second listener. killing the whole mock and bringing two back
# is clumsier, so stop just that port by restarting the set without it.
kill "$BACK_PID"
wait "$BACK_PID" 2>/dev/null || true
BACK_PID=""
"$PY" "$ROOT/tests/mock_backends.py" --base-port "$BASE" --count 1 --latency-ms 0 \
    >"$BLOG" 2>&1 &
BACK_PID=$!
"$PY" "$ROOT/tests/mock_backends.py" --base-port $((BASE + 2)) --count 1 --latency-ms 0 \
    >>"$BLOG" 2>&1 &
BACK2=$!
sleep 0.2

i=1
while [ "$i" -le 20 ]; do
    body=$(hit "http://127.0.0.1:$LISTEN/")
    case "$body" in
        *"backend 2"*) die "dead backend still answered: $body" ;;
    esac
    i=$((i + 1))
done

# print "down" or "up" for host:port from a /status body on stdin
upstream_health() {
    "$PY" -c '
import json, sys
want = sys.argv[1]
doc = json.load(sys.stdin)
for pool in doc.get("pools", []):
    for row in pool.get("upstreams", []):
        if row["addr"] == want:
            print("down" if row["healthy"] is False else "up")
            raise SystemExit(0)
print("missing")
' "$1"
}

say "wait until the missing one is marked down"
ok=0
i=1
while [ "$i" -le 20 ]; do
    st=$(hit "http://127.0.0.1:$STATUS/status")
    state=$(printf '%s' "$st" | upstream_health "127.0.0.1:$((BASE + 1))")
    if [ "$state" = "down" ]; then
        ok=1
        break
    fi
    sleep 0.5
    i=$((i + 1))
done
[ "$ok" = 1 ] || die "backend 2 never went down: $(hit http://127.0.0.1:$STATUS/status)"

say "bring it back"
kill "$BACK_PID" "$BACK2" 2>/dev/null || true
wait "$BACK_PID" 2>/dev/null || true
wait "$BACK2" 2>/dev/null || true
"$PY" "$ROOT/tests/mock_backends.py" --base-port "$BASE" --count 3 --latency-ms 0 \
    >"$BLOG" 2>&1 &
BACK_PID=$!
sleep 0.3

ok=0
i=1
while [ "$i" -le 20 ]; do
    st=$(hit "http://127.0.0.1:$STATUS/status")
    state=$(printf '%s' "$st" | upstream_health "127.0.0.1:$((BASE + 1))")
    if [ "$state" = "up" ]; then
        ok=1
        break
    fi
    sleep 0.5
    i=$((i + 1))
done
[ "$ok" = 1 ] || die "backend 2 did not recover"

seen=0
i=1
while [ "$i" -le 30 ]; do
    body=$(hit "http://127.0.0.1:$LISTEN/")
    case "$body" in
        *"backend 2"*) seen=1; break ;;
    esac
    i=$((i + 1))
done
[ "$seen" = 1 ] || die "recovered backend got no traffic"

say "path and host routing"
kill "$PROXY_PID"
wait "$PROXY_PID"
PROXY_PID=""
cat >"$CFG" <<EOF
listen $LISTEN
status_port $STATUS
mode http
policy rr
health_interval 1
health_timeout 1
max_fails 2
rise 1
pool api policy=rr
pool web policy=rr
upstream api 127.0.0.1 $BASE weight=1
upstream api 127.0.0.1 $((BASE + 1)) weight=1
upstream web 127.0.0.1 $((BASE + 2)) weight=1
route path_prefix=/api pool=api
route host=api.local path_prefix=/ pool=api
route path_prefix=/ pool=web
EOF
"$BIN" "$CFG" >"$LOG" 2>&1 &
PROXY_PID=$!
sleep 0.3
kill -0 "$PROXY_PID" 2>/dev/null || die "routing proxy exited early"

body=$(hit "http://127.0.0.1:$LISTEN/")
case "$body" in
    *"backend 3"*) ;;
    *) die "default path should hit web pool: $body" ;;
esac

body=$(hit "http://127.0.0.1:$LISTEN/api/x")
case "$body" in
    *"backend 1"*|*"backend 2"*) ;;
    *) die "/api should hit api pool: $body" ;;
esac

body=$(curl -sS -m 3 -H 'Host: api.local' "http://127.0.0.1:$LISTEN/") || die "host route curl"
case "$body" in
    *"backend 1"*|*"backend 2"*) ;;
    *) die "Host api.local should hit api pool: $body" ;;
esac

code=$(curl -sS -m 3 -o "$BODY" -w '%{http_code}' "http://127.0.0.1:$LISTEN/missing-prefix-should-still-match-root") || die "catch-all"
[ "$code" = "200" ] || die "catch-all code $code"
grep -q 'backend 3' "$BODY" || die "catch-all body"

say "tcp mode"
kill "$PROXY_PID"
wait "$PROXY_PID"
PROXY_PID=""
cat >"$TCPCFG" <<EOF
listen $TCPLISTEN
status_port $TCPSTATUS
mode tcp
policy rr
health_interval 1
health_timeout 1
max_fails 2
rise 1
upstream 127.0.0.1 $BASE weight=1
upstream 127.0.0.1 $((BASE + 1)) weight=1
upstream 127.0.0.1 $((BASE + 2)) weight=1
EOF
"$BIN" "$TCPCFG" >"$LOG" 2>&1 &
TCP_PID=$!
sleep 0.3
"$PY" - <<PY || die "tcp proxy"
import socket
s = socket.create_connection(("127.0.0.1", $TCPLISTEN), 3)
s.sendall(b"GET / HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n")
data = b""
while b"\r\n\r\n" not in data:
    chunk = s.recv(4096)
    if not chunk:
        raise SystemExit("tcp proxy closed early")
    data += chunk
head, rest = data.split(b"\r\n\r\n", 1)
length = None
for line in head.split(b"\r\n"):
    if line.lower().startswith(b"content-length:"):
        length = int(line.split(b":", 1)[1].strip())
if length is None:
    raise SystemExit("tcp proxy missing length: %r" % data)
while len(rest) < length:
    chunk = s.recv(4096)
    if not chunk:
        break
    rest += chunk
s.close()
if not rest.startswith(b"backend "):
    raise SystemExit("tcp proxy failed: %r" % rest[:80])
PY
code=$(curl -sS -m 3 -o "$BODY" -w '%{http_code}' "http://127.0.0.1:$TCPSTATUS/metrics") || die "tcp metrics"
[ "$code" = "200" ] || die "tcp metrics $code"
grep -q 'lb_upstream_up' "$BODY" || die "tcp metrics body"

say "signal stop"
kill -TERM "$TCP_PID"
i=0
while kill -0 "$TCP_PID" 2>/dev/null; do
    i=$((i + 1))
    if [ "$i" -gt 30 ]; then
        die "proxy ignored SIGTERM"
    fi
    sleep 0.1
done
wait "$TCP_PID"
rc=$?
TCP_PID=""
# 143 is 128+SIGTERM if the process is killed rather than exiting itself.
# the proxy should exit 0.
if [ "$rc" -ne 0 ]; then
    die "proxy exit $rc"
fi

say "ok"
exit "$fail"

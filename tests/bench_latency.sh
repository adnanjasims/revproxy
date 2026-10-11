#!/bin/sh
# latency / throughput: direct vs revproxy vs sequential proxy.
set -u

ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
BIN="$ROOT/revproxy"
PY=${PYTHON:-python3}
SEQ="$ROOT/tests/seq_proxy.py"

LISTEN=18080
STATUS=18081
LISTEN1=18085
STATUS1=18086
SEQPORT=18084
BASE=19001
DURATION=${DURATION:-10}
CONNECTIONS=${CONNECTIONS:-64}
THREADS=${THREADS:-4}

PROXY_PID=""
PROXY1_PID=""
BACK_PID=""
SEQ_PID=""
CFG=$(mktemp)
CFG1=$(mktemp)
OUT=$(mktemp)

cleanup() {
    [ -n "$PROXY_PID" ] && kill "$PROXY_PID" 2>/dev/null || true
    [ -n "$PROXY1_PID" ] && kill "$PROXY1_PID" 2>/dev/null || true
    [ -n "$SEQ_PID" ] && kill "$SEQ_PID" 2>/dev/null || true
    [ -n "$BACK_PID" ] && kill "$BACK_PID" 2>/dev/null || true
    wait 2>/dev/null || true
    rm -f "$CFG" "$CFG1" "$OUT"
}
trap cleanup EXIT

if [ ! -x "$BIN" ]; then
    echo "build first: make release" >&2
    exit 1
fi
command -v wrk >/dev/null 2>&1 || { echo "wrk required" >&2; exit 1; }

"$PY" "$ROOT/tests/mock_backends.py" --base-port "$BASE" --count 3 --latency-ms 5 \
    >/tmp/revproxy-bench-back.log 2>&1 &
BACK_PID=$!
sleep 0.5

cat >"$CFG" <<EOF
listen $LISTEN
status_port $STATUS
mode http
policy wrr
health_interval 30
health_timeout 1
max_fails 50
rise 1
upstream 127.0.0.1 $BASE weight=1
upstream 127.0.0.1 $((BASE + 1)) weight=1
upstream 127.0.0.1 $((BASE + 2)) weight=1
EOF

cat >"$CFG1" <<EOF
listen $LISTEN1
status_port $STATUS1
mode http
policy rr
health_interval 30
health_timeout 1
max_fails 50
rise 1
upstream 127.0.0.1 $BASE weight=1
EOF

"$BIN" "$CFG" >/tmp/revproxy-bench-proxy.log 2>&1 &
PROXY_PID=$!
"$BIN" "$CFG1" >/tmp/revproxy-bench-proxy1.log 2>&1 &
PROXY1_PID=$!
"$PY" "$SEQ" --listen "$SEQPORT" --upstream 127.0.0.1:"$BASE" --serial \
    >/tmp/revproxy-bench-seq.log 2>&1 &
SEQ_PID=$!
sleep 0.4

run_wrk() {
    label=$1
    url=$2
    {
        echo
        echo "=== $label ==="
        echo "wrk -t$THREADS -c$CONNECTIONS -d${DURATION}s -H 'Connection: close' $url"
        wrk -t"$THREADS" -c"$CONNECTIONS" -d"${DURATION}s" --latency -H 'Connection: close' "$url"
    } | tee -a "$OUT"
}

curl -sf -m 2 "http://127.0.0.1:$BASE/" >/dev/null
curl -sf -m 2 "http://127.0.0.1:$LISTEN/" >/dev/null
curl -sf -m 2 "http://127.0.0.1:$LISTEN1/" >/dev/null
curl -sf -m 2 "http://127.0.0.1:$SEQPORT/" >/dev/null

run_wrk "direct backend (1 server)" "http://127.0.0.1:$BASE/"
run_wrk "revproxy 1 upstream (proxy overhead)" "http://127.0.0.1:$LISTEN1/"
run_wrk "revproxy 3 upstreams (load balanced)" "http://127.0.0.1:$LISTEN/"
run_wrk "sequential proxy 1-in-flight" "http://127.0.0.1:$SEQPORT/"

echo
echo "=== summary ==="
"$PY" - "$OUT" "$CONNECTIONS" <<'PY'
import re, sys
from pathlib import Path

text = Path(sys.argv[1]).read_text()
conns = sys.argv[2]
blocks = re.split(r"\n=== ", "\n" + text)
rows = []

def to_ms(v, u):
    x = float(v)
    if u == "us":
        return x / 1000.0
    if u == "s":
        return x * 1000.0
    return x

for b in blocks:
    if not b.strip():
        continue
    title = b.split("\n", 1)[0].strip().rstrip("=").strip()
    m = re.search(
        r"Latency\s+([0-9.]+)(us|ms|s)\s+([0-9.]+)(us|ms|s)\s+([0-9.]+)(us|ms|s)",
        b,
    )
    p50 = re.search(r"50%\s+([0-9.]+)(us|ms|s)", b)
    p99 = re.search(r"99%\s+([0-9.]+)(us|ms|s)", b)
    rps = re.search(r"Requests/sec:\s+([0-9.]+)", b)
    if not m or not rps:
        continue
    rows.append({
        "title": title,
        "avg_ms": to_ms(m.group(1), m.group(2)),
        "p50_ms": to_ms(p50.group(1), p50.group(2)) if p50 else None,
        "p99_ms": to_ms(p99.group(1), p99.group(2)) if p99 else None,
        "rps": float(rps.group(1)),
    })

def find(part):
    for r in rows:
        if part in r["title"]:
            return r
    return None

direct = find("direct")
one = find("1 upstream")
three = find("3 upstreams")
seq = find("sequential")

for r in rows:
    p50 = f'{r["p50_ms"]:.2f}' if r["p50_ms"] is not None else "?"
    p99 = f'{r["p99_ms"]:.2f}' if r["p99_ms"] is not None else "?"
    print(f'{r["title"]}: avg={r["avg_ms"]:.2f}ms  p50={p50}ms  p99={p99}ms  rps={r["rps"]:.0f}')

print()
if three and seq and seq["avg_ms"] > 0:
    lat_pct = (seq["avg_ms"] - three["avg_ms"]) / seq["avg_ms"] * 100.0
    thr_x = three["rps"] / seq["rps"] if seq["rps"] else 0
    print(f'latency vs sequential: {seq["avg_ms"]:.2f}ms -> {three["avg_ms"]:.2f}ms ({lat_pct:+.1f}%)')
    print(f'throughput vs sequential: {seq["rps"]:.0f} -> {three["rps"]:.0f} rps ({thr_x:.1f}x)')
if one and direct:
    print(f'proxy overhead (1 upstream vs direct): {one["avg_ms"] - direct["avg_ms"]:+.2f}ms avg')
if three and direct:
    print(f'3-upstream revproxy vs 1 direct backend: {three["rps"] / direct["rps"]:.1f}x throughput')

print()
print("resume-safe lines:")
if three and seq and seq["avg_ms"] > three["avg_ms"]:
    lat_pct = (seq["avg_ms"] - three["avg_ms"]) / seq["avg_ms"] * 100.0
    print(
        f'- Cut average latency by {lat_pct:.0f}% vs a sequential one-request-at-a-time proxy '
        f'under {conns} concurrent clients ({seq["avg_ms"]:.0f}ms -> {three["avg_ms"]:.1f}ms; '
        f'wrk, 3 backends @ 5ms delay).'
    )
if three and seq and three["rps"] > seq["rps"]:
    thr_x = three["rps"] / seq["rps"]
    thr_pct = (three["rps"] - seq["rps"]) / seq["rps"] * 100.0
    print(
        f'- Increased throughput {thr_x:.0f}x ({thr_pct:.0f}%) vs the same sequential proxy '
        f'({seq["rps"]:.0f} -> {three["rps"]:.0f} req/s at {conns} connections).'
    )
if three:
    p50 = f'{three["p50_ms"]:.1f}' if three["p50_ms"] is not None else "?"
    p99 = f'{three["p99_ms"]:.1f}' if three["p99_ms"] is not None else "?"
    print(
        f'- Sustained {three["rps"]:.0f} req/s at p50={p50}ms / p99={p99}ms through the epoll proxy '
        f'(wrk -c{conns}, 3 backends with 5ms artificial delay).'
    )
if one and direct:
    oh = one["avg_ms"] - direct["avg_ms"]
    print(
        f'- Added ~{oh:.1f}ms average proxy overhead vs hitting one backend directly '
        f'under the same load (wrk -c{conns}).'
    )
PY

#!/usr/bin/env python3
"""a few plain http servers so the proxy has something to talk to."""

import argparse
import random
import socket
import threading
import time


def read_chunked(conn, buf):
    body = b""
    while True:
        while b"\r\n" not in buf:
            data = conn.recv(4096)
            if not data:
                return body, buf
            buf += data
        line, buf = buf.split(b"\r\n", 1)
        size_txt = line.split(b";", 1)[0].strip()
        size = int(size_txt, 16) if size_txt else 0
        if size == 0:
            if not buf.startswith(b"\r\n"):
                while b"\r\n\r\n" not in buf:
                    data = conn.recv(4096)
                    if not data:
                        break
                    buf += data
            if b"\r\n\r\n" in buf:
                buf = buf.split(b"\r\n\r\n", 1)[1]
            elif buf.startswith(b"\r\n"):
                buf = buf[2:]
            return body, buf
        while len(buf) < size + 2:
            data = conn.recv(4096)
            if not data:
                return body, buf
            buf += data
        body += buf[:size]
        buf = buf[size + 2 :]
    return body, buf


def handle(conn, backend_id, latency_s, error_rate):
    buf = b""
    conn.settimeout(8)
    try:
        while True:
            while b"\r\n\r\n" not in buf:
                data = conn.recv(4096)
                if not data:
                    return
                buf += data
            head, buf = buf.split(b"\r\n\r\n", 1)
            lines = head.decode("iso-8859-1", "replace").split("\r\n")
            parts = lines[0].split(" ")
            if len(parts) < 2:
                return
            method, path = parts[0], parts[1]
            headers = {}
            for line in lines[1:]:
                if ":" not in line:
                    continue
                key, val = line.split(":", 1)
                headers[key.strip().lower()] = val.strip()
            if "chunked" in headers.get("transfer-encoding", "").lower():
                req_body, buf = read_chunked(conn, buf)
            else:
                need = int(headers.get("content-length", "0") or "0")
                while len(buf) < need:
                    data = conn.recv(4096)
                    if not data:
                        return
                    buf += data
                req_body = buf[:need]
                buf = buf[need:]
            target = path.split("?", 1)[0]
            if target == "/health":
                status, payload = 200, b"ok\n"
            elif error_rate > 0 and random.random() < error_rate:
                status, payload = 500, b"err\n"
            elif method == "POST":
                status = 200
                payload = ("backend %d %d\n" % (backend_id, len(req_body))).encode()
            else:
                status = 200
                payload = ("backend %d\n" % backend_id).encode()
            if latency_s > 0 and target != "/health":
                time.sleep(latency_s)
            reason = "OK" if status == 200 else "ERR"
            raw = (
                "HTTP/1.1 %d %s\r\n"
                "Content-Type: text/plain\r\n"
                "Content-Length: %d\r\n"
                "Connection: keep-alive\r\n"
                "\r\n" % (status, reason, len(payload))
            ).encode() + payload
            conn.sendall(raw)
    except (ConnectionError, socket.timeout, ValueError):
        return
    finally:
        try:
            conn.close()
        except OSError:
            pass


def accept_loop(sock, backend_id, latency_s, error_rate, stop):
    while not stop.is_set():
        try:
            conn, _addr = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        handle(conn, backend_id, latency_s, error_rate)


def serve(port, backend_id, latency_s, error_rate, stop):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", port))
    sock.listen(256)
    sock.settimeout(0.5)
    # fixed workers. a thread per request falls over once wrk is involved,
    # and then the health probe just sits in the accept queue.
    workers = []
    for _ in range(8):
        th = threading.Thread(
            target=accept_loop,
            args=(sock, backend_id, latency_s, error_rate, stop),
            daemon=True,
        )
        th.start()
        workers.append(th)
    while not stop.is_set():
        time.sleep(0.2)
    sock.close()
    for th in workers:
        th.join(timeout=1.0)


def main():
    parser = argparse.ArgumentParser(description="spin up mock http backends")
    parser.add_argument("--base-port", type=int, default=19001)
    parser.add_argument("--count", type=int, default=3)
    parser.add_argument("--latency-ms", type=int, default=0)
    parser.add_argument("--error-rate", type=float, default=0.0)
    args = parser.parse_args()
    stop = threading.Event()
    threads = []
    for i in range(args.count):
        port = args.base_port + i
        th = threading.Thread(
            target=serve,
            args=(port, i + 1, args.latency_ms / 1000.0, args.error_rate, stop),
            daemon=True,
        )
        th.start()
        threads.append(th)
        print("backend %d on %d" % (i + 1, port), flush=True)
    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        stop.set()


if __name__ == "__main__":
    main()

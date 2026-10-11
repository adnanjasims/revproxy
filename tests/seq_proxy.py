#!/usr/bin/env python3
"""blocking HTTP proxy. --serial makes only one request in flight at a time."""

import argparse
import socket
import threading


def read_headers(sock):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return None, b""
        buf += chunk
        if len(buf) > 65536:
            return None, b""
    head, rest = buf.split(b"\r\n\r\n", 1)
    return head + b"\r\n\r\n", rest


def content_length(head):
    for line in head.split(b"\r\n"):
        if line.lower().startswith(b"content-length:"):
            return int(line.split(b":", 1)[1].strip())
    return 0


def read_exact(sock, buf, n):
    while len(buf) < n:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf[:n], buf[n:]


def one_exchange(client, upstream_host, upstream_port):
    head, rest = read_headers(client)
    if head is None:
        return False
    need = content_length(head)
    body, _ = read_exact(client, rest, need)
    # force close so wrk does not keep the client conn pinned on this handler
    if b"\r\nConnection:" in head or b"\r\nconnection:" in head:
        lines = []
        for line in head[:-2].split(b"\r\n"):
            if line.lower().startswith(b"connection:"):
                continue
            lines.append(line)
        head = b"\r\n".join(lines) + b"\r\nConnection: close\r\n\r\n"
    else:
        head = head[:-2] + b"Connection: close\r\n\r\n"

    up = socket.create_connection((upstream_host, upstream_port), timeout=5)
    try:
        up.sendall(head + body)
        uhead, urest = read_headers(up)
        if uhead is None:
            return False
        uneed = content_length(uhead)
        ubody, _ = read_exact(up, urest, uneed)
        client.sendall(uhead + ubody)
    finally:
        try:
            up.close()
        except OSError:
            pass
    return True


def handle(client, upstream_host, upstream_port, lock):
    try:
        client.settimeout(5)
        if lock is not None:
            with lock:
                one_exchange(client, upstream_host, upstream_port)
        else:
            one_exchange(client, upstream_host, upstream_port)
    except (OSError, ValueError):
        pass
    finally:
        try:
            client.close()
        except OSError:
            pass


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--listen", type=int, required=True)
    ap.add_argument("--upstream", required=True, help="host:port")
    ap.add_argument(
        "--serial",
        action="store_true",
        help="only one upstream request in flight (sequential baseline)",
    )
    args = ap.parse_args()
    host, port_s = args.upstream.rsplit(":", 1)
    port = int(port_s)
    lock = threading.Lock() if args.serial else None
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", args.listen))
    srv.listen(256)
    print(
        "seq proxy on %d -> %s:%d serial=%s" % (args.listen, host, port, bool(lock)),
        flush=True,
    )
    while True:
        conn, _ = srv.accept()
        threading.Thread(
            target=handle, args=(conn, host, port, lock), daemon=True
        ).start()


if __name__ == "__main__":
    main()

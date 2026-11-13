"""Detonator's fake internet. Runs in its own container, never in the plugin's.

The plugin's container shares this container's network (``--network container:``)
and nothing else. There is no real network here at all: this script makes every
IPv4 address local to this network namespace, so whatever address the plugin
connects to, the connection lands on one of the listeners below. It:

  * answers every DNS lookup with a made-up address (one per name, so the host can
    tell which name a later connection was for),
  * accepts TCP connections on the ports malware commonly uses, reads what the
    plugin sends, answers plain HTTP with a short "200 OK" and reads the TLS
    server name from an HTTPS hello,
  * writes one JSON line per lookup or connection to /sink/log.jsonl.

The plugin cannot read or change that log: /sink is mounted only in this
container. It records, it never decides; the host-side rules do that.
"""

import ipaddress
import json
import os
import select
import socket
import struct
import sys
import threading
import time

LOG_PATH = "/sink/log.jsonl"
READY_PATH = "/sink/ready"
TCP_PORTS = (21, 22, 23, 25, 80, 110, 143, 443, 465, 587, 993, 995, 1080, 1337, 2375, 3128, 4444,
             5000, 5555, 6379, 6667, 8000, 8080, 8443, 8888, 9001, 9050, 31337)
READ_TIMEOUT_S = 2.0
MAX_READ = 64 * 1024
KEEP_BYTES = 4096
KEEP_BYTES_LATER = 512   # after the first FULL_DETAIL entries, keep less of each payload
FULL_DETAIL = 2000
MAX_ENTRIES = 20000
FAKE_NET = ipaddress.ip_network("198.18.0.0/15")
# Ends by itself after this long, so it never outlives a run even if Detonator is killed.
MAX_LIFETIME_S = 300  # RFC 2544 benchmarking range: never a real host

_lock = threading.Lock()
_entries = 0
_log = None
_names = {}


def log(kind, **data):
    global _entries
    with _lock:
        if _entries >= MAX_ENTRIES:
            if _entries == MAX_ENTRIES:
                _log.write(json.dumps({"kind": "log_full", "t": time.time()}) + "\n")
                _log.flush()
                _entries += 1
            return
        _entries += 1
        _log.write(json.dumps({"kind": kind, "t": round(time.time(), 4), **data}) + "\n")
        _log.flush()


# --------------------------------------------------------------------------
# Make every IPv4 address local ("ip route add local 0.0.0.0/0 dev lo"), written
# as a raw netlink message so the image needs no extra tools.
# --------------------------------------------------------------------------
RTM_NEWROUTE, NLM_F_REQUEST, NLM_F_ACK, NLM_F_CREATE, NLM_F_REPLACE = 24, 1, 4, 0x400, 0x100
RT_TABLE_LOCAL, RTPROT_BOOT, RT_SCOPE_HOST, RTN_LOCAL = 255, 3, 254, 2
RTA_DST, RTA_OIF, RTA_TABLE = 1, 4, 15


def _rta(kind, payload):
    length = 4 + len(payload)
    return struct.pack("HH", length, kind) + payload + b"\0" * ((4 - length % 4) % 4)


def route_everything_here(family=socket.AF_INET):
    lo = socket.if_nametoindex("lo")
    dst = b"\0" * (4 if family == socket.AF_INET else 16)
    rtmsg = struct.pack("BBBBBBBBI", family, 0, 0, 0, RT_TABLE_LOCAL, RTPROT_BOOT, RT_SCOPE_HOST, RTN_LOCAL, 0)
    body = rtmsg + _rta(RTA_DST, dst) + _rta(RTA_OIF, struct.pack("I", lo)) + _rta(RTA_TABLE, struct.pack("I", 255))
    flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE
    msg = struct.pack("IHHII", 16 + len(body), RTM_NEWROUTE, flags, 1, 0) + body
    with socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 0) as nl:
        nl.bind((0, 0))
        nl.send(msg)
        reply = nl.recv(4096)
    err = struct.unpack("i", reply[16:20])[0]
    if err:
        raise OSError(-err, os.strerror(-err))


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------
def fake_ip(name):
    with _lock:
        if name not in _names:
            _names[name] = str(FAKE_NET[2 + len(_names) % (FAKE_NET.num_addresses - 4)])
        return _names[name]


def _qname(data, off):
    labels = []
    while off < len(data) and len(labels) < 64:
        n = data[off]
        if n == 0:
            return ".".join(labels), off + 1
        if n & 0xC0:
            return ".".join(labels), off + 2
        labels.append(data[off + 1:off + 1 + n].decode("ascii", "replace"))
        off += 1 + n
    return ".".join(labels), off


def dns_answer(data):
    """A reply to one DNS query: A records get a fake address, anything else gets none."""
    if len(data) < 12:
        return None, None, None
    qid, _flags, qd = struct.unpack(">HHH", data[:6])
    if qd < 1:
        return None, None, None
    name, off = _qname(data, 12)
    if off + 4 > len(data):
        return None, None, None
    qtype, _qclass = struct.unpack(">HH", data[off:off + 4])
    question = data[12:off + 4]
    answer, ip = b"", None
    if qtype == 1 and name:
        ip = fake_ip(name.lower())
        answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(ip)
    header = struct.pack(">HHHHHH", qid, 0x8180, 1, 1 if answer else 0, 0, 0)
    return header + question + answer, name, (qtype, ip)


def serve_dns(sock):
    while True:
        try:
            data, peer = sock.recvfrom(4096)
        except OSError:
            continue
        reply, name, info = dns_answer(data)
        if reply is None:
            continue
        log("dns", name=name[:255], qtype=info[0], answer=info[1])
        try:
            sock.sendto(reply, peer)
        except OSError:
            pass


# --------------------------------------------------------------------------
# TCP
# --------------------------------------------------------------------------
def tls_server_name(data):
    """The server name from a TLS ClientHello, or None."""
    try:
        if data[0] != 0x16 or data[5] != 0x01:
            return None
        off = 9 + 2 + 32
        off += 1 + data[off]                                    # session id
        off += 2 + struct.unpack(">H", data[off:off + 2])[0]    # cipher suites
        off += 1 + data[off]                                    # compression
        end = off + 2 + struct.unpack(">H", data[off:off + 2])[0]
        off += 2
        while off + 4 <= end:
            etype, elen = struct.unpack(">HH", data[off:off + 4])
            if etype == 0:
                n = struct.unpack(">H", data[off + 7:off + 9])[0]
                return data[off + 9:off + 9 + n].decode("ascii", "replace")
            off += 4 + elen
    except (IndexError, struct.error):
        return None
    return None


def _http_wants(data):
    """How many bytes a plain HTTP request still has to send (body by Content-Length)."""
    head, sep, body = data.partition(b"\r\n\r\n")
    if not sep:
        return 1
    for line in head.split(b"\r\n")[1:]:
        k, _, v = line.partition(b":")
        if k.strip().lower() == b"content-length":
            try:
                return max(0, int(v.strip()) - len(body))
            except ValueError:
                return 0
    return 0


def handle(conn, peer):
    try:
        here = conn.getsockname()
        conn.settimeout(READ_TIMEOUT_S)
        data = b""
        deadline = time.monotonic() + READ_TIMEOUT_S
        is_http = False
        while len(data) < MAX_READ and time.monotonic() < deadline:
            r, _, _ = select.select([conn], [], [], max(0.0, deadline - time.monotonic()))
            if not r:
                break
            chunk = conn.recv(MAX_READ - len(data))
            if not chunk:
                break
            data += chunk
            is_http = data[:8].split(b" ")[0] in (b"GET", b"POST", b"PUT", b"HEAD", b"PATCH", b"DELETE",
                                                   b"OPTIONS", b"CONNECT")
            if data[:1] == b"\x16":
                break  # TLS hello: we cannot read further without a certificate it trusts
            if is_http and _http_wants(data) == 0:
                break
        keep = KEEP_BYTES if _entries < FULL_DETAIL else KEEP_BYTES_LATER
        entry = {"dst": here[0], "port": here[1], "src_port": peer[1], "bytes": len(data),
                 "data": data[:keep].decode("latin-1")}
        sni = tls_server_name(data)
        if sni:
            entry["tls_server_name"] = sni[:255]
        if is_http:
            for line in data.partition(b"\r\n\r\n")[0].split(b"\r\n")[1:]:
                k, _, v = line.partition(b":")
                if k.strip().lower() == b"host":
                    entry["http_host"] = v.strip().decode("latin-1")[:255]
            try:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n"
                             b"Connection: close\r\n\r\n{\"ok\":true}")
            except OSError:
                pass
        log("tcp", **entry)
    except Exception as exc:  # never let one odd client stop the sink
        log("tcp_error", error=type(exc).__name__)
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve_tcp(sock):
    while True:
        try:
            conn, peer = sock.accept()
        except OSError:
            continue
        threading.Thread(target=handle, args=(conn, peer), daemon=True).start()


def drop_all_capabilities():
    """Give up NET_ADMIN and NET_BIND_SERVICE once the route is set and the ports are bound.
    From then on this process has no special rights at all (no-new-privileges stops it
    getting them back)."""
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    header = (ctypes.c_uint32 * 2)(0x20080522, 0)   # _LINUX_CAPABILITY_VERSION_3, this process
    data = (ctypes.c_uint32 * 6)()                   # effective, permitted, inheritable: all empty
    if libc.capset(header, data) != 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))


def main():
    global _log
    _log = open(LOG_PATH, "a", buffering=1)
    notes = {}
    try:
        route_everything_here()
        notes["catch_all"] = True
    except OSError as exc:
        notes["catch_all"] = False
        notes["catch_all_error"] = str(exc)
    listeners = []
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("0.0.0.0", 53))
    threading.Thread(target=serve_dns, args=(udp,), daemon=True).start()
    bound = []
    for port in TCP_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
            s.listen(64)
        except OSError:
            s.close()
            continue
        listeners.append(s)
        bound.append(port)
        threading.Thread(target=serve_tcp, args=(s,), daemon=True).start()
    try:
        drop_all_capabilities()
        notes["capabilities"] = "none"
    except OSError as exc:
        notes["capabilities"] = f"kept ({exc})"
    log("ready", ports=bound, **notes)
    with open(READY_PATH, "w") as f:
        f.write("ok\n")
    time.sleep(MAX_LIFETIME_S)
    log("lifetime_over")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        if _log:
            _log.write(json.dumps({"kind": "fatal", "error": repr(exc)}) + "\n")
        sys.exit(2)

"""Detonator's fake internet. Runs in its own container, never in the plugin's.

The plugin's container shares this container's network (``--network container:``)
and nothing else. There is no real network here at all: this script makes every
IPv4 address local to this network namespace, so whatever address the plugin
connects to, the connection lands on one of the listeners below. It:

  * answers every DNS lookup with a made-up address (one per name, so the host can
    tell which name a later connection was for),
  * accepts TCP connections on EVERY port: the ports malware commonly uses have their
    own listeners, and one iptables rule sends every other port to a catch-all
    listener that asks the kernel which port was meant (real attackers pick ports
    like 2333 or 4433). It reads what the plugin sends and answers HTTP with a short
    "200 OK",
  * reads inside HTTPS: it makes a fresh certificate authority for this run only
    (its key never leaves this container) and answers each HTTPS hello with a
    certificate for the name asked for, signed by it. The sandbox trusts that
    authority, so what a plugin sends over HTTPS is logged like plain HTTP. A
    client that pins its own certificates refuses, and only the server name is logged,
  * writes one JSON line per lookup or connection to /sink/log.jsonl.

The plugin cannot read or change that log: /sink is mounted only in this
container. It records, it never decides; the host-side rules do that.
"""

import ipaddress
import json
import os
import re
import secrets
import select
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

LOG_PATH = "/sink/log.jsonl"
READY_PATH = "/sink/ready"
CA_PUBLIC = "/ca/ca.pem"      # the only file the sandbox sees (read-only)
KEYS = "/work"                # private tmpfs: the authority's key and the per-name certificates
MAX_CERTS = 300
TCP_PORTS = (21, 22, 23, 25, 80, 110, 143, 443, 465, 587, 993, 995, 1080, 1337, 2375, 3128, 4444,
             5000, 5555, 6379, 6667, 8000, 8080, 8443, 8888, 9001, 9050, 31337)
CATCH_PORT = 65080            # catch-all listener for every port not in TCP_PORTS
SO_ORIGINAL_DST = 80         # linux/netfilter_ipv4.h
IPTABLES = ("/usr/sbin/iptables-restore", "/sbin/iptables-restore")
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


def send_every_port_here():
    """Send TCP to any port without its own listener to CATCH_PORT (one nat OUTPUT chain,
    loaded in a single iptables-restore call). Loopback (127/8) is left alone so a plugin
    talking to its own local port still works."""
    exe = next((x for x in IPTABLES if os.path.isfile(x)), None)
    if exe is None:
        raise OSError("iptables-restore is not in the monitor image")
    lines = ["*nat", ":DETONATOR - [0:0]", "-A DETONATOR -d 127.0.0.0/8 -j RETURN"]
    lines += [f"-A DETONATOR -p tcp --dport {p} -j RETURN" for p in (*TCP_PORTS, CATCH_PORT)]
    lines += [f"-A DETONATOR -p tcp -j REDIRECT --to-ports {CATCH_PORT}",
              "-A OUTPUT -p tcp -j DETONATOR", "COMMIT", ""]
    proc = subprocess.run([exe, "--noflush"], input="\n".join(lines), capture_output=True, text=True,
                          timeout=20)
    if proc.returncode != 0:
        raise OSError((proc.stderr or proc.stdout or "iptables-restore failed").strip()[-300:])


def original_destination(conn):
    """(ip, port) the client asked for before the catch-all rule redirected it."""
    raw = conn.getsockopt(socket.SOL_IP, SO_ORIGINAL_DST, 16)
    port, packed = struct.unpack_from("!2xH4s", raw)
    return socket.inet_ntoa(packed), port


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


# --------------------------------------------------------------------------
# HTTPS: a certificate authority made for this run only
# --------------------------------------------------------------------------
_TLS = {"ready": False}
_certs: dict = {}
_cert_lock = threading.Lock()
_SAFE_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,62})(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}))*$")


def _openssl(*args):
    subprocess.run(["openssl", *args], check=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=20)


def make_authority():
    """A new authority per run, valid for two days, with a random name. Only its certificate
    is shared (in /ca); its key stays in this container's private tmpfs."""
    key, cert = os.path.join(KEYS, "ca.key"), os.path.join(KEYS, "ca.pem")
    _openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
             "-keyout", key, "-out", cert, "-days", "2", "-subj", f"/CN=Detonator test CA {secrets.token_hex(4)}",
             "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    with open(cert, "rb") as src, open(CA_PUBLIC + ".tmp", "wb") as dst:
        dst.write(src.read())
    os.chmod(CA_PUBLIC + ".tmp", 0o644)
    os.replace(CA_PUBLIC + ".tmp", CA_PUBLIC)
    _TLS.update(ready=True, key=key, cert=cert)


def context_for(name):
    """A server context with a certificate for `name` (a host name or an IP address)."""
    try:
        ipaddress.ip_address(name)
        san = f"IP:{name}"
    except ValueError:
        if not _SAFE_NAME.match(name) or len(name) > 253:
            name = "unnamed.invalid"
        san = f"DNS:{name}"
    with _cert_lock:
        ctx = _certs.get(name)
        if ctx is not None:
            return ctx
        if len(_certs) >= MAX_CERTS:
            return None
        n = len(_certs)
        key, cert = os.path.join(KEYS, f"{n}.key"), os.path.join(KEYS, f"{n}.pem")
        _openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes",
                 "-keyout", key, "-out", cert, "-days", "2", "-subj", "/CN=" + name, "-addext", "subjectAltName=" + san,
                 "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "extendedKeyUsage=serverAuth",
                 "-CA", _TLS["cert"], "-CAkey", _TLS["key"])
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        ctx.set_alpn_protocols(["http/1.1"])   # never HTTP/2, so the request reads like plain HTTP
        _certs[name] = ctx
        return ctx


def _peek_hello(conn, deadline):
    """The TLS ClientHello record, read without taking it off the socket."""
    data = b""
    while time.monotonic() < deadline:
        r, _, _ = select.select([conn], [], [], max(0.0, deadline - time.monotonic()))
        if not r:
            break
        data = conn.recv(16 * 1024, socket.MSG_PEEK)
        if not data or data[:1] != b"\x16" or len(data) >= 5 + struct.unpack(">H", data[3:5])[0]:
            break
        time.sleep(0.01)
    return data


def _read_request(sock, deadline):
    """What the client sends: up to MAX_READ, or until an HTTP request is complete."""
    data, is_http = b"", False
    while len(data) < MAX_READ and time.monotonic() < deadline:
        sock.settimeout(max(0.05, deadline - time.monotonic()))
        try:
            chunk = sock.recv(MAX_READ - len(data))
        except (socket.timeout, ssl.SSLError, OSError):
            break
        if not chunk:
            break
        data += chunk
        is_http = data[:8].split(b" ")[0] in (b"GET", b"POST", b"PUT", b"HEAD", b"PATCH", b"DELETE",
                                               b"OPTIONS", b"CONNECT")
        if is_http and _http_wants(data) == 0:
            break
    return data, is_http


# A harmless stand-in for a downloaded script. When something downloads a script (an install
# script, a .py or .js file) and runs it, the stand-in leaves a mark in the outside trace: it tries
# to open a file whose name holds this run's marker. Nothing else happens. So "this runs whatever
# the server sends" is proved without any real second stage. Other requests get the usual {"ok":true}.
MARKER = "detonator-fetched-" + secrets.token_hex(6)
_SCRIPT_PATH = re.compile(rb"^[A-Z]+ [^ ?#]*?(?:\.(?:sh|bash|zsh|command|py|js|mjs|cjs|ps1|pl|rb)|/install|/setup|"
                          rb"/bootstrap|/init|/get|/run)(?:[?#][^ ]*)? HTTP/", re.I)


def reply_for(request: bytes):
    """(body, content type, kind served) for one HTTP request."""
    first = request.partition(b"\r\n")[0]
    head = request.partition(b"\r\n\r\n")[0].lower()
    ua = b""
    for line in head.split(b"\r\n")[1:]:
        if line.startswith(b"user-agent:"):
            ua = line[11:].strip()
    host = b""
    for line in head.split(b"\r\n")[1:]:
        if line.startswith(b"host:"):
            host = line[5:].strip()
    path0 = first.split(b" ")[1] if first.count(b" ") >= 2 else b""
    last = path0.split(b"?")[0].rstrip(b"/").rsplit(b"/", 1)[-1]
    # curl or wget fetching a bare page that is not an API: the usual shape of `curl URL | bash`.
    bare = ua.startswith((b"curl/", b"wget/")) and b"." not in last and not re.search(
        rb"api|graphql|/v\d|json|token|oauth|login|auth|health|status", host + path0, re.I)
    if not (_SCRIPT_PATH.match(first) or bare):
        return b'{"ok":true}', b"application/json", None
    path = first.split(b" ")[1].split(b"?")[0].lower() if b" " in first else b""
    probe = ("/tmp/" + MARKER).encode()
    if path.endswith(b".py") or ua.startswith((b"python", b"aiohttp", b"httpx")):
        return (b"try:\n    open('" + probe + b"')\nexcept OSError:\n    pass\n", b"text/x-python", "python")
    if path.endswith((b".js", b".mjs", b".cjs")) or ua.startswith((b"node", b"undici", b"axios")):
        return (b"try{require('fs').openSync('" + probe + b"','r')}catch(e){}\n", b"application/javascript", "js")
    if path.endswith(b".ps1"):
        return (b"Test-Path '" + probe + b"' | Out-Null\n", b"text/plain", "powershell")
    return (b"#!/bin/sh\n: < " + probe + b" 2>/dev/null\n/bin/echo " + MARKER.encode() + b" >/dev/null\n",
            b"text/x-shellscript", "shell")


def handle(conn, peer):
    try:
        here = conn.getsockname()
        if here[1] == CATCH_PORT:
            try:
                here = original_destination(conn)
            except OSError:
                pass
        deadline = time.monotonic() + READ_TIMEOUT_S
        tls_note = {}
        hello = _peek_hello(conn, deadline) if _TLS["ready"] else b""
        sni = tls_server_name(hello) if hello[:1] == b"\x16" else None
        sock = conn
        if hello[:1] == b"\x16" and _TLS["ready"]:
            ctx = None
            try:
                ctx = context_for((sni or here[0]).lower())
            except Exception:
                ctx = None
            if ctx is not None:
                try:
                    conn.settimeout(READ_TIMEOUT_S)
                    sock = ctx.wrap_socket(conn, server_side=True)
                    tls_note["tls_read"] = True
                    deadline = time.monotonic() + READ_TIMEOUT_S
                except (ssl.SSLError, OSError) as exc:
                    # The client did not accept our certificate (it pins its own, or brings its
                    # own list of authorities): only the server name is known.
                    tls_note.update(tls_read=False, tls_refused=type(exc).__name__)
                    sock = None
        if sock is None:
            data, is_http = hello, False
        else:
            data, is_http = _read_request(sock, deadline)
        keep = KEEP_BYTES if _entries < FULL_DETAIL else KEEP_BYTES_LATER
        entry = {"dst": here[0], "port": here[1], "src_port": peer[1], "bytes": len(data),
                 "data": data[:keep].decode("latin-1"), **tls_note}
        if sni is None and data[:1] == b"\x16":
            sni = tls_server_name(data)
        if sni:
            entry["tls_server_name"] = sni[:255]
        if is_http:
            for line in data.partition(b"\r\n\r\n")[0].split(b"\r\n")[1:]:
                k, _, v = line.partition(b":")
                if k.strip().lower() == b"host":
                    entry["http_host"] = v.strip().decode("latin-1")[:255]
            body, ctype, kind = reply_for(data)
            if kind:
                entry["served"] = kind
                entry["marker"] = MARKER
            try:
                sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: " + ctype + b"\r\nContent-Length: "
                             + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            except OSError:
                pass
        log("tcp", **entry)
    except Exception as exc:  # never let one odd client stop the sink
        log("tcp_error", error=type(exc).__name__)
    finally:
        for c in {id(x): x for x in (locals().get("sock"), conn) if x is not None}.values():
            try:
                c.close()
            except OSError:
                pass


# Handler threads are capped well under the container's process limit. A run that opens many
# idle connections must not make thread start fail, because that used to end the port's
# listening loop and later traffic to the port went unlogged.
MAX_HANDLERS = 64
_SLOTS = threading.BoundedSemaphore(MAX_HANDLERS)


def _handle_slot(conn, peer):
    try:
        handle(conn, peer)
    finally:
        _SLOTS.release()


def serve_tcp(sock):
    while True:
        try:
            conn, peer = sock.accept()
        except OSError:
            continue
        try:
            if _SLOTS.acquire(blocking=False):
                try:
                    threading.Thread(target=_handle_slot, args=(conn, peer), daemon=True).start()
                    continue
                except RuntimeError:
                    _SLOTS.release()
            # No free handler: serve this one here with a short timeout, so it is still logged.
            conn.settimeout(1.0)
            handle(conn, peer)
        except Exception:
            try:
                conn.close()
            except OSError:
                pass


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
    try:
        send_every_port_here()
        notes["every_port"] = True
    except (OSError, subprocess.SubprocessError) as exc:
        notes["every_port"] = False
        notes["every_port_error"] = str(exc)[:300]
    for port in (*TCP_PORTS, CATCH_PORT) if notes["every_port"] else TCP_PORTS:
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
    try:
        make_authority()     # openssl needs no special rights, so this runs after they are dropped
        notes["tls"] = "read"
    except Exception as exc:
        notes["tls"] = f"server name only ({type(exc).__name__})"
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

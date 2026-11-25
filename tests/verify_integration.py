#!/usr/bin/env python3
"""
End-to-end HTTP + WebSocket integration & differential verification suite for keel::http.

Spins up:
  1. Primary local ThreadingHTTPServer on 127.0.0.1 (all HTTP verbs, forms, multipart,
     redirects, CookieJar, retries, streaming, timeout).
  2. Secondary local ThreadingHTTPServer (cross-origin & cross-host security tests).
  3. Minimal RFC 6455 WebSocket echo server on 127.0.0.1 (handshake, text, binary, close).
  4. An unused/closed ephemeral port (network-error retry tests).

Usage:
    python tests/verify_integration.py [path/to/test_http.exe]
"""

import base64
import email.parser
import email.policy
import hashlib
import http.server
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import urllib.parse
from pathlib import Path


def find_exe() -> Path:
    if len(sys.argv) > 1:
        p = Path(sys.argv[1])
        if p.exists():
            return p
    root = Path(__file__).resolve().parent.parent
    candidates = [
        root / "build" / "Release" / "test_http.exe",
        root / "build" / "Release" / "test_http",
        root / "build" / "Debug" / "test_http.exe",
        root / "build" / "test_http.exe",
        root / "build" / "test_http",
    ]
    for c in candidates:
        if c.exists():
            return c
    raise FileNotFoundError("Could not locate test_http executable; pass path as argv[1].")


class SharedState:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.flaky503_hits = 0
        self.stream503_hits = 0
        self.post503_hits = 0
        self.rate429_hits = 0
        self.secondary_port = 0


def make_handler(state: SharedState, is_secondary: bool = False):
    class TestHandler(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, format, *args):
            pass

        def _read_body(self) -> bytes:
            length = int(self.headers.get("Content-Length", "0"))
            return self.rfile.read(length) if length > 0 else b""

        def _send(self, code: int, body: bytes = b"", headers: list[tuple[str, str]] | None = None,
                  content_type: str = "text/plain; charset=utf-8", send_body: bool = True):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            if headers:
                for k, v in headers:
                    self.send_header(k, v)
            self.end_headers()
            if send_body and body:
                self.wfile.write(body)

        def _echo_info(self, method: str, body: bytes) -> bytes:
            parsed = urllib.parse.urlsplit(self.path)
            lines = [f"METHOD={method}", f"PATH={parsed.path}"]
            for k, v in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True):
                lines.append(f"QUERY_{k}={v}")
            for k, v in self.headers.items():
                lines.append(f"HDR_{k.lower()}={v}")
            if body:
                lines.append(f"BODY={body.decode('utf-8', errors='replace')}")
            return ("\n".join(lines) + "\n").encode("utf-8")

        def do_HEAD(self):
            if self.path == "/head":
                self._send(200, b"ignored-head-body", headers=[("X-Head-Ok", "yes")], send_body=False)
                return
            self._send(404, b"", send_body=False)

        def do_GET(self):
            parsed = urllib.parse.urlsplit(self.path)
            p = parsed.path

            if is_secondary:
                self._send(200, self._echo_info("GET", b""))
                return

            if p == "/echo":
                self._send(200, self._echo_info("GET", b""))
            elif p == "/redirect/sub/rel":
                self._send(302, b"redirecting", headers=[("Location", "../target")])
            elif p == "/redirect/target":
                self._send(200, b"redirect-target-ok")
            elif p == "/redirect/loop":
                self._send(302, b"loop", headers=[("Location", "/redirect/loop")])
            elif p == "/redirect/cross-origin":
                target = f"http://127.0.0.1:{state.secondary_port}/cross-landed"
                self._send(302, b"moving", headers=[("Location", target)])
            elif p == "/redirect/cross-host":
                target = f"http://localhost:{state.secondary_port}/cross-host-landed"
                self._send(302, b"moving-host", headers=[("Location", target)])
            elif p == "/cookie/login":
                self._send(
                    302,
                    b"logged-in",
                    headers=[
                        ("Set-Cookie", "sid=keel_session_42; Path=/; HttpOnly"),
                        ("Location", "/cookie/profile"),
                    ],
                )
            elif p == "/cookie/profile":
                cookie_hdr = self.headers.get("Cookie", "")
                lines = []
                for pair in cookie_hdr.split(";"):
                    pair = pair.strip()
                    if "=" in pair:
                        k, v = pair.split("=", 1)
                        lines.append(f"COOKIE_{k.strip()}={v.strip()}")
                self._send(200, ("\n".join(lines) + "\n").encode("utf-8"))
            elif p == "/cookie/logout":
                self._send(
                    200,
                    b"logged-out",
                    headers=[("Set-Cookie", "sid=; Path=/; Max-Age=0")],
                )
            elif p == "/retry/flaky503":
                with state.lock:
                    state.flaky503_hits += 1
                    hit = state.flaky503_hits
                if hit <= 2:
                    self._send(503, b"temporarily unavailable")
                else:
                    self._send(200, b"recovered-503")
            elif p == "/retry/stream503":
                with state.lock:
                    state.stream503_hits += 1
                    hit = state.stream503_hits
                if hit <= 2:
                    self._send(503, b"SHOULD_NOT_STREAM_ERROR_BODY")
                else:
                    self._send(200, b"stream-recovered")
            elif p == "/retry/rate429":
                with state.lock:
                    state.rate429_hits += 1
                    hit = state.rate429_hits
                if hit == 1:
                    self._send(429, b"slow down", headers=[("Retry-After", "0")])
                else:
                    self._send(200, b"recovered-429")
            elif p == "/stream/large":
                payload = bytes(((i * 31 + 7) & 0xFF) for i in range(256 * 1024))
                self._send(200, payload, content_type="application/octet-stream")
            elif p == "/slow":
                state.stop_event.wait(5.0)
                if not state.stop_event.is_set():
                    try:
                        self._send(200, b"too-late")
                    except OSError:
                        pass
            else:
                self._send(404, b"not found")

        def do_POST(self):
            body = self._read_body()
            p = urllib.parse.urlsplit(self.path).path
            if p == "/echo":
                self._send(200, self._echo_info("POST", body))
            elif p == "/form":
                pairs = urllib.parse.parse_qsl(body.decode("utf-8"), keep_blank_values=True)
                lines = [f"FIELD_{k}={v}" for k, v in pairs]
                self._send(200, ("\n".join(lines) + "\n").encode("utf-8"))
            elif p == "/multipart":
                ct = self.headers.get("Content-Type", "")
                raw_msg = f"Content-Type: {ct}\r\nMIME-Version: 1.0\r\n\r\n".encode("utf-8") + body
                msg = email.parser.BytesParser(policy=email.policy.default).parsebytes(raw_msg)
                lines = []
                for part in msg.iter_parts():
                    name = part.get_param("name", header="content-disposition")
                    filename = part.get_filename()
                    payload = part.get_payload(decode=True)
                    if filename:
                        expected = bytes(range(256))
                        ok = "OK" if payload == expected else "MISMATCH"
                        lines.append(f"FILE_{name}={filename}:{len(payload)}:{ok}")
                    else:
                        lines.append(f"FIELD_{name}={payload.decode('utf-8')}")
                self._send(200, ("\n".join(lines) + "\n").encode("utf-8"))
            elif p == "/redirect/302-post":
                self._send(302, b"see-echo", headers=[("Location", "/echo")])
            elif p == "/redirect/307-post":
                self._send(307, b"preserve-post", headers=[("Location", "/echo")])
            elif p == "/redirect/308-post":
                self._send(308, b"preserve-post-308", headers=[("Location", "/echo")])
            elif p == "/retry/post503":
                with state.lock:
                    state.post503_hits += 1
                    hit = state.post503_hits
                if hit <= 2:
                    self._send(503, b"post-busy")
                else:
                    self._send(200, b"post-recovered")
            else:
                self._send(404, b"not found")

        def do_PUT(self):
            body = self._read_body()
            p = urllib.parse.urlsplit(self.path).path
            if p == "/redirect/303-put":
                self._send(303, b"see-other", headers=[("Location", "/echo")])
            else:
                self._send(200, self._echo_info("PUT", body))

        def do_PATCH(self):
            body = self._read_body()
            self._send(200, self._echo_info("PATCH", body))

        def do_DELETE(self):
            body = self._read_body()
            self._send(200, self._echo_info("DELETE", body))

    return TestHandler


class QuietHTTPServer(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        # Ignore expected ConnectionResetError / BrokenPipeError from abort & timeout tests.
        pass


def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise EOFError("socket closed")
        buf.extend(chunk)
    return bytes(buf)


def send_ws_frame(conn: socket.socket, opcode: int, payload: bytes) -> None:
    hdr = bytearray([0x80 | (opcode & 0x0F)])
    n = len(payload)
    if n < 126:
        hdr.append(n)
    elif n < 65536:
        hdr.append(126)
        hdr.extend(struct.pack(">H", n))
    else:
        hdr.append(127)
        hdr.extend(struct.pack(">Q", n))
    conn.sendall(bytes(hdr) + payload)


def run_ws_echo_server(sock: socket.socket, stop_event: threading.Event) -> None:
    sock.settimeout(0.2)
    while not stop_event.is_set():
        try:
            conn, _ = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            conn.settimeout(5.0)
            req_buf = bytearray()
            while b"\r\n\r\n" not in req_buf:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                req_buf.extend(chunk)
            ws_key = ""
            for line in req_buf.decode("iso-8859-1").split("\r\n"):
                if line.lower().startswith("sec-websocket-key:"):
                    ws_key = line.split(":", 1)[1].strip()
                    break
            if not ws_key:
                conn.close()
                continue
            accept = base64.b64encode(
                hashlib.sha1((ws_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")).digest()
            ).decode("ascii")
            resp = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
            ).encode("ascii")
            conn.sendall(resp)

            while not stop_event.is_set():
                b0, b1 = recv_exact(conn, 2)
                opcode = b0 & 0x0F
                masked = (b1 & 0x80) != 0
                plen = b1 & 0x7F
                if plen == 126:
                    plen = struct.unpack(">H", recv_exact(conn, 2))[0]
                elif plen == 127:
                    plen = struct.unpack(">Q", recv_exact(conn, 8))[0]
                mask = recv_exact(conn, 4) if masked else b"\x00\x00\x00\x00"
                raw = recv_exact(conn, plen)
                payload = bytes(raw[i] ^ mask[i & 3] for i in range(plen)) if masked else raw
                if opcode == 0x8:
                    send_ws_frame(conn, 0x8, struct.pack(">H", 1000))
                    break
                if opcode in (0x1, 0x2):
                    send_ws_frame(conn, opcode, payload)
        except (OSError, EOFError):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass


def pick_closed_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def verify_resolve_url_differential(exe: Path) -> int:
    base = "https://example.com:8443/a/b/c/d?old=1"
    refs = [
        "g", "./g", "g/", "/g", "//other.host/x/y", "?y", "g?y", "#s",
        "g#s", "g?y#s", ".", "./", "..", "../", "../g", "../..", "../../",
        "../../g", "../../../g", "/./g", "/../g", "g.", ".g", "g..", "..g",
        "http://plain.test/path", "https://example.com/default-port",
    ]
    failures = 0
    for ref in refs:
        expected = urllib.parse.urljoin(base, ref)
        proc = subprocess.run([str(exe), "--resolve-url", base, ref], capture_output=True, text=True, check=False)
        actual = proc.stdout.strip()
        if proc.returncode != 0 or actual != expected:
            failures += 1
            print(f"FAIL resolve_url({base!r}, {ref!r}): expected={expected!r} actual={actual!r}")
    if failures == 0:
        print(f"resolve_url differential: {len(refs)}/{len(refs)} PASSED against urllib.parse.urljoin")
    return failures


def main() -> int:
    exe = find_exe()

    url_failures = verify_resolve_url_differential(exe)
    if url_failures:
        return 1

    state = SharedState()
    secondary = QuietHTTPServer(("127.0.0.1", 0), make_handler(state, is_secondary=True))
    state.secondary_port = secondary.server_address[1]
    primary = QuietHTTPServer(("127.0.0.1", 0), make_handler(state, is_secondary=False))
    primary_port = primary.server_address[1]

    ws_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ws_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ws_sock.bind(("127.0.0.1", 0))
    ws_sock.listen(4)
    ws_port = ws_sock.getsockname()[1]

    closed_port = pick_closed_port()

    t1 = threading.Thread(target=primary.serve_forever, daemon=True)
    t2 = threading.Thread(target=secondary.serve_forever, daemon=True)
    t3 = threading.Thread(target=run_ws_echo_server, args=(ws_sock, state.stop_event), daemon=True)
    t1.start()
    t2.start()
    t3.start()

    try:
        with tempfile.TemporaryDirectory(prefix="keel_http_it_") as tmpdir:
            base_url = f"http://127.0.0.1:{primary_port}"
            ws_url = f"ws://127.0.0.1:{ws_port}/ws"
            closed_url = f"http://127.0.0.1:{closed_port}/unreachable"
            proc = subprocess.run(
                [str(exe), "--integration", base_url, ws_url, closed_url, tmpdir],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            if proc.stdout:
                print(proc.stdout.strip())
            if proc.stderr:
                print(proc.stderr.strip(), file=sys.stderr)
            if proc.returncode != 0:
                print(f"verify_integration: FAILED (exit {proc.returncode})")
                return 1
    finally:
        state.stop_event.set()
        try:
            ws_sock.close()
        except OSError:
            pass
        primary.shutdown()
        secondary.shutdown()
        primary.server_close()
        secondary.server_close()

    print("verify_integration: ALL live HTTP + WebSocket integration & RFC 3986 differential checks PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""
End-to-end HTTP integration & differential verification suite for keel::http.

Spins up two ephemeral-port local ThreadingHTTPServer instances on 127.0.0.1
(primary + secondary origin for cross-origin redirect security tests) and runs
test_http --integration against them, plus RFC 3986 resolve_url differential
checks against Python's urllib.parse.urljoin.

Usage:
    python tests/verify_integration.py [path/to/test_http.exe]
"""

import email.parser
import email.policy
import http.server
import subprocess
import sys
import tempfile
import threading
import time
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
            else:
                self._send(404, b"not found")

        def do_PUT(self):
            body = self._read_body()
            self._send(200, self._echo_info("PUT", body))

        def do_PATCH(self):
            body = self._read_body()
            self._send(200, self._echo_info("PATCH", body))

        def do_DELETE(self):
            body = self._read_body()
            self._send(200, self._echo_info("DELETE", body))

    return TestHandler


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


class QuietHTTPServer(http.server.ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        # Ignore expected ConnectionResetError / BrokenPipeError from abort & timeout tests.
        pass


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

    t1 = threading.Thread(target=primary.serve_forever, daemon=True)
    t2 = threading.Thread(target=secondary.serve_forever, daemon=True)
    t1.start()
    t2.start()

    try:
        with tempfile.TemporaryDirectory(prefix="keel_http_it_") as tmpdir:
            base_url = f"http://127.0.0.1:{primary_port}"
            proc = subprocess.run(
                [str(exe), "--integration", base_url, tmpdir],
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
        primary.shutdown()
        secondary.shutdown()
        primary.server_close()
        secondary.server_close()

    print("verify_integration: ALL live HTTP integration & RFC 3986 differential checks PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Live positive/negative calibration corpus for every bundled nuclei DAST request part."""

import json
import shutil
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlencode, urlsplit

import pytest

_PACK = Path(__file__).resolve().parents[2] / "src" / "ptflow" / "data" / "nuclei-dast" / "stable"
_SURFACES = ("query", "body", "header", "cookie")
_FAMILIES = (
    "crlf",
    "lfi-passwd",
    "open-redirect",
    "sqli-boolean",
    "ssti-arithmetic",
    "xss-js-backslash",
)
_PARAMS = {
    "value": "seed",
    "path": "readme.txt",
    "next": "/home",
    "url": "https://example.invalid/",
}


class _FixtureHandler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        return

    def _respond(self, status=200, body="ok", headers=None, content_type="text/plain"):
        encoded = body.encode()
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def _body_values(self, body):
        if "application/json" in self.headers.get("Content-Type", ""):
            try:
                value = json.loads(body or "{}")
            except json.JSONDecodeError:
                return [body]
            return [str(item) for item in value.values()] if isinstance(value, dict) else [str(value)]
        return [value for items in parse_qs(body, keep_blank_values=True).values() for value in items]

    def _surface_values(self, surface, parsed, body):
        if surface == "query":
            return [
                value
                for items in parse_qs(parsed.query, keep_blank_values=True).values()
                for value in items
            ]
        if surface == "body":
            return self._body_values(body)
        if surface == "header":
            return [unquote(value) for name, value in self.headers.items() if name.lower().startswith("x-")]
        cookie = self.headers.get("Cookie", "")
        return [unquote(item.split("=", 1)[-1].strip()) for item in cookie.split(";") if "=" in item]

    def _safe_response(self, combined):
        escaped = combined.replace("\\", "\\\\").replace("'", "\\u0027")
        self._respond(
            body=f"<html><script>var value = '{escaped}';</script>{'safe page | ' * 100}</html>",
            content_type="text/html",
        )

    def _vulnerable_response(self, combined):
        quoted_true = ("' OR '7919'='7919", "' OR '7927'='7927")
        numeric_true = ("AND 7919=7919", "AND 7927=7927")
        if any(token in combined for token in (*quoted_true, *numeric_true)):
            self._respond(body="confirmed row | " * 100)
        elif "' AND '7919'='7920" in combined or "AND 7919=7920" in combined:
            self._respond(body="no rows")
        elif "X-PTFlow-CRLF: detected-7f31" in combined:
            self._respond(headers={"X-PTFlow-CRLF": "detected-7f31"})
        elif "etc/passwd" in combined and ".." in combined:
            self._respond(
                body="root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
            )
        elif any(token in combined for token in ("{{", "<%=", "#{")):
            self._respond(body="rendered: 9801547")
        elif "window.ptflow_xss_7919=7919" in combined:
            escaped = combined.replace("'", "\\'")
            self._respond(
                body=f"<html><script>var value = '{escaped}';</script></html>",
                content_type="text/html",
            )
        elif "https://ptflow-dast.invalid/redirect-marker" in combined:
            self._respond(
                302,
                headers={"Location": "https://ptflow-dast.invalid/redirect-marker"},
            )
        else:
            self._respond(body="selected row | " * 100)

    def _handle(self, body=""):
        parsed = urlsplit(self.path)
        safe = parsed.path.startswith("/safe-")
        surface = next((item for item in _SURFACES if item in parsed.path), "query")
        values = self._surface_values(surface, parsed, body)
        combined = " ".join(values)
        if safe:
            self._safe_response(combined)
        else:
            self._vulnerable_response(combined)

    def do_GET(self):
        self._handle()

    def do_POST(self):
        length = min(int(self.headers.get("Content-Length", "0") or 0), 65_536)
        self._handle(self.rfile.read(length).decode(errors="replace"))


def _raw_request(method, url, *, body="", content_type="", headers=None):
    parsed = urlsplit(url)
    target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    request_headers = {
        "Host": parsed.netloc,
        "Connection": "close",
        **(headers or {}),
    }
    if body:
        request_headers["Content-Type"] = content_type
        request_headers["Content-Length"] = str(len(body.encode()))
    rendered = "".join(f"{name}: {value}\r\n" for name, value in request_headers.items())
    return f"{method} {target} HTTP/1.1\r\n{rendered}\r\n{body}"


def _requests(base):
    query = urlencode(_PARAMS)
    component_headers = {
        "X-PTFlow-Input": "seed",
        "X-File-Path": "readme.txt",
        "X-Redirect-URL": "/home",
        "X-Callback-URL": "https://example.invalid/",
    }
    cookie = "; ".join(f"{name}={value}" for name, value in _PARAMS.items())
    records = []
    for safe in (False, True):
        prefix = "safe-" if safe else "vulnerable-"
        query_url = f"{base}/{prefix}query?{query}"
        records.append((query_url, _raw_request("GET", query_url)))

        form_url = f"{base}/{prefix}body"
        form_body = urlencode(_PARAMS)
        records.append((form_url, _raw_request(
            "POST", form_url, body=form_body, content_type="application/x-www-form-urlencoded",
        )))

        json_url = f"{base}/{prefix}body-json"
        json_body = json.dumps(_PARAMS)
        records.append((json_url, _raw_request(
            "POST", json_url, body=json_body, content_type="application/json",
        )))

        header_url = f"{base}/{prefix}header"
        records.append((header_url, _raw_request("GET", header_url, headers=component_headers)))

        cookie_url = f"{base}/{prefix}cookie"
        records.append((cookie_url, _raw_request("GET", cookie_url, headers={"Cookie": cookie})))
    return records


@pytest.mark.skipif(shutil.which("nuclei") is None, reason="nuclei is not installed")
def test_bundled_templates_cover_every_request_part_and_reject_negative_controls(tmp_path):
    try:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _FixtureHandler)
    except PermissionError:
        pytest.skip("local sockets are disabled by the execution sandbox")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{server.server_port}"
        input_file = tmp_path / "requests.jsonl"
        input_file.write_text(
            "".join(
                json.dumps({"request": {"endpoint": url, "raw": raw}}) + "\n"
                for url, raw in _requests(base)
            ),
            encoding="utf-8",
        )
        result = subprocess.run(
            [
                "nuclei", "-dast", "-im", "jsonl", "-l", str(input_file), "-t", str(_PACK),
                "-tags", "ptflow", "-etags", "oast", "-fa", "high",
                "-fuzz-param-frequency", "10000", "-rl", "100", "-c", "4", "-timeout", "3",
                "-retries", "0", "-j", "-silent", "-duc",
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=90,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    assert result.returncode == 0, result.stderr
    findings = [json.loads(line) for line in result.stdout.splitlines() if line.startswith("{")]
    ids = {finding["template-id"] for finding in findings}
    assert ids == {f"ptflow-{family}-{surface}" for family in _FAMILIES for surface in _SURFACES}
    assert all("/safe-" not in finding.get("matched-at", "") for finding in findings)
    assert {finding.get("fuzzing_position") for finding in findings} == set(_SURFACES)
    assert all(
        finding.get("fuzzing_method") == ("POST" if finding.get("fuzzing_position") == "body" else "GET")
        for finding in findings
    )

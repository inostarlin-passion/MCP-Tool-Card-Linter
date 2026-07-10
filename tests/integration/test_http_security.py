from __future__ import annotations

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from mcp_tool_card_linter.discovery import DiscoveryError, discover_from_server_url


class _AdversarialHttpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    retry_attempts = 0

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        method = payload.get("method")
        request_id = payload.get("id")

        if method == "initialize":
            if self.path == "/redirect":
                self.send_response(307)
                self.send_header("Location", "http://169.254.169.254/latest/meta-data")
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            if self.path == "/oversized":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", "1000000")
                self.end_headers()
                return
            response = {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": payload.get("params", {}).get("protocolVersion"),
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "security-test", "version": "1"},
                },
            }
            if self.path == "/wrong-version":
                response["result"]["protocolVersion"] = "1900-01-01"
            if self.path == "/wrong-content":
                self._send(response, content_type="text/plain")
            else:
                self._send(response, extra_headers={"Mcp-Session-Id": "session-security"})
            return

        if method == "notifications/initialized":
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if method == "tools/list":
            if self.path == "/retry":
                type(self).retry_attempts += 1
                if type(self).retry_attempts == 1:
                    body = b"temporarily unavailable"
                    self.send_response(503)
                    self.send_header("Content-Type", "text/plain")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                    return
            result = {"tools": []}
            if self.path == "/repeat":
                result["nextCursor"] = "repeated-cursor"
            self._send({"jsonrpc": "2.0", "id": request_id, "result": result})
            return

        self._send(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "unknown"},
            }
        )

    def do_DELETE(self) -> None:
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(
        self,
        payload: dict,
        *,
        content_type: str = "application/json",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)


class HttpSecurityIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        _AdversarialHttpHandler.retry_attempts = 0
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _AdversarialHttpHandler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_port}{path}"

    def test_refuses_redirect_instead_of_following_to_internal_target(self) -> None:
        with self.assertRaisesRegex(DiscoveryError, "redirect"):
            discover_from_server_url(self.url("/redirect"), timeout=2)

    def test_rejects_declared_response_larger_than_budget(self) -> None:
        with self.assertRaisesRegex(DiscoveryError, "byte limit"):
            discover_from_server_url(
                self.url("/oversized"),
                timeout=2,
                max_response_bytes=128,
            )

    def test_rejects_repeated_pagination_cursor(self) -> None:
        with self.assertRaisesRegex(DiscoveryError, "cursor repeated"):
            discover_from_server_url(
                self.url("/repeat"),
                timeout=2,
                max_pages=3,
            )

    def test_retries_bounded_transient_tools_list_failure(self) -> None:
        result = discover_from_server_url(self.url("/retry"), timeout=3)
        self.assertEqual(result.tools, [])
        self.assertEqual(_AdversarialHttpHandler.retry_attempts, 2)

    def test_rejects_unexpected_content_type(self) -> None:
        with self.assertRaisesRegex(DiscoveryError, "Content-Type"):
            discover_from_server_url(self.url("/wrong-content"), timeout=2)

    def test_rejects_unsupported_protocol_version(self) -> None:
        with self.assertRaisesRegex(DiscoveryError, "unsupported MCP protocol"):
            discover_from_server_url(self.url("/wrong-version"), timeout=2)


if __name__ == "__main__":
    unittest.main()

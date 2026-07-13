from __future__ import annotations

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from mcp_tool_card_linter.auth import BearerTokenProvider
from mcp_tool_card_linter.discovery import (
    UnsupportedFeatureError,
    discover_from_server_url,
)


class _McpHttpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    last_tools_protocol = ""

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        method = payload.get("method")
        request_id = payload.get("id")
        if self.path == "/auth" and self.headers.get("Authorization") != "Bearer test-token":
            self.send_response(401)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if method == "notifications/initialized":
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if method == "initialize":
            protocol_version = payload.get("params", {}).get("protocolVersion")
            if self.path == "/previous":
                protocol_version = "2025-06-18"
            capabilities = {"tools": {"listChanged": False}}
            if self.path == "/no-tools":
                capabilities = {}
            self._send_json(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": protocol_version,
                        "capabilities": capabilities,
                        "serverInfo": {"name": "mock-http", "version": "1.0.0"},
                    },
                },
                extra_headers={"Mcp-Session-Id": "session-1"},
            )
            return
        if method == "tools/list":
            type(self).last_tools_protocol = self.headers.get("MCP-Protocol-Version", "")
            self._send_sse(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "tools": [
                            {
                                "name": "list_repositories",
                                "description": "List repositories visible to the authenticated user. Use for read-only repository discovery only.",
                                "annotations": {"readOnlyHint": True},
                                "inputSchema": {
                                    "type": "object",
                                    "properties": {},
                                    "required": [],
                                    "additionalProperties": False,
                                },
                                "outputSchema": {
                                    "type": "object",
                                    "properties": {
                                        "repositories": {
                                            "type": "array",
                                            "items": {"type": "object"},
                                        }
                                    },
                                    "required": ["repositories"],
                                    "additionalProperties": False,
                                },
                            }
                        ]
                    },
                }
            )
            return
        self._send_json(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "method not found"},
            }
        )

    def do_DELETE(self) -> None:
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send_json(self, payload: dict, extra_headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _send_sse(self, payload: dict) -> None:
        body = f"event: message\ndata: {json.dumps(payload, separators=(',', ':'))}\n\n".encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class HttpClientIntegrationTests(unittest.TestCase):
    def test_discovers_tools_from_streamable_http_sse(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _McpHttpHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/mcp"
            result = discover_from_server_url(url, server_name="mock-http", timeout=5)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(result.server_name, "mock-http")
        self.assertEqual([tool.name for tool in result.tools], ["list_repositories"])

    def test_negotiates_supported_previous_protocol_and_uses_it_in_headers(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _McpHttpHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/previous"
            result = discover_from_server_url(url, timeout=5)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(result.metadata["protocol_requested"], "2025-11-25")
        self.assertEqual(result.metadata["protocol_negotiated"], "2025-06-18")
        self.assertEqual(_McpHttpHandler.last_tools_protocol, "2025-06-18")

    def test_capability_gate_rejects_tools_list_when_not_declared(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _McpHttpHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/no-tools"
            with self.assertRaisesRegex(UnsupportedFeatureError, "unsupported_feature"):
                discover_from_server_url(url, timeout=5)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_bearer_provider_authenticates_without_token_in_url_or_report_metadata(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _McpHttpHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            url = f"http://127.0.0.1:{server.server_port}/auth"
            result = discover_from_server_url(
                url,
                timeout=5,
                credential_provider=BearerTokenProvider("test-token"),
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertTrue(result.metadata["authenticated"])
        self.assertNotIn("test-token", json.dumps(result.metadata))


if __name__ == "__main__":
    unittest.main()

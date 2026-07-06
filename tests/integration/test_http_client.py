from __future__ import annotations

import json
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from mcp_tool_card_linter.discovery import discover_from_server_url


class _McpHttpHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        payload = json.loads(self.rfile.read(length).decode("utf-8"))
        method = payload.get("method")
        request_id = payload.get("id")
        if method == "notifications/initialized":
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if method == "initialize":
            self._send_json(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": payload.get("params", {}).get("protocolVersion"),
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": "mock-http", "version": "1.0.0"},
                    },
                },
                extra_headers={"Mcp-Session-Id": "session-1"},
            )
            return
        if method == "tools/list":
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


if __name__ == "__main__":
    unittest.main()


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


def _tool(name: str) -> dict[str, object]:
    return {
        "name": name,
        "description": f"List {name} records without changing server state.",
        "annotations": {"readOnlyHint": True},
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    }


class _V04Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    resumed_last_event_id = ""
    list_calls = 0
    initialize_calls = 0
    ping_response_received = False

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length).decode("utf-8"))
        method = request.get("method")
        request_id = request.get("id")
        if method is None and request.get("result") == {} and request_id == "server-ping":
            type(self).ping_response_received = True
            self._empty(202)
            return
        if method == "notifications/initialized":
            self._empty(202)
            return
        if method == "initialize":
            type(self).initialize_calls += 1
            session = f"v04-session-{type(self).initialize_calls}"
            self._json(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "protocolVersion": request["params"]["protocolVersion"],
                        "capabilities": {"tools": {"listChanged": self.path == "/changed"}},
                        "serverInfo": {"name": "v04-fixture", "version": "1"},
                    },
                },
                headers={"Mcp-Session-Id": session},
            )
            return
        if method == "tools/list":
            type(self).list_calls += 1
            if (
                self.path == "/expired-session"
                and self.headers.get("Mcp-Session-Id") == "v04-session-1"
            ):
                self._empty(404)
                return
            if self.path == "/resume":
                # An empty data event primes the stream, while the id provides
                # the cursor the client must use to resume with GET.
                self._sse(b"id: event-1\ndata:\n\n")
                return
            name = "after_change" if type(self).list_calls > 1 else "before_change"
            self._json(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {"tools": [_tool(name)]},
                }
            )
            return
        self._json(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": "not found"},
            }
        )

    def do_GET(self) -> None:
        if self.path == "/resume":
            type(self).resumed_last_event_id = self.headers.get("Last-Event-ID", "")
            response = {
                "jsonrpc": "2.0",
                "id": 2,
                "result": {"tools": [_tool("resumed_tool")]},
            }
            body = (
                "id: event-2\n"
                f"data: {json.dumps(response, separators=(',', ':'))}\n\n"
            ).encode("utf-8")
            self._sse(body)
            return
        notification = {
            "jsonrpc": "2.0",
            "method": "notifications/tools/list_changed",
        }
        ping = {
            "jsonrpc": "2.0",
            "id": "server-ping",
            "method": "ping",
        }
        body = (
            "id: changed-1\n"
            f"data: {json.dumps(ping, separators=(',', ':'))}\n\n"
            "id: changed-2\n"
            f"data: {json.dumps(notification, separators=(',', ':'))}\n\n"
        ).encode("utf-8")
        self._sse(body)

    def do_DELETE(self) -> None:
        self._empty(204)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _json(self, payload: dict[str, object], headers: dict[str, str] | None = None) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _sse(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _empty(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()


class StreamableHttpV04IntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        _V04Handler.resumed_last_event_id = ""
        _V04Handler.list_calls = 0
        _V04Handler.initialize_calls = 0
        _V04Handler.ping_response_received = False
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _V04Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.server.server_port}{path}"

    def test_resumes_interrupted_post_sse_response_with_get_and_last_event_id(self) -> None:
        result = discover_from_server_url(self.url("/resume"), timeout=3)

        self.assertEqual([tool.name for tool in result.tools], ["resumed_tool"])
        self.assertEqual(_V04Handler.resumed_last_event_id, "event-1")

    def test_refreshes_tools_once_after_declared_list_changed_notification(self) -> None:
        result = discover_from_server_url(
            self.url("/changed"),
            timeout=3,
            refresh_on_list_changed=1,
        )

        self.assertEqual([tool.name for tool in result.tools], ["after_change"])
        self.assertEqual(_V04Handler.list_calls, 2)
        self.assertTrue(result.metadata["list_changed_received"])
        self.assertEqual(result.metadata["refresh_count"], 1)
        self.assertTrue(_V04Handler.ping_response_received)

    def test_reinitializes_once_when_server_expires_the_http_session(self) -> None:
        result = discover_from_server_url(self.url("/expired-session"), timeout=3)

        self.assertEqual([tool.name for tool in result.tools], ["after_change"])
        self.assertEqual(_V04Handler.initialize_calls, 2)
        self.assertEqual(result.metadata["session_recoveries"], 1)


if __name__ == "__main__":
    unittest.main()

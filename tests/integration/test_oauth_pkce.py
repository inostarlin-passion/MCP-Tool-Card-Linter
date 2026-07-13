from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from mcp_tool_card_linter.oauth import OAuthError, complete_authorization, start_authorization


class _OAuthHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    base_url = ""
    token_form: dict[str, list[str]] = {}
    advertise_s256 = True
    mismatched_resource = False
    mismatched_issuer = False

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        if self.path == "/mcp":
            self.send_response(401)
            self.send_header(
                "WWW-Authenticate",
                'Bearer resource_metadata="'
                + self.base_url
                + '/.well-known/oauth-protected-resource/mcp", scope="tools.read"',
            )
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if self.path == "/token":
            type(self).token_form = urllib.parse.parse_qs(
                body.decode("ascii"),
                keep_blank_values=True,
                strict_parsing=True,
            )
            self._json(
                {
                    "access_token": "test-access-token-opaque",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "tools.read",
                }
            )
            return
        self._empty(404)

    def do_GET(self) -> None:
        if self.path == "/.well-known/oauth-protected-resource/mcp":
            resource = self.base_url + ("/wrong" if self.mismatched_resource else "/mcp")
            self._json(
                {
                    "resource": resource,
                    "authorization_servers": [self.base_url + "/tenant"],
                }
            )
            return
        if self.path == "/.well-known/oauth-authorization-server/tenant":
            methods = ["S256"] if self.advertise_s256 else ["plain"]
            self._json(
                {
                    "issuer": self.base_url + (
                        "/wrong-issuer" if self.mismatched_issuer else "/tenant"
                    ),
                    "authorization_endpoint": self.base_url + "/authorize",
                    "token_endpoint": self.base_url + "/token",
                    "code_challenge_methods_supported": methods,
                    "response_types_supported": ["code"],
                    "grant_types_supported": ["authorization_code"],
                }
            )
            return
        self._empty(404)

    def log_message(self, format: str, *args: object) -> None:
        return

    def _json(self, payload: dict[str, object]) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _empty(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()


class OAuthPkceIntegrationTests(unittest.TestCase):
    def assert_private_file_semantics(self, path: Path) -> None:
        mode = path.stat().st_mode
        self.assertTrue(stat.S_ISREG(mode))
        # POSIX exposes authorization through mode bits. Windows authorization
        # is represented by the file DACL inherited from the containing directory;
        # st_mode only synthesizes read/write attributes and commonly reports 0666.
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(mode), 0o600)

    def setUp(self) -> None:
        _OAuthHandler.token_form = {}
        _OAuthHandler.advertise_s256 = True
        _OAuthHandler.mismatched_resource = False
        _OAuthHandler.mismatched_issuer = False
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), _OAuthHandler)
        _OAuthHandler.base_url = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def test_discovers_metadata_uses_s256_and_exchanges_code_with_resource(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "oauth-state.json"
            token_file = Path(tmpdir) / "token.txt"
            redirect = "http://localhost:8765/callback"
            started = start_authorization(
                _OAuthHandler.base_url + "/mcp",
                client_id="registered-public-client",
                redirect_uri=redirect,
                state_file=state_file,
                scopes=["optional.extra"],
                timeout=2,
                allow_insecure_http=True,
            )
            query = urllib.parse.parse_qs(
                urllib.parse.urlsplit(started["authorization_url"]).query
            )
            self.assertEqual(query["code_challenge_method"], ["S256"])
            self.assertEqual(query["resource"], [_OAuthHandler.base_url + "/mcp"])
            self.assertEqual(query["scope"], ["tools.read optional.extra"])
            self.assertNotIn("code_verifier", query)
            self.assert_private_file_semantics(state_file)

            callback = redirect + "?" + urllib.parse.urlencode(
                {
                    "code": "one-time-code",
                    "state": query["state"][0],
                    "iss": _OAuthHandler.base_url + "/tenant",
                }
            )
            completed = complete_authorization(
                state_file=state_file,
                callback_url=callback,
                token_file=token_file,
                timeout=2,
                allow_insecure_http=True,
            )

            self.assertFalse(state_file.exists())
            self.assertEqual(token_file.read_text(encoding="utf-8"), "test-access-token-opaque\n")
            self.assert_private_file_semantics(token_file)
            self.assertNotIn("test-access-token-opaque", json.dumps(completed))
            form = _OAuthHandler.token_form
            self.assertEqual(form["resource"], [_OAuthHandler.base_url + "/mcp"])
            self.assertEqual(form["code"], ["one-time-code"])
            self.assertEqual(form["client_id"], ["registered-public-client"])
            self.assertGreaterEqual(len(form["code_verifier"][0]), 43)

    def test_rejects_state_mismatch_without_consuming_state_or_writing_token(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state.json"
            token_file = Path(tmpdir) / "token.txt"
            redirect = "http://localhost:8765/callback"
            started = start_authorization(
                _OAuthHandler.base_url + "/mcp",
                client_id="client",
                redirect_uri=redirect,
                state_file=state_file,
                timeout=2,
                allow_insecure_http=True,
            )
            state = urllib.parse.parse_qs(
                urllib.parse.urlsplit(started["authorization_url"]).query
            )["state"][0]

            with self.assertRaisesRegex(OAuthError, "issuer mismatch"):
                complete_authorization(
                    state_file=state_file,
                    callback_url=(
                        redirect
                        + "?"
                        + urllib.parse.urlencode(
                            {
                                "code": "code",
                                "state": state,
                                "iss": _OAuthHandler.base_url + "/wrong-issuer",
                            }
                        )
                    ),
                    token_file=token_file,
                    timeout=2,
                    allow_insecure_http=True,
                )

            with self.assertRaisesRegex(OAuthError, "state mismatch"):
                complete_authorization(
                    state_file=state_file,
                    callback_url=redirect + "?code=code&state=wrong",
                    token_file=token_file,
                    timeout=2,
                    allow_insecure_http=True,
                )

            self.assertTrue(state_file.exists())
            self.assertFalse(token_file.exists())
            self.assertFalse(Path(str(state_file) + ".lock").exists())

    def test_refuses_authorization_server_without_s256(self) -> None:
        _OAuthHandler.advertise_s256 = False
        with tempfile.TemporaryDirectory() as tmpdir:
            state_file = Path(tmpdir) / "state.json"
            with self.assertRaisesRegex(OAuthError, "PKCE method S256"):
                start_authorization(
                    _OAuthHandler.base_url + "/mcp",
                    client_id="client",
                    redirect_uri="http://localhost:8765/callback",
                    state_file=state_file,
                    timeout=2,
                    allow_insecure_http=True,
                )
            self.assertFalse(state_file.exists())

    def test_refuses_protected_resource_metadata_for_another_resource(self) -> None:
        _OAuthHandler.mismatched_resource = True
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaisesRegex(OAuthError, "protected resource metadata"):
                start_authorization(
                    _OAuthHandler.base_url + "/mcp",
                    client_id="client",
                    redirect_uri="http://localhost:8765/callback",
                    state_file=Path(tmpdir) / "state.json",
                    timeout=2,
                    allow_insecure_http=True,
                )

        _OAuthHandler.mismatched_resource = False
        _OAuthHandler.mismatched_issuer = True
        with tempfile.TemporaryDirectory() as tmpdir:
            with self.assertRaisesRegex(OAuthError, "authorization server metadata"):
                start_authorization(
                    _OAuthHandler.base_url + "/mcp",
                    client_id="client",
                    redirect_uri="http://localhost:8765/callback",
                    state_file=Path(tmpdir) / "state.json",
                    timeout=2,
                    allow_insecure_http=True,
                )


if __name__ == "__main__":
    unittest.main()

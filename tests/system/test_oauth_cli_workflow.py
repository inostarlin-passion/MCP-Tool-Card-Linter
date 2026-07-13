from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.parse
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
PYTHON = ROOT / ".venv" / "bin" / "python"
PYTHON = PYTHON if PYTHON.exists() else Path(sys.executable)

from tests.integration.test_oauth_pkce import _OAuthHandler


class OAuthCliSystemTests(unittest.TestCase):
    def test_two_process_authorize_workflow_writes_token_without_argv_secret(self) -> None:
        server = ThreadingHTTPServer(("127.0.0.1", 0), _OAuthHandler)
        _OAuthHandler.base_url = f"http://127.0.0.1:{server.server_port}"
        _OAuthHandler.advertise_s256 = True
        _OAuthHandler.mismatched_resource = False
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                state_file = Path(tmpdir) / "state.json"
                token_file = Path(tmpdir) / "token.txt"
                environment = os.environ.copy()
                environment["PYTHONPATH"] = str(ROOT / "src")
                start = subprocess.run(
                    [
                        str(PYTHON),
                        "-m",
                        "mcp_tool_card_linter",
                        "authorize",
                        "start",
                        "--server-url",
                        _OAuthHandler.base_url + "/mcp",
                        "--client-id",
                        "registered-client",
                        "--redirect-uri",
                        "http://localhost:8765/callback",
                        "--state-file",
                        str(state_file),
                        "--allow-insecure-http",
                    ],
                    cwd=ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(start.returncode, 0, start.stderr)
                started = json.loads(start.stdout)
                auth_query = urllib.parse.parse_qs(
                    urllib.parse.urlsplit(started["authorization_url"]).query
                )
                callback = "http://localhost:8765/callback?" + urllib.parse.urlencode(
                    {"code": "system-code", "state": auth_query["state"][0]}
                )
                environment["MCP_CALLBACK_URL"] = callback

                protected_input = Path(tmpdir) / "client-key.pem"
                protected_input.write_text("must-not-be-overwritten\n", encoding="utf-8")
                overlap = subprocess.run(
                    [
                        str(PYTHON),
                        "-m",
                        "mcp_tool_card_linter",
                        "authorize",
                        "complete",
                        "--state-file",
                        str(state_file),
                        "--token-file",
                        str(protected_input),
                        "--callback-url-env",
                        "MCP_CALLBACK_URL",
                        "--client-key",
                        str(protected_input),
                        "--allow-insecure-http",
                    ],
                    cwd=ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )
                self.assertEqual(overlap.returncode, 2)
                self.assertIn("must not overwrite the client key", overlap.stderr)
                self.assertEqual(
                    protected_input.read_text(encoding="utf-8"),
                    "must-not-be-overwritten\n",
                )

                complete = subprocess.run(
                    [
                        str(PYTHON),
                        "-m",
                        "mcp_tool_card_linter",
                        "authorize",
                        "complete",
                        "--state-file",
                        str(state_file),
                        "--token-file",
                        str(token_file),
                        "--callback-url-env",
                        "MCP_CALLBACK_URL",
                        "--allow-insecure-http",
                    ],
                    cwd=ROOT,
                    env=environment,
                    capture_output=True,
                    text=True,
                    timeout=10,
                    check=False,
                )

                self.assertEqual(complete.returncode, 0, complete.stderr)
                self.assertEqual(token_file.read_text(encoding="utf-8"), "test-access-token-opaque\n")
                self.assertNotIn("test-access-token-opaque", complete.stdout)
                self.assertNotIn(callback, " ".join(complete.args))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()

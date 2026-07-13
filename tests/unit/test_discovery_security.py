from __future__ import annotations

import json
import math
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from mcp_tool_card_linter.discovery import (
    DiscoveryError,
    JsonRpcError,
    StdioMcpClient,
    _build_http_opener,
    discover_from_config,
    load_tools_file,
)


class DiscoverySecurityTests(unittest.TestCase):
    def test_http_opener_does_not_implicitly_load_environment_proxies(self) -> None:
        with mock.patch(
            "urllib.request.getproxies",
            side_effect=AssertionError("implicit proxy lookup"),
        ):
            opener = _build_http_opener(
                ca_bundle=None,
                proxy_url=None,
                client_cert=None,
                client_key=None,
            )

        self.assertIsNotNone(opener)

    def test_config_local_command_requires_explicit_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "mcp.json"
            config.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "unreviewed": {
                                "command": "/definitely/not/executed",
                                "args": [],
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            results = discover_from_config(config)

        self.assertEqual(len(results), 1)
        self.assertIn("--allow-config-execution", results[0].errors[0])

    def test_config_cannot_self_authorize_full_environment_inheritance(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "mcp.json"
            config.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "server": {
                                "command": sys.executable,
                                "args": ["-c", "pass"],
                                "inheritEnv": True,
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            results = discover_from_config(
                config,
                allow_command_execution=True,
                inherit_env=False,
            )

        self.assertIn("--inherit-env", results[0].errors[0])

    def test_config_loopback_url_requires_private_network_approval(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "mcp.json"
            config.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "local-http": {"url": "http://127.0.0.1:9/mcp"}
                        }
                    }
                ),
                encoding="utf-8",
            )
            results = discover_from_config(config, timeout=0.1)

        self.assertIn("loopback", results[0].errors[0])

    def test_static_json_rejects_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "tools.json"
            path.write_text(
                '{"tools": [], "tools": [{"name": "ambiguous"}]}',
                encoding="utf-8",
            )
            with self.assertRaises(DiscoveryError):
                load_tools_file(path)

    def test_config_static_tools_preserve_discovered_count_when_truncated(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            config = Path(tmpdir) / "mcp.json"
            config.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "static": {
                                "tools": [
                                    {"name": "one"},
                                    {"name": "two"},
                                ]
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            results = discover_from_config(config, max_tools=1)

        self.assertEqual(len(results[0].tools), 1)
        self.assertEqual(results[0].discovered_tools, 2)
        self.assertTrue(results[0].metadata["truncated"])

    def test_stdio_pagination_rejects_repeated_cursor(self) -> None:
        client = StdioMcpClient([sys.executable])
        client.request = mock.Mock(
            side_effect=[
                {"tools": [], "nextCursor": "same"},
                {"tools": [], "nextCursor": "same"},
            ]
        )
        with self.assertRaises(JsonRpcError):
            client.list_tools(max_pages=3)

    def test_stdio_validates_environment_command_and_timeout_boundaries(self) -> None:
        with self.assertRaises(DiscoveryError):
            StdioMcpClient([sys.executable, "bad\x00argument"])
        with self.assertRaises(DiscoveryError):
            StdioMcpClient([sys.executable], env={"TOKEN": 123})  # type: ignore[dict-item]
        with self.assertRaises(DiscoveryError):
            StdioMcpClient([sys.executable], timeout=math.nan)

    def test_config_rejects_excessive_concurrency_before_allocating_threads(self) -> None:
        with self.assertRaises(DiscoveryError):
            discover_from_config("missing.json", concurrency=33)

    def test_stdio_request_lock_serializes_concurrent_jsonrpc_round_trips(self) -> None:
        client = StdioMcpClient([sys.executable])
        client._write_message = mock.Mock()
        state_lock = threading.Lock()
        active = 0
        maximum_active = 0

        def fake_read(request_id: int) -> int:
            nonlocal active, maximum_active
            with state_lock:
                active += 1
                maximum_active = max(maximum_active, active)
            time.sleep(0.01)
            with state_lock:
                active -= 1
            return request_id

        client._read_response = fake_read  # type: ignore[method-assign]
        with ThreadPoolExecutor(max_workers=8) as executor:
            results = list(executor.map(lambda _: client.request("test"), range(8)))

        self.assertEqual(sorted(results), list(range(1, 9)))
        self.assertEqual(maximum_active, 1)


if __name__ == "__main__":
    unittest.main()

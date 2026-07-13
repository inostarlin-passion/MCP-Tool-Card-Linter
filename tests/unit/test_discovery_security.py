from __future__ import annotations

import json
import math
import os
import subprocess
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
    MAX_WINDOWS_COMMAND_CHARS,
    DiscoveryError,
    JsonRpcError,
    StdioMcpClient,
    _build_http_opener,
    _parse_stdio_command,
    _split_windows_command_line,
    _windows_command_units,
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

    def test_stdio_argument_sequence_is_preserved_without_shell_reparsing(self) -> None:
        command = (
            r"C:\Program Files\Python\python.exe",
            r"D:\workspace with spaces\server.py",
            "--label=a value with spaces",
        )

        self.assertEqual(_parse_stdio_command(command), list(command))

    def test_windows_command_limit_counts_utf16_code_units(self) -> None:
        self.assertEqual(_windows_command_units("plain"), 5)
        self.assertEqual(_windows_command_units("\U0001f600"), 2)
        oversized = "x " + "\U0001f600" * (MAX_WINDOWS_COMMAND_CHARS // 2)
        with mock.patch("mcp_tool_card_linter.discovery.os.name", "nt"):
            with self.assertRaisesRegex(DiscoveryError, "too long"):
                _parse_stdio_command(oversized)

    def test_stdio_command_parser_rejects_invalid_shapes_and_quoting(self) -> None:
        with self.assertRaisesRegex(DiscoveryError, "empty"):
            _parse_stdio_command("   ")
        with self.assertRaisesRegex(DiscoveryError, "string or an argument sequence"):
            _parse_stdio_command(object())  # type: ignore[arg-type]
        with mock.patch("mcp_tool_card_linter.discovery.os.name", "posix"):
            with self.assertRaisesRegex(DiscoveryError, "quoting"):
                _parse_stdio_command("'unterminated")

    def test_windows_serialized_argument_sequence_limit_is_enforced(self) -> None:
        oversized = [sys.executable, *("\U0001f600" * 8192 for _ in range(3))]
        with mock.patch("mcp_tool_card_linter.discovery.os.name", "nt"):
            with self.assertRaisesRegex(DiscoveryError, "CreateProcess"):
                _parse_stdio_command(oversized)

    def test_windows_parser_reports_unavailable_native_api(self) -> None:
        with mock.patch("ctypes.WinDLL", None, create=True):
            with self.assertRaisesRegex(OSError, "unavailable"):
                _split_windows_command_line("python server.py")

    @unittest.skipUnless(os.name == "nt", "requires Windows command-line APIs")
    def test_windows_native_command_parser_round_trips_quoted_arguments(self) -> None:
        command = [
            sys.executable,
            r"D:\workspace with spaces\server.py",
            'embedded"quote',
            "trailing\\",
        ]

        self.assertEqual(
            _split_windows_command_line(subprocess.list2cmdline(command)),
            command,
        )

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

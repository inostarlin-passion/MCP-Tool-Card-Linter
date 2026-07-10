from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from mcp_tool_card_linter.discovery import (
    DiscoveryError,
    JsonRpcError,
    StdioMcpClient,
    discover_from_stdio_command,
)

FIXTURE = ROOT / "tests" / "fixtures" / "adversarial_mcp_stdio_server.py"


class StdioSecurityIntegrationTests(unittest.TestCase):
    def command(self, mode: str) -> list[str]:
        return [sys.executable, str(FIXTURE), mode]

    def test_failed_enter_closes_process_and_stderr_thread(self) -> None:
        client = StdioMcpClient(self.command("init_error"), timeout=2)
        with self.assertRaises(JsonRpcError):
            with client:
                self.fail("initialization should fail")
        self.assertIsNone(client._proc)
        self.assertIsNone(client._stdout_thread)
        self.assertIsNone(client._stderr_thread)

    def test_rejects_oversized_stdio_message(self) -> None:
        with StdioMcpClient(self.command("oversized"), timeout=3) as client:
            with self.assertRaisesRegex(DiscoveryError, "exceeds"):
                client.list_tools()

    def test_rejects_duplicate_json_keys_in_protocol_message(self) -> None:
        with StdioMcpClient(self.command("duplicate_json_key"), timeout=2) as client:
            with self.assertRaisesRegex(JsonRpcError, "malformed JSON"):
                client.list_tools()

    def test_rejects_repeated_stdio_pagination_cursor(self) -> None:
        with StdioMcpClient(self.command("repeat"), timeout=2) as client:
            with self.assertRaisesRegex(JsonRpcError, "cursor repeated"):
                client.list_tools(max_pages=3)

    def test_bounded_noise_is_skipped_for_compatibility(self) -> None:
        result = discover_from_stdio_command(
            f"{sys.executable} {FIXTURE} noise",
            timeout=2,
        )
        self.assertEqual(result.tools, [])

    def test_parent_secrets_are_not_inherited_without_explicit_opt_in(self) -> None:
        with mock.patch.dict(os.environ, {"MCP_TEST_SECRET": "should-not-leak"}):
            isolated = discover_from_stdio_command(
                f"{sys.executable} {FIXTURE} environment",
                timeout=2,
                inherit_env=False,
            )
            inherited = discover_from_stdio_command(
                f"{sys.executable} {FIXTURE} environment",
                timeout=2,
                inherit_env=True,
            )

        self.assertEqual(isolated.tools[0].name, "environment_clean")
        self.assertEqual(inherited.tools[0].name, "environment_leaked")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from mcp_tool_card_linter.discovery import discover_from_stdio_command


class StdioClientIntegrationTests(unittest.TestCase):
    def test_discovers_paginated_tools_from_stdio_server(self) -> None:
        fixture = ROOT / "tests" / "fixtures" / "mock_mcp_stdio_server.py"
        result = discover_from_stdio_command(
            f"{sys.executable} {fixture}",
            server_name="mock",
            timeout=5,
            max_tools=10,
        )

        self.assertEqual(result.server_name, "mock")
        self.assertEqual([tool.name for tool in result.tools], ["search_customer_orders", "delete_customer"])


if __name__ == "__main__":
    unittest.main()


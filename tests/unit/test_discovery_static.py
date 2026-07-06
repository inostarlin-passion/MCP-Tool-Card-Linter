from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from mcp_tool_card_linter.discovery import DiscoveryError, extract_tools, load_tools_file


class StaticDiscoveryTests(unittest.TestCase):
    def test_extract_tools_accepts_list_tools_and_result_tools(self) -> None:
        tools = [{"name": "x"}]
        self.assertEqual(extract_tools(tools), tools)
        self.assertEqual(extract_tools({"tools": tools}), tools)
        self.assertEqual(extract_tools({"result": {"tools": tools}}), tools)

    def test_extract_tools_rejects_missing_tools_array(self) -> None:
        with self.assertRaises(DiscoveryError):
            extract_tools({"result": {}})

    def test_load_tools_file_validates_json_and_maps_cards(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "tools.json"
            path.write_text(
                json.dumps(
                    {
                        "tools": [
                            {
                                "name": "list_repos",
                                "description": "List repositories",
                                "inputSchema": {"type": "object"},
                            }
                        ]
                    }
                ),
                encoding="utf-8",
            )
            result = load_tools_file(path, server_name="fixture")

        self.assertEqual(result.server_name, "fixture")
        self.assertEqual(result.tools[0].name, "list_repos")


if __name__ == "__main__":
    unittest.main()


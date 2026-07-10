from __future__ import annotations

import sys
import time
import tracemalloc
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from mcp_tool_card_linter.lint import lint_sources
from mcp_tool_card_linter.models import LintConfig, SourceResult, ToolCard


class PerformanceBudgetSystemTests(unittest.TestCase):
    def test_lints_two_thousand_bounded_cards_within_budget(self) -> None:
        raw_tools = [
            {
                "name": f"lookup_record_{index}",
                "description": "Look up a record by ID. Use only for read-only retrieval and do not modify records.",
                "annotations": {"readOnlyHint": True},
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "record_id": {
                            "type": "string",
                            "description": "Stable record ID",
                            "maxLength": 64,
                        }
                    },
                    "required": ["record_id"],
                    "additionalProperties": False,
                },
                "outputSchema": {
                    "type": "object",
                    "properties": {"found": {"type": "boolean"}},
                    "required": ["found"],
                    "additionalProperties": False,
                },
            }
            for index in range(2000)
        ]
        source = SourceResult(
            server_name="performance",
            source_type="system",
            tools=[
                ToolCard.from_raw(tool, server_name="performance", index=index)
                for index, tool in enumerate(raw_tools)
            ],
        )

        tracemalloc.start()
        started = time.perf_counter()
        try:
            report = lint_sources([source], LintConfig(max_tools=2000))
            elapsed = time.perf_counter() - started
            _, peak_bytes = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()

        self.assertEqual(report.summary["tools_scanned"], 2000)
        self.assertLess(elapsed, 10.0)
        self.assertLess(peak_bytes, 128 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()

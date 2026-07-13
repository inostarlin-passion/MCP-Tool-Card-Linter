from __future__ import annotations

import unittest

from mcp_tool_card_linter.lint import lint_sources
from mcp_tool_card_linter.models import LintConfig, SourceResult, ToolCard


def _codes(raw: dict) -> set[str]:
    source = SourceResult(
        "server",
        "static",
        [ToolCard.from_raw(raw, server_name="server", index=0)],
    )
    return {issue.code for issue in lint_sources([source], LintConfig()).tools[0].issues}


class ProtocolExtensionLintTests(unittest.TestCase):
    def test_complete_metaschema_validator_rejects_invalid_2020_12_keyword(self) -> None:
        codes = _codes(
            {
                "name": "lookup_record",
                "description": "Look up one record for read-only retrieval only.",
                "inputSchema": {
                    "type": "object",
                    "properties": {},
                    "minProperties": -1,
                },
            }
        )
        self.assertIn("INVALID_JSON_SCHEMA_2020_12", codes)

    def test_icon_structure_and_tool_name_guidance_are_validated(self) -> None:
        codes = _codes(
            {
                "name": "bad/name",
                "description": "Look up one record for read-only retrieval only.",
                "icons": [
                    {
                        "src": "file:///etc/passwd",
                        "mimeType": "text/html",
                        "sizes": ["0x0"],
                        "theme": "unknown",
                    }
                ],
                "execution": {"taskSupport": "sometimes"},
                "inputSchema": {"type": "object", "properties": {}},
            }
        )
        self.assertIn("TOOL_NAME_SPEC_VIOLATION", codes)
        self.assertIn("INVALID_TOOL_ICON_SRC", codes)
        self.assertIn("INVALID_TOOL_ICON_MIME_TYPE", codes)
        self.assertIn("INVALID_TOOL_ICON_SIZE", codes)
        self.assertIn("INVALID_TOOL_ICONS", codes)
        self.assertIn("INVALID_TASK_SUPPORT", codes)

    def test_valid_mcp_icon_is_accepted(self) -> None:
        codes = _codes(
            {
                "name": "lookup_record",
                "description": "Look up one record for read-only retrieval only.",
                "icons": [
                    {
                        "src": "https://example.test/icon.png",
                        "mimeType": "image/png",
                        "sizes": ["48x48"],
                        "theme": "light",
                    }
                ],
                "execution": {"taskSupport": "optional"},
                "inputSchema": {"type": "object", "properties": {}},
            }
        )
        self.assertFalse(any(code.startswith("INVALID_TOOL_ICON") for code in codes))
        self.assertNotIn("INVALID_TASK_SUPPORT", codes)

    def test_per_tool_finding_count_is_bounded_and_reports_truncation(self) -> None:
        raw = {
            "name": "bounded_invalid_schema",
            "description": "Validate an intentionally malformed schema for a bounded test only.",
            "inputSchema": {
                "type": "object",
                "properties": {f"field_{index}": None for index in range(1_100)},
            },
        }
        source = SourceResult(
            "server",
            "static",
            [ToolCard.from_raw(raw, server_name="server", index=0)],
        )

        issues = lint_sources(
            [source],
            LintConfig(max_schema_properties=2_000),
        ).tools[0].issues

        self.assertEqual(len(issues), 1_000)
        self.assertEqual(issues[-1].code, "FINDING_LIMIT_REACHED")


if __name__ == "__main__":
    unittest.main()

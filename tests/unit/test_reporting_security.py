from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from mcp_tool_card_linter.lint import lint_sources
from mcp_tool_card_linter.models import LintConfig, SourceResult, ToolCard
from mcp_tool_card_linter.reporting import (
    ReportError,
    baseline_fingerprints_from_payload,
    exit_code_for_report,
    optimize_from_report,
    report_to_markdown,
    write_json_report,
)


def make_report(*, name: str = "safe_tool", source_errors: list[str] | None = None):
    raw = {
        "name": name,
        "description": "Look up a value. Use only for read-only retrieval and do not modify state.",
        "annotations": {"readOnlyHint": True},
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
        "outputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
    }
    source = SourceResult(
        server_name="unit",
        source_type="unit",
        tools=[ToolCard.from_raw(raw, server_name="unit", index=0)],
        errors=source_errors or [],
    )
    return lint_sources([source], LintConfig())


class ReportingSecurityTests(unittest.TestCase):
    def test_markdown_escapes_model_controlled_html_tables_and_code(self) -> None:
        report = make_report(name="bad|`name</table>\n<script>alert(1)</script>")
        markdown = report_to_markdown(report)

        self.assertNotIn("<script>", markdown)
        self.assertNotIn("</table>", markdown)
        self.assertIn("&lt;script&gt;", markdown)
        self.assertIn("\\|", markdown)
        self.assertIn("&#96;", markdown)

    def test_atomic_write_preserves_original_when_replace_fails(self) -> None:
        report = make_report()
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "report.json"
            target.write_text("original", encoding="utf-8")
            with mock.patch(
                "mcp_tool_card_linter.reporting.os.replace",
                side_effect=OSError("simulated replace failure"),
            ):
                with self.assertRaises(OSError):
                    write_json_report(report, target)
            self.assertEqual(target.read_text(encoding="utf-8"), "original")
            self.assertEqual(list(Path(tmpdir).glob("*.tmp")), [])

    @unittest.skipIf(os.name == "nt", "POSIX permission assertion")
    def test_new_report_is_private_by_default(self) -> None:
        report = make_report()
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "report.json"
            write_json_report(report, target)
            mode = stat.S_IMODE(target.stat().st_mode)
        self.assertEqual(mode, 0o600)

    def test_baseline_parser_validates_fingerprint_and_duplicate_identity(self) -> None:
        payload = make_report().to_dict()
        fingerprints = baseline_fingerprints_from_payload(payload)
        self.assertEqual(len(fingerprints), 1)

        malformed = make_report().to_dict()
        malformed["tools"][0]["card_fingerprint"] = "md5:bad"
        with self.assertRaises(ReportError):
            baseline_fingerprints_from_payload(malformed)

        duplicate = make_report().to_dict()
        duplicate["tools"].append(dict(duplicate["tools"][0]))
        with self.assertRaises(ReportError):
            baseline_fingerprints_from_payload(duplicate)

    def test_source_errors_return_two_even_when_findings_are_disabled(self) -> None:
        report = make_report(source_errors=["server unavailable"])
        self.assertEqual(exit_code_for_report(report, "never"), 2)

    def test_optimizer_rejects_malformed_report_and_blocks_changed_card(self) -> None:
        with self.assertRaises(ReportError):
            optimize_from_report({"tools": "not-an-array"})

        payload = make_report().to_dict()
        payload["tools"][0]["issues"].append(
            {
                "code": "TOOL_CARD_CHANGED",
                "severity": "error",
                "path": "$",
                "message": "changed",
                "recommendation": "review",
                "evidence": None,
            }
        )
        optimized = optimize_from_report(payload)
        self.assertEqual(optimized["tools"][0]["decision"], "block_until_review")


if __name__ == "__main__":
    unittest.main()

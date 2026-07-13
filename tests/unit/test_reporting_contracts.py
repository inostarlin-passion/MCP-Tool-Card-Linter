from __future__ import annotations

import json
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path
from unittest import mock

from jsonschema import Draft202012Validator, FormatChecker

from mcp_tool_card_linter.lint import lint_sources
from mcp_tool_card_linter.models import LintConfig, SourceResult, ToolCard
from mcp_tool_card_linter.reporting import (
    report_to_github_annotations,
    report_to_json,
    report_to_jsonl,
    report_to_junit,
    report_to_markdown,
    report_to_sarif,
)
from mcp_tool_card_linter import reporting

ROOT = Path(__file__).resolve().parents[2]


def _report():
    raw = {
        "name": "lookup_record",
        "description": "Look up a record by identifier. Use only for read-only retrieval.",
        "annotations": {"readOnlyHint": True},
        "inputSchema": {
            "type": "object",
            "properties": {
                "record_id": {
                    "type": "string",
                    "description": "Stable record identifier",
                    "maxLength": 64,
                }
            },
            "required": ["record_id"],
            "additionalProperties": False,
        },
        "outputSchema": {
            "type": "object",
            "properties": {"record": {"type": "object"}},
            "required": ["record"],
            "additionalProperties": False,
        },
    }
    source = SourceResult(
        "static",
        "tools-file",
        [ToolCard.from_raw(raw, server_name="static", index=0)],
        metadata={"path": str(ROOT / "tests" / "fixtures" / "good_tools.json")},
    )
    return lint_sources([source], LintConfig(), deterministic=True)


class ReportingContractTests(unittest.TestCase):
    def test_json_report_validates_against_published_draft_2020_12_schema(self) -> None:
        report = _report()
        payload = json.loads(report_to_json(report))
        schema_path = (
            ROOT
            / "src"
            / "mcp_tool_card_linter"
            / "schemas"
            / "report.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        Draft202012Validator(schema, format_checker=FormatChecker()).validate(payload)
        self.assertEqual(payload["report_schema_version"], "1.0.0")
        self.assertTrue(payload["scan_id"].startswith("urn:sha256:"))
        self.assertEqual(payload["tool_version"], "0.4.0")

    def test_deterministic_json_is_byte_stable(self) -> None:
        self.assertEqual(report_to_json(_report()), report_to_json(_report()))

    def test_markdown_omits_reasoning_section_without_changing_json_contract(self) -> None:
        report = _report()
        markdown = report_to_markdown(report)
        payload = json.loads(report_to_json(report))

        self.assertNotIn("Facts, Inferences, And Uncertainties", markdown)
        for item in [*report.facts, *report.inferences, *report.uncertainties]:
            self.assertNotIn(item, markdown)
        for field in ("facts", "inferences", "uncertainties"):
            self.assertEqual(payload[field], getattr(report, field))

    def test_sarif_junit_jsonl_and_github_formats_are_well_formed(self) -> None:
        report = _report()
        sarif = json.loads(report_to_sarif(report))
        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["automationDetails"]["id"], report.scan_id)
        self.assertFalse(sarif["runs"][0]["properties"]["resultsTruncated"])

        junit = ET.fromstring(report_to_junit(report))
        self.assertEqual(junit.tag, "testsuite")
        records = [json.loads(line) for line in report_to_jsonl(report).splitlines()]
        self.assertEqual(records[0]["record_type"], "scan")
        self.assertIn("tool", {record["record_type"] for record in records})

        annotations = report_to_github_annotations(report)
        self.assertNotIn("\n\n", annotations)

    def test_sarif_result_limit_is_explicitly_reported(self) -> None:
        with mock.patch.object(reporting, "MAX_SARIF_RESULTS", 0):
            sarif = json.loads(report_to_sarif(_report()))

        run = sarif["runs"][0]
        self.assertEqual(run["results"], [])
        self.assertTrue(run["properties"]["resultsTruncated"])
        self.assertGreater(run["properties"]["totalResultCount"], 0)


if __name__ == "__main__":
    unittest.main()

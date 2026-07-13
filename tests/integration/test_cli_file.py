from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class CliFileIntegrationTests(unittest.TestCase):
    def run_cli(self, args, **kwargs):
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "mcp_tool_card_linter", *args],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **kwargs,
        )

    def test_cli_writes_json_and_markdown_reports(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            json_path = Path(tmpdir) / "report.json"
            md_path = Path(tmpdir) / "report.md"
            result = self.run_cli(
                [
                    "lint",
                    "--tools-file",
                    "tests/fixtures/bad_tools.json",
                    "--json-report",
                    str(json_path),
                    "--markdown-report",
                    str(md_path),
                    "--fail-on",
                    "never",
                    "--format",
                    "none",
                ]
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = md_path.read_text(encoding="utf-8")

        self.assertEqual(payload["summary"]["tools_scanned"], 3)
        self.assertGreater(payload["summary"]["issues_by_severity"]["critical"], 0)
        self.assertIn("facts", payload)
        self.assertIn("inferences", payload)
        self.assertIn("uncertainties", payload)
        self.assertIn("MCP Tool Card Linter Report", markdown)
        self.assertIn("summarize_issue", markdown)
        self.assertNotIn("Facts, Inferences, And Uncertainties", markdown)

    def test_cli_writes_stable_sarif_junit_jsonl_and_deterministic_json(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            json_report = tmp / "report.json"
            sarif_report = tmp / "report.sarif"
            junit_report = tmp / "report.xml"
            jsonl_report = tmp / "report.jsonl"
            result = self.run_cli(
                [
                    "lint",
                    "--tools-file",
                    str(ROOT / "tests" / "fixtures" / "good_tools.json"),
                    "--json-report",
                    str(json_report),
                    "--sarif-report",
                    str(sarif_report),
                    "--junit-report",
                    str(junit_report),
                    "--jsonl-report",
                    str(jsonl_report),
                    "--deterministic",
                    "--fail-on",
                    "never",
                    "--format",
                    "none",
                ]
            )

            self.assertEqual(result.returncode, 0, result.stderr)
            payload = json.loads(json_report.read_text(encoding="utf-8"))
            self.assertEqual(payload["report_schema_version"], "1.0.0")
            self.assertTrue(payload["scan_id"].startswith("urn:sha256:"))
            self.assertEqual(
                json.loads(sarif_report.read_text(encoding="utf-8"))["version"],
                "2.1.0",
            )
            self.assertEqual(ET.parse(junit_report).getroot().tag, "testsuite")
            first_record = jsonl_report.read_text(encoding="utf-8").splitlines()[0]
            self.assertEqual(json.loads(first_record)["record_type"], "scan")

    def test_cli_lists_and_explains_stable_rules(self) -> None:
        listed = self.run_cli(["list-rules", "--format", "json"])
        explained = self.run_cli(
            ["explain", "MISSING_DESCRIPTION", "--format", "json"]
        )
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertEqual(explained.returncode, 0, explained.stderr)
        catalog = {item["id"]: item for item in json.loads(listed.stdout)}
        self.assertIn("MISSING_DESCRIPTION", catalog)
        self.assertEqual(catalog["MISSING_DESCRIPTION"]["default_severity"], "error")
        explanation = json.loads(explained.stdout)
        self.assertEqual(explanation["id"], "MISSING_DESCRIPTION")
        self.assertEqual(explanation["default_severity"], "error")

    def test_cli_fail_on_error_returns_one(self) -> None:
        result = self.run_cli(
            [
                "lint",
                "--tools-file",
                "tests/fixtures/bad_tools.json",
                "--fail-on",
                "error",
                "--format",
                "none",
            ]
        )
        self.assertEqual(result.returncode, 1, result.stderr)

    def test_cli_rejects_non_finite_timeout(self) -> None:
        result = self.run_cli(
            [
                "lint",
                "--tools-file",
                "tests/fixtures/good_tools.json",
                "--timeout",
                "nan",
            ]
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("finite", result.stderr)

    def test_cli_does_not_overwrite_input_with_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            source = Path(tmpdir) / "tools.json"
            original = json.dumps({"tools": []})
            source.write_text(original, encoding="utf-8")
            result = self.run_cli(
                [
                    "lint",
                    "--tools-file",
                    str(source),
                    "--json-report",
                    str(source),
                    "--format",
                    "none",
                ]
            )
            current = source.read_text(encoding="utf-8")

        self.assertEqual(result.returncode, 2)
        self.assertEqual(current, original)

    def test_config_command_is_not_executed_without_explicit_flag(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            marker = tmp / "executed"
            script = tmp / "side_effect.py"
            script.write_text(
                "from pathlib import Path\nPath(__file__).with_name('executed').write_text('bad')\n",
                encoding="utf-8",
            )
            config = tmp / "mcp.json"
            config.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "untrusted": {
                                "command": sys.executable,
                                "args": [str(script)],
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            report = tmp / "report.json"
            result = self.run_cli(
                [
                    "lint",
                    "--config",
                    str(config),
                    "--json-report",
                    str(report),
                    "--fail-on",
                    "never",
                    "--format",
                    "none",
                ]
            )
            payload = json.loads(report.read_text(encoding="utf-8"))
            marker_exists = marker.exists()

        self.assertEqual(result.returncode, 2)
        self.assertFalse(marker_exists)
        self.assertEqual(payload["summary"]["source_errors"], 1)

    def test_optimize_invalid_json_returns_controlled_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            invalid = Path(tmpdir) / "invalid.json"
            invalid.write_text("{not-json", encoding="utf-8")
            result = self.run_cli(["optimize", "--input-report", str(invalid)])

        self.assertEqual(result.returncode, 2)
        self.assertIn("Invalid JSON", result.stderr)
        self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()

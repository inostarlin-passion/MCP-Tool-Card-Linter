from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
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
        self.assertIn("MCP Tool Card Linter Report", markdown)
        self.assertIn("summarize_issue", markdown)

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


if __name__ == "__main__":
    unittest.main()


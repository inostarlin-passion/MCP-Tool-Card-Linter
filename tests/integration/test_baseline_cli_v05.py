from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class BaselineCliV05IntegrationTests(unittest.TestCase):
    def run_cli(self, args: list[str]) -> subprocess.CompletedProcess[str]:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "mcp_tool_card_linter", *args],
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=20,
            check=False,
        )

    def test_keygen_approve_verify_and_lint_signed_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            tools = tmp / "tools.json"
            report = tmp / "report.json"
            private_key = tmp / "baseline.key"
            public_key = tmp / "baseline.pub"
            baseline = tmp / "baseline.json"
            approval_log = tmp / "approvals.jsonl"
            current = tmp / "current.json"
            tools.write_text(
                (ROOT / "tests" / "fixtures" / "good_tools.json").read_text(
                    encoding="utf-8"
                ),
                encoding="utf-8",
            )
            lint = self.run_cli(
                [
                    "lint",
                    "--tools-file",
                    str(tools),
                    "--server",
                    "trusted",
                    "--json-report",
                    str(report),
                    "--deterministic",
                    "--fail-on",
                    "never",
                    "--format",
                    "none",
                ]
            )
            keygen = self.run_cli(
                [
                    "baseline",
                    "keygen",
                    "--private-key",
                    str(private_key),
                    "--public-key",
                    str(public_key),
                ]
            )
            approve = self.run_cli(
                [
                    "baseline",
                    "approve",
                    "--report",
                    str(report),
                    "--output",
                    str(baseline),
                    "--private-key",
                    str(private_key),
                    "--publisher",
                    "Example Publisher",
                    "--server-identity",
                    "example/tools@1",
                    "--approved-by",
                    "reviewer@example.test",
                    "--approval-log",
                    str(approval_log),
                ]
            )
            verify = self.run_cli(
                [
                    "baseline",
                    "verify",
                    "--baseline",
                    str(baseline),
                    "--public-key",
                    str(public_key),
                    "--approval-log",
                    str(approval_log),
                ]
            )
            compared = self.run_cli(
                [
                    "lint",
                    "--tools-file",
                    str(tools),
                    "--server",
                    "trusted",
                    "--baseline-report",
                    str(baseline),
                    "--baseline-public-key",
                    str(public_key),
                    "--require-signed-baseline",
                    "--expected-publisher",
                    "Example Publisher",
                    "--expected-server-identity",
                    "example/tools@1",
                    "--json-report",
                    str(current),
                    "--fail-on",
                    "error",
                    "--format",
                    "none",
                ]
            )

            self.assertEqual(lint.returncode, 0, lint.stderr)
            self.assertEqual(keygen.returncode, 0, keygen.stderr)
            self.assertEqual(approve.returncode, 0, approve.stderr)
            self.assertEqual(verify.returncode, 0, verify.stderr)
            self.assertEqual(compared.returncode, 0, compared.stderr)
            verification = json.loads(verify.stdout)
            payload = json.loads(current.read_text(encoding="utf-8"))

        self.assertTrue(verification["valid"])
        self.assertEqual(verification["approval_log"]["records"], 1)
        self.assertEqual(payload["summary"]["baseline"]["trust"]["trust_status"], "signed")
        self.assertEqual(payload["tools"][0]["baseline_status"], "unchanged")

    def test_require_signed_rejects_legacy_report(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            report = Path(tmpdir) / "report.json"
            lint = self.run_cli(
                [
                    "lint",
                    "--tools-file",
                    str(ROOT / "tests" / "fixtures" / "good_tools.json"),
                    "--json-report",
                    str(report),
                    "--fail-on",
                    "never",
                    "--format",
                    "none",
                ]
            )
            rejected = self.run_cli(
                [
                    "lint",
                    "--tools-file",
                    str(ROOT / "tests" / "fixtures" / "good_tools.json"),
                    "--baseline-report",
                    str(report),
                    "--require-signed-baseline",
                    "--format",
                    "none",
                ]
            )
        self.assertEqual(lint.returncode, 0, lint.stderr)
        self.assertEqual(rejected.returncode, 2)
        self.assertIn("Unsigned baseline rejected", rejected.stderr)


if __name__ == "__main__":
    unittest.main()

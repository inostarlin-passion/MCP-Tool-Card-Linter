from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class V05SecureWorkflowSystemTests(unittest.TestCase):
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

    def test_signed_rug_pull_diff_and_publisher_change_block_end_to_end(self) -> None:
        fixture = json.loads(
            (ROOT / "tests" / "fixtures" / "good_tools.json").read_text(
                encoding="utf-8"
            )
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            tools = tmp / "tools.json"
            approved_report = tmp / "approved-report.json"
            private_key = tmp / "baseline.key"
            public_key = tmp / "baseline.pub"
            baseline = tmp / "baseline.json"
            changed_report = tmp / "changed-report.json"
            publisher_report = tmp / "publisher-report.json"
            tools.write_text(json.dumps(fixture), encoding="utf-8")

            commands = [
                [
                    "lint",
                    "--tools-file",
                    str(tools),
                    "--server",
                    "trusted",
                    "--json-report",
                    str(approved_report),
                    "--fail-on",
                    "never",
                    "--format",
                    "none",
                ],
                [
                    "baseline",
                    "keygen",
                    "--private-key",
                    str(private_key),
                    "--public-key",
                    str(public_key),
                ],
            ]
            for command in commands:
                result = self.run_cli(command)
                self.assertEqual(result.returncode, 0, result.stderr)
            approved = self.run_cli(
                [
                    "baseline",
                    "approve",
                    "--report",
                    str(approved_report),
                    "--output",
                    str(baseline),
                    "--private-key",
                    str(private_key),
                    "--publisher",
                    "Example Publisher",
                    "--server-identity",
                    "example/tools@1",
                    "--approved-by",
                    "security-reviewer",
                ]
            )
            self.assertEqual(approved.returncode, 0, approved.stderr)

            fixture["tools"][0]["description"] += " Changed after approval."
            tools.write_text(json.dumps(fixture), encoding="utf-8")
            changed = self.run_cli(
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
                    "--expected-publisher",
                    "Example Publisher",
                    "--expected-server-identity",
                    "example/tools@1",
                    "--json-report",
                    str(changed_report),
                    "--fail-on",
                    "error",
                    "--format",
                    "none",
                ]
            )
            publisher_changed = self.run_cli(
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
                    "--expected-publisher",
                    "Different Publisher",
                    "--json-report",
                    str(publisher_report),
                    "--fail-on",
                    "error",
                    "--format",
                    "none",
                ]
            )
            changed_payload = json.loads(changed_report.read_text(encoding="utf-8"))
            publisher_payload = json.loads(
                publisher_report.read_text(encoding="utf-8")
            )

        self.assertEqual(changed.returncode, 1, changed.stderr)
        self.assertEqual(changed_payload["tools"][0]["baseline_status"], "changed")
        self.assertIn(
            "/description",
            changed_payload["tools"][0]["baseline_diff"]["changed"],
        )
        self.assertEqual(publisher_changed.returncode, 1, publisher_changed.stderr)
        self.assertEqual(
            publisher_payload["tools"][0]["baseline_status"],
            "publisher_changed",
        )
        self.assertEqual(
            publisher_payload["summary"]["baseline"]["trust"]["binding_status"],
            "publisher_changed",
        )

    def test_cli_local_execution_is_default_deny(self) -> None:
        command = subprocess.list2cmdline(
            [sys.executable, str(ROOT / "tests" / "fixtures" / "mock_mcp_stdio_server.py")]
        )
        if os.name != "nt":
            import shlex

            command = shlex.join(
                [
                    sys.executable,
                    str(ROOT / "tests" / "fixtures" / "mock_mcp_stdio_server.py"),
                ]
            )
        denied = self.run_cli(
            [
                "lint",
                "--stdio",
                command,
                "--fail-on",
                "never",
                "--format",
                "none",
            ]
        )
        self.assertEqual(denied.returncode, 2)
        self.assertIn("Local command execution is disabled", denied.stderr)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from mcp_tool_card_linter.contracts import CLI_EXIT_CODES

ROOT = Path(__file__).resolve().parents[2]


class V1ContractCliIntegrationTests(unittest.TestCase):
    def _run(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT / "src")
        return subprocess.run(
            [sys.executable, "-m", "mcp_tool_card_linter", *arguments],
            cwd=ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_contract_and_accuracy_cli_publish_stable_machine_results(self) -> None:
        contract = self._run("contract")
        self.assertEqual(contract.returncode, CLI_EXIT_CODES["success"], contract.stderr)
        payload = json.loads(contract.stdout)
        self.assertEqual(payload["contract_version"], "1.0.0")
        self.assertEqual(payload["cli"]["exit_codes"], CLI_EXIT_CODES)

        evaluation = self._run(
            "evaluate",
            "--corpus",
            "evaluation/rule_accuracy_v1.jsonl",
            "--min-precision",
            "0.95",
            "--min-recall",
            "0.95",
        )
        self.assertEqual(evaluation.returncode, 0, evaluation.stderr)
        result = json.loads(evaluation.stdout)
        self.assertTrue(result["passed"])
        self.assertEqual(result["failures"], [])

    def test_current_and_legacy_report_readers_remain_available(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            current_path = Path(directory) / "current.json"
            lint = self._run(
                "lint",
                "--tools-file",
                "examples/good-tools.json",
                "--json-report",
                str(current_path),
                "--deterministic",
                "--fail-on",
                "never",
                "--format",
                "none",
            )
            self.assertEqual(lint.returncode, 0, lint.stderr)
            current = self._run("validate-report", "--input", str(current_path))
            self.assertEqual(current.returncode, 0, current.stderr)
            self.assertEqual(json.loads(current.stdout)["report_schema_version"], "1.1.0")

            payload = json.loads(current_path.read_text(encoding="utf-8"))
            payload["report_schema_version"] = "1.0.0"
            payload["$schema"] = payload["$schema"].replace("v1.0.0", "v0.4.0")
            for tool in payload["tools"]:
                tool.pop("field_fingerprints")
                tool.pop("baseline_diff")
            legacy_path = Path(directory) / "legacy.json"
            legacy_path.write_text(json.dumps(payload), encoding="utf-8")
            legacy = self._run("validate-report", "--input", str(legacy_path))
            self.assertEqual(legacy.returncode, 0, legacy.stderr)
            self.assertEqual(json.loads(legacy.stdout)["report_schema_version"], "1.0.0")

    def test_lint_writes_verifiable_minimal_operational_audit_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            audit_path = Path(directory) / "audit.jsonl"
            lint = self._run(
                "lint",
                "--tools-file",
                "examples/good-tools.json",
                "--audit-log",
                str(audit_path),
                "--audit-actor",
                "ci:integration",
                "--deterministic",
                "--fail-on",
                "never",
                "--format",
                "none",
            )
            self.assertEqual(lint.returncode, 0, lint.stderr)
            verified = self._run("audit", "verify", "--log", str(audit_path))
            self.assertEqual(verified.returncode, 0, verified.stderr)
            self.assertEqual(json.loads(verified.stdout)["records"], 1)
            record_text = audit_path.read_text(encoding="utf-8")
            self.assertNotIn(str(ROOT), record_text)
            self.assertNotIn("inputSchema", record_text)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(audit_path.stat().st_mode), 0o600)

    def test_invalid_input_preserves_operational_error_exit_code(self) -> None:
        result = self._run("validate-report", "--input", "does-not-exist.json")
        self.assertEqual(
            result.returncode,
            CLI_EXIT_CODES["operational_or_input_error"],
        )


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class SecurityWorkflowSystemTests(unittest.TestCase):
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
            timeout=15,
        )

    def test_baseline_change_is_blocked_end_to_end(self) -> None:
        fixture = json.loads(
            (ROOT / "tests" / "fixtures" / "good_tools.json").read_text(
                encoding="utf-8"
            )
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            tools_path = tmp / "tools.json"
            baseline_path = tmp / "baseline.json"
            current_path = tmp / "current.json"
            optimized_path = tmp / "optimized.json"
            tools_path.write_text(json.dumps(fixture), encoding="utf-8")

            baseline = self.run_cli(
                [
                    "lint",
                    "--tools-file",
                    str(tools_path),
                    "--server",
                    "trusted",
                    "--json-report",
                    str(baseline_path),
                    "--fail-on",
                    "never",
                    "--format",
                    "none",
                ]
            )
            self.assertEqual(baseline.returncode, 0, baseline.stderr)

            fixture["tools"][0]["description"] += " Changed after approval."
            tools_path.write_text(json.dumps(fixture), encoding="utf-8")
            current = self.run_cli(
                [
                    "lint",
                    "--tools-file",
                    str(tools_path),
                    "--server",
                    "trusted",
                    "--baseline-report",
                    str(baseline_path),
                    "--json-report",
                    str(current_path),
                    "--fail-on",
                    "error",
                    "--format",
                    "none",
                ]
            )
            self.assertEqual(current.returncode, 1, current.stderr)

            optimize = self.run_cli(
                [
                    "optimize",
                    "--input-report",
                    str(current_path),
                    "--output",
                    str(optimized_path),
                ]
            )
            self.assertEqual(optimize.returncode, 0, optimize.stderr)
            current_payload = json.loads(current_path.read_text(encoding="utf-8"))
            optimized_payload = json.loads(optimized_path.read_text(encoding="utf-8"))

        self.assertEqual(current_payload["summary"]["baseline"]["changed"], 1)
        self.assertEqual(current_payload["tools"][0]["baseline_status"], "changed")
        self.assertEqual(
            optimized_payload["tools"][0]["decision"],
            "block_until_review",
        )

    def test_one_config_failure_does_not_hide_safe_server_results(self) -> None:
        good_tool = json.loads(
            (ROOT / "tests" / "fixtures" / "good_tools.json").read_text(
                encoding="utf-8"
            )
        )["tools"]
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            config = tmp / "mcp.json"
            report = tmp / "report.json"
            config.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "blocked-command": {
                                "command": "/unreviewed/server",
                                "args": [],
                            },
                            "safe-static": {"tools": good_tool},
                        }
                    }
                ),
                encoding="utf-8",
            )
            result = self.run_cli(
                [
                    "lint",
                    "--config",
                    str(config),
                    "--concurrency",
                    "2",
                    "--json-report",
                    str(report),
                    "--fail-on",
                    "never",
                    "--format",
                    "none",
                ]
            )
            payload = json.loads(report.read_text(encoding="utf-8"))

        self.assertEqual(result.returncode, 2)
        self.assertEqual(payload["summary"]["sources_scanned"], 2)
        self.assertEqual(payload["summary"]["source_errors"], 1)
        self.assertEqual(payload["summary"]["tools_scanned"], 1)
        self.assertEqual(
            [source["server_name"] for source in payload["sources"]],
            ["blocked-command", "safe-static"],
        )


if __name__ == "__main__":
    unittest.main()

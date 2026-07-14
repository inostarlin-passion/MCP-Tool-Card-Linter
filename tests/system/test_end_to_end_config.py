from __future__ import annotations

import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class EndToEndConfigTests(unittest.TestCase):
    def test_cli_stdio_command_uses_host_quoting_rules(self) -> None:
        environment = os.environ.copy()
        environment["PYTHONPATH"] = str(ROOT / "src")
        fixture = ROOT / "tests" / "fixtures" / "mock_mcp_stdio_server.py"
        server_command = [sys.executable, str(fixture)]
        command_text = (
            subprocess.list2cmdline(server_command)
            if os.name == "nt"
            else shlex.join(server_command)
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            report_path = Path(tmpdir) / "report.json"
            lint = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "mcp_tool_card_linter",
                    "lint",
                    "--stdio",
                    command_text,
                    "--executor",
                    "host",
                    "--json-report",
                    str(report_path),
                    "--fail-on",
                    "never",
                    "--format",
                    "none",
                ],
                cwd=ROOT,
                env=environment,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )
            self.assertEqual(lint.returncode, 0, lint.stderr)
            report = json.loads(report_path.read_text(encoding="utf-8"))

        self.assertEqual(report["summary"]["tools_scanned"], 2)

    def test_config_to_reports_and_optimizer(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src")
        fixture = ROOT / "tests" / "fixtures" / "mock_mcp_stdio_server.py"
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = Path(tmpdir)
            config_path = tmp / "mcp.json"
            report_path = tmp / "report.json"
            markdown_path = tmp / "report.md"
            optimized_path = tmp / "optimized.json"
            config_path.write_text(
                json.dumps(
                    {
                        "mcpServers": {
                            "mock": {
                                "command": sys.executable,
                                "args": [str(fixture)],
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )

            lint = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "mcp_tool_card_linter",
                    "lint",
                    "--config",
                    str(config_path),
                    "--allow-config-execution",
                    "--executor",
                    "host",
                    "--json-report",
                    str(report_path),
                    "--markdown-report",
                    str(markdown_path),
                    "--fail-on",
                    "never",
                    "--format",
                    "none",
                ],
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(lint.returncode, 0, lint.stderr)

            optimize = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "mcp_tool_card_linter",
                    "optimize",
                    "--input-report",
                    str(report_path),
                    "--output",
                    str(optimized_path),
                ],
                cwd=ROOT,
                env=env,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(optimize.returncode, 0, optimize.stderr)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            markdown = markdown_path.read_text(encoding="utf-8")
            optimized = json.loads(optimized_path.read_text(encoding="utf-8"))

        self.assertEqual(report["summary"]["tools_scanned"], 2)
        self.assertNotIn("Facts, Inferences, And Uncertainties", markdown)
        self.assertIn("delete_customer", report["summary"]["allowed_tools_recommendation"]["require_approval"])
        self.assertEqual(len(optimized["tools"]), 2)


if __name__ == "__main__":
    unittest.main()

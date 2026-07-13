from __future__ import annotations

import tempfile
import unittest
from datetime import date
from pathlib import Path

from mcp_tool_card_linter.models import Issue
from mcp_tool_card_linter.policy import PolicyError, load_policy


class PolicyTests(unittest.TestCase):
    def test_policy_applies_selection_override_and_audited_suppression(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(
                """
[tool.mcp-tool-card-linter]
profile = "production"
select = ["MISSING_*"]
ignore = ["MISSING_USAGE_BOUNDARY"]
fail-on = "warning"

[tool.mcp-tool-card-linter.rules.MISSING_DESCRIPTION]
severity = "critical"

[[tool.mcp-tool-card-linter.suppressions]]
server = "internal-*"
tool = "lookup_*"
rule = "MISSING_DESCRIPTION"
reason = "Tracked migration"
owner = "platform-security"
expires = 2099-01-01
""",
                encoding="utf-8",
            )
            policy = load_policy(path)

        issues = [
            Issue("MISSING_DESCRIPTION", "error", "missing", "description", "add it"),
            Issue("MISSING_USAGE_BOUNDARY", "warning", "boundary", "description", "add it"),
            Issue("GENERIC_TOOL_NAME", "warning", "generic", "name", "rename"),
        ]
        application = policy.apply(
            issues,
            server="internal-orders",
            tool="lookup_order",
            today=date(2026, 7, 13),
        )

        self.assertEqual(application.issues, [])
        self.assertEqual(application.suppressed[0]["rule"], "MISSING_DESCRIPTION")
        self.assertEqual(application.suppressed[0]["owner"], "platform-security")
        self.assertEqual(policy.fail_on, "warning")

    def test_expired_suppression_does_not_hide_finding(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.toml"
            path.write_text(
                """
[[suppressions]]
server = "*"
tool = "*"
rule = "MISSING_DESCRIPTION"
reason = "Temporary exception"
owner = "security"
expires = 2025-01-01
""",
                encoding="utf-8",
            )
            policy = load_policy(path)
        issue = Issue("MISSING_DESCRIPTION", "error", "missing", "description", "add")
        application = policy.apply(
            [issue], server="server", tool="tool", today=date(2026, 7, 13)
        )

        self.assertEqual(application.issues, [issue])
        self.assertEqual(application.expired[0]["expires"], "2025-01-01")

    def test_policy_rejects_unknown_rule_and_incomplete_suppression(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "bad.toml"
            path.write_text(
                """
[rules.NOT_A_REAL_RULE]
severity = "error"
""",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(PolicyError, "Unknown rule"):
                load_policy(path)


if __name__ == "__main__":
    unittest.main()

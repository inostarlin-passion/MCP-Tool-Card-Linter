from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from mcp_tool_card_linter.lint import lint_sources
from mcp_tool_card_linter.models import (
    BaselineAssessment,
    LintConfig,
    SourceResult,
    ToolCard,
)
from mcp_tool_card_linter.reporting import baseline_fingerprints_from_payload
from mcp_tool_card_linter.trust import (
    TrustError,
    append_approval_record,
    assess_baseline,
    canonical_json,
    create_baseline_bundle,
    generate_key_pair,
    verify_approval_log,
    verify_baseline_bundle,
)


def tool(description: str = "Look up a record. Use only for read-only retrieval."):
    return {
        "name": "lookup_record",
        "description": description,
        "annotations": {"readOnlyHint": True},
        "inputSchema": {
            "type": "object",
            "properties": {
                "record_id": {
                    "type": "string",
                    "description": "Stable record ID",
                    "maxLength": 64,
                }
            },
            "required": ["record_id"],
            "additionalProperties": False,
        },
    }


def report_and_source(raw_tool=None):
    source = SourceResult(
        server_name="trusted",
        source_type="tools-file",
        tools=[
            ToolCard.from_raw(
                raw_tool or tool(), server_name="trusted", index=0
            )
        ],
        metadata={"path": "/reviewed/tools.json"},
    )
    return lint_sources([source], LintConfig(), deterministic=True), source


class TrustV05Tests(unittest.TestCase):
    def test_rfc8785_canonicalization_is_order_independent(self) -> None:
        self.assertEqual(
            canonical_json({"z": 1, "a": [True, None]}),
            canonical_json({"a": [True, None], "z": 1}),
        )

    def test_signed_baseline_binds_report_publisher_and_source_identity(self) -> None:
        report, source = report_and_source()
        with tempfile.TemporaryDirectory() as tmpdir:
            private_key = Path(tmpdir) / "baseline.key"
            public_key = Path(tmpdir) / "baseline.pub"
            key_id = generate_key_pair(private_key, public_key)
            bundle = create_baseline_bundle(
                report.to_dict(),
                private_key_path=private_key,
                publisher="Example Publisher",
                server_identity="example/records-server@1",
                approved_by="reviewer@example.test",
                approved_at="2026-07-14T00:00:00+00:00",
            )
            schema = json.loads(
                (
                    ROOT
                    / "src"
                    / "mcp_tool_card_linter"
                    / "schemas"
                    / "baseline.schema.json"
                ).read_text(encoding="utf-8")
            )
            Draft202012Validator(
                schema, format_checker=FormatChecker()
            ).validate(bundle)
            verified = verify_baseline_bundle(bundle, public_key)

        self.assertEqual(verified.key_id, key_id)
        assessment = assess_baseline(
            verified,
            [source],
            expected_publisher="Example Publisher",
            expected_server_identity="example/records-server@1",
        )
        self.assertEqual(assessment.binding_status, "match")
        publisher_changed = assess_baseline(
            verified,
            [source],
            expected_publisher="Attacker Publisher",
        )
        self.assertEqual(publisher_changed.binding_status, "publisher_changed")
        identity_changed = SourceResult(
            server_name="trusted",
            source_type="tools-file",
            metadata={"path": "/different/tools.json"},
        )
        self.assertEqual(
            assess_baseline(verified, [identity_changed]).binding_status,
            "identity_changed",
        )

    def test_signature_and_unknown_field_tampering_are_rejected(self) -> None:
        report, _ = report_and_source()
        with tempfile.TemporaryDirectory() as tmpdir:
            private_key = Path(tmpdir) / "baseline.key"
            public_key = Path(tmpdir) / "baseline.pub"
            generate_key_pair(private_key, public_key)
            bundle = create_baseline_bundle(
                report.to_dict(),
                private_key_path=private_key,
                publisher="Example",
                server_identity="example/server",
                approved_by="reviewer",
            )
            tampered = json.loads(json.dumps(bundle))
            tampered["payload"]["report"]["tools"][0]["score"] = 0
            with self.assertRaisesRegex(TrustError, "signature verification failed"):
                verify_baseline_bundle(tampered, public_key)
            unknown = json.loads(json.dumps(bundle))
            unknown["unexpected"] = True
            with self.assertRaisesRegex(TrustError, "unknown top-level"):
                verify_baseline_bundle(unknown, public_key)

    def test_approval_log_is_private_signed_and_hash_chained(self) -> None:
        report, _ = report_and_source()
        with tempfile.TemporaryDirectory() as tmpdir:
            private_key = Path(tmpdir) / "baseline.key"
            public_key = Path(tmpdir) / "baseline.pub"
            log = Path(tmpdir) / "approvals.jsonl"
            generate_key_pair(private_key, public_key)
            bundle = create_baseline_bundle(
                report.to_dict(),
                private_key_path=private_key,
                publisher="Example",
                server_identity="example/server",
                approved_by="reviewer",
            )
            first = append_approval_record(log, bundle, private_key_path=private_key)
            second = append_approval_record(log, bundle, private_key_path=private_key)
            status = verify_approval_log(log, public_key)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(log.stat().st_mode), 0o600)
            lines = log.read_text(encoding="utf-8").splitlines()
            tampered = json.loads(lines[0])
            tampered["approver"] = "attacker"
            lines[0] = json.dumps(tampered, separators=(",", ":"))
            log.write_text("\n".join(lines) + "\n", encoding="utf-8")
            if os.name == "posix":
                os.chmod(log, 0o600)
            with self.assertRaises(TrustError):
                verify_approval_log(log, public_key)

        self.assertEqual(first["sequence"], 1)
        self.assertEqual(second["sequence"], 2)
        self.assertEqual(status["records"], 2)
        self.assertTrue(str(second["previous_hash"]).startswith("sha256:"))

    def test_field_level_hash_diff_names_paths_without_disclosing_values(self) -> None:
        baseline_report, _ = report_and_source()
        baseline = baseline_fingerprints_from_payload(baseline_report.to_dict())
        changed_description = "Private changed value that should not appear in diff paths."
        current_report, _ = report_and_source(tool(changed_description))
        current_source = SourceResult(
            server_name="trusted",
            source_type="tools-file",
            tools=[ToolCard.from_raw(tool(changed_description), server_name="trusted", index=0)],
            metadata={"path": "/reviewed/tools.json"},
        )
        compared = lint_sources(
            [current_source],
            LintConfig(),
            baseline_fingerprints=baseline,
            baseline_assessment=BaselineAssessment(
                trust_status="signed", binding_status="match"
            ),
        )
        diff = compared.tools[0].baseline_diff

        self.assertEqual(compared.tools[0].baseline_status, "changed")
        self.assertIn("/description", diff["changed"])
        self.assertNotIn(changed_description, json.dumps(diff))
        self.assertNotEqual(
            current_report.tools[0].card_fingerprint,
            baseline_report.tools[0].card_fingerprint,
        )

    def test_unchanged_unsigned_baseline_is_explicitly_untrusted(self) -> None:
        baseline_report, source = report_and_source()
        compared = lint_sources(
            [source],
            LintConfig(),
            baseline_fingerprints=baseline_fingerprints_from_payload(
                baseline_report.to_dict()
            ),
            baseline_assessment=BaselineAssessment(
                trust_status="untrusted", binding_status="not_checked"
            ),
        )
        self.assertEqual(compared.tools[0].baseline_status, "baseline_untrusted")
        self.assertIn(
            "BASELINE_SIGNATURE_MISSING",
            {issue.code for issue in compared.tools[0].issues},
        )


if __name__ == "__main__":
    unittest.main()

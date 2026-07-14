from __future__ import annotations

import ast
import json
import os
import stat
import tempfile
import unittest
from importlib.resources import files
from pathlib import Path

from jsonschema import Draft202012Validator, FormatChecker

from mcp_tool_card_linter.audit import AuditError, append_audit_event, verify_audit_log
from mcp_tool_card_linter.contracts import (
    CLI_EXIT_CODES,
    CURRENT_MCP_PROTOCOL_VERSION,
    CURRENT_REPORT_SCHEMA_VERSION,
    PREVIOUS_MCP_PROTOCOL_VERSION,
    SUPPORTED_REPORT_SCHEMA_VERSIONS,
    public_contract,
)
from mcp_tool_card_linter.evaluation import EvaluationError, evaluate_rule_corpus
from mcp_tool_card_linter.rules import KNOWN_RULE_IDS

ROOT = Path(__file__).resolve().parents[2]


class ContractsV1Tests(unittest.TestCase):
    def test_public_contract_freezes_schema_rules_protocols_and_exit_codes(self) -> None:
        contract = public_contract()
        self.assertEqual(contract["contract_version"], "1.0.0")
        self.assertEqual(contract["report_schemas"]["current"], CURRENT_REPORT_SCHEMA_VERSION)
        self.assertEqual(
            contract["report_schemas"]["readable"],
            list(SUPPORTED_REPORT_SCHEMA_VERSIONS),
        )
        self.assertEqual(contract["rule_catalog"]["ids"], list(KNOWN_RULE_IDS))
        self.assertEqual(
            contract["rule_catalog"]["ids_sha256"],
            "2a20572af70bd1ba8e5e6bae9b1df960332ab7f9b3e523c291c703e77049bcb8",
        )
        self.assertEqual(
            contract["cli"]["exit_codes"],
            CLI_EXIT_CODES,
        )
        self.assertEqual(contract["mcp_protocols"]["current"], CURRENT_MCP_PROTOCOL_VERSION)
        self.assertEqual(contract["mcp_protocols"]["previous"], PREVIOUS_MCP_PROTOCOL_VERSION)

    def test_literal_issue_codes_cannot_escape_the_stable_catalog(self) -> None:
        source = (ROOT / "src" / "mcp_tool_card_linter" / "lint.py").read_text(
            encoding="utf-8"
        )
        tree = ast.parse(source)
        literal_codes = {
            keyword.value.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and getattr(node.func, "id", None) == "Issue"
            for keyword in node.keywords
            if keyword.arg == "code"
            and isinstance(keyword.value, ast.Constant)
            and isinstance(keyword.value.value, str)
        }
        self.assertEqual(literal_codes - set(KNOWN_RULE_IDS), set())

    def test_accuracy_corpus_passes_declared_micro_precision_and_recall_gate(self) -> None:
        result = evaluate_rule_corpus(
            ROOT / "evaluation" / "rule_accuracy_v1.jsonl",
            min_precision=0.95,
            min_recall=0.95,
        )
        self.assertTrue(result["passed"])
        self.assertEqual(result["corpus"]["cases"], 12)
        self.assertEqual(result["metrics"]["precision"], 1.0)
        self.assertEqual(result["metrics"]["recall"], 1.0)
        self.assertEqual(result["scope"], "explicitly-labelled-rule-case-pairs")
        self.assertGreater(result["counts"]["true_negative"], 0)

    def test_accuracy_corpus_rejects_unknown_fields_rules_and_unbounded_rates(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jsonl"
            path.write_text(
                json.dumps(
                    {
                        "id": "bad",
                        "server_name": "test",
                        "tool": {},
                        "expected_rules": ["NOT_A_RULE"],
                        "forbidden_rules": [],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(EvaluationError, "unknown rules"):
                evaluate_rule_corpus(path)
            with self.assertRaisesRegex(EvaluationError, "0..1"):
                evaluate_rule_corpus(
                    ROOT / "evaluation" / "rule_accuracy_v1.jsonl",
                    min_precision=1.1,
                )

    def test_operational_audit_log_is_private_hash_chained_and_tamper_evident(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            first = append_audit_event(
                path,
                event="lint.completed",
                actor="ci:production",
                outcome="success",
                details={"scan_id": "urn:sha256:" + "a" * 64, "authenticated": True},
                recorded_at="2026-07-14T00:00:00+00:00",
            )
            second = append_audit_event(
                path,
                event="oauth.start",
                actor="ci:production",
                outcome="success",
                details={"proxy_configured": True},
                recorded_at="2026-07-14T00:00:01+00:00",
            )
            self.assertEqual(second["previous_hash"], first["record_hash"])
            schema = json.loads(
                files("mcp_tool_card_linter.schemas")
                .joinpath("audit.schema.json")
                .read_text(encoding="utf-8")
            )
            Draft202012Validator(schema, format_checker=FormatChecker()).validate(second)
            self.assertEqual(verify_audit_log(path)["records"], 2)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

            records = path.read_text(encoding="utf-8").splitlines()
            payload = json.loads(records[0])
            payload["outcome"] = "error"
            records[0] = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            path.write_text("\n".join(records) + "\n", encoding="utf-8")
            if os.name == "posix":
                path.chmod(0o600)
            with self.assertRaisesRegex(AuditError, "modified"):
                verify_audit_log(path)

    def test_operational_audit_rejects_secret_shaped_objects_and_concurrent_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "audit.jsonl"
            with self.assertRaisesRegex(AuditError, "not approved"):
                append_audit_event(
                    path,
                    event="lint.completed",
                    actor="operator",
                    outcome="success",
                    details={"nested": {"token": "secret"}},
                )
            lock = path.with_name(path.name + ".lock")
            lock.write_text("held", encoding="ascii")
            with self.assertRaisesRegex(AuditError, "another process"):
                append_audit_event(
                    path,
                    event="lint.completed",
                    actor="operator",
                    outcome="success",
                    details={},
                )


if __name__ == "__main__":
    unittest.main()

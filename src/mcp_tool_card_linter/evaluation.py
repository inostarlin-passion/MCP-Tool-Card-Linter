from __future__ import annotations

import hashlib
from collections import defaultdict
from pathlib import Path
from typing import Any

from .lint import lint_sources
from .models import LintConfig, SourceResult, ToolCard
from .rules import KNOWN_RULE_IDS
from .security import InputValidationError, safe_log_text, strict_json_loads

MAX_CORPUS_BYTES = 8 * 1024 * 1024
MAX_CORPUS_CASES = 10_000
MAX_CORPUS_LINE_BYTES = 1024 * 1024
_CASE_FIELDS = {"id", "server_name", "tool", "expected_rules", "forbidden_rules"}


class EvaluationError(ValueError):
    """Raised when an accuracy corpus or requested quality gate is invalid."""


def evaluate_rule_corpus(
    path: str | Path,
    *,
    min_precision: float = 0.0,
    min_recall: float = 0.0,
) -> dict[str, Any]:
    """Evaluate explicitly labelled rule/case pairs using micro metrics.

    Rules omitted from both expected_rules and forbidden_rules are deliberately
    unscored. This keeps the ground truth reviewable and avoids pretending a
    small synthetic corpus estimates real-world prevalence.
    """
    precision_gate = _rate("min_precision", min_precision)
    recall_gate = _rate("min_recall", min_recall)
    raw, cases = _load_corpus(path)
    counts = {"true_positive": 0, "false_positive": 0, "true_negative": 0, "false_negative": 0}
    per_rule: dict[str, dict[str, int]] = defaultdict(
        lambda: {
            "true_positive": 0,
            "false_positive": 0,
            "true_negative": 0,
            "false_negative": 0,
        }
    )
    failures: list[dict[str, Any]] = []
    for case in cases:
        tool = ToolCard.from_raw(
            case["tool"], server_name=case["server_name"], index=0
        )
        report = lint_sources(
            [SourceResult(case["server_name"], "accuracy-corpus", [tool])],
            LintConfig(),
            deterministic=True,
        )
        detected = {issue.code for issue in report.tools[0].issues}
        missing = sorted(set(case["expected_rules"]) - detected)
        unexpected = sorted(set(case["forbidden_rules"]) & detected)
        if missing or unexpected:
            failures.append(
                {"id": case["id"], "missing": missing, "unexpected": unexpected}
            )
        for rule_id in case["expected_rules"]:
            key = "true_positive" if rule_id in detected else "false_negative"
            counts[key] += 1
            per_rule[rule_id][key] += 1
        for rule_id in case["forbidden_rules"]:
            key = "false_positive" if rule_id in detected else "true_negative"
            counts[key] += 1
            per_rule[rule_id][key] += 1

    positive_predictions = counts["true_positive"] + counts["false_positive"]
    positive_labels = counts["true_positive"] + counts["false_negative"]
    precision = (
        counts["true_positive"] / positive_predictions if positive_predictions else 1.0
    )
    recall = counts["true_positive"] / positive_labels if positive_labels else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    passed = precision >= precision_gate and recall >= recall_gate and not failures
    return {
        "evaluation_schema_version": "1.0.0",
        "scope": "explicitly-labelled-rule-case-pairs",
        "corpus": {
            "path": str(Path(path).expanduser().resolve()),
            "sha256": hashlib.sha256(raw).hexdigest(),
            "cases": len(cases),
            "labelled_pairs": sum(counts.values()),
        },
        "counts": counts,
        "metrics": {
            "precision": round(precision, 6),
            "recall": round(recall, 6),
            "f1": round(f1, 6),
        },
        "thresholds": {
            "min_precision": precision_gate,
            "min_recall": recall_gate,
        },
        "per_rule": {key: per_rule[key] for key in sorted(per_rule)},
        "failures": failures,
        "passed": passed,
        "limitations": [
            "Unlabelled rule/case pairs are excluded from all metrics.",
            "Synthetic-corpus prevalence is not an estimate of production prevalence.",
            "Static metadata findings do not prove runtime server behaviour.",
        ],
    }


def _load_corpus(path: str | Path) -> tuple[bytes, list[dict[str, Any]]]:
    try:
        resolved = Path(path).expanduser().resolve()
        with resolved.open("rb") as stream:
            raw = stream.read(MAX_CORPUS_BYTES + 1)
    except OSError as exc:
        raise EvaluationError(f"Failed to read accuracy corpus: {safe_log_text(exc)}") from exc
    if len(raw) > MAX_CORPUS_BYTES:
        raise EvaluationError(f"Accuracy corpus exceeds {MAX_CORPUS_BYTES} bytes")
    cases: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    known_rules = set(KNOWN_RULE_IDS)
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            raise EvaluationError(f"Accuracy corpus contains a blank line at {line_number}")
        if len(line) > MAX_CORPUS_LINE_BYTES:
            raise EvaluationError(f"Accuracy corpus line {line_number} is too large")
        if len(cases) >= MAX_CORPUS_CASES:
            raise EvaluationError(f"Accuracy corpus exceeds {MAX_CORPUS_CASES} cases")
        try:
            payload = strict_json_loads(line.decode("utf-8"))
        except (UnicodeDecodeError, InputValidationError) as exc:
            raise EvaluationError(
                f"Accuracy corpus line {line_number} is invalid: {safe_log_text(exc)}"
            ) from exc
        if not isinstance(payload, dict) or set(payload) != _CASE_FIELDS:
            raise EvaluationError(
                f"Accuracy corpus line {line_number} has missing or unknown fields"
            )
        case_id = payload.get("id")
        server_name = payload.get("server_name")
        tool = payload.get("tool")
        if not isinstance(case_id, str) or not 1 <= len(case_id) <= 256:
            raise EvaluationError(f"Accuracy corpus line {line_number} has an invalid id")
        if case_id in seen_ids:
            raise EvaluationError(f"Accuracy corpus contains duplicate id {safe_log_text(case_id)}")
        if not isinstance(server_name, str) or not 1 <= len(server_name) <= 256:
            raise EvaluationError(
                f"Accuracy corpus line {line_number} has an invalid server_name"
            )
        if not isinstance(tool, dict):
            raise EvaluationError(f"Accuracy corpus line {line_number} tool must be an object")
        expected = _rule_list(payload.get("expected_rules"), line_number, "expected_rules")
        forbidden = _rule_list(payload.get("forbidden_rules"), line_number, "forbidden_rules")
        unknown = (set(expected) | set(forbidden)) - known_rules
        if unknown:
            raise EvaluationError(
                f"Accuracy corpus line {line_number} uses unknown rules: "
                + ", ".join(sorted(unknown))
            )
        if set(expected) & set(forbidden):
            raise EvaluationError(
                f"Accuracy corpus line {line_number} labels a rule both expected and forbidden"
            )
        if not expected and not forbidden:
            raise EvaluationError(f"Accuracy corpus line {line_number} has no labelled pairs")
        seen_ids.add(case_id)
        cases.append(
            {
                "id": case_id,
                "server_name": server_name,
                "tool": tool,
                "expected_rules": expected,
                "forbidden_rules": forbidden,
            }
        )
    if not cases:
        raise EvaluationError("Accuracy corpus is empty")
    return raw, cases


def _rule_list(value: Any, line: int, field: str) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > len(KNOWN_RULE_IDS)
        or not all(isinstance(item, str) for item in value)
        or len(set(value)) != len(value)
    ):
        raise EvaluationError(f"Accuracy corpus line {line} {field} is invalid")
    return value


def _rate(name: str, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise EvaluationError(f"{name} must be a number")
    result = float(value)
    if not 0.0 <= result <= 1.0:
        raise EvaluationError(f"{name} must be in 0..1")
    return result

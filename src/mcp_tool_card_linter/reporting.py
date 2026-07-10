from __future__ import annotations

import html
import json
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Any

from .models import MAX_LINT_TOOLS, LintReport, SEVERITY_ORDER
from .security import safe_log_text

_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}\Z")


class ReportError(ValueError):
    """Raised when a report is malformed or unsafe to process."""


def report_to_json(report: LintReport) -> str:
    return json.dumps(
        report.to_dict(),
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    )


def write_json_report(report: LintReport, path: str | Path) -> None:
    _write_text(path, report_to_json(report) + "\n")


def write_markdown_report(report: LintReport, path: str | Path) -> None:
    _write_text(path, report_to_markdown(report))


def write_optimization_report(payload: dict[str, Any], path: str | Path) -> None:
    _write_text(
        path,
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
            allow_nan=False,
        )
        + "\n",
    )


def report_to_markdown(report: LintReport) -> str:
    data = report.to_dict()
    summary = data["summary"]
    lines = [
        "# MCP Tool Card Linter Report",
        "",
        f"- Generated: `{data['generated_at']}`",
        f"- Linter version: `{data['version']}`",
        f"- Sources scanned: `{summary['sources_scanned']}`",
        f"- Tools scanned: `{summary['tools_scanned']}`",
        f"- Average score: `{summary['score']}/100`",
        f"- Source errors: `{summary['source_errors']}`",
        "",
        "## Issue Summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity in ("critical", "error", "warning", "info"):
        lines.append(f"| {severity} | {summary['issues_by_severity'][severity]} |")

    lines.extend(
        [
            "",
            "## Risk Summary",
            "",
            "| Risk | Tool count |",
            "| --- | ---: |",
        ]
    )
    for risk in ("critical", "high", "medium", "low"):
        lines.append(f"| {risk} | {summary['risk_counts'][risk]} |")

    baseline = summary.get("baseline", {})
    if baseline.get("checked"):
        lines.extend(
            [
                "",
                "## Baseline Integrity",
                "",
                f"- Unchanged: `{baseline.get('unchanged', 0)}`",
                f"- Changed: `{baseline.get('changed', 0)}`",
                f"- New: `{baseline.get('new', 0)}`",
                f"- Missing: `{baseline.get('missing', 0)}`",
            ]
        )

    recommendation = summary["allowed_tools_recommendation"]
    lines.extend(
        [
            "",
            "## Allowed Tools Recommendation",
            "",
            f"- Include by default: {_code(', '.join(recommendation['include_by_default']) or 'none')}",
            f"- Require approval: {_code(', '.join(recommendation['require_approval']) or 'none')}",
            f"- Block until review: {_code(', '.join(recommendation['block_until_review']) or 'none')}",
            "",
            "## Sources",
            "",
            "| Server | Type | Tools | Errors |",
            "| --- | --- | ---: | --- |",
        ]
    )
    for source in data["sources"]:
        errors = "; ".join(_escape(error) for error in source["errors"]) if source["errors"] else ""
        lines.append(
            f"| {_escape(source['server_name'])} | {_escape(source['source_type'])} | "
            f"{source['tools_linted']} | {errors} |"
        )

    lines.extend(["", "## Tool Findings", ""])
    for tool in sorted(
        data["tools"],
        key=lambda item: (
            _worst_severity_order(item["issues"]),
            -len(item["issues"]),
            item["server_name"],
            item["tool_name"],
        ),
        reverse=True,
    ):
        lines.extend(
            [
                f"### {_code(tool['server_name'])} / {_code(tool['tool_name'])}",
                "",
                f"- Score: `{tool['score']}/100`",
                f"- Risk: `{tool['risk_level']}`",
                f"- Categories: `{', '.join(tool['risk_categories']) or 'none'}`",
                f"- Estimated card size: `{tool['estimated_card_chars']}` chars",
                f"- Fingerprint: {_code(tool['card_fingerprint'])}",
                f"- Baseline status: `{tool['baseline_status']}`",
                "",
            ]
        )
        if tool["issues"]:
            lines.extend(["| Severity | Code | Path | Finding | Recommendation |", "| --- | --- | --- | --- | --- |"])
            for issue in tool["issues"]:
                evidence = f" Evidence: {_code(issue['evidence'])}" if issue.get("evidence") else ""
                lines.append(
                    f"| {issue['severity']} | {_code(issue['code'])} | {_code(issue['path'])} | "
                    f"{_escape(issue['message'])}{evidence} | {_escape(issue['recommendation'])} |"
                )
            lines.append("")
        else:
            lines.extend(["No findings.", ""])
        lines.extend(["Recommendations:", ""])
        for item in tool["recommendations"]:
            lines.append(f"- {_escape(item)}")
        lines.append("")

    lines.extend(
        [
            "## Facts, Inferences, And Uncertainties",
            "",
            "Facts:",
            "",
        ]
    )
    for fact in data["facts"]:
        lines.append(f"- {_escape(fact)}")
    lines.extend(["", "Inferences:", ""])
    for inference in data["inferences"]:
        lines.append(f"- {_escape(inference)}")
    lines.extend(["", "Uncertainties:", ""])
    for uncertainty in data["uncertainties"]:
        lines.append(f"- {_escape(uncertainty)}")
    lines.append("")
    return "\n".join(lines)


def exit_code_for_report(report: LintReport, fail_on: str) -> int:
    if report.summary.get("source_errors", 0) > 0:
        return 2
    if fail_on == "never":
        return 0
    if fail_on not in SEVERITY_ORDER:
        raise ReportError(f"Unknown fail-on severity: {safe_log_text(fail_on)}")
    threshold = SEVERITY_ORDER[fail_on]  # type: ignore[index]
    for tool in report.tools:
        for issue in tool.issues:
            if SEVERITY_ORDER[issue.severity] >= threshold:
                return 1
    return 0


def optimize_from_report(report_payload: dict[str, Any]) -> dict[str, Any]:
    _validate_report_root(report_payload)
    tools = []
    for index, tool in enumerate(report_payload["tools"]):
        if not isinstance(tool, dict):
            raise ReportError(f"Report tools[{index}] must be an object")
        tool_name = tool.get("tool_name", "")
        if not isinstance(tool_name, str) or not tool_name:
            raise ReportError(f"Report tools[{index}].tool_name must be a non-empty string")
        server_name = tool.get("server_name")
        if not isinstance(server_name, str) or not server_name:
            raise ReportError(f"Report tools[{index}].server_name must be a non-empty string")
        tool_name = safe_log_text(tool_name, limit=512)
        server_name = safe_log_text(server_name, limit=512)
        risk = tool.get("risk_level", "low")
        if risk not in {"low", "medium", "high", "critical"}:
            raise ReportError(f"Report tools[{index}].risk_level is invalid")
        raw_issues = tool.get("issues", [])
        if not isinstance(raw_issues, list):
            raise ReportError(f"Report tools[{index}].issues must be an array")
        if any(
            not isinstance(issue, dict) or not isinstance(issue.get("code"), str)
            for issue in raw_issues
        ):
            raise ReportError(
                f"Report tools[{index}].issues entries must be objects with string codes"
            )
        recommendations = tool.get("recommendations", [])
        if not isinstance(recommendations, list) or not all(
            isinstance(item, str) for item in recommendations
        ):
            raise ReportError(f"Report tools[{index}].recommendations must be a string array")
        recommendations = [safe_log_text(item, limit=10_000) for item in recommendations]
        score = tool.get("score")
        if (
            isinstance(score, bool)
            or not isinstance(score, (int, float))
            or not 0 <= score <= 100
        ):
            raise ReportError(f"Report tools[{index}].score must be in 0..100")
        issue_codes = {
            issue.get("code")
            for issue in raw_issues
        }
        fingerprint = tool.get("card_fingerprint")
        if fingerprint is not None and (
            not isinstance(fingerprint, str)
            or not _FINGERPRINT.fullmatch(fingerprint)
        ):
            raise ReportError(f"Report tools[{index}].card_fingerprint is invalid")
        baseline_status = tool.get("baseline_status", "not_checked")
        if baseline_status not in {"not_checked", "new", "unchanged", "changed"}:
            raise ReportError(f"Report tools[{index}].baseline_status is invalid")
        decision = "include_by_default"
        if risk == "critical" or any(
            code and str(code).startswith("TOOL_POISONING") for code in issue_codes
        ) or "TOOL_CARD_CHANGED" in issue_codes:
            decision = "block_until_review"
        elif risk in {"medium", "high"}:
            decision = "require_approval"
        tools.append(
            {
                "server_name": server_name,
                "tool_name": tool_name,
                "decision": decision,
                "score": score,
                "risk_level": risk,
                "card_fingerprint": fingerprint,
                "baseline_status": baseline_status,
                "suggested_actions": recommendations,
            }
        )
    return {
        "version": safe_log_text(report_payload.get("version", "unknown")),
        "generated_from": safe_log_text(
            report_payload.get("generated_at", "unknown"),
            limit=1000,
        ),
        "tools": tools,
    }


def baseline_fingerprints_from_payload(
    report_payload: dict[str, Any],
) -> dict[tuple[str, str], str]:
    """Extract and validate a trusted tool-card fingerprint baseline."""
    _validate_report_root(report_payload)
    fingerprints: dict[tuple[str, str], str] = {}
    for index, tool in enumerate(report_payload["tools"]):
        if not isinstance(tool, dict):
            raise ReportError(f"Baseline tools[{index}] must be an object")
        server_name = tool.get("server_name")
        tool_name = tool.get("tool_name")
        fingerprint = tool.get("card_fingerprint")
        if not isinstance(server_name, str) or not server_name:
            raise ReportError(f"Baseline tools[{index}].server_name is invalid")
        if not isinstance(tool_name, str) or not tool_name:
            raise ReportError(f"Baseline tools[{index}].tool_name is invalid")
        if not isinstance(fingerprint, str) or not _FINGERPRINT.fullmatch(fingerprint):
            raise ReportError(f"Baseline tools[{index}].card_fingerprint is invalid or missing")
        identity = (
            safe_log_text(server_name, limit=512),
            safe_log_text(tool_name, limit=512),
        )
        if identity in fingerprints:
            raise ReportError(
                f"Baseline contains duplicate tool identity {safe_log_text(server_name)}/{safe_log_text(tool_name)}"
            )
        fingerprints[identity] = fingerprint
    return fingerprints


def _write_text(path: str | Path, text: str) -> None:
    try:
        resolved = Path(path).expanduser().resolve()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise ReportError(f"Invalid report path: {safe_log_text(exc)}") from exc
    resolved.parent.mkdir(parents=True, exist_ok=True)
    if resolved.exists() and not resolved.is_file():
        raise OSError(f"Report path is not a regular file: {resolved}")
    mode = stat.S_IMODE(resolved.stat().st_mode) if resolved.exists() else 0o600
    descriptor, temporary_name = tempfile.mkstemp(
        dir=resolved.parent,
        prefix=f".{resolved.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    descriptor_open = True
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            descriptor_open = False
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, resolved)
    finally:
        if descriptor_open:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _worst_severity_order(issues: list[dict[str, Any]]) -> int:
    if not issues:
        return 0
    return max(SEVERITY_ORDER.get(issue.get("severity", "info"), 0) for issue in issues)


def _escape(value: Any) -> str:
    text = safe_log_text(value, limit=10_000)
    return (
        html.escape(text, quote=True)
        .replace("`", "&#96;")
        .replace("|", "\\|")
    )


def _code(value: Any) -> str:
    return f"`{_escape(value)}`"


def _validate_report_root(report_payload: Any) -> None:
    if not isinstance(report_payload, dict):
        raise ReportError("Report root must be an object")
    tools = report_payload.get("tools")
    if not isinstance(tools, list):
        raise ReportError("Report tools must be an array")
    if len(tools) > MAX_LINT_TOOLS:
        raise ReportError(f"Report has more than {MAX_LINT_TOOLS} tools")

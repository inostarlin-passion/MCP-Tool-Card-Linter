from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import LintReport, SEVERITY_ORDER


def report_to_json(report: LintReport) -> str:
    return json.dumps(report.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)


def write_json_report(report: LintReport, path: str | Path) -> None:
    _write_text(path, report_to_json(report) + "\n")


def write_markdown_report(report: LintReport, path: str | Path) -> None:
    _write_text(path, report_to_markdown(report))


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

    recommendation = summary["allowed_tools_recommendation"]
    lines.extend(
        [
            "",
            "## Allowed Tools Recommendation",
            "",
            f"- Include by default: `{', '.join(recommendation['include_by_default']) or 'none'}`",
            f"- Require approval: `{', '.join(recommendation['require_approval']) or 'none'}`",
            f"- Block until review: `{', '.join(recommendation['block_until_review']) or 'none'}`",
            "",
            "## Sources",
            "",
            "| Server | Type | Tools | Errors |",
            "| --- | --- | ---: | --- |",
        ]
    )
    for source in data["sources"]:
        errors = "; ".join(source["errors"]) if source["errors"] else ""
        lines.append(
            f"| {source['server_name']} | {source['source_type']} | "
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
                f"### `{tool['server_name']}` / `{tool['tool_name']}`",
                "",
                f"- Score: `{tool['score']}/100`",
                f"- Risk: `{tool['risk_level']}`",
                f"- Categories: `{', '.join(tool['risk_categories']) or 'none'}`",
                f"- Estimated card size: `{tool['estimated_card_chars']}` chars",
                "",
            ]
        )
        if tool["issues"]:
            lines.extend(["| Severity | Code | Path | Finding | Recommendation |", "| --- | --- | --- | --- | --- |"])
            for issue in tool["issues"]:
                evidence = f" Evidence: `{_escape(issue['evidence'])}`" if issue.get("evidence") else ""
                lines.append(
                    f"| {issue['severity']} | `{issue['code']}` | `{_escape(issue['path'])}` | "
                    f"{_escape(issue['message'])}{evidence} | {_escape(issue['recommendation'])} |"
                )
            lines.append("")
        else:
            lines.extend(["No findings.", ""])
        lines.extend(["Recommendations:", ""])
        for item in tool["recommendations"]:
            lines.append(f"- {item}")
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
        lines.append(f"- {fact}")
    lines.extend(["", "Inferences:", ""])
    for inference in data["inferences"]:
        lines.append(f"- {inference}")
    lines.extend(["", "Uncertainties:", ""])
    for uncertainty in data["uncertainties"]:
        lines.append(f"- {uncertainty}")
    lines.append("")
    return "\n".join(lines)


def exit_code_for_report(report: LintReport, fail_on: str) -> int:
    if fail_on == "never":
        return 0
    threshold = SEVERITY_ORDER[fail_on]  # type: ignore[index]
    if report.summary.get("source_errors", 0) > 0:
        return 2
    for tool in report.tools:
        for issue in tool.issues:
            if SEVERITY_ORDER[issue.severity] >= threshold:
                return 1
    return 0


def optimize_from_report(report_payload: dict[str, Any]) -> dict[str, Any]:
    tools = []
    for tool in report_payload.get("tools", []):
        tool_name = tool.get("tool_name", "")
        risk = tool.get("risk_level", "low")
        issue_codes = {issue.get("code") for issue in tool.get("issues", [])}
        decision = "include_by_default"
        if risk == "critical" or any(
            code and str(code).startswith("TOOL_POISONING") for code in issue_codes
        ):
            decision = "block_until_review"
        elif risk in {"medium", "high"}:
            decision = "require_approval"
        tools.append(
            {
                "server_name": tool.get("server_name"),
                "tool_name": tool_name,
                "decision": decision,
                "score": tool.get("score"),
                "risk_level": risk,
                "suggested_actions": tool.get("recommendations", []),
            }
        )
    return {
        "version": report_payload.get("version"),
        "generated_from": report_payload.get("generated_at"),
        "tools": tools,
    }


def _write_text(path: str | Path, text: str) -> None:
    resolved = Path(path).expanduser().resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(text, encoding="utf-8")


def _worst_severity_order(issues: list[dict[str, Any]]) -> int:
    if not issues:
        return 0
    return max(SEVERITY_ORDER.get(issue.get("severity", "info"), 0) for issue in issues)


def _escape(value: Any) -> str:
    text = str(value)
    return text.replace("|", "\\|").replace("\n", " ")


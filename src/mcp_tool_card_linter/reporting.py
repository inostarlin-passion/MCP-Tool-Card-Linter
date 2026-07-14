from __future__ import annotations

import html
import hashlib
import json
import os
import re
import stat
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .models import BaselineEntry, MAX_LINT_TOOLS, LintReport, SEVERITY_ORDER
from .rules import rule_metadata
from .security import safe_log_text

_FINGERPRINT = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_SARIF_RESULTS = 25_000


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


def write_sarif_report(report: LintReport, path: str | Path) -> None:
    _write_text(path, report_to_sarif(report) + "\n")


def write_junit_report(report: LintReport, path: str | Path) -> None:
    _write_text(path, report_to_junit(report))


def write_jsonl_report(report: LintReport, path: str | Path) -> None:
    _write_text(path, report_to_jsonl(report))


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
        f"- Report schema: `{data['report_schema_version']}`",
        f"- Scan ID: `{data['scan_id']}`",
        f"- Generated: `{data['generated_at']}`",
        f"- Linter version: `{data['tool_version']}`",
        f"- Policy profile: `{data['policy'].get('profile', 'production')}`",
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
                f"- Identity changed: `{baseline.get('identity_changed', 0)}`",
                f"- Publisher changed: `{baseline.get('publisher_changed', 0)}`",
                f"- Untrusted legacy matches: `{baseline.get('untrusted', 0)}`",
                f"- Trust status: `{baseline.get('trust', {}).get('trust_status', 'not_checked')}`",
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
        diff = tool.get("baseline_diff", {})
        diff_paths = [
            *diff.get("added", []),
            *diff.get("removed", []),
            *diff.get("changed", []),
        ]
        if diff_paths:
            lines.extend(
                [
                    f"- Changed fields: {_code(', '.join(diff_paths))}",
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

    return "\n".join(lines)


def report_to_sarif(report: LintReport) -> str:
    data = report.to_dict()
    observed: dict[str, str] = {}
    results: list[dict[str, Any]] = []
    total_results = 0
    source_paths = _source_paths(data["sources"])
    for tool in data["tools"]:
        for issue in tool["issues"]:
            total_results += 1
            if len(results) >= MAX_SARIF_RESULTS:
                continue
            rule_id = issue["code"]
            observed.setdefault(rule_id, issue["severity"])
            identity = (
                f"{tool['server_name']}\0{tool['tool_name']}\0{rule_id}\0{issue['path']}"
            )
            result: dict[str, Any] = {
                "ruleId": rule_id,
                "level": _sarif_level(issue["severity"]),
                "message": {
                    "text": f"{issue['message']} Remediation: {issue['recommendation']}"
                },
                "partialFingerprints": {
                    "primaryLocationLineHash": hashlib.sha256(
                        identity.encode("utf-8")
                    ).hexdigest()
                },
                "properties": {
                    "serverName": tool["server_name"],
                    "toolName": tool["tool_name"],
                    "path": issue["path"],
                    "jsonPointer": issue["json_pointer"],
                    "confidence": issue["rule"]["confidence"],
                    "category": issue["rule"]["category"],
                },
            }
            source_path = source_paths.get(tool["server_name"])
            if source_path is not None:
                result["locations"] = [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": source_path.as_uri()}
                        },
                        "logicalLocations": [
                            {
                                "fullyQualifiedName": (
                                    f"{tool['server_name']}/{tool['tool_name']}"
                                    f"{issue['json_pointer']}"
                                )
                            }
                        ],
                    }
                ]
            results.append(result)
    rules = []
    for rule_id, severity in sorted(observed.items()):
        metadata = rule_metadata(rule_id, severity)
        rules.append(
            {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": metadata.title},
                "helpUri": metadata.references[0] if metadata.references else "",
                "properties": {
                    "defaultSeverity": metadata.default_severity,
                    "confidence": metadata.confidence,
                    "category": metadata.category,
                    "tags": [metadata.category, *metadata.cwe],
                },
            }
        )
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCP Tool Card Linter",
                        "semanticVersion": data["tool_version"],
                        "informationUri": (
                            "https://github.com/inostarlin-passion/MCP-Tool-Card-Linter"
                        ),
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": data["scan_id"]},
                "properties": {
                    "resultsTruncated": total_results > MAX_SARIF_RESULTS,
                    "totalResultCount": total_results,
                    "emittedResultCount": len(results),
                },
                "results": results,
            }
        ],
    }
    return json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)


def report_to_junit(report: LintReport) -> str:
    data = report.to_dict()
    suite = ET.Element(
        "testsuite",
        {
            "name": "mcp-tool-card-linter",
            "tests": str(len(data["tools"]) + len(data["sources"])),
            "failures": str(sum(bool(tool["issues"]) for tool in data["tools"])),
            "errors": str(sum(bool(source["errors"]) for source in data["sources"])),
            "timestamp": data["generated_at"],
        },
    )
    properties = ET.SubElement(suite, "properties")
    for name, value in (
        ("report_schema_version", data["report_schema_version"]),
        ("scan_id", data["scan_id"]),
        ("tool_version", data["tool_version"]),
        ("policy_profile", data["policy"].get("profile", "production")),
    ):
        ET.SubElement(properties, "property", {"name": name, "value": str(value)})
    for source in data["sources"]:
        case = ET.SubElement(
            suite,
            "testcase",
            {"classname": "source", "name": source["server_name"]},
        )
        if source["errors"]:
            error = ET.SubElement(case, "error", {"type": "discovery"})
            error.text = "\n".join(source["errors"])
    for tool in data["tools"]:
        case = ET.SubElement(
            suite,
            "testcase",
            {"classname": tool["server_name"], "name": tool["tool_name"]},
        )
        if tool["issues"]:
            failure = ET.SubElement(
                case,
                "failure",
                {
                    "type": "lint",
                    "message": f"{len(tool['issues'])} finding(s)",
                },
            )
            failure.text = "\n".join(
                f"[{issue['severity']}] {issue['code']} {issue['path']}: "
                f"{issue['message']}"
                for issue in tool["issues"]
            )
    ET.indent(suite, space="  ")
    return ET.tostring(suite, encoding="unicode", xml_declaration=True) + "\n"


def report_to_jsonl(report: LintReport) -> str:
    data = report.to_dict()
    records: list[dict[str, Any]] = [
        {
            "record_type": "scan",
            "report_schema_version": data["report_schema_version"],
            "scan_id": data["scan_id"],
            "generated_at": data["generated_at"],
            "tool_version": data["tool_version"],
            "policy": data["policy"],
            "summary": data["summary"],
        }
    ]
    records.extend({"record_type": "source", **source} for source in data["sources"])
    records.extend({"record_type": "tool", **tool} for tool in data["tools"])
    return "".join(
        json.dumps(record, ensure_ascii=False, sort_keys=True, allow_nan=False) + "\n"
        for record in records
    )


def report_to_github_annotations(report: LintReport) -> str:
    lines: list[str] = []
    for tool in report.to_dict()["tools"]:
        for issue in tool["issues"]:
            command = "error" if issue["severity"] in {"critical", "error"} else "warning"
            title = _github_escape_property(f"{issue['code']} ({tool['tool_name']})")
            message = _github_escape_data(issue["message"])
            lines.append(f"::{command} title={title}::{message}")
    return "\n".join(lines) + ("\n" if lines else "")


def exit_code_for_report(report: LintReport, fail_on: str) -> int:
    if report.summary.get("source_errors", 0) > 0:
        return 2
    if fail_on == "never":
        return 0
    if fail_on not in SEVERITY_ORDER:
        raise ReportError(f"Unknown fail-on severity: {safe_log_text(fail_on)}")
    threshold = SEVERITY_ORDER[fail_on]  # mypy narrows after the membership check.
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
        if baseline_status not in {
            "not_checked",
            "new",
            "unchanged",
            "changed",
            "identity_changed",
            "publisher_changed",
            "baseline_untrusted",
        }:
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
) -> dict[tuple[str, str], BaselineEntry]:
    """Extract and validate a trusted tool-card fingerprint baseline."""
    _validate_report_root(report_payload)
    fingerprints: dict[tuple[str, str], BaselineEntry] = {}
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
        raw_fields = tool.get("field_fingerprints", {})
        if not isinstance(raw_fields, dict) or len(raw_fields) > 4097:
            raise ReportError(
                f"Baseline tools[{index}].field_fingerprints must be a bounded object"
            )
        field_fingerprints: dict[str, str] = {}
        for pointer, field_fingerprint in raw_fields.items():
            if (
                not isinstance(pointer, str)
                or not pointer.startswith("/")
                or len(pointer) > 10_000
                or not isinstance(field_fingerprint, str)
                or not _FINGERPRINT.fullmatch(field_fingerprint)
            ):
                raise ReportError(
                    f"Baseline tools[{index}].field_fingerprints is invalid"
                )
            field_fingerprints[pointer] = field_fingerprint
        identity = (
            safe_log_text(server_name, limit=512),
            safe_log_text(tool_name, limit=512),
        )
        if identity in fingerprints:
            raise ReportError(
                f"Baseline contains duplicate tool identity {safe_log_text(server_name)}/{safe_log_text(tool_name)}"
            )
        fingerprints[identity] = BaselineEntry(
            card_fingerprint=fingerprint,
            field_fingerprints=field_fingerprints,
        )
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


def _source_paths(sources: list[dict[str, Any]]) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for source in sources:
        metadata = source.get("metadata", {})
        if not isinstance(metadata, dict):
            continue
        candidate = metadata.get("path") or metadata.get("config_path")
        if not isinstance(candidate, str):
            continue
        try:
            path = Path(candidate).expanduser().resolve()
        except (OSError, RuntimeError, ValueError):
            continue
        if path.is_absolute():
            result[source["server_name"]] = path
    return result


def _sarif_level(severity: str) -> str:
    if severity in {"critical", "error"}:
        return "error"
    if severity == "warning":
        return "warning"
    return "note"


def _github_escape_data(value: Any) -> str:
    return safe_log_text(value, limit=10_000).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def _github_escape_property(value: Any) -> str:
    return _github_escape_data(value).replace(":", "%3A").replace(",", "%2C")


def _validate_report_root(report_payload: Any) -> None:
    if not isinstance(report_payload, dict):
        raise ReportError("Report root must be an object")
    tools = report_payload.get("tools")
    if not isinstance(tools, list):
        raise ReportError("Report tools must be an array")
    if len(tools) > MAX_LINT_TOOLS:
        raise ReportError(f"Report has more than {MAX_LINT_TOOLS} tools")
    schema_version = report_payload.get("report_schema_version")
    if schema_version is not None and schema_version not in {"1.0.0", "1.1.0"}:
        raise ReportError(
            f"Unsupported report schema version: {safe_log_text(schema_version)}"
        )
    scan_id = report_payload.get("scan_id")
    if scan_id is not None and (
        not isinstance(scan_id, str) or not 1 <= len(scan_id) <= 512
    ):
        raise ReportError("Report scan_id is invalid")

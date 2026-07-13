from __future__ import annotations

import math
from dataclasses import asdict, dataclass, field
from typing import Any, Literal, cast

from .rules import RULE_CATALOG_VERSION, json_pointer, rule_metadata
from .security import safe_log_text

Severity = Literal["info", "warning", "error", "critical"]
BaselineStatus = Literal["not_checked", "new", "unchanged", "changed"]

MAX_LINT_TOOLS = 100_000
MAX_SCHEMA_DEPTH_LIMIT = 64
MAX_SCHEMA_NODES_LIMIT = 100_000
MAX_CARD_CHARS_LIMIT = 1_000_000
MAX_DESCRIPTION_CHARS_LIMIT = 100_000

SEVERITY_ORDER: dict[Severity, int] = {
    "info": 1,
    "warning": 2,
    "error": 3,
    "critical": 4,
}

SEVERITY_WEIGHTS: dict[Severity, int] = {
    "info": 1,
    "warning": 5,
    "error": 15,
    "critical": 35,
}


@dataclass(frozen=True, slots=True)
class Issue:
    code: str
    severity: Severity
    message: str
    path: str
    recommendation: str
    evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["json_pointer"] = json_pointer(self.path)
        data["rule"] = rule_metadata(self.code, self.severity).to_dict()
        return cast(dict[str, Any], _sanitize_report_value(data))


@dataclass(slots=True)
class ToolCard:
    name: str
    description: str | None
    input_schema: dict[str, Any] | None
    output_schema: dict[str, Any] | None
    annotations: dict[str, Any]
    raw: dict[str, Any]
    server_name: str = "static"
    index: int = 0

    @classmethod
    def from_raw(cls, raw: Any, *, server_name: str, index: int) -> "ToolCard":
        safe_raw = raw if isinstance(raw, dict) else {"_invalid_tool": raw}
        name = safe_raw.get("name")
        if not isinstance(name, str) or not name.strip():
            name = f"<unnamed-{index}>"

        description = safe_raw.get("description")
        if description is not None and not isinstance(description, str):
            description = None

        input_schema = _object_or_none(
            safe_raw.get("inputSchema", safe_raw.get("input_schema"))
        )
        output_schema = _object_or_none(
            safe_raw.get("outputSchema", safe_raw.get("output_schema"))
        )
        annotations = _object_or_empty(safe_raw.get("annotations"))
        return cls(
            name=name.strip(),
            description=description,
            input_schema=input_schema,
            output_schema=output_schema,
            annotations=annotations,
            raw=safe_raw,
            server_name=server_name,
            index=index,
        )

    @property
    def display_name(self) -> str:
        return self.name or f"<unnamed-{self.index}>"


@dataclass(slots=True)
class SourceResult:
    server_name: str
    source_type: str
    tools: list[ToolCard] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    discovered_tools: int | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.server_name, str) or not self.server_name:
            raise ValueError("server_name must be a non-empty string")
        if not isinstance(self.source_type, str) or not self.source_type:
            raise ValueError("source_type must be a non-empty string")
        if not isinstance(self.tools, list) or not all(
            isinstance(tool, ToolCard) for tool in self.tools
        ):
            raise TypeError("tools must be a list of ToolCard values")
        if not isinstance(self.errors, list) or not all(
            isinstance(error, str) for error in self.errors
        ):
            raise TypeError("errors must be a list of strings")
        if not isinstance(self.metadata, dict):
            raise TypeError("metadata must be an object")
        if self.discovered_tools is not None and (
            isinstance(self.discovered_tools, bool)
            or not isinstance(self.discovered_tools, int)
            or self.discovered_tools < len(self.tools)
        ):
            raise ValueError("discovered_tools must be an integer at least len(tools)")


@dataclass(frozen=True, slots=True)
class LintConfig:
    max_tools: int = 1000
    max_schema_depth: int = 8
    max_schema_properties: int = 2000
    max_card_chars: int = 2800
    max_description_chars: int = 1200

    def __post_init__(self) -> None:
        _validate_positive_limit("max_tools", self.max_tools, MAX_LINT_TOOLS)
        _validate_positive_limit(
            "max_schema_depth", self.max_schema_depth, MAX_SCHEMA_DEPTH_LIMIT
        )
        _validate_positive_limit(
            "max_schema_properties",
            self.max_schema_properties,
            MAX_SCHEMA_NODES_LIMIT,
        )
        _validate_positive_limit(
            "max_card_chars", self.max_card_chars, MAX_CARD_CHARS_LIMIT
        )
        _validate_positive_limit(
            "max_description_chars",
            self.max_description_chars,
            MAX_DESCRIPTION_CHARS_LIMIT,
        )


@dataclass(slots=True)
class ToolReport:
    server_name: str
    tool_name: str
    score: int
    risk_level: str
    risk_categories: list[str]
    estimated_card_chars: int
    card_fingerprint: str
    baseline_status: BaselineStatus
    issues: list[Issue]
    recommendations: list[str]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["issues"] = [issue.to_dict() for issue in self.issues]
        return cast(dict[str, Any], _sanitize_report_value(data))


@dataclass(slots=True)
class LintReport:
    generated_at: str
    version: str
    sources: list[dict[str, Any]]
    summary: dict[str, Any]
    tools: list[ToolReport]
    scan_id: str = ""
    report_schema: str = (
        "https://raw.githubusercontent.com/inostarlin-passion/"
        "MCP-Tool-Card-Linter/v0.3.0/src/mcp_tool_card_linter/schemas/report.schema.json"
    )
    report_schema_version: str = "1.0.0"
    policy: dict[str, Any] = field(default_factory=dict)
    protocol: list[dict[str, Any]] = field(default_factory=list)
    facts: list[str] = field(default_factory=list)
    inferences: list[str] = field(default_factory=list)
    uncertainties: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "$schema": safe_log_text(self.report_schema),
            "report_schema_version": safe_log_text(self.report_schema_version),
            "rule_catalog_version": RULE_CATALOG_VERSION,
            "scan_id": safe_log_text(self.scan_id),
            "generated_at": safe_log_text(self.generated_at),
            "tool_version": safe_log_text(self.version),
            # Preserved for consumers of the 0.2 report shape.
            "version": safe_log_text(self.version),
            "policy": _sanitize_report_value(self.policy),
            "protocol": _sanitize_report_value(self.protocol),
            "sources": _sanitize_report_value(self.sources),
            "summary": _sanitize_report_value(self.summary),
            "tools": [tool.to_dict() for tool in self.tools],
            "facts": _sanitize_report_value(self.facts),
            "inferences": _sanitize_report_value(self.inferences),
            "uncertainties": _sanitize_report_value(self.uncertainties),
        }


def _object_or_none(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _object_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _validate_positive_limit(name: str, value: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if not 1 <= value <= maximum:
        raise ValueError(f"{name} must be in 1..{maximum}")


def _sanitize_report_value(value: Any, *, depth: int = 0) -> Any:
    if depth > 32:
        return "<truncated-depth>"
    if isinstance(value, str):
        return safe_log_text(value, limit=10_000)
    if isinstance(value, list):
        return [_sanitize_report_value(item, depth=depth + 1) for item in value]
    if isinstance(value, tuple):
        return [_sanitize_report_value(item, depth=depth + 1) for item in value]
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            safe_key = safe_log_text(key, limit=1000)
            candidate = safe_key
            suffix = 2
            while candidate in result:
                candidate = f"{safe_key}#{suffix}"
                suffix += 1
            result[candidate] = _sanitize_report_value(item, depth=depth + 1)
        return result
    if isinstance(value, float) and not math.isfinite(value):
        return "<non-finite-number>"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return safe_log_text(value, limit=10_000)

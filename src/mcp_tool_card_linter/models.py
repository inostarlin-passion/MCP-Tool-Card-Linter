from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Literal

Severity = Literal["info", "warning", "error", "critical"]

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
        return asdict(self)


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
            description = str(description)

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


@dataclass(frozen=True, slots=True)
class LintConfig:
    max_tools: int = 1000
    max_schema_depth: int = 8
    max_schema_properties: int = 2000
    max_card_chars: int = 2800
    max_description_chars: int = 1200


@dataclass(slots=True)
class ToolReport:
    server_name: str
    tool_name: str
    score: int
    risk_level: str
    risk_categories: list[str]
    estimated_card_chars: int
    issues: list[Issue]
    recommendations: list[str]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["issues"] = [issue.to_dict() for issue in self.issues]
        return data


@dataclass(slots=True)
class LintReport:
    generated_at: str
    version: str
    sources: list[dict[str, Any]]
    summary: dict[str, Any]
    tools: list[ToolReport]
    facts: list[str] = field(default_factory=list)
    inferences: list[str] = field(default_factory=list)
    uncertainties: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "version": self.version,
            "sources": self.sources,
            "summary": self.summary,
            "tools": [tool.to_dict() for tool in self.tools],
            "facts": self.facts,
            "inferences": self.inferences,
            "uncertainties": self.uncertainties,
        }


def _object_or_none(value: Any) -> dict[str, Any] | None:
    return value if isinstance(value, dict) else None


def _object_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


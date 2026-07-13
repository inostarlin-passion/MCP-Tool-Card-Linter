from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

RULE_CATALOG_VERSION = "1.0.0"

MCP_TOOLS_REFERENCE = (
    "https://modelcontextprotocol.io/specification/2025-11-25/server/tools"
)
MCP_SCHEMA_REFERENCE = (
    "https://modelcontextprotocol.io/specification/2025-11-25/schema"
)
JSON_SCHEMA_REFERENCE = "https://json-schema.org/draft/2020-12"
MCP_SECURITY_REFERENCE = (
    "https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices"
)

# Kept explicit so policy configuration, SARIF consumers, and documentation can
# depend on a stable enumerable catalog without importing or executing lint.py.
KNOWN_RULE_IDS = tuple(
    sorted(
        {
            "ADDITIONAL_PROPERTIES_ALLOWED",
            "ADDITIONAL_PROPERTIES_SCHEMA_BROAD",
            "ADDITIONAL_PROPERTIES_UNSPECIFIED",
            "ANNOTATION_CONFLICT_DESTRUCTIVE_READ_ONLY",
            "ANNOTATION_CONFLICT_OPEN_WORLD",
            "ANNOTATION_CONFLICT_READ_ONLY",
            "ARRAY_BOUND_RECOMMENDED",
            "ARRAY_ITEMS_MISSING",
            "COMMAND_PARAMETER_UNCONSTRAINED",
            "CROSS_SERVER_TOOL_SHADOWING",
            "DESCRIPTION_REPEATS_NAME",
            "DESCRIPTION_TOO_LONG",
            "DESCRIPTION_TOO_SHORT",
            "DESTRUCTIVE_HINT_MISSING",
            "DUPLICATE_REQUIRED_ENTRY",
            "DUPLICATE_SCHEMA_TYPE",
            "DUPLICATE_TOOL_NAME",
            "ENUM_RECOMMENDED",
            "ENUM_TOO_LARGE",
            "EXTERNAL_SCHEMA_REF",
            "FINDING_LIMIT_REACHED",
            "GENERIC_TOOL_NAME",
            "HARDCODED_SECRET_IN_METADATA",
            "HIDDEN_UNICODE_CONTROL",
            "INEFFECTIVE_SIZE_BOUND",
            "INVALID_ADDITIONAL_PROPERTIES",
            "INVALID_ANNOTATIONS_TYPE",
            "INVALID_ANNOTATION_VALUE",
            "INVALID_DESCRIPTION_TYPE",
            "INVALID_ENUM",
            "INVALID_EXECUTION_METADATA",
            "INVALID_FORMAT",
            "INVALID_INPUTSCHEMA",
            "INVALID_INPUTSCHEMA_TYPE",
            "INVALID_JSON_SCHEMA_2020_12",
            "INVALID_MULTIPLE_OF",
            "INVALID_NUMERIC_BOUND",
            "INVALID_OUTPUTSCHEMA",
            "INVALID_OUTPUTSCHEMA_TYPE",
            "INVALID_PATTERN",
            "INVALID_PREFIX_ITEMS",
            "INVALID_PROPERTIES",
            "INVALID_PROPERTY_NAME",
            "INVALID_REQUIRED",
            "INVALID_REQUIRED_ENTRY",
            "INVALID_SCHEMA_ANNOTATION",
            "INVALID_SCHEMA_COMPOSITION",
            "INVALID_SCHEMA_DIALECT",
            "INVALID_SCHEMA_MAP",
            "INVALID_SCHEMA_REF",
            "INVALID_SCHEMA_TYPE",
            "INVALID_SIZE_BOUND",
            "INVALID_SUBSCHEMA",
            "INVALID_TASK_SUPPORT",
            "INVALID_TITLE_TYPE",
            "INVALID_TOOL_ICONS",
            "INVALID_TOOL_ICON_MIME_TYPE",
            "INVALID_TOOL_ICON_SIZE",
            "INVALID_TOOL_ICON_SRC",
            "INVALID_TOOL_NAME_TYPE",
            "INVALID_TOOL_OBJECT",
            "INVALID_UNIQUE_ITEMS",
            "INVERTED_NUMERIC_BOUNDS",
            "INVERTED_SIZE_BOUNDS",
            "MISSING_DESCRIPTION",
            "MISSING_INPUTSCHEMA",
            "MISSING_OUTPUTSCHEMA",
            "MISSING_REQUIRED_FIELDS",
            "MISSING_SIDE_EFFECT_WARNING",
            "MISSING_TOOL_NAME",
            "MISSING_USAGE_BOUNDARY",
            "NESTED_SCHEMA_DIALECT",
            "NUMERIC_BOUNDS_MISSING",
            "OBJECT_SCHEMA_WITHOUT_PROPERTIES",
            "OBFUSCATED_METADATA",
            "PARAMETER_DESCRIPTION_MISSING",
            "PATH_PARAMETER_CONSTRAINT_MISSING",
            "PATTERN_TOO_LONG",
            "PERMISSIVE_PATTERN",
            "POTENTIAL_REDOS_PATTERN",
            "READ_ONLY_HINT_RECOMMENDED",
            "ROOT_SCHEMA_NOT_OBJECT",
            "SCHEMA_META_VALIDATION_SKIPPED",
            "SCHEMA_NODE_NOT_OBJECT",
            "SCHEMA_TOO_DEEP",
            "SCHEMA_TOO_LARGE",
            "SCHEMA_TYPE_MISSING",
            "SENSITIVE_PARAMETER_EXPOSED",
            "STRING_BOUND_RECOMMENDED",
            "TOOL_CARD_CHANGED",
            "TOOL_CARD_NOT_IN_BASELINE",
            "TOOL_CARD_TOO_LARGE",
            "TOOL_NAME_TOO_LONG",
            "TOOL_NAME_SPEC_VIOLATION",
            "TOOL_NAME_UNSTABLE_CHARACTERS",
            "TOOL_POISONING_HIDDEN_INSTRUCTION",
            "TOOL_POISONING_IGNORE_INSTRUCTIONS",
            "TOOL_POISONING_SECRET_EXFILTRATION",
            "TOOL_POISONING_TOOL_COERCION",
            "TOO_MANY_TOOL_ICONS",
            "UNKNOWN_REQUIRED_FIELD",
            "UNSAFE_PROPERTY_NAME",
            "URL_PARAMETER_ALLOWLIST_MISSING",
        }
    )
)


@dataclass(frozen=True, slots=True)
class RuleMetadata:
    rule_id: str
    title: str
    default_severity: str
    confidence: str
    category: str
    references: tuple[str, ...]
    cwe: tuple[str, ...]
    introduced_in: str
    auto_fix: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.rule_id,
            "title": self.title,
            "default_severity": self.default_severity,
            "confidence": self.confidence,
            "category": self.category,
            "references": list(self.references),
            "cwe": list(self.cwe),
            "introduced_in": self.introduced_in,
            "auto_fix": self.auto_fix,
        }


def rule_metadata(rule_id: str, default_severity: str | None = None) -> RuleMetadata:
    category = _category(rule_id)
    references: tuple[str, ...]
    if category == "spec":
        references = (MCP_SCHEMA_REFERENCE, JSON_SCHEMA_REFERENCE)
    elif category in {"security", "integrity"}:
        references = (MCP_SECURITY_REFERENCE, MCP_TOOLS_REFERENCE)
    else:
        references = (MCP_TOOLS_REFERENCE,)
    return RuleMetadata(
        rule_id=rule_id,
        title=rule_id.replace("_", " ").title(),
        default_severity=default_severity or _DEFAULT_SEVERITY.get(rule_id, "warning"),
        confidence=_confidence(rule_id),
        category=category,
        references=references,
        cwe=_cwe(rule_id),
        introduced_in="0.3.0" if rule_id in _V03_RULES else "0.2.0",
    )


def list_rule_metadata() -> list[dict[str, Any]]:
    return [rule_metadata(rule_id).to_dict() for rule_id in KNOWN_RULE_IDS]


def json_pointer(path: str) -> str:
    """Translate the linter's bounded dotted path into a JSON Pointer."""
    if path in {"", "$"}:
        return ""
    value = path[2:] if path.startswith("$.") else path
    value = value[1:] if value.startswith("$") else value
    tokens: list[str] = []
    for part in re.finditer(r"(?:^|\.)([^.\[]+)|\[([^\]]+)\]", value):
        token = part.group(1) if part.group(1) is not None else part.group(2)
        if token is None:
            continue
        if len(token) >= 2 and token[0] == token[-1] and token[0] in {"'", '"'}:
            token = token[1:-1]
        tokens.append(token.replace("~", "~0").replace("/", "~1"))
    return "/" + "/".join(tokens) if tokens else ""


def _category(rule_id: str) -> str:
    if rule_id.startswith("TOOL_CARD_"):
        return "integrity"
    security_terms = (
        "POISONING",
        "SECRET",
        "HIDDEN_UNICODE",
        "OBFUSCATED",
        "COMMAND_PARAMETER",
        "URL_PARAMETER",
        "PATH_PARAMETER",
        "UNSAFE_PROPERTY",
        "SHADOWING",
        "PERMISSIVE_PATTERN",
        "REDOS",
        "SIDE_EFFECT",
        "DESTRUCTIVE",
        "SENSITIVE_PARAMETER",
    )
    if any(term in rule_id for term in security_terms):
        return "security"
    if rule_id.startswith(("INVALID_", "ROOT_SCHEMA_", "SCHEMA_", "EXTERNAL_SCHEMA_")):
        return "spec"
    if rule_id in {
        "MISSING_INPUTSCHEMA",
        "MISSING_TOOL_NAME",
        "UNKNOWN_REQUIRED_FIELD",
        "DUPLICATE_REQUIRED_ENTRY",
        "ARRAY_ITEMS_MISSING",
    }:
        return "spec"
    return "quality"


def _confidence(rule_id: str) -> str:
    if rule_id.startswith(("INVALID_", "MISSING_", "DUPLICATE_", "ROOT_SCHEMA_")):
        return "high"
    if any(term in rule_id for term in ("POTENTIAL", "RECOMMENDED", "TOOL_POISONING")):
        return "medium"
    return "high"


def _cwe(rule_id: str) -> tuple[str, ...]:
    if any(term in rule_id for term in ("TOO_LARGE", "TOO_DEEP", "BOUND", "REDOS")):
        return ("CWE-400", "CWE-770")
    if any(term in rule_id for term in ("URL_PARAMETER", "EXTERNAL_SCHEMA_REF")):
        return ("CWE-918",)
    if "SECRET" in rule_id:
        return ("CWE-200", "CWE-798")
    if "COMMAND_PARAMETER" in rule_id:
        return ("CWE-78",)
    if "TOOL_POISONING" in rule_id:
        return ("CWE-74",)
    return ()


_DEFAULT_SEVERITY = {
    **{
        rule_id: "error"
        for rule_id in KNOWN_RULE_IDS
        if rule_id.startswith("INVALID_")
        or rule_id
        in {
            "ANNOTATION_CONFLICT_DESTRUCTIVE_READ_ONLY",
            "ANNOTATION_CONFLICT_READ_ONLY",
            "ARRAY_ITEMS_MISSING",
            "COMMAND_PARAMETER_UNCONSTRAINED",
            "DUPLICATE_TOOL_NAME",
            "EXTERNAL_SCHEMA_REF",
            "FINDING_LIMIT_REACHED",
            "HIDDEN_UNICODE_CONTROL",
            "INVERTED_NUMERIC_BOUNDS",
            "INVERTED_SIZE_BOUNDS",
            "MISSING_DESCRIPTION",
            "MISSING_INPUTSCHEMA",
            "ROOT_SCHEMA_NOT_OBJECT",
            "SCHEMA_NODE_NOT_OBJECT",
            "SCHEMA_TOO_LARGE",
            "TOOL_CARD_CHANGED",
            "TOOL_POISONING_HIDDEN_INSTRUCTION",
            "TOOL_POISONING_TOOL_COERCION",
            "UNKNOWN_REQUIRED_FIELD",
            "UNSAFE_PROPERTY_NAME",
        }
    },
    **{
        rule_id: "critical"
        for rule_id in {
            "HARDCODED_SECRET_IN_METADATA",
            "INVALID_TOOL_NAME_TYPE",
            "INVALID_TOOL_OBJECT",
            "MISSING_TOOL_NAME",
            "TOOL_POISONING_IGNORE_INSTRUCTIONS",
            "TOOL_POISONING_SECRET_EXFILTRATION",
        }
    },
    **{
        rule_id: "info"
        for rule_id in {
            "READ_ONLY_HINT_RECOMMENDED",
            "SCHEMA_META_VALIDATION_SKIPPED",
            "STRING_BOUND_RECOMMENDED",
            "TOOL_CARD_NOT_IN_BASELINE",
        }
    },
    # These intentionally override the broad INVALID_ family: the server can
    # still be linted safely and the violations are compatibility guidance.
    "INVALID_TITLE_TYPE": "warning",
    "INVALID_TOOL_ICON_MIME_TYPE": "warning",
    "INVALID_TOOL_ICON_SIZE": "warning",
}


_V03_RULES = frozenset(
    {
        "FINDING_LIMIT_REACHED",
        "INVALID_JSON_SCHEMA_2020_12",
        "INVALID_TOOL_ICONS",
        "INVALID_TOOL_ICON_MIME_TYPE",
        "INVALID_TOOL_ICON_SIZE",
        "INVALID_TOOL_ICON_SRC",
        "SCHEMA_META_VALIDATION_SKIPPED",
        "TOOL_NAME_SPEC_VIOLATION",
        "TOO_MANY_TOOL_ICONS",
    }
)

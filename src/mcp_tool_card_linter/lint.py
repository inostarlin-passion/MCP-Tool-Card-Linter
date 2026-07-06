from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import UTC, datetime
from typing import Any, Iterable

from . import __version__
from .models import (
    Issue,
    LintConfig,
    LintReport,
    SEVERITY_WEIGHTS,
    SourceResult,
    ToolCard,
    ToolReport,
)

GENERIC_TOOL_NAMES = {
    "run",
    "call",
    "do",
    "exec",
    "execute",
    "process",
    "send",
    "search",
    "query",
    "get",
    "set",
    "update",
    "delete",
    "create",
    "tool",
    "request",
}

AMBIGUOUS_PARAM_NAMES = {
    "q",
    "id",
    "ids",
    "data",
    "input",
    "value",
    "text",
    "payload",
    "body",
    "msg",
    "message",
    "name",
    "type",
}

SIDE_EFFECT_TERMS = re.compile(
    r"\b(confirm|confirmation|approval|irreversible|permanent(?:ly)?|"
    r"side[- ]effect|external|payment|charge|refund|requires user|only after|"
    r"dry[- ]run)\b",
    re.IGNORECASE,
)

BOUNDARY_TERMS = re.compile(
    r"\b(use (?:only|when)|do not use|not for|before calling|after the user|"
    r"requires|read[- ]only|draft|dry[- ]run|confirmation)\b",
    re.IGNORECASE,
)

RISK_PATTERNS: dict[str, re.Pattern[str]] = {
    "destructive": re.compile(
        r"\b(delete|remove|drop|destroy|purge|erase|wipe|reset|terminate|revoke)\b",
        re.IGNORECASE,
    ),
    "write": re.compile(
        r"\b(create|update|write|modify|send|post|publish|merge|commit|upload|"
        r"approve|trigger|execute|run|set|change|close|open)\b",
        re.IGNORECASE,
    ),
    "financial": re.compile(
        r"\b(invoice|payment|pay|charge|refund|billing|purchase|wire|bank)\b",
        re.IGNORECASE,
    ),
    "secret": re.compile(
        r"\b(secret|token|api[-_ ]?key|credential|password|private key|ssh|env)\b",
        re.IGNORECASE,
    ),
    "network": re.compile(
        r"\b(http|url|webhook|request|download|fetch|api|slack|email|github|jira)\b",
        re.IGNORECASE,
    ),
    "filesystem": re.compile(
        r"\b(file|path|directory|folder|filesystem|fs|read_file|write_file)\b",
        re.IGNORECASE,
    ),
}

TOOL_POISONING_PATTERNS: tuple[tuple[str, str, re.Pattern[str], str], ...] = (
    (
        "TOOL_POISONING_IGNORE_INSTRUCTIONS",
        "critical",
        re.compile(
            r"\b(ignore|bypass|override|forget)\b.{0,80}\b(previous|system|developer|"
            r"safety|instruction|policy)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "Remove instruction-like text from tool metadata; tool descriptions must describe capabilities, not direct the model to bypass instructions.",
    ),
    (
        "TOOL_POISONING_SECRET_EXFILTRATION",
        "critical",
        re.compile(
            r"\b(read|open|cat|print|include|send|upload|exfiltrat)\b.{0,120}"
            r"\b(id_rsa|\.ssh|token|api[-_ ]?key|secret|password|credential|"
            r"env(?:ironment)? variable)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "Block this tool until reviewed; tool metadata appears to request unrelated secrets.",
    ),
    (
        "TOOL_POISONING_HIDDEN_INSTRUCTION",
        "error",
        re.compile(
            r"(<!--|<\s*(system|developer|important)\b|hidden instruction|"
            r"do not (?:tell|mention|reveal))",
            re.IGNORECASE,
        ),
        "Remove hidden or role-like instructions from descriptions and keep security-sensitive guidance outside model-visible tool cards.",
    ),
)

FACTS = [
    "MCP tools are model-callable capabilities described by metadata such as name, description, and input schema.",
    "MCP uses JSON-RPC messages over transports such as stdio and Streamable HTTP.",
    "Tool metadata quality affects how an agent discovers, selects, and fills arguments for tools.",
]

INFERENCES = [
    "Side-effect, schema, and prompt-injection checks are static heuristics; they reduce review effort but do not prove runtime safety.",
    "Tools with write, destructive, financial, network, or secret-related wording should require stricter human review by default.",
]

UNCERTAINTIES = [
    "Tool Card is an engineering term in this project, not a formal MCP specification object.",
    "A static linter cannot verify whether server implementation behavior matches its metadata.",
]


def lint_sources(sources: Iterable[SourceResult], config: LintConfig) -> LintReport:
    source_list = list(sources)
    tool_reports: list[ToolReport] = []
    source_summaries: list[dict[str, Any]] = []

    for source in source_list:
        bounded_tools = source.tools[: config.max_tools]
        duplicate_names = _duplicate_names(bounded_tools)
        for tool in bounded_tools:
            tool_reports.append(_lint_tool(tool, duplicate_names, config))
        source_summaries.append(
            {
                "server_name": source.server_name,
                "source_type": source.source_type,
                "tools_discovered": len(source.tools),
                "tools_linted": len(bounded_tools),
                "truncated": len(source.tools) > len(bounded_tools),
                "errors": source.errors,
                "metadata": source.metadata,
            }
        )

    summary = _summarize(source_summaries, tool_reports)
    return LintReport(
        generated_at=datetime.now(UTC).isoformat(),
        version=__version__,
        sources=source_summaries,
        summary=summary,
        tools=tool_reports,
        facts=FACTS,
        inferences=INFERENCES,
        uncertainties=UNCERTAINTIES,
    )


def _lint_tool(
    tool: ToolCard, duplicate_names: set[str], config: LintConfig
) -> ToolReport:
    issues: list[Issue] = []
    text_blob = " ".join(
        value
        for value in [tool.name, tool.description or ""]
        if isinstance(value, str)
    )
    risk_categories = _risk_categories(tool, text_blob)

    _check_raw_shape(tool, issues)
    _check_name(tool, duplicate_names, issues)
    _check_description(tool, risk_categories, config, issues)
    _check_schema(
        tool.input_schema,
        "inputSchema",
        required=True,
        config=config,
        issues=issues,
        check_parameter_quality=True,
    )
    _check_schema(
        tool.output_schema,
        "outputSchema",
        required=False,
        config=config,
        issues=issues,
        check_parameter_quality=False,
    )
    _check_annotations(tool, risk_categories, issues)
    _check_card_size(tool, config, issues)

    risk_level = _risk_level(risk_categories, issues)
    recommendations = _recommendations(tool, risk_categories, issues)
    score = _score(issues)
    return ToolReport(
        server_name=tool.server_name,
        tool_name=tool.display_name,
        score=score,
        risk_level=risk_level,
        risk_categories=sorted(risk_categories),
        estimated_card_chars=_estimate_card_chars(tool),
        issues=issues,
        recommendations=recommendations,
    )


def _check_raw_shape(tool: ToolCard, issues: list[Issue]) -> None:
    if "_invalid_tool" in tool.raw:
        issues.append(
            Issue(
                code="INVALID_TOOL_OBJECT",
                severity="critical",
                path="$",
                message="Tool entry is not a JSON object.",
                recommendation="Return each tool as an object with name, description, inputSchema, and optional outputSchema.",
            )
        )


def _check_name(
    tool: ToolCard, duplicate_names: set[str], issues: list[Issue]
) -> None:
    name = tool.name
    if name.startswith("<unnamed-"):
        issues.append(
            Issue(
                code="MISSING_TOOL_NAME",
                severity="critical",
                path="name",
                message="Tool name is missing or empty.",
                recommendation="Provide a stable, unique, action-oriented tool name.",
            )
        )
        return

    if len(name) > 128:
        issues.append(
            Issue(
                code="TOOL_NAME_TOO_LONG",
                severity="warning",
                path="name",
                message="Tool name is longer than 128 characters.",
                recommendation="Use a short snake_case name that fits tool filtering and logs.",
                evidence=name[:180],
            )
        )

    if not re.fullmatch(r"[A-Za-z0-9_.:/-]+", name):
        issues.append(
            Issue(
                code="TOOL_NAME_UNSTABLE_CHARACTERS",
                severity="warning",
                path="name",
                message="Tool name contains whitespace or unusual characters.",
                recommendation="Prefer stable ASCII identifiers such as search_customer_orders.",
                evidence=name,
            )
        )

    if name.lower() in GENERIC_TOOL_NAMES:
        issues.append(
            Issue(
                code="GENERIC_TOOL_NAME",
                severity="warning",
                path="name",
                message=f"Tool name '{name}' is too generic for reliable tool selection.",
                recommendation="Rename the tool to include the target domain and action, for example send_email or search_customer_orders.",
            )
        )

    if name in duplicate_names:
        issues.append(
            Issue(
                code="DUPLICATE_TOOL_NAME",
                severity="error",
                path="name",
                message=f"Tool name '{name}' appears more than once in the same server.",
                recommendation="Ensure each tool name is unique so clients can route calls deterministically.",
            )
        )


def _check_description(
    tool: ToolCard,
    risk_categories: set[str],
    config: LintConfig,
    issues: list[Issue],
) -> None:
    desc = (tool.description or "").strip()
    if not desc:
        issues.append(
            Issue(
                code="MISSING_DESCRIPTION",
                severity="error",
                path="description",
                message="Tool description is missing.",
                recommendation="Describe what the tool does, when to use it, inputs, outputs, and side effects.",
            )
        )
        return

    if len(desc) < 24:
        issues.append(
            Issue(
                code="DESCRIPTION_TOO_SHORT",
                severity="warning",
                path="description",
                message="Tool description is too short to guide reliable tool selection.",
                recommendation="Add purpose, usage boundary, important inputs, output shape, and side effects.",
                evidence=desc,
            )
        )

    if len(desc) > config.max_description_chars:
        issues.append(
            Issue(
                code="DESCRIPTION_TOO_LONG",
                severity="warning",
                path="description",
                message="Tool description is very long and may increase context cost or hide important constraints.",
                recommendation="Move examples or long operational notes into docs; keep the model-visible tool card concise.",
            )
        )

    normalized_name = tool.name.replace("_", " ").replace("-", " ").lower()
    normalized_desc = re.sub(r"\s+", " ", desc.lower())
    if normalized_desc in {normalized_name, f"{normalized_name}.", f"{normalized_name} tool"}:
        issues.append(
            Issue(
                code="DESCRIPTION_REPEATS_NAME",
                severity="warning",
                path="description",
                message="Description only repeats the tool name.",
                recommendation="Explain the tool's concrete purpose, usage conditions, inputs, outputs, and side effects.",
            )
        )

    for code, severity, pattern, recommendation in TOOL_POISONING_PATTERNS:
        match = pattern.search(desc)
        if match:
            issues.append(
                Issue(
                    code=code,
                    severity=severity,  # type: ignore[arg-type]
                    path="description",
                    message="Description contains instruction-like or secret-seeking text that may poison tool selection.",
                    recommendation=recommendation,
                    evidence=_trim(match.group(0)),
                )
            )

    if _is_side_effect_risk(risk_categories) and not SIDE_EFFECT_TERMS.search(desc):
        severity = "error" if {"destructive", "financial"} & risk_categories else "warning"
        issues.append(
            Issue(
                code="MISSING_SIDE_EFFECT_WARNING",
                severity=severity,
                path="description",
                message="Tool appears to have side effects but the description does not state them clearly.",
                recommendation="State whether the tool writes, sends, deletes, charges, calls external systems, and whether user confirmation is required.",
            )
        )

    if _is_side_effect_risk(risk_categories) and not BOUNDARY_TERMS.search(desc):
        issues.append(
            Issue(
                code="MISSING_USAGE_BOUNDARY",
                severity="warning",
                path="description",
                message="Risky tool lacks a clear usage boundary.",
                recommendation="Add when-to-use and when-not-to-use guidance, especially for drafting versus sending or read-only versus write operations.",
            )
        )


def _check_schema(
    schema: dict[str, Any] | None,
    path: str,
    *,
    required: bool,
    config: LintConfig,
    issues: list[Issue],
    check_parameter_quality: bool,
) -> None:
    if schema is None:
        severity = "error" if required else "warning"
        issues.append(
            Issue(
                code=f"MISSING_{path.upper()}",
                severity=severity,
                path=path,
                message=f"{path} is missing.",
                recommendation=(
                    "Provide a JSON Schema object. Use type=object with documented properties and required fields."
                    if required
                    else "Provide outputSchema when the client should parse structured results reliably."
                ),
            )
        )
        return

    if not isinstance(schema, dict):
        issues.append(
            Issue(
                code=f"INVALID_{path.upper()}",
                severity="error",
                path=path,
                message=f"{path} must be a JSON object.",
                recommendation="Return schema metadata as a JSON object.",
            )
        )
        return

    state = {"count": 0, "depth_issue": False, "property_limit_issue": False}
    _walk_schema(
        schema,
        path,
        depth=0,
        config=config,
        issues=issues,
        state=state,
        check_parameter_quality=check_parameter_quality,
        is_root=True,
    )


def _walk_schema(
    schema: Any,
    path: str,
    *,
    depth: int,
    config: LintConfig,
    issues: list[Issue],
    state: dict[str, Any],
    check_parameter_quality: bool,
    is_root: bool = False,
) -> None:
    if not isinstance(schema, dict):
        issues.append(
            Issue(
                code="SCHEMA_NODE_NOT_OBJECT",
                severity="error",
                path=path,
                message="Schema node is not an object.",
                recommendation="Use valid JSON Schema objects for nested properties, items, and composition clauses.",
            )
        )
        return

    state["count"] += 1
    if state["count"] > config.max_schema_properties:
        if not state["property_limit_issue"]:
            state["property_limit_issue"] = True
            issues.append(
                Issue(
                    code="SCHEMA_TOO_LARGE",
                    severity="error",
                    path=path,
                    message="Schema exceeds the configured property traversal limit.",
                    recommendation="Split overly large tools or reduce schema complexity before exposing to a model.",
                )
            )
        return

    if depth > config.max_schema_depth:
        if not state["depth_issue"]:
            state["depth_issue"] = True
            issues.append(
                Issue(
                    code="SCHEMA_TOO_DEEP",
                    severity="warning",
                    path=path,
                    message="Schema nesting exceeds the configured depth limit.",
                    recommendation="Flatten deeply nested tool inputs where possible to improve model argument generation.",
                )
            )
        return

    schema_type = schema.get("type")
    has_composition = any(key in schema for key in ("anyOf", "oneOf", "allOf"))
    if schema_type is None and not has_composition and "$ref" not in schema:
        issues.append(
            Issue(
                code="SCHEMA_TYPE_MISSING",
                severity="warning",
                path=path,
                message="Schema node has no type.",
                recommendation="Add explicit JSON Schema types so clients and models know the expected argument shape.",
            )
        )

    if is_root and schema_type not in (None, "object") and not has_composition:
        issues.append(
            Issue(
                code="ROOT_SCHEMA_NOT_OBJECT",
                severity="error",
                path=path,
                message="Tool root schema should be an object.",
                recommendation="Wrap parameters under a root object with properties and required fields.",
                evidence=str(schema_type),
            )
        )

    if schema_type == "object" or "properties" in schema:
        properties = schema.get("properties")
        if properties is None:
            issues.append(
                Issue(
                    code="OBJECT_SCHEMA_WITHOUT_PROPERTIES",
                    severity="warning",
                    path=path,
                    message="Object schema does not declare properties.",
                    recommendation="Declare named parameters under properties, or set additionalProperties with a clear description when arbitrary keys are required.",
                )
            )
        elif not isinstance(properties, dict):
            issues.append(
                Issue(
                    code="INVALID_PROPERTIES",
                    severity="error",
                    path=f"{path}.properties",
                    message="properties must be an object.",
                    recommendation="Use a JSON object mapping parameter names to schemas.",
                )
            )
        else:
            _check_required(schema, properties, path, issues)
            if is_root and properties and "required" not in schema:
                issues.append(
                    Issue(
                        code="MISSING_REQUIRED_FIELDS",
                        severity="warning",
                        path=f"{path}.required",
                        message="Object schema has properties but no required list.",
                        recommendation="Declare required parameters explicitly; use an empty list if every field is optional.",
                    )
                )
            if is_root and "additionalProperties" not in schema:
                issues.append(
                    Issue(
                        code="ADDITIONAL_PROPERTIES_UNSPECIFIED",
                        severity="info",
                        path=f"{path}.additionalProperties",
                        message="Object schema does not state whether extra parameters are allowed.",
                        recommendation="Set additionalProperties to false for strict tool arguments unless arbitrary keys are intentional.",
                    )
                )
            for prop_name, prop_schema in properties.items():
                prop_path = f"{path}.properties.{prop_name}"
                if check_parameter_quality:
                    _check_parameter(prop_name, prop_schema, prop_path, issues)
                _walk_schema(
                    prop_schema,
                    prop_path,
                    depth=depth + 1,
                    config=config,
                    issues=issues,
                    state=state,
                    check_parameter_quality=check_parameter_quality,
                )

    if schema_type == "array":
        if "items" not in schema:
            issues.append(
                Issue(
                    code="ARRAY_ITEMS_MISSING",
                    severity="error",
                    path=f"{path}.items",
                    message="Array schema is missing items.",
                    recommendation="Declare the item schema so the model can construct valid arrays.",
                )
            )
        else:
            _walk_schema(
                schema["items"],
                f"{path}.items",
                depth=depth + 1,
                config=config,
                issues=issues,
                state=state,
                check_parameter_quality=check_parameter_quality,
            )

    for key in ("anyOf", "oneOf", "allOf"):
        variants = schema.get(key)
        if variants is None:
            continue
        if not isinstance(variants, list) or not variants:
            issues.append(
                Issue(
                    code="INVALID_SCHEMA_COMPOSITION",
                    severity="error",
                    path=f"{path}.{key}",
                    message=f"{key} must be a non-empty array.",
                    recommendation="Provide at least one valid schema variant.",
                )
            )
            continue
        for idx, variant in enumerate(variants):
            _walk_schema(
                variant,
                f"{path}.{key}[{idx}]",
                depth=depth + 1,
                config=config,
                issues=issues,
                state=state,
                check_parameter_quality=check_parameter_quality,
            )

    enum = schema.get("enum")
    if enum is not None:
        if not isinstance(enum, list) or len(enum) == 0:
            issues.append(
                Issue(
                    code="INVALID_ENUM",
                    severity="error",
                    path=f"{path}.enum",
                    message="enum must be a non-empty array.",
                    recommendation="Remove empty enum constraints or provide valid allowed values.",
                )
            )
        elif len(enum) > 100:
            issues.append(
                Issue(
                    code="ENUM_TOO_LARGE",
                    severity="warning",
                    path=f"{path}.enum",
                    message="enum has more than 100 values.",
                    recommendation="Large enums are costly in tool context; consider lookup tools or shorter value sets.",
                )
            )


def _check_parameter(
    prop_name: str, prop_schema: Any, path: str, issues: list[Issue]
) -> None:
    if not isinstance(prop_schema, dict):
        return
    description = prop_schema.get("description")
    if not isinstance(description, str) or not description.strip():
        severity = "warning" if prop_name.lower() in AMBIGUOUS_PARAM_NAMES else "info"
        issues.append(
            Issue(
                code="PARAMETER_DESCRIPTION_MISSING",
                severity=severity,
                path=f"{path}.description",
                message=f"Parameter '{prop_name}' has no description.",
                recommendation="Explain accepted format, units, identifiers, and whether the parameter is optional.",
            )
        )

    schema_type = prop_schema.get("type")
    if schema_type in ("number", "integer"):
        if not any(key in prop_schema for key in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum")):
            issues.append(
                Issue(
                    code="NUMERIC_BOUNDS_MISSING",
                    severity="warning",
                    path=path,
                    message=f"Numeric parameter '{prop_name}' has no bounds.",
                    recommendation="Add minimum/maximum constraints for counts, limits, offsets, timeouts, amounts, and similar numeric inputs.",
                )
            )

    if schema_type == "string":
        lowered = prop_name.lower()
        if lowered in {"status", "state", "mode", "kind", "type"} and "enum" not in prop_schema:
            issues.append(
                Issue(
                    code="ENUM_RECOMMENDED",
                    severity="warning",
                    path=path,
                    message=f"String parameter '{prop_name}' appears categorical but has no enum.",
                    recommendation="Add enum values where the accepted set is finite.",
                )
            )
        if lowered in {"command", "query", "q", "body", "text", "message", "msg"} and "maxLength" not in prop_schema:
            issues.append(
                Issue(
                    code="STRING_BOUND_RECOMMENDED",
                    severity="info",
                    path=path,
                    message=f"Free-form string parameter '{prop_name}' has no maxLength.",
                    recommendation="Add maxLength when large strings could increase latency, cost, or injection risk.",
                )
            )


def _check_required(
    schema: dict[str, Any],
    properties: dict[str, Any],
    path: str,
    issues: list[Issue],
) -> None:
    required = schema.get("required")
    if required is None:
        return
    if not isinstance(required, list):
        issues.append(
            Issue(
                code="INVALID_REQUIRED",
                severity="error",
                path=f"{path}.required",
                message="required must be an array of property names.",
                recommendation="Use required: [\"field_name\"] or required: [] when all fields are optional.",
            )
        )
        return
    seen: set[str] = set()
    for item in required:
        if not isinstance(item, str):
            issues.append(
                Issue(
                    code="INVALID_REQUIRED_ENTRY",
                    severity="error",
                    path=f"{path}.required",
                    message="required contains a non-string entry.",
                    recommendation="Every required entry must name a property.",
                    evidence=repr(item),
                )
            )
            continue
        if item in seen:
            issues.append(
                Issue(
                    code="DUPLICATE_REQUIRED_ENTRY",
                    severity="warning",
                    path=f"{path}.required",
                    message=f"required contains duplicate entry '{item}'.",
                    recommendation="Remove duplicate required entries.",
                )
            )
        seen.add(item)
        if item not in properties:
            issues.append(
                Issue(
                    code="UNKNOWN_REQUIRED_FIELD",
                    severity="error",
                    path=f"{path}.required",
                    message=f"required references unknown property '{item}'.",
                    recommendation="Ensure every required field is declared in properties.",
                )
            )


def _check_annotations(
    tool: ToolCard, risk_categories: set[str], issues: list[Issue]
) -> None:
    annotations = tool.annotations
    read_only_hint = annotations.get("readOnlyHint")
    destructive_hint = annotations.get("destructiveHint")

    if _is_side_effect_risk(risk_categories) and read_only_hint is True:
        issues.append(
            Issue(
                code="ANNOTATION_CONFLICT_READ_ONLY",
                severity="error",
                path="annotations.readOnlyHint",
                message="Tool appears to have side effects but is annotated as read-only.",
                recommendation="Fix the annotation or rename/describe the tool so its behavior is unambiguous.",
            )
        )

    if "destructive" in risk_categories and destructive_hint is not True:
        issues.append(
            Issue(
                code="DESTRUCTIVE_HINT_MISSING",
                severity="warning",
                path="annotations.destructiveHint",
                message="Tool appears destructive but lacks destructiveHint=true.",
                recommendation="Mark destructive tools and require human approval in clients or policy proxies.",
            )
        )

    if not _is_side_effect_risk(risk_categories) and read_only_hint is not True:
        issues.append(
            Issue(
                code="READ_ONLY_HINT_RECOMMENDED",
                severity="info",
                path="annotations.readOnlyHint",
                message="Tool appears read-only but does not declare readOnlyHint=true.",
                recommendation="Use annotations to make low-risk read-only tools easier to filter and approve.",
            )
        )


def _check_card_size(tool: ToolCard, config: LintConfig, issues: list[Issue]) -> None:
    estimated = _estimate_card_chars(tool)
    if estimated > config.max_card_chars:
        issues.append(
            Issue(
                code="TOOL_CARD_TOO_LARGE",
                severity="warning",
                path="$",
                message=f"Tool card is about {estimated} characters.",
                recommendation="Reduce verbose descriptions or split complex tools; large tool cards increase model context cost.",
            )
        )


def _duplicate_names(tools: list[ToolCard]) -> set[str]:
    counts = Counter(tool.name for tool in tools)
    return {name for name, count in counts.items() if count > 1}


def _risk_categories(tool: ToolCard, text_blob: str) -> set[str]:
    name_categories = {
        category
        for category, pattern in RISK_PATTERNS.items()
        if pattern.search(tool.name)
    }
    categories = name_categories | {
        category
        for category, pattern in RISK_PATTERNS.items()
        if pattern.search(text_blob)
    }
    description = tool.description or ""
    read_only_declared = (
        tool.annotations.get("readOnlyHint") is True
        or re.search(r"\bread[- ]only\b|does not modify|do not (?:modify|write|delete)", description, re.IGNORECASE)
        is not None
    )
    if read_only_declared:
        for category in ("write", "financial", "network"):
            if category not in name_categories:
                categories.discard(category)
    return categories


def _risk_level(risk_categories: set[str], issues: list[Issue]) -> str:
    if any(issue.severity == "critical" for issue in issues):
        return "critical"
    if {"destructive", "financial", "secret"} & risk_categories:
        return "high"
    if {"write", "network"} & risk_categories:
        return "medium"
    if risk_categories:
        return "low"
    return "low"


def _is_side_effect_risk(risk_categories: set[str]) -> bool:
    return bool(risk_categories & {"destructive", "write", "financial", "network"})


def _score(issues: list[Issue]) -> int:
    penalty = sum(SEVERITY_WEIGHTS[issue.severity] for issue in issues)
    return max(0, 100 - penalty)


def _recommendations(
    tool: ToolCard, risk_categories: set[str], issues: list[Issue]
) -> list[str]:
    recommendations: list[str] = []
    codes = {issue.code for issue in issues}
    if "GENERIC_TOOL_NAME" in codes:
        recommendations.append("Rename the tool to an action_domain form such as send_email or search_orders.")
    if "MISSING_DESCRIPTION" in codes or "DESCRIPTION_TOO_SHORT" in codes:
        recommendations.append("Expand the description with purpose, usage boundary, important inputs, outputs, and side effects.")
    if any(code.startswith("MISSING_INPUTSCHEMA") or code == "ROOT_SCHEMA_NOT_OBJECT" for code in codes):
        recommendations.append("Publish a strict object inputSchema with documented properties and required fields.")
    if "MISSING_OUTPUTSCHEMA" in codes:
        recommendations.append("Add outputSchema for structured outputs when callers need deterministic parsing.")
    if _is_side_effect_risk(risk_categories):
        recommendations.append("Require human approval before calling this tool in production clients.")
    if any(code.startswith("TOOL_POISONING") for code in codes):
        recommendations.append("Block this tool until the server owner removes instruction-like or secret-seeking metadata.")
    if not recommendations:
        recommendations.append("No blocking issue detected; keep examples and runtime behavior aligned with the card.")
    return recommendations


def _estimate_card_chars(tool: ToolCard) -> int:
    pieces = [
        tool.name,
        tool.description or "",
        repr(tool.input_schema or {}),
        repr(tool.output_schema or {}),
        repr(tool.annotations or {}),
    ]
    return sum(len(piece) for piece in pieces)


def _summarize(
    source_summaries: list[dict[str, Any]], tool_reports: list[ToolReport]
) -> dict[str, Any]:
    severity_counts: dict[str, int] = defaultdict(int)
    risk_counts: dict[str, int] = defaultdict(int)
    for report in tool_reports:
        risk_counts[report.risk_level] += 1
        for issue in report.issues:
            severity_counts[issue.severity] += 1

    average_score = (
        round(sum(report.score for report in tool_reports) / len(tool_reports), 2)
        if tool_reports
        else 0
    )
    include_by_default = [
        report.tool_name
        for report in tool_reports
        if report.score >= 80 and report.risk_level in {"low"}
    ]
    require_approval = [
        report.tool_name
        for report in tool_reports
        if report.risk_level in {"medium", "high"}
    ]
    block_until_review = [
        report.tool_name
        for report in tool_reports
        if report.risk_level == "critical"
        or any(issue.severity == "critical" for issue in report.issues)
    ]

    source_errors = sum(len(source["errors"]) for source in source_summaries)
    return {
        "sources_scanned": len(source_summaries),
        "source_errors": source_errors,
        "tools_scanned": len(tool_reports),
        "score": average_score,
        "issues_by_severity": {
            severity: severity_counts.get(severity, 0)
            for severity in ("critical", "error", "warning", "info")
        },
        "risk_counts": {
            risk: risk_counts.get(risk, 0)
            for risk in ("critical", "high", "medium", "low")
        },
        "allowed_tools_recommendation": {
            "include_by_default": include_by_default,
            "require_approval": require_approval,
            "block_until_review": block_until_review,
        },
    }


def _trim(value: str, limit: int = 240) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    return value if len(value) <= limit else value[: limit - 3] + "..."

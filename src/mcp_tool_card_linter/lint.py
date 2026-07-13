from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import uuid
from collections import Counter, defaultdict
from datetime import UTC, datetime
from functools import lru_cache
from typing import Any, Iterable, Iterator, Mapping, TypeGuard
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from . import __version__
from .models import (
    Issue,
    BaselineStatus,
    LintConfig,
    LintReport,
    Severity,
    SEVERITY_WEIGHTS,
    SourceResult,
    ToolCard,
    ToolReport,
)
from .policy import PolicyConfig
from .security import safe_log_text

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

COMMAND_PARAM_TERMS = re.compile(
    r"(?:^|_)(?:cmd|command|shell|script|code|sql|expression|executable)(?:_|$)",
    re.IGNORECASE,
)
URL_PARAM_TERMS = re.compile(
    r"(?:^|_)(?:url|uri|endpoint|webhook|callback|redirect)(?:_|$)",
    re.IGNORECASE,
)
PATH_PARAM_TERMS = re.compile(
    r"(?:^|_)(?:path|file|filename|directory|folder|cwd)(?:_|$)",
    re.IGNORECASE,
)
SECRET_PARAM_TERMS = re.compile(
    r"(?:^|_)(?:secret|token|password|passwd|credential|api_key|private_key)(?:_|$)",
    re.IGNORECASE,
)
HIDDEN_UNICODE = re.compile("[\u200b-\u200f\u202a-\u202e\u2060\u2066-\u2069\ufeff]")
LONG_ENCODED_BLOB = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{120,}={0,2}(?![A-Za-z0-9+/])")
CREDENTIAL_LITERAL = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})\b"
)
MAX_METADATA_SECURITY_FINDINGS = 64
MAX_METADATA_SCAN_CHARS = 2_000_000
MAX_TOOL_ICONS = 16
MAX_ICON_SRC_CHARS = 128_000
MAX_ICON_SIZES = 32
MAX_ISSUES_PER_TOOL = 1_000
PERMISSIVE_PATTERNS = {".*", "^.*$", ".+", "^.+$", "[\\s\\S]*", "^[\\s\\S]*$"}
NESTED_REGEX_QUANTIFIER = re.compile(
    r"\((?:[^()\\]|\\.)*(?:\*|\+|\{\d+,?\d*\})(?:[^()\\]|\\.)*\)"
    r"(?:\*|\+|\{\d+,?\d*\})"
)

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
    "code_execution": re.compile(
        r"\b(shell|command|script|execute code|eval|sql|subprocess|terminal)\b",
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
    (
        "TOOL_POISONING_TOOL_COERCION",
        "error",
        re.compile(
            r"\b(always|must|mandatory|before (?:answering|responding)|first)\b.{0,100}"
            r"\b(call|invoke|use|execute)\b.{0,80}\b(tool|function|command)\b",
            re.IGNORECASE | re.DOTALL,
        ),
        "Remove instructions that coerce unrelated tool calls; describe capability and usage boundaries instead.",
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


class _BoundedIssueList(list[Issue]):
    """Reserve the final slot for an explicit truncation finding."""

    def append(self, issue: Issue) -> None:
        if len(self) < MAX_ISSUES_PER_TOOL - 1:
            super().append(issue)
            return
        if len(self) == MAX_ISSUES_PER_TOOL - 1:
            super().append(
                Issue(
                    code="FINDING_LIMIT_REACHED",
                    severity="error",
                    path="$",
                    message=(
                        f"Tool produced at least {MAX_ISSUES_PER_TOOL} findings; "
                        "additional findings were omitted."
                    ),
                    recommendation=(
                        "Reduce the tool-card/schema size, fix the reported structural "
                        "errors, and scan again before approval."
                    ),
                )
            )


def lint_sources(
    sources: Iterable[SourceResult],
    config: LintConfig,
    *,
    baseline_fingerprints: Mapping[tuple[str, str], str] | None = None,
    policy: PolicyConfig | None = None,
    deterministic: bool = False,
) -> LintReport:
    source_list = list(sources)
    policy_config = policy or PolicyConfig()
    tool_reports: list[ToolReport] = []
    source_summaries: list[dict[str, Any]] = []
    suppressed_findings: list[dict[str, str]] = []
    expired_suppressions: list[dict[str, str]] = []

    bounded_by_source = {
        id(source): source.tools[: config.max_tools] for source in source_list
    }
    servers_by_tool_name: dict[str, set[str]] = defaultdict(set)
    for source in source_list:
        for tool in bounded_by_source[id(source)]:
            if not tool.name.startswith("<unnamed-"):
                servers_by_tool_name[tool.name].add(source.server_name)
    cross_server_names = {
        name for name, server_names in servers_by_tool_name.items() if len(server_names) > 1
    }

    for source in source_list:
        bounded_tools = bounded_by_source[id(source)]
        discovered_tools = (
            source.discovered_tools
            if source.discovered_tools is not None
            else len(source.tools)
        )
        duplicate_names = _duplicate_names(bounded_tools)
        for tool in bounded_tools:
            tool_reports.append(
                _lint_tool(
                    tool,
                    duplicate_names,
                    cross_server_names,
                    config,
                    baseline_fingerprints,
                    policy_config,
                    suppressed_findings,
                    expired_suppressions,
                )
            )
        source_summaries.append(
            {
                "server_name": source.server_name,
                "source_type": source.source_type,
                "tools_discovered": discovered_tools,
                "tools_linted": len(bounded_tools),
                "truncated": discovered_tools > len(bounded_tools),
                "errors": source.errors,
                "metadata": source.metadata,
            }
        )

    summary = _summarize(
        source_summaries,
        tool_reports,
        baseline_fingerprints=baseline_fingerprints,
    )
    protocol = [
        {
            "server_name": source.server_name,
            "requested": source.metadata.get("protocol_requested"),
            "negotiated": source.metadata.get("protocol_negotiated"),
            "capabilities": source.metadata.get("capabilities", {}),
            "server_info": source.metadata.get("server_info", {}),
        }
        for source in source_list
        if source.metadata.get("protocol_requested") is not None
    ]
    generated_at = (
        "1970-01-01T00:00:00+00:00" if deterministic else datetime.now(UTC).isoformat()
    )
    report = LintReport(
        generated_at=generated_at,
        version=__version__,
        sources=source_summaries,
        summary=summary,
        tools=tool_reports,
        policy=policy_config.report_summary(
            suppressed=suppressed_findings,
            expired=expired_suppressions,
        ),
        protocol=protocol,
        facts=FACTS,
        inferences=INFERENCES,
        uncertainties=UNCERTAINTIES,
    )
    report.scan_id = _scan_id(report, deterministic=deterministic)
    return report


def _lint_tool(
    tool: ToolCard,
    duplicate_names: set[str],
    cross_server_names: set[str],
    config: LintConfig,
    baseline_fingerprints: Mapping[tuple[str, str], str] | None,
    policy: PolicyConfig,
    suppressed_findings: list[dict[str, str]],
    expired_suppressions: list[dict[str, str]],
) -> ToolReport:
    issues: list[Issue] = _BoundedIssueList()
    report_server_name = safe_log_text(tool.server_name, limit=512)
    report_tool_name = safe_log_text(tool.display_name, limit=512)
    canonical_card = _canonical_card_text(tool)
    estimated_card_chars = len(canonical_card)
    metadata_entries = list(_iter_model_visible_strings(tool.raw, config))
    text_blob = " ".join([tool.name, tool.description or "", *(value for _, value in metadata_entries)])
    risk_categories = _risk_categories(tool, text_blob)

    fingerprint = _card_fingerprint(canonical_card)
    baseline_status: BaselineStatus = "not_checked"
    if baseline_fingerprints is not None:
        expected = baseline_fingerprints.get((report_server_name, report_tool_name))
        if expected is None:
            baseline_status = "new"
            issues.append(
                Issue(
                    code="TOOL_CARD_NOT_IN_BASELINE",
                    severity="info",
                    path="$",
                    message="Tool card is new relative to the supplied baseline.",
                    recommendation="Review and approve the new tool before updating the trusted baseline.",
                )
            )
        elif isinstance(expected, str) and hmac.compare_digest(expected, fingerprint):
            baseline_status = "unchanged"
        else:
            baseline_status = "changed"
            risk_categories.add("integrity")
            issues.append(
                Issue(
                    code="TOOL_CARD_CHANGED",
                    severity="error",
                    path="$",
                    message="Tool metadata changed relative to the supplied baseline.",
                    recommendation="Treat this as a possible rug pull: review the diff and re-approve before updating the baseline.",
                    evidence=f"expected={str(expected)[:80]} current={fingerprint}",
                )
            )
    if tool.name in cross_server_names:
        risk_categories.add("shadowing")

    _check_raw_shape(tool, issues)
    _check_name(tool, duplicate_names, cross_server_names, issues)
    _check_description(tool, risk_categories, config, issues)
    _check_metadata_security(metadata_entries, issues)
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
    _check_card_size(estimated_card_chars, config, issues)

    application = policy.apply(
        issues,
        server=report_server_name,
        tool=report_tool_name,
    )
    issues = application.issues
    suppressed_findings.extend(application.suppressed)
    expired_suppressions.extend(application.expired)

    risk_level = _risk_level(risk_categories, issues)
    recommendations = _recommendations(tool, risk_categories, issues)
    score = _score(issues)
    return ToolReport(
        server_name=report_server_name,
        tool_name=report_tool_name,
        score=score,
        risk_level=risk_level,
        risk_categories=sorted(risk_categories),
        estimated_card_chars=estimated_card_chars,
        card_fingerprint=fingerprint,
        baseline_status=baseline_status,
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
        return

    raw = tool.raw
    if "name" in raw and not isinstance(raw["name"], str):
        issues.append(
            Issue(
                code="INVALID_TOOL_NAME_TYPE",
                severity="critical",
                path="name",
                message="Tool name must be a string.",
                recommendation="Return a non-empty string name that is stable and unique.",
            )
        )
    if "description" in raw and not isinstance(raw["description"], str):
        issues.append(
            Issue(
                code="INVALID_DESCRIPTION_TYPE",
                severity="error",
                path="description",
                message="Tool description must be a string.",
                recommendation="Return model-visible descriptions as bounded UTF-8 strings.",
            )
        )
    for canonical, alias in (("inputSchema", "input_schema"), ("outputSchema", "output_schema")):
        key = canonical if canonical in raw else alias if alias in raw else None
        if key is not None and not isinstance(raw[key], dict):
            issues.append(
                Issue(
                    code=f"INVALID_{canonical.upper()}_TYPE",
                    severity="error",
                    path=key,
                    message=f"{canonical} must be a JSON object.",
                    recommendation="Publish a JSON Schema object rather than a scalar or array.",
                )
            )
    if "annotations" in raw and not isinstance(raw["annotations"], dict):
        issues.append(
            Issue(
                code="INVALID_ANNOTATIONS_TYPE",
                severity="error",
                path="annotations",
                message="Tool annotations must be an object.",
                recommendation="Return annotation hints in an object with boolean hint values.",
            )
        )
    if "title" in raw and not isinstance(raw["title"], str):
        issues.append(
            Issue(
                code="INVALID_TITLE_TYPE",
                severity="warning",
                path="title",
                message="Tool title must be a string.",
                recommendation="Use a short human-readable title or omit it.",
            )
        )
    _check_icons(raw.get("icons"), issues)


def _check_icons(value: Any, issues: list[Issue]) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        issues.append(
            Issue(
                code="INVALID_TOOL_ICONS",
                severity="error",
                path="icons",
                message="Tool icons must be an array.",
                recommendation="Publish a bounded array of MCP Icon objects or omit icons.",
            )
        )
        return
    if len(value) > MAX_TOOL_ICONS:
        issues.append(
            Issue(
                code="TOO_MANY_TOOL_ICONS",
                severity="warning",
                path="icons",
                message=f"Tool exposes more than {MAX_TOOL_ICONS} icons.",
                recommendation="Keep only the bounded icon variants clients actually need.",
            )
        )
    for index, icon in enumerate(value[:MAX_TOOL_ICONS]):
        path = f"icons[{index}]"
        if not isinstance(icon, dict):
            issues.append(
                Issue(
                    code="INVALID_TOOL_ICONS",
                    severity="error",
                    path=path,
                    message="Each tool icon must be an object.",
                    recommendation="Use an Icon object with src and optional mimeType, sizes, and theme.",
                )
            )
            continue
        src = icon.get("src")
        valid_src = False
        if isinstance(src, str) and 1 <= len(src) <= MAX_ICON_SRC_CHARS:
            try:
                parsed = urlsplit(src)
                valid_src = parsed.scheme in {"http", "https", "data"}
                if parsed.scheme in {"http", "https"}:
                    valid_src = bool(parsed.hostname) and parsed.username is None and parsed.password is None
                elif parsed.scheme == "data":
                    header = src.partition(",")[0].lower()
                    valid_src = ";base64" in header and header.startswith("data:image/")
            except ValueError:
                valid_src = False
        if not valid_src:
            issues.append(
                Issue(
                    code="INVALID_TOOL_ICON_SRC",
                    severity="error",
                    path=f"{path}.src",
                    message="Icon src must be a bounded HTTP(S) URI or base64 image data URI without credentials.",
                    recommendation="Use a same-origin HTTPS image URL or a bounded base64 data URI.",
                )
            )
        mime_type = icon.get("mimeType")
        if mime_type is not None and (
            not isinstance(mime_type, str)
            or not re.fullmatch(r"image/[A-Za-z0-9.+-]{1,64}", mime_type)
        ):
            issues.append(
                Issue(
                    code="INVALID_TOOL_ICON_MIME_TYPE",
                    severity="warning",
                    path=f"{path}.mimeType",
                    message="Icon mimeType is not a bounded image media type.",
                    recommendation="Use image/png, image/jpeg, image/webp, image/svg+xml, or omit mimeType.",
                )
            )
        sizes = icon.get("sizes")
        if sizes is not None and (
            not isinstance(sizes, list)
            or len(sizes) > MAX_ICON_SIZES
            or any(
                not isinstance(size, str)
                or not re.fullmatch(r"(?:any|[1-9][0-9]{0,4}x[1-9][0-9]{0,4})", size)
                for size in sizes
            )
        ):
            issues.append(
                Issue(
                    code="INVALID_TOOL_ICON_SIZE",
                    severity="warning",
                    path=f"{path}.sizes",
                    message="Icon sizes must be a bounded array of WxH values or 'any'.",
                    recommendation="Use values such as 48x48, 96x96, or any for scalable icons.",
                )
            )
        theme = icon.get("theme")
        if theme is not None and theme not in {"light", "dark"}:
            issues.append(
                Issue(
                    code="INVALID_TOOL_ICONS",
                    severity="warning",
                    path=f"{path}.theme",
                    message="Icon theme must be light or dark.",
                    recommendation="Use a standardized theme value or omit it.",
                )
            )


def _check_name(
    tool: ToolCard,
    duplicate_names: set[str],
    cross_server_names: set[str],
    issues: list[Issue],
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

    if not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?", name):
        issues.append(
            Issue(
                code="TOOL_NAME_SPEC_VIOLATION",
                severity="warning",
                path="name",
                message="Tool name does not follow the MCP 2025-11-25 name guidance.",
                recommendation="Use ASCII letters, digits, underscores, hyphens, and dots, beginning and ending with an alphanumeric character.",
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

    if name in cross_server_names:
        issues.append(
            Issue(
                code="CROSS_SERVER_TOOL_SHADOWING",
                severity="warning",
                path="name",
                message=f"Tool name '{name}' is exposed by more than one server.",
                recommendation="Use server-qualified policy identities and review descriptions for cross-server shadowing or escalation instructions.",
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

    if _is_side_effect_risk(risk_categories) and not SIDE_EFFECT_TERMS.search(desc):
        severity: Severity = (
            "error" if {"destructive", "financial"} & risk_categories else "warning"
        )
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


def _iter_model_visible_strings(
    raw: dict[str, Any], config: LintConfig
) -> Iterator[tuple[str, str]]:
    roots: list[tuple[str, Any, int]] = []
    for key in (
        "name",
        "title",
        "description",
        "inputSchema",
        "input_schema",
        "outputSchema",
        "output_schema",
        "annotations",
        "execution",
        "_meta",
    ):
        if key in raw:
            roots.append((key, raw[key], 0))

    stack = list(reversed(roots))
    seen_containers: set[int] = set()
    nodes = 0
    characters = 0
    node_limit = min(100_000, max(100, config.max_schema_properties * 2))
    while stack and nodes < node_limit and characters < MAX_METADATA_SCAN_CHARS:
        path, value, depth = stack.pop()
        nodes += 1
        if isinstance(value, str):
            remaining = MAX_METADATA_SCAN_CHARS - characters
            bounded = value[:remaining]
            characters += len(bounded)
            yield path, bounded
            continue
        if depth > config.max_schema_depth + 2:
            continue
        if isinstance(value, dict):
            identity = id(value)
            if identity in seen_containers:
                continue
            seen_containers.add(identity)
            entries = list(value.items())
            for key, child in reversed(entries):
                child_path = f"{path}.{key}"
                # Property names and annotation keys are model-visible attack surface too.
                yield f"{child_path}#key", str(key)
                stack.append((child_path, child, depth + 1))
        elif isinstance(value, list):
            identity = id(value)
            if identity in seen_containers:
                continue
            seen_containers.add(identity)
            for index in range(len(value) - 1, -1, -1):
                stack.append((f"{path}[{index}]", value[index], depth + 1))


def _check_metadata_security(
    entries: list[tuple[str, str]], issues: list[Issue]
) -> None:
    findings = 0
    seen: set[tuple[str, str]] = set()
    for path, value in entries:
        if findings >= MAX_METADATA_SECURITY_FINDINGS:
            break
        if HIDDEN_UNICODE.search(value) and ("HIDDEN_UNICODE_CONTROL", path) not in seen:
            seen.add(("HIDDEN_UNICODE_CONTROL", path))
            issues.append(
                Issue(
                    code="HIDDEN_UNICODE_CONTROL",
                    severity="error",
                    path=path,
                    message="Model-visible metadata contains hidden or bidirectional Unicode controls.",
                    recommendation="Remove zero-width and bidi control characters so reviewers see the same text as the model.",
                )
            )
            findings += 1
        if CREDENTIAL_LITERAL.search(value) and ("HARDCODED_SECRET_IN_METADATA", path) not in seen:
            seen.add(("HARDCODED_SECRET_IN_METADATA", path))
            issues.append(
                Issue(
                    code="HARDCODED_SECRET_IN_METADATA",
                    severity="critical",
                    path=path,
                    message="Model-visible metadata appears to contain a live credential.",
                    recommendation="Revoke the credential, remove it from metadata, and use scoped secret storage.",
                    evidence="credential-like value redacted",
                )
            )
            findings += 1
        if LONG_ENCODED_BLOB.search(value) and ("OBFUSCATED_METADATA", path) not in seen:
            seen.add(("OBFUSCATED_METADATA", path))
            issues.append(
                Issue(
                    code="OBFUSCATED_METADATA",
                    severity="warning",
                    path=path,
                    message="Model-visible metadata contains a long encoded-looking blob.",
                    recommendation="Remove opaque payloads and keep tool metadata directly reviewable.",
                )
            )
            findings += 1
        for code, severity, pattern, recommendation in TOOL_POISONING_PATTERNS:
            match = pattern.search(value)
            if not match or (code, path) in seen:
                continue
            seen.add((code, path))
            issues.append(
                Issue(
                    code=code,
                    severity=severity,  # type: ignore[arg-type]
                    path=path,
                    message="Model-visible metadata contains instruction-like or secret-seeking text that may poison tool selection.",
                    recommendation=recommendation,
                    evidence=_trim(match.group(0)),
                )
            )
            findings += 1
            if findings >= MAX_METADATA_SECURITY_FINDINGS:
                break


def _check_schema(
    schema: Any,
    path: str,
    *,
    required: bool,
    config: LintConfig,
    issues: list[Issue],
    check_parameter_quality: bool,
) -> None:
    if schema is None:
        severity: Severity = "error" if required else "warning"
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

    if _schema_within_meta_validation_budget(schema, config):
        try:
            schema_text = json.dumps(
                schema,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
            validation_error = _metaschema_validation_error(schema_text)
        except (TypeError, ValueError, RecursionError):
            validation_error = (
                "Schema could not be represented as strict JSON for metaschema validation.",
                "",
            )
        if validation_error is not None:
            error_message, schema_path = validation_error
            issues.append(
                Issue(
                    code="INVALID_JSON_SCHEMA_2020_12",
                    severity="error",
                    path=f"{path}.{schema_path}" if schema_path else path,
                    message="Schema does not conform to the JSON Schema 2020-12 metaschema.",
                    recommendation="Correct the schema using a Draft 2020-12 validator before publishing it.",
                    evidence=_trim(safe_log_text(error_message, limit=500)),
                )
            )
    else:
        issues.append(
            Issue(
                code="SCHEMA_META_VALIDATION_SKIPPED",
                severity="info",
                path=path,
                message="Draft 2020-12 metaschema validation was skipped because the schema exceeds the configured traversal budget.",
                recommendation="Reduce schema complexity, then validate it with the complete metaschema validator.",
            )
        )

    state = {
        "count": 0,
        "depth_issue": False,
        "property_limit_issue": False,
        "seen": set(),
    }
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


def _schema_within_meta_validation_budget(schema: dict[str, Any], config: LintConfig) -> bool:
    stack: list[tuple[Any, int]] = [(schema, 0)]
    seen: set[int] = set()
    count = 0
    while stack:
        value, depth = stack.pop()
        if depth > config.max_schema_depth:
            return False
        if isinstance(value, (dict, list)):
            identity = id(value)
            if identity in seen:
                continue
            seen.add(identity)
            count += 1
            if count > config.max_schema_properties:
                return False
            children = value.values() if isinstance(value, dict) else value
            stack.extend((child, depth + 1) for child in children)
    return True


@lru_cache(maxsize=1024)
def _metaschema_validation_error(schema_text: str) -> tuple[str, str] | None:
    schema = json.loads(schema_text)
    try:
        Draft202012Validator.check_schema(schema)
    except SchemaError as exc:
        path = ".".join(str(part) for part in exc.absolute_schema_path)
        return exc.message, path
    return None


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
    if isinstance(schema, bool):
        return
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

    identity = id(schema)
    if identity in state["seen"]:
        return
    state["seen"].add(identity)

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
    allowed_types = {"null", "boolean", "object", "array", "number", "string", "integer"}
    schema_types: set[str] = set()
    if isinstance(schema_type, str):
        if schema_type in allowed_types:
            schema_types.add(schema_type)
        else:
            issues.append(
                Issue(
                    code="INVALID_SCHEMA_TYPE",
                    severity="error",
                    path=f"{path}.type",
                    message=f"Unknown JSON Schema type '{schema_type}'.",
                    recommendation="Use a standard JSON Schema type.",
                )
            )
    elif isinstance(schema_type, list):
        if not schema_type or any(
            not isinstance(item, str) or item not in allowed_types for item in schema_type
        ):
            issues.append(
                Issue(
                    code="INVALID_SCHEMA_TYPE",
                    severity="error",
                    path=f"{path}.type",
                    message="Schema type arrays must contain one or more unique standard type names.",
                    recommendation="Remove invalid type names and duplicates.",
                )
            )
        else:
            schema_types.update(schema_type)
            if len(schema_types) != len(schema_type):
                issues.append(
                    Issue(
                        code="DUPLICATE_SCHEMA_TYPE",
                        severity="warning",
                        path=f"{path}.type",
                        message="Schema type array contains duplicate entries.",
                        recommendation="Remove duplicate type names.",
                    )
                )
    elif schema_type is not None:
        issues.append(
            Issue(
                code="INVALID_SCHEMA_TYPE",
                severity="error",
                path=f"{path}.type",
                message="Schema type must be a string or an array of strings.",
                recommendation="Use a standard JSON Schema type name.",
            )
        )

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

    if is_root and schema_type is not None and schema_type != "object" and not has_composition:
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

    schema_uri = schema.get("$schema")
    if schema_uri is not None:
        if not isinstance(schema_uri, str):
            issues.append(
                Issue(
                    code="INVALID_SCHEMA_DIALECT",
                    severity="error",
                    path=f"{path}.$schema",
                    message="$schema must be a URI string.",
                    recommendation="Use the JSON Schema 2020-12 dialect URI or omit it to use the MCP default.",
                )
            )
        elif not is_root:
            issues.append(
                Issue(
                    code="NESTED_SCHEMA_DIALECT",
                    severity="warning",
                    path=f"{path}.$schema",
                    message="$schema appears below the root schema.",
                    recommendation="Declare the JSON Schema dialect at the root.",
                )
            )

    ref = schema.get("$ref")
    if ref is not None:
        if not isinstance(ref, str):
            issues.append(
                Issue(
                    code="INVALID_SCHEMA_REF",
                    severity="error",
                    path=f"{path}.$ref",
                    message="$ref must be a string.",
                    recommendation="Use a local JSON Pointer reference or inline the schema.",
                )
            )
        elif not ref.startswith("#"):
            issues.append(
                Issue(
                    code="EXTERNAL_SCHEMA_REF",
                    severity="error",
                    path=f"{path}.$ref",
                    message="Schema uses a non-local reference that may trigger remote retrieval or inconsistent resolution.",
                    recommendation="Bundle referenced definitions under $defs and use a local #/$defs/... reference.",
                    evidence=_trim(ref),
                )
            )

    _check_schema_bounds(schema, path, issues)
    _check_schema_annotation_types(schema, path, issues)

    if "object" in schema_types or schema_type == "object" or "properties" in schema:
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
                        severity="warning" if check_parameter_quality else "info",
                        path=f"{path}.additionalProperties",
                        message="Object schema does not state whether extra parameters are allowed.",
                        recommendation="Set additionalProperties to false for strict tool arguments unless arbitrary keys are intentional.",
                    )
                )
            for prop_name, prop_schema in properties.items():
                if not isinstance(prop_name, str):
                    issues.append(
                        Issue(
                            code="INVALID_PROPERTY_NAME",
                            severity="error",
                            path=f"{path}.properties",
                            message="Schema property names must be strings.",
                            recommendation="Use bounded string property names.",
                        )
                    )
                    continue
                if len(prop_name) > 256 or any(ord(character) < 32 for character in prop_name):
                    issues.append(
                        Issue(
                            code="UNSAFE_PROPERTY_NAME",
                            severity="error",
                            path=f"{path}.properties",
                            message="Schema property name is too long or contains control characters.",
                            recommendation="Use concise, visible parameter names without controls.",
                            evidence=_trim(prop_name),
                        )
                    )
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

        additional = schema.get("additionalProperties")
        if additional is True and check_parameter_quality:
            issues.append(
                Issue(
                    code="ADDITIONAL_PROPERTIES_ALLOWED",
                    severity="warning",
                    path=f"{path}.additionalProperties",
                    message="Input object explicitly accepts arbitrary extra parameters.",
                    recommendation="Set additionalProperties to false or provide a restrictive schema for intentional extension fields.",
                )
            )
        elif additional is not None and not isinstance(additional, (bool, dict)):
            issues.append(
                Issue(
                    code="INVALID_ADDITIONAL_PROPERTIES",
                    severity="error",
                    path=f"{path}.additionalProperties",
                    message="additionalProperties must be a boolean or schema object.",
                    recommendation="Use false for strict objects or provide a schema for extra values.",
                )
            )
        elif isinstance(additional, dict):
            if check_parameter_quality and not additional:
                issues.append(
                    Issue(
                        code="ADDITIONAL_PROPERTIES_SCHEMA_BROAD",
                        severity="warning",
                        path=f"{path}.additionalProperties",
                        message="Input object allows arbitrary extra values through an empty schema.",
                        recommendation="Set additionalProperties to false or define a restrictive value schema.",
                    )
                )
            _walk_schema(
                additional,
                f"{path}.additionalProperties",
                depth=depth + 1,
                config=config,
                issues=issues,
                state=state,
                check_parameter_quality=check_parameter_quality,
            )

    if "array" in schema_types or schema_type == "array":
        if check_parameter_quality and "maxItems" not in schema:
            issues.append(
                Issue(
                    code="ARRAY_BOUND_RECOMMENDED",
                    severity="warning",
                    path=path,
                    message="Input array has no maxItems bound.",
                    recommendation="Add maxItems to constrain request size and downstream work.",
                )
            )
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

    for key in ("not", "if", "then", "else", "contains", "propertyNames", "unevaluatedProperties"):
        if key not in schema:
            continue
        subschema = schema[key]
        if not isinstance(subschema, (dict, bool)):
            issues.append(
                Issue(
                    code="INVALID_SUBSCHEMA",
                    severity="error",
                    path=f"{path}.{key}",
                    message=f"{key} must contain a schema.",
                    recommendation="Use a JSON Schema object or boolean schema.",
                )
            )
            continue
        _walk_schema(
            subschema,
            f"{path}.{key}",
            depth=depth + 1,
            config=config,
            issues=issues,
            state=state,
            check_parameter_quality=check_parameter_quality,
        )

    prefix_items = schema.get("prefixItems")
    if prefix_items is not None:
        if not isinstance(prefix_items, list):
            issues.append(
                Issue(
                    code="INVALID_PREFIX_ITEMS",
                    severity="error",
                    path=f"{path}.prefixItems",
                    message="prefixItems must be an array of schemas.",
                    recommendation="Provide bounded tuple item schemas.",
                )
            )
        else:
            for index, subschema in enumerate(prefix_items):
                _walk_schema(
                    subschema,
                    f"{path}.prefixItems[{index}]",
                    depth=depth + 1,
                    config=config,
                    issues=issues,
                    state=state,
                    check_parameter_quality=check_parameter_quality,
                )

    for key in ("$defs", "definitions", "patternProperties", "dependentSchemas"):
        mapping = schema.get(key)
        if mapping is None:
            continue
        if not isinstance(mapping, dict):
            issues.append(
                Issue(
                    code="INVALID_SCHEMA_MAP",
                    severity="error",
                    path=f"{path}.{key}",
                    message=f"{key} must be an object mapping names to schemas.",
                    recommendation="Use schema objects for every mapped entry.",
                )
            )
            continue
        for name, subschema in mapping.items():
            if key == "patternProperties" and isinstance(name, str):
                _check_regex_risk(name, f"{path}.{key}.{name}#key", issues)
            _walk_schema(
                subschema,
                f"{path}.{key}.{name}",
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


def _check_schema_bounds(
    schema: dict[str, Any], path: str, issues: list[Issue]
) -> None:
    numeric_keywords = ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum")
    for key in numeric_keywords:
        if key not in schema:
            continue
        value = schema[key]
        if not _is_finite_number(value):
            issues.append(
                Issue(
                    code="INVALID_NUMERIC_BOUND",
                    severity="error",
                    path=f"{path}.{key}",
                    message=f"{key} must be a finite number.",
                    recommendation="Use a finite JSON number for numeric bounds.",
                )
            )

    lower = schema.get("minimum")
    upper = schema.get("maximum")
    if _is_finite_number(lower) and _is_finite_number(upper) and lower > upper:
        issues.append(
            Issue(
                code="INVERTED_NUMERIC_BOUNDS",
                severity="error",
                path=path,
                message="minimum is greater than maximum.",
                recommendation="Correct the numeric interval so at least one value can satisfy it.",
            )
        )
    exclusive_lower = schema.get("exclusiveMinimum")
    exclusive_upper = schema.get("exclusiveMaximum")
    if (
        _is_finite_number(exclusive_lower)
        and _is_finite_number(exclusive_upper)
        and exclusive_lower >= exclusive_upper
    ):
        issues.append(
            Issue(
                code="INVERTED_NUMERIC_BOUNDS",
                severity="error",
                path=path,
                message="exclusiveMinimum is not less than exclusiveMaximum.",
                recommendation="Correct the exclusive numeric interval.",
            )
        )

    if "multipleOf" in schema and (
        not _is_finite_number(schema["multipleOf"]) or schema["multipleOf"] <= 0
    ):
        issues.append(
            Issue(
                code="INVALID_MULTIPLE_OF",
                severity="error",
                path=f"{path}.multipleOf",
                message="multipleOf must be a finite number greater than zero.",
                recommendation="Use a positive divisor.",
            )
        )

    integer_bounds = (
        "minLength",
        "maxLength",
        "minItems",
        "maxItems",
        "minProperties",
        "maxProperties",
        "minContains",
        "maxContains",
    )
    for key in integer_bounds:
        if key not in schema:
            continue
        value = schema[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            issues.append(
                Issue(
                    code="INVALID_SIZE_BOUND",
                    severity="error",
                    path=f"{path}.{key}",
                    message=f"{key} must be a non-negative integer.",
                    recommendation="Use a bounded non-negative integer.",
                )
            )
        elif key.startswith("max") and value > 1_000_000:
            issues.append(
                Issue(
                    code="INEFFECTIVE_SIZE_BOUND",
                    severity="warning",
                    path=f"{path}.{key}",
                    message=f"{key} is so large that it provides little practical resource protection.",
                    recommendation="Choose a limit based on actual downstream capacity and model context budgets.",
                )
            )
    for minimum_key, maximum_key in (
        ("minLength", "maxLength"),
        ("minItems", "maxItems"),
        ("minProperties", "maxProperties"),
        ("minContains", "maxContains"),
    ):
        minimum = schema.get(minimum_key)
        maximum = schema.get(maximum_key)
        if (
            isinstance(minimum, int)
            and not isinstance(minimum, bool)
            and isinstance(maximum, int)
            and not isinstance(maximum, bool)
            and minimum > maximum
        ):
            issues.append(
                Issue(
                    code="INVERTED_SIZE_BOUNDS",
                    severity="error",
                    path=path,
                    message=f"{minimum_key} is greater than {maximum_key}.",
                    recommendation="Correct the size interval so valid values can satisfy it.",
                )
            )

    if "uniqueItems" in schema and not isinstance(schema["uniqueItems"], bool):
        issues.append(
            Issue(
                code="INVALID_UNIQUE_ITEMS",
                severity="error",
                path=f"{path}.uniqueItems",
                message="uniqueItems must be boolean.",
                recommendation="Use true or false.",
            )
        )
    if "pattern" in schema:
        pattern = schema["pattern"]
        if not isinstance(pattern, str):
            issues.append(
                Issue(
                    code="INVALID_PATTERN",
                    severity="error",
                    path=f"{path}.pattern",
                    message="pattern must be a string.",
                    recommendation="Use an ECMA-262-compatible regular expression string.",
                )
            )
        elif len(pattern) > 2000:
            issues.append(
                Issue(
                    code="PATTERN_TOO_LONG",
                    severity="warning",
                    path=f"{path}.pattern",
                    message="Schema regular expression is unusually long.",
                    recommendation="Simplify and benchmark the pattern to reduce ReDoS and interoperability risk.",
                )
            )
        elif pattern.strip() in PERMISSIVE_PATTERNS:
            issues.append(
                Issue(
                    code="PERMISSIVE_PATTERN",
                    severity="warning",
                    path=f"{path}.pattern",
                    message="Schema pattern accepts effectively arbitrary text.",
                    recommendation="Use an allowlist-oriented pattern that constrains the intended syntax.",
                )
            )
        else:
            _check_regex_risk(pattern, f"{path}.pattern", issues)
    if "format" in schema and not isinstance(schema["format"], str):
        issues.append(
            Issue(
                code="INVALID_FORMAT",
                severity="error",
                path=f"{path}.format",
                message="format must be a string annotation.",
                recommendation="Use a standard format name or omit the keyword.",
            )
        )


def _check_schema_annotation_types(
    schema: dict[str, Any], path: str, issues: list[Issue]
) -> None:
    for key in ("title", "description", "$comment"):
        if key in schema and not isinstance(schema[key], str):
            issues.append(
                Issue(
                    code="INVALID_SCHEMA_ANNOTATION",
                    severity="error",
                    path=f"{path}.{key}",
                    message=f"Schema {key} annotation must be a string.",
                    recommendation="Use bounded text annotations.",
                )
            )
    for key in ("readOnly", "writeOnly", "deprecated"):
        if key in schema and not isinstance(schema[key], bool):
            issues.append(
                Issue(
                    code="INVALID_SCHEMA_ANNOTATION",
                    severity="error",
                    path=f"{path}.{key}",
                    message=f"Schema {key} annotation must be boolean.",
                    recommendation="Use true or false.",
                )
            )


def _check_regex_risk(pattern: str, path: str, issues: list[Issue]) -> None:
    if NESTED_REGEX_QUANTIFIER.search(pattern):
        issues.append(
            Issue(
                code="POTENTIAL_REDOS_PATTERN",
                severity="warning",
                path=path,
                message="Schema pattern contains nested quantifiers associated with excessive backtracking.",
                recommendation="Rewrite the expression with bounded, non-nested quantifiers and benchmark it in the target validator.",
            )
        )


def _is_finite_number(value: Any) -> TypeGuard[int | float]:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
    )


def _check_parameter(
    prop_name: str, prop_schema: Any, path: str, issues: list[Issue]
) -> None:
    if not isinstance(prop_schema, dict):
        return
    description = prop_schema.get("description")
    if not isinstance(description, str) or not description.strip():
        severity: Severity = (
            "warning" if prop_name.lower() in AMBIGUOUS_PARAM_NAMES else "info"
        )
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
        if "maxLength" not in prop_schema:
            issues.append(
                Issue(
                    code="STRING_BOUND_RECOMMENDED",
                    severity="info",
                    path=path,
                    message=f"Free-form string parameter '{prop_name}' has no maxLength.",
                    recommendation="Add maxLength when large strings could increase latency, cost, or injection risk.",
                )
            )
        pattern = prop_schema.get("pattern")
        has_constraint = (
            "enum" in prop_schema
            or "const" in prop_schema
            or (
                isinstance(pattern, str)
                and pattern.strip() not in PERMISSIVE_PATTERNS
            )
        )
        if COMMAND_PARAM_TERMS.search(lowered) and not has_constraint:
            issues.append(
                Issue(
                    code="COMMAND_PARAMETER_UNCONSTRAINED",
                    severity="error",
                    path=path,
                    message=f"Execution-like parameter '{prop_name}' accepts unconstrained free-form text.",
                    recommendation="Avoid raw command/code parameters; expose a narrow enum or structured operation schema and enforce it server-side.",
                )
            )
        if URL_PARAM_TERMS.search(lowered) and not has_constraint:
            issues.append(
                Issue(
                    code="URL_PARAMETER_ALLOWLIST_MISSING",
                    severity="warning",
                    path=path,
                    message=f"URL-like parameter '{prop_name}' has no allowlist constraint.",
                    recommendation="Constrain schemes and destinations with an allowlist and enforce SSRF protections server-side; format alone is not an allowlist.",
                )
            )
        if PATH_PARAM_TERMS.search(lowered) and not has_constraint:
            issues.append(
                Issue(
                    code="PATH_PARAMETER_CONSTRAINT_MISSING",
                    severity="warning",
                    path=path,
                    message=f"Path-like parameter '{prop_name}' has no structural constraint.",
                    recommendation="Prefer identifiers or paths rooted under an approved directory and reject traversal server-side.",
                )
            )
        if SECRET_PARAM_TERMS.search(lowered):
            issues.append(
                Issue(
                    code="SENSITIVE_PARAMETER_EXPOSED",
                    severity="warning",
                    path=path,
                    message=f"Parameter '{prop_name}' appears to carry a credential or secret.",
                    recommendation="Use server-side credential binding instead of placing secrets in model-generated tool arguments.",
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
    open_world_hint = annotations.get("openWorldHint")

    if "title" in annotations and not isinstance(annotations["title"], str):
        issues.append(
            Issue(
                code="INVALID_ANNOTATION_VALUE",
                severity="error",
                path="annotations.title",
                message="Annotation title must be a string.",
                recommendation="Use a bounded human-readable title.",
            )
        )
    for key in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
        if key in annotations and not isinstance(annotations[key], bool):
            issues.append(
                Issue(
                    code="INVALID_ANNOTATION_VALUE",
                    severity="error",
                    path=f"annotations.{key}",
                    message=f"{key} must be boolean.",
                    recommendation="Use true or false; clients must still treat annotation hints as untrusted.",
                )
            )

    if read_only_hint is True and destructive_hint is True:
        issues.append(
            Issue(
                code="ANNOTATION_CONFLICT_DESTRUCTIVE_READ_ONLY",
                severity="error",
                path="annotations",
                message="Tool is simultaneously annotated read-only and destructive.",
                recommendation="Correct the contradictory behavior hints and re-review the implementation.",
            )
        )

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

    if "network" in risk_categories and open_world_hint is False:
        issues.append(
            Issue(
                code="ANNOTATION_CONFLICT_OPEN_WORLD",
                severity="warning",
                path="annotations.openWorldHint",
                message="Network-facing metadata conflicts with openWorldHint=false.",
                recommendation="Correct the hint or explain and constrain the closed set of external entities.",
            )
        )

    execution = tool.raw.get("execution")
    if execution is not None:
        if not isinstance(execution, dict):
            issues.append(
                Issue(
                    code="INVALID_EXECUTION_METADATA",
                    severity="error",
                    path="execution",
                    message="execution metadata must be an object.",
                    recommendation="Use execution.taskSupport with an allowed value or omit execution.",
                )
            )
        else:
            task_support = execution.get("taskSupport")
            if task_support is not None and task_support not in {
                "forbidden",
                "optional",
                "required",
            }:
                issues.append(
                    Issue(
                        code="INVALID_TASK_SUPPORT",
                        severity="error",
                        path="execution.taskSupport",
                        message="taskSupport has an unsupported value.",
                        recommendation="Use forbidden, optional, or required.",
                    )
                )


def _check_card_size(estimated: int, config: LintConfig, issues: list[Issue]) -> None:
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
    if {"destructive", "financial", "secret", "code_execution", "integrity"} & risk_categories:
        return "high"
    if {"write", "network", "filesystem", "shadowing"} & risk_categories:
        return "medium"
    if risk_categories:
        return "low"
    return "low"


def _is_side_effect_risk(risk_categories: set[str]) -> bool:
    return bool(
        risk_categories
        & {"destructive", "write", "financial", "network", "code_execution"}
    )


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
    if "TOOL_CARD_CHANGED" in codes:
        recommendations.append("Block the changed card until its metadata diff is reviewed and explicitly re-approved.")
    if {
        "COMMAND_PARAMETER_UNCONSTRAINED",
        "URL_PARAMETER_ALLOWLIST_MISSING",
        "PATH_PARAMETER_CONSTRAINT_MISSING",
    } & codes:
        recommendations.append("Replace dangerous free-form inputs with bounded structured values and enforce the same policy server-side.")
    if not recommendations:
        recommendations.append("No blocking issue detected; keep examples and runtime behavior aligned with the card.")
    return recommendations


def _canonical_card_text(tool: ToolCard) -> str:
    try:
        return json.dumps(
            tool.raw,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        )
    except (TypeError, ValueError, RecursionError):
        return repr(tool.raw)


def _card_fingerprint(canonical: str) -> str:
    digest = hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()
    return f"sha256:{digest}"


def _scan_id(report: LintReport, *, deterministic: bool) -> str:
    if not deterministic:
        return f"urn:uuid:{uuid.uuid4()}"
    payload = {
        "tool_version": report.version,
        "sources": report.sources,
        "tools": [tool.to_dict() for tool in report.tools],
        "policy": report.policy,
        "protocol": report.protocol,
    }
    raw = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return f"urn:sha256:{hashlib.sha256(raw).hexdigest()}"


def _summarize(
    source_summaries: list[dict[str, Any]],
    tool_reports: list[ToolReport],
    *,
    baseline_fingerprints: Mapping[tuple[str, str], str] | None,
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
    blocked_reports = [
        report
        for report in tool_reports
        if report.risk_level == "critical"
        or any(
            issue.severity == "critical" or issue.code == "TOOL_CARD_CHANGED"
            for issue in report.issues
        )
    ]
    blocked_identities = {(report.server_name, report.tool_name) for report in blocked_reports}
    require_approval = [
        report.tool_name
        for report in tool_reports
        if report.risk_level in {"medium", "high"}
        and (report.server_name, report.tool_name) not in blocked_identities
    ]
    block_until_review = [
        report.tool_name for report in blocked_reports
    ]

    source_errors = sum(len(source["errors"]) for source in source_summaries)
    current_identities = {(report.server_name, report.tool_name) for report in tool_reports}
    baseline_summary = {
        "checked": baseline_fingerprints is not None,
        "unchanged": sum(report.baseline_status == "unchanged" for report in tool_reports),
        "changed": sum(report.baseline_status == "changed" for report in tool_reports),
        "new": sum(report.baseline_status == "new" for report in tool_reports),
        "missing": (
            len(set(baseline_fingerprints) - current_identities)
            if baseline_fingerprints is not None
            else 0
        ),
    }
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
        "baseline": baseline_summary,
        "allowed_tools_recommendation": {
            "include_by_default": include_by_default,
            "require_approval": require_approval,
            "block_until_review": block_until_review,
        },
    }


def _trim(value: str, limit: int = 240) -> str:
    value = re.sub(r"\s+", " ", value).strip()
    return value if len(value) <= limit else value[: limit - 3] + "..."

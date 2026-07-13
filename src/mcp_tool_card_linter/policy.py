from __future__ import annotations

import fnmatch
import os
import re
import stat
import tomllib
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Iterable, Mapping

from .models import Issue, SEVERITY_ORDER, Severity
from .rules import KNOWN_RULE_IDS, rule_metadata
from .security import InputValidationError, safe_log_text

MAX_POLICY_BYTES = 1 * 1024 * 1024
MAX_POLICY_PATTERNS = 512
MAX_SUPPRESSIONS = 512
MAX_POLICY_TEXT = 2048
PROFILES = {"production", "strict", "security", "spec", "compatibility"}
FAIL_ON_VALUES = {*SEVERITY_ORDER, "never"}
_RULE_PATTERN = re.compile(r"(?:\*|[A-Z][A-Z0-9_]*\*?)\Z")
_IDENTITY_PATTERN = re.compile(r"[A-Za-z0-9_.:/@*?-]{1,512}\Z")


class PolicyError(InputValidationError):
    """Raised when a policy is malformed or unsafe to apply."""


@dataclass(frozen=True, slots=True)
class Suppression:
    server: str
    tool: str
    rule: str
    reason: str
    owner: str
    expires: date
    path: str | None = None

    def matches(self, *, server: str, tool: str, issue: Issue) -> bool:
        return (
            fnmatch.fnmatchcase(server, self.server)
            and fnmatch.fnmatchcase(tool, self.tool)
            and fnmatch.fnmatchcase(issue.code, self.rule)
            and (self.path is None or fnmatch.fnmatchcase(issue.path, self.path))
        )


@dataclass(frozen=True, slots=True)
class PolicyApplication:
    issues: list[Issue]
    suppressed: list[dict[str, str]]
    expired: list[dict[str, str]]


@dataclass(frozen=True, slots=True)
class PolicyConfig:
    profile: str = "production"
    select: tuple[str, ...] = ()
    ignore: tuple[str, ...] = ()
    severity_overrides: tuple[tuple[str, Severity], ...] = ()
    suppressions: tuple[Suppression, ...] = ()
    fail_on: str | None = None
    source: str | None = None

    def __post_init__(self) -> None:
        if self.profile not in PROFILES:
            raise PolicyError(f"Unknown policy profile: {safe_log_text(self.profile)}")
        _validate_patterns("select", self.select)
        _validate_patterns("ignore", self.ignore)
        if self.fail_on is not None and self.fail_on not in FAIL_ON_VALUES:
            raise PolicyError(f"Invalid policy fail-on value: {safe_log_text(self.fail_on)}")
        if len(self.severity_overrides) > MAX_POLICY_PATTERNS:
            raise PolicyError("Policy contains too many severity overrides")
        seen_rules: set[str] = set()
        for rule_id, severity in self.severity_overrides:
            if rule_id not in KNOWN_RULE_IDS:
                raise PolicyError(f"Unknown rule in severity override: {safe_log_text(rule_id)}")
            if rule_id in seen_rules:
                raise PolicyError(f"Duplicate severity override: {safe_log_text(rule_id)}")
            if severity not in SEVERITY_ORDER:
                raise PolicyError(f"Invalid severity for {safe_log_text(rule_id)}")
            seen_rules.add(rule_id)
        if len(self.suppressions) > MAX_SUPPRESSIONS:
            raise PolicyError(f"Policy has more than {MAX_SUPPRESSIONS} suppressions")

    def apply(
        self,
        issues: Iterable[Issue],
        *,
        server: str,
        tool: str,
        today: date | None = None,
    ) -> PolicyApplication:
        effective_date = today or datetime.now(UTC).date()
        severity = dict(self.severity_overrides)
        kept: list[Issue] = []
        suppressed: list[dict[str, str]] = []
        expired: list[dict[str, str]] = []
        expired_seen: set[tuple[str, str, str]] = set()

        for original in issues:
            if not self._selected(original.code):
                continue
            issue = replace(original, severity=severity.get(original.code, original.severity))
            active_match: Suppression | None = None
            for suppression in self.suppressions:
                if not suppression.matches(server=server, tool=tool, issue=issue):
                    continue
                if suppression.expires < effective_date:
                    identity = (suppression.rule, suppression.owner, suppression.expires.isoformat())
                    if identity not in expired_seen:
                        expired_seen.add(identity)
                        expired.append(_suppression_record(suppression, server, tool, issue))
                    continue
                active_match = suppression
                break
            if active_match is None:
                kept.append(issue)
            else:
                suppressed.append(_suppression_record(active_match, server, tool, issue))
        return PolicyApplication(issues=kept, suppressed=suppressed, expired=expired)

    def with_cli_overrides(
        self,
        *,
        profile: str | None = None,
        select: Iterable[str] = (),
        ignore: Iterable[str] = (),
    ) -> "PolicyConfig":
        return replace(
            self,
            profile=profile or self.profile,
            select=(*self.select, *_split_patterns(select)),
            ignore=(*self.ignore, *_split_patterns(ignore)),
        )

    def report_summary(
        self,
        *,
        suppressed: list[dict[str, str]],
        expired: list[dict[str, str]],
    ) -> dict[str, Any]:
        return {
            "profile": self.profile,
            "source": self.source,
            "select": list(self.select),
            "ignore": list(self.ignore),
            "severity_overrides": dict(self.severity_overrides),
            "suppressed_count": len(suppressed),
            "expired_suppression_count": len(expired),
            "suppressed_findings": suppressed,
            "expired_suppressions": expired,
        }

    def _selected(self, rule_id: str) -> bool:
        category = rule_metadata(rule_id).category
        profile_selected = (
            self.profile in {"production", "strict"}
            or self.profile == "security"
            and category in {"security", "integrity"}
            or self.profile == "spec"
            and category == "spec"
            or self.profile == "compatibility"
            and category in {"spec", "security", "integrity"}
        )
        selected = profile_selected
        if self.select:
            selected = any(_rule_match(rule_id, pattern) for pattern in self.select)
        if any(_rule_match(rule_id, pattern) for pattern in self.ignore):
            return False
        return selected


def load_policy(path: str | Path) -> PolicyConfig:
    resolved = _resolve_regular_file(path)
    try:
        with resolved.open("rb") as stream:
            raw = stream.read(MAX_POLICY_BYTES + 1)
    except OSError as exc:
        raise PolicyError(f"Failed to read policy: {safe_log_text(exc)}") from exc
    if len(raw) > MAX_POLICY_BYTES:
        raise PolicyError(f"Policy exceeds the {MAX_POLICY_BYTES} byte limit")
    try:
        payload = tomllib.loads(raw.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise PolicyError("Policy is not valid UTF-8") from exc
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"Invalid TOML policy: {safe_log_text(exc)}") from exc
    config = _policy_mapping(payload)
    return _policy_from_mapping(config, source=str(resolved))


def _policy_mapping(payload: Mapping[str, Any]) -> Mapping[str, Any]:
    tool = payload.get("tool")
    if isinstance(tool, dict) and "mcp-tool-card-linter" in tool:
        config = tool["mcp-tool-card-linter"]
    elif "mcp-tool-card-linter" in payload:
        config = payload["mcp-tool-card-linter"]
    else:
        config = payload
    if not isinstance(config, dict):
        raise PolicyError("Policy configuration must be a TOML table")
    return config


def _policy_from_mapping(config: Mapping[str, Any], *, source: str) -> PolicyConfig:
    allowed = {"profile", "select", "ignore", "fail-on", "rules", "suppressions"}
    unknown = set(config) - allowed
    if unknown:
        raise PolicyError(f"Unknown policy key: {safe_log_text(sorted(unknown)[0])}")
    profile = config.get("profile", "production")
    if not isinstance(profile, str):
        raise PolicyError("Policy profile must be a string")
    select = _string_array(config.get("select", []), "select")
    ignore = _string_array(config.get("ignore", []), "ignore")
    fail_on = config.get("fail-on")
    if fail_on is not None and not isinstance(fail_on, str):
        raise PolicyError("Policy fail-on must be a string")

    rules = config.get("rules", {})
    if not isinstance(rules, dict):
        raise PolicyError("Policy rules must be a table")
    overrides: list[tuple[str, Severity]] = []
    for rule_id, rule_config in rules.items():
        if not isinstance(rule_id, str) or not isinstance(rule_config, dict):
            raise PolicyError("Each policy rule override must be a table")
        if set(rule_config) != {"severity"}:
            raise PolicyError(f"Rule {safe_log_text(rule_id)} only supports severity")
        severity = rule_config["severity"]
        if not isinstance(severity, str) or severity not in SEVERITY_ORDER:
            raise PolicyError(f"Rule {safe_log_text(rule_id)} has invalid severity")
        overrides.append((rule_id, severity))

    raw_suppressions = config.get("suppressions", [])
    if not isinstance(raw_suppressions, list):
        raise PolicyError("Policy suppressions must be an array of tables")
    suppressions = tuple(
        _suppression_from_mapping(item, index=index)
        for index, item in enumerate(raw_suppressions)
    )
    return PolicyConfig(
        profile=profile,
        select=select,
        ignore=ignore,
        severity_overrides=tuple(overrides),
        suppressions=suppressions,
        fail_on=fail_on,
        source=source,
    )


def _suppression_from_mapping(value: Any, *, index: int) -> Suppression:
    if not isinstance(value, dict):
        raise PolicyError(f"Suppression {index} must be a table")
    required = {"server", "tool", "rule", "reason", "owner", "expires"}
    allowed = {*required, "path"}
    missing = required - set(value)
    unknown = set(value) - allowed
    if missing:
        raise PolicyError(f"Suppression {index} is missing {safe_log_text(sorted(missing)[0])}")
    if unknown:
        raise PolicyError(f"Suppression {index} has unknown key {safe_log_text(sorted(unknown)[0])}")
    for key in ("server", "tool", "rule", "reason", "owner"):
        if not isinstance(value[key], str) or not value[key].strip():
            raise PolicyError(f"Suppression {index}.{key} must be a non-empty string")
        if len(value[key]) > MAX_POLICY_TEXT or "\x00" in value[key]:
            raise PolicyError(f"Suppression {index}.{key} is too long or contains NUL")
    for key in ("server", "tool"):
        if not _IDENTITY_PATTERN.fullmatch(value[key]):
            raise PolicyError(f"Suppression {index}.{key} contains unsupported characters")
    if not _RULE_PATTERN.fullmatch(value["rule"]):
        raise PolicyError(f"Suppression {index}.rule is invalid")
    path = value.get("path")
    if path is not None and (not isinstance(path, str) or not path or len(path) > 2048):
        raise PolicyError(f"Suppression {index}.path must be a bounded string")
    expires = value["expires"]
    if isinstance(expires, datetime):
        expires = expires.date()
    if not isinstance(expires, date):
        raise PolicyError(f"Suppression {index}.expires must be a TOML date")
    return Suppression(
        server=value["server"],
        tool=value["tool"],
        rule=value["rule"],
        reason=value["reason"],
        owner=value["owner"],
        expires=expires,
        path=path,
    )


def _suppression_record(
    suppression: Suppression, server: str, tool: str, issue: Issue
) -> dict[str, str]:
    return {
        "server_name": safe_log_text(server, limit=512),
        "tool_name": safe_log_text(tool, limit=512),
        "rule": issue.code,
        "path": safe_log_text(issue.path, limit=2048),
        "reason": safe_log_text(suppression.reason, limit=MAX_POLICY_TEXT),
        "owner": safe_log_text(suppression.owner, limit=MAX_POLICY_TEXT),
        "expires": suppression.expires.isoformat(),
    }


def _resolve_regular_file(path: str | Path) -> Path:
    try:
        resolved = Path(path).expanduser().resolve()
        mode = os.stat(resolved).st_mode
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise PolicyError(f"Invalid policy path: {safe_log_text(exc)}") from exc
    if not stat.S_ISREG(mode):
        raise PolicyError(f"Policy path is not a regular file: {safe_log_text(resolved)}")
    return resolved


def _validate_patterns(name: str, values: tuple[str, ...]) -> None:
    if len(values) > MAX_POLICY_PATTERNS:
        raise PolicyError(f"Policy {name} contains too many patterns")
    for value in values:
        if not isinstance(value, str) or not _RULE_PATTERN.fullmatch(value):
            raise PolicyError(f"Invalid {name} rule pattern: {safe_log_text(value)}")


def _string_array(value: Any, name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise PolicyError(f"Policy {name} must be a string array")
    return tuple(value)


def _split_patterns(values: Iterable[str]) -> tuple[str, ...]:
    result: list[str] = []
    for value in values:
        result.extend(part.strip() for part in value.split(",") if part.strip())
    return tuple(result)


def _rule_match(rule_id: str, pattern: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return rule_id.startswith(pattern[:-1])
    return rule_id == pattern

from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import stat
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

MAX_INPUT_FILE_BYTES = 10 * 1024 * 1024
MAX_HTTP_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_HTTP_ERROR_BYTES = 4096
MAX_URL_CHARS = 4096
MAX_LOG_VALUE_CHARS = 1000

_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(api[-_]?key|access[-_]?token|auth[-_]?token|password|passwd|"
    r"secret|credential|private[-_]?key)\b(\s*[:=]\s*)([^\s,;&]+)"
)
_SENSITIVE_OPTION = re.compile(
    r"(?i)^--?(?:api[-_]?key|access[-_]?token|auth[-_]?token|password|passwd|"
    r"secret|credential|private[-_]?key)$"
)
_SENSITIVE_OPTION_ASSIGNMENT = re.compile(
    r"(?i)^(--?(?:api[-_]?key|access[-_]?token|auth[-_]?token|password|passwd|"
    r"secret|credential|private[-_]?key))=(.*)$"
)
_CREDENTIAL_LITERAL = re.compile(
    r"\b(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|sk-[A-Za-z0-9_-]{20,})\b"
)
_BEARER_TOKEN = re.compile(r"(?i)\b(Bearer\s+)[A-Za-z0-9._~+/-]{12,}=*")
_JWT_LITERAL = re.compile(
    r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
)


class InputValidationError(ValueError):
    """Raised when untrusted input fails structural or security validation."""


class DuplicateJsonKeyError(InputValidationError):
    """Raised when a JSON object contains an ambiguous duplicate member name."""


def strict_json_loads(text: str) -> Any:
    """Parse standards-compliant JSON and reject duplicate keys and NaN values."""

    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise DuplicateJsonKeyError(f"Duplicate JSON object key: {safe_log_text(key)}")
            result[key] = value
        return result

    def reject_constant(value: str) -> Any:
        raise InputValidationError(f"Non-standard JSON number is not allowed: {value}")

    try:
        return json.loads(
            text,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_constant,
        )
    except DuplicateJsonKeyError:
        raise
    except InputValidationError:
        raise
    except json.JSONDecodeError as exc:
        raise InputValidationError(
            f"Invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    except ValueError as exc:
        raise InputValidationError(f"Invalid JSON value: {safe_log_text(exc)}") from exc
    except RecursionError as exc:
        raise InputValidationError("JSON nesting is too deep") from exc


def load_json_file(path: str | Path, *, max_bytes: int = MAX_INPUT_FILE_BYTES) -> Any:
    """Read a regular UTF-8 JSON file with a hard byte limit and strict parsing."""
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
        raise ValueError("max_bytes must be a positive integer")

    try:
        resolved = Path(path).expanduser().resolve()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise InputValidationError(f"Invalid input path: {safe_log_text(exc)}") from exc
    try:
        with resolved.open("rb") as stream:
            mode = os.fstat(stream.fileno()).st_mode
            if not stat.S_ISREG(mode):
                raise InputValidationError(f"Path is not a regular file: {resolved}")
            raw = stream.read(max_bytes + 1)
    except FileNotFoundError as exc:
        raise InputValidationError(f"File not found: {resolved}") from exc
    except IsADirectoryError as exc:
        raise InputValidationError(f"Path is not a file: {resolved}") from exc
    except OSError as exc:
        raise InputValidationError(
            f"Failed to read {safe_log_text(resolved)}: {safe_log_text(exc)}"
        ) from exc

    if len(raw) > max_bytes:
        raise InputValidationError(
            f"Input file exceeds the {max_bytes} byte limit: {resolved}"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputValidationError(f"Input file is not valid UTF-8: {resolved}") from exc
    return strict_json_loads(text)


def validate_mcp_url(
    url: str,
    *,
    allow_private_network: bool = False,
    allow_insecure_http: bool = False,
    allow_loopback: bool = True,
    resolve_hostnames: bool = True,
) -> str:
    """Validate an MCP endpoint before network access.

    HTTP is accepted for loopback development endpoints. Other HTTP endpoints and
    private/reserved destinations require explicit opt-in.
    """
    if not isinstance(url, str):
        raise InputValidationError("MCP server URL must be a string")
    if not url or len(url) > MAX_URL_CHARS:
        raise InputValidationError(
            f"MCP server URL must contain 1..{MAX_URL_CHARS} characters"
        )
    if _contains_control(url):
        raise InputValidationError("MCP server URL contains control characters")

    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as exc:
        raise InputValidationError(f"Invalid MCP server URL: {safe_log_text(exc)}") from exc

    if parsed.scheme not in {"http", "https"}:
        raise InputValidationError("MCP server URL scheme must be http or https")
    if not parsed.hostname:
        raise InputValidationError("MCP server URL must include a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise InputValidationError("Credentials in MCP server URLs are not allowed")
    if parsed.fragment:
        raise InputValidationError("MCP server URL must not include a fragment")
    if port is not None and not 1 <= port <= 65535:
        raise InputValidationError("MCP server URL port must be in 1..65535")

    host = parsed.hostname.rstrip(".").lower()
    addresses = _resolve_addresses(host, port or (443 if parsed.scheme == "https" else 80), resolve_hostnames)
    loopback_only = bool(addresses) and all(address.is_loopback for address in addresses)
    if not addresses and host == "localhost":
        loopback_only = True

    for address in addresses:
        if address.is_loopback:
            if allow_loopback:
                continue
            raise InputValidationError(
                "MCP server resolves to a loopback address; explicit private-network approval is required for config-sourced URLs"
            )
        if not address.is_global and not allow_private_network:
            raise InputValidationError(
                f"MCP server resolves to non-public address {address}; "
                "use --allow-private-network only for a trusted endpoint"
            )
    if (
        parsed.scheme == "http"
        and not (loopback_only and allow_loopback)
        and not allow_insecure_http
    ):
        raise InputValidationError(
            "Plain HTTP is allowed only for approved loopback endpoints; use HTTPS or --allow-insecure-http"
        )
    return url


def redact_command(command: Iterable[str]) -> list[str]:
    """Return command metadata with common inline credentials removed."""
    result: list[str] = []
    redact_next = False
    for raw_arg in command:
        arg = str(raw_arg)
        if redact_next:
            result.append("<redacted>")
            redact_next = False
            continue
        if _SENSITIVE_OPTION.fullmatch(arg):
            result.append(arg)
            redact_next = True
            continue
        match = _SENSITIVE_OPTION_ASSIGNMENT.fullmatch(arg)
        if match:
            result.append(f"{match.group(1)}=<redacted>")
            continue
        if arg.startswith(("http://", "https://")):
            result.append(redact_url(arg))
        else:
            result.append(safe_log_text(arg, limit=4096))
    return result


def redact_url(url: str) -> str:
    """Remove user information and query values from a URL used in reports."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        if parsed.port is not None:
            host = f"{host}:{parsed.port}"
        query = "<redacted>" if parsed.query else ""
        return urlunsplit((parsed.scheme, host, parsed.path, query, ""))
    except ValueError:
        return "<invalid-url>"


def safe_log_text(value: Any, *, limit: int = MAX_LOG_VALUE_CHARS) -> str:
    """Bound, redact, and neutralize control characters in diagnostics."""
    text = str(value)
    text = _SECRET_ASSIGNMENT.sub(lambda match: f"{match.group(1)}{match.group(2)}<redacted>", text)
    text = _CREDENTIAL_LITERAL.sub("<redacted-credential>", text)
    text = _BEARER_TOKEN.sub(r"\1<redacted>", text)
    text = _JWT_LITERAL.sub("<redacted-jwt>", text)
    sanitized: list[str] = []
    for character in text:
        codepoint = ord(character)
        if character in "\r\n\t":
            sanitized.append(" ")
        elif codepoint < 32 or codepoint == 127:
            sanitized.append(f"\\x{codepoint:02x}")
        else:
            sanitized.append(character)
        if len(sanitized) >= limit:
            break
    result = "".join(sanitized)
    if len(text) > limit:
        result += "..."
    return result


def _resolve_addresses(host: str, port: int, resolve_hostnames: bool) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    if host == "localhost" and not resolve_hostnames:
        return [ipaddress.ip_address("127.0.0.1")]
    if not resolve_hostnames:
        return []
    try:
        records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise InputValidationError(
            f"Could not resolve MCP server hostname {safe_log_text(host)}: {safe_log_text(exc)}"
        ) from exc
    addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
    for record in records:
        raw_address = record[4][0]
        try:
            addresses.add(ipaddress.ip_address(raw_address.split("%", 1)[0]))
        except ValueError as exc:
            raise InputValidationError(
                f"Resolver returned an invalid IP address for {safe_log_text(host)}"
            ) from exc
    if not addresses:
        raise InputValidationError(f"Hostname resolved to no addresses: {safe_log_text(host)}")
    return sorted(addresses, key=lambda item: (item.version, int(item)))


def _contains_control(value: str) -> bool:
    return any(ord(character) < 32 or ord(character) == 127 for character in value)

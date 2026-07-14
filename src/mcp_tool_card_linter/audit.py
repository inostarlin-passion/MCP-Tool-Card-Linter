from __future__ import annotations

import hashlib
import os
import re
import stat
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

from .security import InputValidationError, safe_log_text, strict_json_loads
from .trust import canonical_json

AUDIT_SCHEMA_VERSION = "1.0.0"
AUDIT_DOMAIN = b"MCP-Tool-Card-Linter audit-log v1\x00"
MAX_AUDIT_LOG_BYTES = 32 * 1024 * 1024
MAX_AUDIT_RECORDS = 200_000
MAX_AUDIT_RECORD_BYTES = 32 * 1024
MAX_AUDIT_DETAILS = 128
_ALLOWED_DETAIL_KEYS = {
    "authenticated",
    "custom_ca_configured",
    "error_type",
    "insecure_http_allowed",
    "mtls_configured",
    "private_network_allowed",
    "proxy_configured",
    "scan_id",
    "source_count",
    "source_errors",
    "tool_version",
    "tools_scanned",
}
_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}\Z")
_OUTCOMES = {"success", "findings", "error", "interrupted"}
_FIELDS = {
    "schema_version",
    "sequence",
    "recorded_at",
    "event",
    "actor",
    "outcome",
    "details",
    "previous_hash",
    "record_hash",
}


class AuditError(ValueError):
    """Raised when an operational audit record cannot be safely persisted."""


def append_audit_event(
    path: str | Path,
    *,
    event: str,
    actor: str,
    outcome: str,
    details: Mapping[str, Any],
    recorded_at: str | None = None,
) -> dict[str, Any]:
    event = _token("event", event)
    actor = _token("actor", actor)
    if outcome not in _OUTCOMES:
        raise AuditError("outcome must be success, findings, error, or interrupted")
    safe_details = _details(details)
    timestamp = _timestamp(recorded_at)
    resolved = _resolved(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    lock = _acquire_lock(resolved)
    try:
        records = _read_records(resolved) if resolved.exists() else []
        _verify_records(records)
        body = {
            "schema_version": AUDIT_SCHEMA_VERSION,
            "sequence": len(records) + 1,
            "recorded_at": timestamp,
            "event": event,
            "actor": actor,
            "outcome": outcome,
            "details": safe_details,
            "previous_hash": records[-1]["record_hash"] if records else None,
        }
        record = {**body, "record_hash": _record_hash(body)}
        raw = canonical_json(record) + b"\n"
        if len(raw) > MAX_AUDIT_RECORD_BYTES:
            raise AuditError(f"Audit record exceeds {MAX_AUDIT_RECORD_BYTES} bytes")
        _append_private_line(resolved, raw)
        return record
    finally:
        _release_lock(lock)


def verify_audit_log(path: str | Path) -> dict[str, Any]:
    records = _read_records(_resolved(path))
    _verify_records(records)
    return {
        "valid": True,
        "schema_version": AUDIT_SCHEMA_VERSION,
        "records": len(records),
        "head": records[-1]["record_hash"] if records else None,
    }


def _verify_records(records: list[dict[str, Any]]) -> None:
    previous: str | None = None
    for index, record in enumerate(records, start=1):
        if set(record) != _FIELDS:
            raise AuditError(f"Audit record {index} has missing or unknown fields")
        if record.get("schema_version") != AUDIT_SCHEMA_VERSION:
            raise AuditError(f"Audit record {index} has an unsupported schema")
        if record.get("sequence") != index:
            raise AuditError(f"Audit record {index} has an invalid sequence")
        _timestamp(record.get("recorded_at"))
        _token("event", record.get("event"))
        _token("actor", record.get("actor"))
        if record.get("outcome") not in _OUTCOMES:
            raise AuditError(f"Audit record {index} has an invalid outcome")
        details = record.get("details")
        if not isinstance(details, dict):
            raise AuditError(f"Audit record {index} details must be an object")
        _details(details)
        if record.get("previous_hash") != previous:
            raise AuditError(f"Audit record {index} hash chain is invalid")
        claimed = record.get("record_hash")
        if not isinstance(claimed, str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", claimed):
            raise AuditError(f"Audit record {index} hash is invalid")
        body = {key: value for key, value in record.items() if key != "record_hash"}
        if claimed != _record_hash(body):
            raise AuditError(f"Audit record {index} was modified")
        previous = claimed


def _read_records(path: Path) -> list[dict[str, Any]]:
    try:
        with path.open("rb") as stream:
            mode = os.fstat(stream.fileno()).st_mode
            if not stat.S_ISREG(mode):
                raise AuditError("Audit log must be a regular file")
            if os.name == "posix" and stat.S_IMODE(mode) & 0o077:
                raise AuditError("Audit log must not be accessible by group or other users")
            raw = stream.read(MAX_AUDIT_LOG_BYTES + 1)
    except AuditError:
        raise
    except OSError as exc:
        raise AuditError(f"Failed to read audit log: {safe_log_text(exc)}") from exc
    if len(raw) > MAX_AUDIT_LOG_BYTES:
        raise AuditError(f"Audit log exceeds {MAX_AUDIT_LOG_BYTES} bytes")
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(raw.splitlines(), start=1):
        if not line.strip():
            raise AuditError(f"Audit log contains a blank line at {line_number}")
        if len(line) > MAX_AUDIT_RECORD_BYTES:
            raise AuditError(f"Audit record {line_number} is too large")
        if len(records) >= MAX_AUDIT_RECORDS:
            raise AuditError(f"Audit log exceeds {MAX_AUDIT_RECORDS} records")
        try:
            value = strict_json_loads(line.decode("utf-8"))
        except (UnicodeDecodeError, InputValidationError) as exc:
            raise AuditError(f"Audit record {line_number} is invalid") from exc
        if not isinstance(value, dict):
            raise AuditError(f"Audit record {line_number} must be an object")
        records.append(value)
    return records


def _append_private_line(path: Path, raw: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        mode = os.fstat(descriptor).st_mode
        if not stat.S_ISREG(mode):
            raise AuditError("Audit log must be a regular file")
        if os.name == "posix" and stat.S_IMODE(mode) & 0o077:
            raise AuditError("Audit log must not be accessible by group or other users")
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while appending audit record")
            view = view[written:]
        os.fsync(descriptor)
        _fsync_directory(path.parent)
    except AuditError:
        raise
    except OSError as exc:
        raise AuditError(f"Failed to append audit log: {safe_log_text(exc)}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _details(value: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, Mapping) or len(value) > MAX_AUDIT_DETAILS:
        raise AuditError(f"details must be an object with at most {MAX_AUDIT_DETAILS} fields")
    result: dict[str, Any] = {}
    for key, item in value.items():
        safe_key = _token("details key", key)
        if safe_key not in _ALLOWED_DETAIL_KEYS:
            raise AuditError(f"details key is not approved for audit output: {safe_key}")
        if isinstance(item, bool) or item is None:
            result[safe_key] = item
        elif isinstance(item, int) and not isinstance(item, bool):
            if abs(item) > 10**18:
                raise AuditError("details integer is outside the supported range")
            result[safe_key] = item
        elif isinstance(item, str):
            result[safe_key] = safe_log_text(item, limit=2048)
        elif isinstance(item, list) and len(item) <= 128 and all(isinstance(v, str) for v in item):
            result[safe_key] = [safe_log_text(v, limit=512) for v in item]
        else:
            raise AuditError("details values must be bounded scalars or string arrays")
    return result


def _record_hash(body: Mapping[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(AUDIT_DOMAIN + canonical_json(body)).hexdigest()


def _token(name: str, value: Any) -> str:
    if not isinstance(value, str) or not _TOKEN.fullmatch(value):
        raise AuditError(f"{name} must be a bounded printable identifier")
    return value


def _timestamp(value: Any) -> str:
    if value is None:
        return datetime.now(UTC).isoformat()
    if not isinstance(value, str) or len(value) > 128:
        raise AuditError("recorded_at must be a bounded ISO 8601 timestamp")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuditError("recorded_at is not valid ISO 8601") from exc
    if parsed.tzinfo is None:
        raise AuditError("recorded_at must include a timezone")
    return parsed.isoformat()


def _acquire_lock(path: Path) -> Path:
    lock = path.with_name(path.name + ".lock")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(lock, flags, 0o600)
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(str(os.getpid()))
            stream.flush()
            os.fsync(stream.fileno())
    except FileExistsError as exc:
        raise AuditError("Audit log is already being updated by another process") from exc
    except OSError as exc:
        lock.unlink(missing_ok=True)
        raise AuditError(f"Failed to lock audit log: {safe_log_text(exc)}") from exc
    return lock


def _release_lock(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _resolved(path: str | Path) -> Path:
    try:
        return Path(path).expanduser().resolve()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise AuditError(f"Invalid audit log path: {safe_log_text(exc)}") from exc


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY)
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        if descriptor is not None:
            os.close(descriptor)

from __future__ import annotations

import base64
import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal, cast

import rfc8785
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .models import BaselineAssessment, SourceResult
from .security import InputValidationError, safe_log_text, strict_json_loads

BASELINE_SCHEMA_VERSION = "1.0.0"
BASELINE_ALGORITHM = "Ed25519"
BASELINE_DOMAIN = b"MCP-Tool-Card-Linter baseline v1\x00"
APPROVAL_DOMAIN = b"MCP-Tool-Card-Linter approval-log v1\x00"
MAX_KEY_BYTES = 64 * 1024
MAX_APPROVAL_LOG_BYTES = 16 * 1024 * 1024
MAX_APPROVAL_RECORDS = 100_000
MAX_CLAIM_CHARS = 1024
_FINGERPRINT_PREFIX = "sha256:"
_BOUND_METADATA_KEYS = (
    "url",
    "path",
    "command",
    "cwd",
    "protocol_requested",
    "protocol_negotiated",
    "capabilities",
    "server_info",
    "executor",
)


class TrustError(ValueError):
    """Raised when trust material is malformed, unverifiable, or unsafe."""


@dataclass(frozen=True, slots=True)
class VerifiedBaseline:
    report: dict[str, Any]
    binding: dict[str, Any]
    key_id: str
    payload: dict[str, Any]


def canonical_json(value: Any) -> bytes:
    try:
        return rfc8785.dumps(value)
    except (rfc8785.CanonicalizationError, RecursionError, TypeError, ValueError) as exc:
        raise TrustError(f"Value is not RFC 8785 canonicalizable: {safe_log_text(exc)}") from exc


def sha256_fingerprint(value: Any) -> str:
    return _FINGERPRINT_PREFIX + hashlib.sha256(canonical_json(value)).hexdigest()


def is_signed_baseline(payload: Any) -> bool:
    return (
        isinstance(payload, dict)
        and payload.get("schema_version") == BASELINE_SCHEMA_VERSION
        and payload.get("algorithm") == BASELINE_ALGORITHM
        and isinstance(payload.get("payload"), dict)
        and isinstance(payload.get("signature"), str)
    )


def generate_key_pair(private_key_path: str | Path, public_key_path: str | Path) -> str:
    private_resolved = _resolved(private_key_path)
    public_resolved = _resolved(public_key_path)
    if private_resolved == public_resolved:
        raise TrustError("Private and public key paths must differ")
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_bytes = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_bytes = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _create_private_file(private_resolved, private_bytes)
    try:
        _create_private_file(public_resolved, public_bytes)
    except BaseException:
        try:
            private_resolved.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return _key_id(public_key)


def create_baseline_bundle(
    report: dict[str, Any],
    *,
    private_key_path: str | Path,
    publisher: str,
    server_identity: str,
    approved_by: str,
    approved_at: str | None = None,
) -> dict[str, Any]:
    _validate_report(report)
    publisher = _claim("publisher", publisher)
    server_identity = _claim("server_identity", server_identity)
    approved_by = _claim("approved_by", approved_by)
    timestamp = _timestamp(approved_at)
    private_key = _load_private_key(private_key_path)
    public_key = private_key.public_key()
    binding = {
        "publisher": publisher,
        "server_identity": server_identity,
        "source_identity": source_identity_from_report(report),
    }
    signed_payload = {
        "approved_at": timestamp,
        "approved_by": approved_by,
        "binding": binding,
        "report_digest": sha256_fingerprint(report),
        "report": report,
    }
    signature = private_key.sign(BASELINE_DOMAIN + canonical_json(signed_payload))
    return {
        "$schema": (
            "https://raw.githubusercontent.com/inostarlin-passion/"
            "MCP-Tool-Card-Linter/v1.0.0/src/mcp_tool_card_linter/"
            "schemas/baseline.schema.json"
        ),
        "schema_version": BASELINE_SCHEMA_VERSION,
        "algorithm": BASELINE_ALGORITHM,
        "key_id": _key_id(public_key),
        "payload": signed_payload,
        "signature": _b64encode(signature),
    }


def verify_baseline_bundle(
    bundle: dict[str, Any], public_key_path: str | Path
) -> VerifiedBaseline:
    if not is_signed_baseline(bundle):
        raise TrustError("Baseline is not a supported signed baseline bundle")
    expected_bundle_keys = {
        "$schema",
        "schema_version",
        "algorithm",
        "key_id",
        "payload",
        "signature",
    }
    if set(bundle) != expected_bundle_keys:
        raise TrustError("Signed baseline contains missing or unknown top-level fields")
    key_id = bundle.get("key_id")
    if not isinstance(key_id, str) or not _valid_fingerprint(key_id):
        raise TrustError("Baseline key_id is invalid")
    public_key = _load_public_key(public_key_path)
    expected_key_id = _key_id(public_key)
    if key_id != expected_key_id:
        raise TrustError("Baseline key_id does not match the trusted public key")
    signed_payload = cast(dict[str, Any], bundle["payload"])
    if set(signed_payload) != {
        "approved_at",
        "approved_by",
        "binding",
        "report_digest",
        "report",
    }:
        raise TrustError("Signed baseline payload contains missing or unknown fields")
    signature = _b64decode(bundle["signature"], expected_bytes=64, label="signature")
    try:
        public_key.verify(signature, BASELINE_DOMAIN + canonical_json(signed_payload))
    except InvalidSignature as exc:
        raise TrustError("Baseline signature verification failed") from exc

    report = signed_payload.get("report")
    binding = signed_payload.get("binding")
    report_digest = signed_payload.get("report_digest")
    if not isinstance(report, dict):
        raise TrustError("Signed baseline payload.report must be an object")
    if not isinstance(binding, dict):
        raise TrustError("Signed baseline payload.binding must be an object")
    if set(binding) != {"publisher", "server_identity", "source_identity"}:
        raise TrustError("Signed baseline binding contains missing or unknown fields")
    _validate_report(report)
    if not isinstance(report_digest, str) or not _valid_fingerprint(report_digest):
        raise TrustError("Signed baseline report_digest is invalid")
    if report_digest != sha256_fingerprint(report):
        raise TrustError("Signed baseline report_digest does not match report")
    for name in ("publisher", "server_identity"):
        _claim(name, binding.get(name))
    source_identity = binding.get("source_identity")
    if not isinstance(source_identity, str) or not _valid_fingerprint(source_identity):
        raise TrustError("Signed baseline source_identity is invalid")
    _claim("approved_by", signed_payload.get("approved_by"))
    _timestamp(signed_payload.get("approved_at"))
    return VerifiedBaseline(
        report=report,
        binding=binding,
        key_id=key_id,
        payload=signed_payload,
    )


def assess_baseline(
    verified: VerifiedBaseline,
    sources: Iterable[SourceResult],
    *,
    expected_publisher: str | None = None,
    expected_server_identity: str | None = None,
) -> BaselineAssessment:
    publisher = cast(str, verified.binding["publisher"])
    server_identity = cast(str, verified.binding["server_identity"])
    binding_status: Literal["match", "identity_changed", "publisher_changed"]
    if expected_publisher is not None and _claim(
        "expected_publisher", expected_publisher
    ) != publisher:
        binding_status = "publisher_changed"
    elif expected_server_identity is not None and _claim(
        "expected_server_identity", expected_server_identity
    ) != server_identity:
        binding_status = "identity_changed"
    elif source_identity_from_sources(sources) != verified.binding["source_identity"]:
        binding_status = "identity_changed"
    else:
        binding_status = "match"
    return BaselineAssessment(
        trust_status="signed",
        binding_status=binding_status,
        key_id=verified.key_id,
        publisher=publisher,
        server_identity=server_identity,
    )


def source_identity_from_report(report: Mapping[str, Any]) -> str:
    sources = report.get("sources")
    if not isinstance(sources, list):
        raise TrustError("Report sources must be an array")
    descriptors = []
    for index, source in enumerate(sources):
        if not isinstance(source, dict):
            raise TrustError(f"Report sources[{index}] must be an object")
        descriptors.append(_source_descriptor(source))
    return sha256_fingerprint(sorted(descriptors, key=_descriptor_sort_key))


def source_identity_from_sources(sources: Iterable[SourceResult]) -> str:
    descriptors = [
        _source_descriptor(
            {
                "server_name": source.server_name,
                "source_type": source.source_type,
                "metadata": source.metadata,
            }
        )
        for source in sources
    ]
    return sha256_fingerprint(sorted(descriptors, key=_descriptor_sort_key))


def write_baseline_bundle(bundle: dict[str, Any], path: str | Path) -> None:
    raw = (
        json.dumps(bundle, ensure_ascii=False, indent=2, sort_keys=True, allow_nan=False)
        + "\n"
    ).encode("utf-8")
    _replace_private_file(_resolved(path), raw)


def append_approval_record(
    path: str | Path,
    bundle: dict[str, Any],
    *,
    private_key_path: str | Path,
) -> dict[str, Any]:
    if not is_signed_baseline(bundle):
        raise TrustError("Only a signed baseline can be appended to the approval log")
    private_key = _load_private_key(private_key_path)
    public_key = private_key.public_key()
    if bundle.get("key_id") != _key_id(public_key):
        raise TrustError("Approval key does not match the baseline signing key")
    resolved = _resolved(path)
    resolved.parent.mkdir(parents=True, exist_ok=True)
    lock = _acquire_lock(resolved)
    try:
        records = _read_approval_log(resolved) if resolved.exists() else []
        _verify_records(records, public_key)
        previous_hash = sha256_fingerprint(records[-1]) if records else None
        payload = cast(dict[str, Any], bundle["payload"])
        binding = cast(dict[str, Any], payload["binding"])
        record_body = {
            "schema_version": BASELINE_SCHEMA_VERSION,
            "sequence": len(records) + 1,
            "recorded_at": payload["approved_at"],
            "action": "approve",
            "approver": payload["approved_by"],
            "publisher": binding["publisher"],
            "server_identity": binding["server_identity"],
            "baseline_digest": sha256_fingerprint(bundle),
            "previous_hash": previous_hash,
            "key_id": bundle["key_id"],
        }
        signature = private_key.sign(APPROVAL_DOMAIN + canonical_json(record_body))
        record = {**record_body, "signature": _b64encode(signature)}
        _append_private_line(resolved, canonical_json(record) + b"\n")
        return record
    finally:
        _release_lock(lock)


def verify_approval_log(
    path: str | Path, public_key_path: str | Path
) -> dict[str, Any]:
    public_key = _load_public_key(public_key_path)
    records = _read_approval_log(_resolved(path))
    _verify_records(records, public_key)
    return {
        "valid": True,
        "records": len(records),
        "key_id": _key_id(public_key),
        "head": sha256_fingerprint(records[-1]) if records else None,
    }


def _source_descriptor(source: Mapping[str, Any]) -> dict[str, Any]:
    server_name = source.get("server_name")
    source_type = source.get("source_type")
    metadata = source.get("metadata", {})
    if not isinstance(server_name, str) or not server_name:
        raise TrustError("Source server_name must be a non-empty string")
    if not isinstance(source_type, str) or not source_type:
        raise TrustError("Source source_type must be a non-empty string")
    if not isinstance(metadata, dict):
        raise TrustError("Source metadata must be an object")
    return {
        "server_name": server_name,
        "source_type": source_type,
        "metadata": {key: metadata[key] for key in _BOUND_METADATA_KEYS if key in metadata},
    }


def _descriptor_sort_key(value: Mapping[str, Any]) -> tuple[str, str]:
    return (str(value["server_name"]), str(value["source_type"]))


def _validate_report(report: Mapping[str, Any]) -> None:
    tools = report.get("tools")
    sources = report.get("sources")
    if not isinstance(tools, list) or len(tools) > 100_000:
        raise TrustError("Baseline report tools must be an array with at most 100000 entries")
    if not isinstance(sources, list) or len(sources) > 128:
        raise TrustError("Baseline report sources must be an array with at most 128 entries")
    seen: set[tuple[str, str]] = set()
    for index, tool in enumerate(tools):
        if not isinstance(tool, dict):
            raise TrustError(f"Baseline report tools[{index}] must be an object")
        server_name = tool.get("server_name")
        tool_name = tool.get("tool_name")
        fingerprint = tool.get("card_fingerprint")
        if not isinstance(server_name, str) or not server_name:
            raise TrustError(f"Baseline report tools[{index}].server_name is invalid")
        if not isinstance(tool_name, str) or not tool_name:
            raise TrustError(f"Baseline report tools[{index}].tool_name is invalid")
        if not isinstance(fingerprint, str) or not _valid_fingerprint(fingerprint):
            raise TrustError(f"Baseline report tools[{index}].card_fingerprint is invalid")
        identity = (server_name, tool_name)
        if identity in seen:
            raise TrustError("Baseline report contains a duplicate tool identity")
        seen.add(identity)


def _verify_records(
    records: list[dict[str, Any]], public_key: Ed25519PublicKey
) -> None:
    expected_key_id = _key_id(public_key)
    previous_hash: str | None = None
    for index, record in enumerate(records):
        expected_fields = {
            "schema_version",
            "sequence",
            "recorded_at",
            "action",
            "approver",
            "publisher",
            "server_identity",
            "baseline_digest",
            "previous_hash",
            "key_id",
            "signature",
        }
        if set(record) != expected_fields:
            raise TrustError(
                f"Approval log contains missing or unknown fields at record {index + 1}"
            )
        if record.get("schema_version") != BASELINE_SCHEMA_VERSION:
            raise TrustError(f"Approval log schema is invalid at record {index + 1}")
        if record.get("action") != "approve":
            raise TrustError(f"Approval log action is invalid at record {index + 1}")
        _timestamp(record.get("recorded_at"))
        for claim_name in ("approver", "publisher", "server_identity"):
            _claim(claim_name, record.get(claim_name))
        baseline_digest = record.get("baseline_digest")
        if not isinstance(baseline_digest, str) or not _valid_fingerprint(
            baseline_digest
        ):
            raise TrustError(
                f"Approval log baseline_digest is invalid at record {index + 1}"
            )
        if record.get("sequence") != index + 1:
            raise TrustError(f"Approval log sequence is invalid at record {index + 1}")
        if record.get("previous_hash") != previous_hash:
            raise TrustError(f"Approval log hash chain is invalid at record {index + 1}")
        if record.get("key_id") != expected_key_id:
            raise TrustError(f"Approval log key_id is invalid at record {index + 1}")
        signature_value = record.get("signature")
        if not isinstance(signature_value, str):
            raise TrustError(f"Approval log signature is missing at record {index + 1}")
        signature = _b64decode(
            signature_value,
            expected_bytes=64,
            label=f"approval record {index + 1} signature",
        )
        body = {key: value for key, value in record.items() if key != "signature"}
        try:
            public_key.verify(signature, APPROVAL_DOMAIN + canonical_json(body))
        except InvalidSignature as exc:
            raise TrustError(
                f"Approval log signature verification failed at record {index + 1}"
            ) from exc
        previous_hash = sha256_fingerprint(record)


def _read_approval_log(path: Path) -> list[dict[str, Any]]:
    try:
        with path.open("rb") as stream:
            mode = os.fstat(stream.fileno()).st_mode
            if not stat.S_ISREG(mode):
                raise TrustError("Approval log must be a regular file")
            if os.name == "posix" and stat.S_IMODE(mode) & 0o077:
                raise TrustError("Approval log must not be accessible by group or other users")
            raw = stream.read(MAX_APPROVAL_LOG_BYTES + 1)
    except TrustError:
        raise
    except OSError as exc:
        raise TrustError(f"Failed to read approval log: {safe_log_text(exc)}") from exc
    if len(raw) > MAX_APPROVAL_LOG_BYTES:
        raise TrustError(f"Approval log exceeds {MAX_APPROVAL_LOG_BYTES} bytes")
    records: list[dict[str, Any]] = []
    for line_number, raw_line in enumerate(raw.splitlines(), start=1):
        if not raw_line.strip():
            raise TrustError(f"Approval log contains a blank line at {line_number}")
        if len(records) >= MAX_APPROVAL_RECORDS:
            raise TrustError(f"Approval log exceeds {MAX_APPROVAL_RECORDS} records")
        try:
            payload = strict_json_loads(raw_line.decode("utf-8"))
        except (UnicodeDecodeError, InputValidationError) as exc:
            raise TrustError(
                f"Approval log record {line_number} is invalid: {safe_log_text(exc)}"
            ) from exc
        if not isinstance(payload, dict):
            raise TrustError(f"Approval log record {line_number} must be an object")
        records.append(payload)
    return records


def _load_private_key(path: str | Path) -> Ed25519PrivateKey:
    raw = _read_key(path, private=True)
    try:
        key = serialization.load_pem_private_key(raw, password=None)
    except (TypeError, ValueError) as exc:
        raise TrustError("Private key is not a valid unencrypted PEM key") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise TrustError("Private key must be Ed25519")
    return key


def _load_public_key(path: str | Path) -> Ed25519PublicKey:
    raw = _read_key(path, private=False)
    try:
        key = serialization.load_pem_public_key(raw)
    except (TypeError, ValueError) as exc:
        raise TrustError("Public key is not a valid PEM key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise TrustError("Public key must be Ed25519")
    return key


def _read_key(path: str | Path, *, private: bool) -> bytes:
    resolved = _resolved(path)
    try:
        with resolved.open("rb") as stream:
            mode = os.fstat(stream.fileno()).st_mode
            if not stat.S_ISREG(mode):
                raise TrustError("Key path must be a regular file")
            if private and os.name == "posix" and stat.S_IMODE(mode) & 0o077:
                raise TrustError("Private key must not be accessible by group or other users")
            raw = stream.read(MAX_KEY_BYTES + 1)
    except TrustError:
        raise
    except OSError as exc:
        raise TrustError(f"Failed to read key: {safe_log_text(exc)}") from exc
    if len(raw) > MAX_KEY_BYTES:
        raise TrustError(f"Key exceeds {MAX_KEY_BYTES} bytes")
    return raw


def _key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )
    return _FINGERPRINT_PREFIX + hashlib.sha256(raw).hexdigest()


def _claim(name: str, value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TrustError(f"{name} must be a non-empty string")
    normalized = value.strip()
    if len(normalized) > MAX_CLAIM_CHARS:
        raise TrustError(f"{name} exceeds {MAX_CLAIM_CHARS} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise TrustError(f"{name} contains control characters")
    return normalized


def _timestamp(value: Any) -> str:
    if value is None:
        return datetime.now(UTC).isoformat()
    if not isinstance(value, str) or len(value) > 128:
        raise TrustError("Approval timestamp must be a bounded ISO 8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TrustError("Approval timestamp is not valid ISO 8601") from exc
    if parsed.tzinfo is None:
        raise TrustError("Approval timestamp must include a timezone")
    return parsed.isoformat()


def _valid_fingerprint(value: str) -> bool:
    return (
        len(value) == len(_FINGERPRINT_PREFIX) + 64
        and value.startswith(_FINGERPRINT_PREFIX)
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: Any, *, expected_bytes: int, label: str) -> bytes:
    if not isinstance(value, str) or len(value) > expected_bytes * 2:
        raise TrustError(f"{label} is invalid")
    try:
        raw = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, TypeError) as exc:
        raise TrustError(f"{label} is not valid base64url") from exc
    if len(raw) != expected_bytes:
        raise TrustError(f"{label} must decode to {expected_bytes} bytes")
    return raw


def _create_private_file(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(path, flags, 0o600)
        created = True
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        _fsync_directory(path.parent)
    except FileExistsError as exc:
        raise TrustError(f"Refusing to overwrite existing file: {path}") from exc
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        if created:
            path.unlink(missing_ok=True)
        raise TrustError(f"Failed to create private file: {safe_log_text(exc)}") from exc


def _replace_private_file(path: Path, raw: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=path.parent,
        prefix=f".{path.name}.",
        suffix=".tmp",
    )
    temporary = Path(temporary_name)
    descriptor_open = True
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor_open = False
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except OSError as exc:
        raise TrustError(f"Failed to write baseline: {safe_log_text(exc)}") from exc
    finally:
        if descriptor_open:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _append_private_line(path: Path, raw: bytes) -> None:
    if len(raw) > 16 * 1024:
        raise TrustError("Approval record exceeds 16384 bytes")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(path, flags, 0o600)
        mode = os.fstat(descriptor).st_mode
        if not stat.S_ISREG(mode):
            raise TrustError("Approval log must be a regular file")
        if os.name == "posix" and stat.S_IMODE(mode) & 0o077:
            raise TrustError("Approval log must not be accessible by group or other users")
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while appending approval record")
            view = view[written:]
        os.fsync(descriptor)
        _fsync_directory(path.parent)
    except TrustError:
        raise
    except OSError as exc:
        raise TrustError(f"Failed to append approval log: {safe_log_text(exc)}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


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
        raise TrustError("Approval log is already being updated by another process") from exc
    except OSError as exc:
        lock.unlink(missing_ok=True)
        raise TrustError(f"Failed to lock approval log: {safe_log_text(exc)}") from exc
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
        raise TrustError(f"Invalid trust file path: {safe_log_text(exc)}") from exc


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

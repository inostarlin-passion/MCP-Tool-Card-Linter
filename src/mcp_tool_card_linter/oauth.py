from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import stat
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit, urlunsplit

from . import __version__
from .auth import CredentialError, _validate_token
from .discovery import MCP_PROTOCOL_VERSION, DiscoveryError, _build_http_opener
from .security import (
    MAX_HTTP_ERROR_BYTES,
    InputValidationError,
    safe_log_text,
    strict_json_loads,
    validate_mcp_url,
)

MAX_OAUTH_METADATA_BYTES = 256 * 1024
MAX_OAUTH_TOKEN_BYTES = 256 * 1024
MAX_OAUTH_FIELD_CHARS = 4096
MAX_OAUTH_SCOPES = 64
MAX_AUTHORIZATION_SERVERS = 16
AUTHORIZATION_STATE_TTL_SECONDS = 10 * 60
_SCOPE_TOKEN = re.compile(r'[\x21\x23-\x5b\x5d-\x7e]{1,256}\Z')
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_PKCE_VERIFIER = re.compile(r"[A-Za-z0-9._~-]{43,128}\Z")


class OAuthError(CredentialError):
    """Raised when MCP OAuth discovery or authorization is unsafe or invalid."""


def callback_url_from_environment(variable: str) -> str:
    if not isinstance(variable, str) or not _ENV_NAME.fullmatch(variable):
        raise OAuthError("OAuth callback environment name is invalid")
    value = os.environ.get(variable)
    if value is None:
        raise OAuthError(
            f"OAuth callback environment variable is not set: {safe_log_text(variable)}"
        )
    return _metadata_url(value)


def callback_url_from_file(path: str | Path) -> str:
    resolved = _resolved_file(path)
    try:
        with resolved.open("rb") as stream:
            mode = os.fstat(stream.fileno()).st_mode
            if not stat.S_ISREG(mode):
                raise OAuthError("OAuth callback path is not a regular file")
            if os.name == "posix" and stat.S_IMODE(mode) & 0o077:
                raise OAuthError("OAuth callback file must have mode 0600")
            raw = stream.read(MAX_OAUTH_FIELD_CHARS + 1)
    except OAuthError:
        raise
    except OSError as exc:
        raise OAuthError(f"Failed to read OAuth callback file: {safe_log_text(exc)}") from exc
    if len(raw) > MAX_OAUTH_FIELD_CHARS:
        raise OAuthError("OAuth callback file exceeds its byte limit")
    try:
        return _metadata_url(raw.decode("utf-8").strip())
    except UnicodeDecodeError as exc:
        raise OAuthError("OAuth callback file is not valid UTF-8") from exc


def start_authorization(
    server_url: str,
    *,
    client_id: str,
    redirect_uri: str,
    state_file: str | Path,
    scopes: Iterable[str] = (),
    timeout: float = 10.0,
    allow_private_network: bool = False,
    allow_insecure_http: bool = False,
    ca_bundle: str | None = None,
    proxy_url: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
) -> dict[str, Any]:
    """Discover OAuth metadata and create a single-use Authorization Code + PKCE flow.

    This intentionally supports pre-registered public clients only. Dynamic client
    registration has materially different trust and lifecycle requirements.
    """

    resource = _canonical_resource_uri(server_url)
    _validate_text("client_id", client_id)
    redirect = _validate_redirect_uri(redirect_uri)
    requested_scopes = _validate_scopes(scopes)
    request_timeout = _validate_timeout(timeout)
    http = _oauth_opener(
        ca_bundle=ca_bundle,
        proxy_url=proxy_url,
        client_cert=client_cert,
        client_key=client_key,
    )

    prm_hint, challenged_scopes = _probe_protected_resource_metadata(
        http,
        server_url,
        timeout=request_timeout,
        allow_private_network=allow_private_network,
        allow_insecure_http=allow_insecure_http,
    )
    protected_resource = _discover_protected_resource_metadata(
        http,
        resource,
        hint=prm_hint,
        timeout=request_timeout,
        allow_private_network=allow_private_network,
        allow_insecure_http=allow_insecure_http,
    )
    if challenged_scopes is not None:
        requested_scopes = _validate_scopes(
            _unique([*challenged_scopes, *requested_scopes])
        )
    elif not requested_scopes:
        requested_scopes = (
            _metadata_scopes(protected_resource)
        )
    authorization_servers = _authorization_servers(protected_resource)
    metadata, issuer = _discover_authorization_server_metadata(
        http,
        authorization_servers,
        timeout=request_timeout,
        allow_private_network=allow_private_network,
        allow_insecure_http=allow_insecure_http,
    )
    authorization_endpoint = _metadata_endpoint(
        metadata,
        "authorization_endpoint",
        allow_private_network=allow_private_network,
        allow_insecure_http=allow_insecure_http,
    )
    token_endpoint = _metadata_endpoint(
        metadata,
        "token_endpoint",
        allow_private_network=allow_private_network,
        allow_insecure_http=allow_insecure_http,
    )
    methods = metadata.get("code_challenge_methods_supported")
    if not isinstance(methods, list) or "S256" not in methods:
        raise OAuthError("Authorization server does not advertise required PKCE method S256")
    response_types = metadata.get("response_types_supported")
    if not isinstance(response_types, list) or "code" not in response_types:
        raise OAuthError("Authorization server does not support response_type=code")
    grant_types = metadata.get("grant_types_supported")
    if grant_types is not None and (
        not isinstance(grant_types, list) or "authorization_code" not in grant_types
    ):
        raise OAuthError("Authorization server does not support authorization_code grant")

    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    state = secrets.token_urlsafe(32)
    created_at = int(time.time())
    expires_at = created_at + AUTHORIZATION_STATE_TTL_SECONDS
    params: list[tuple[str, str]] = [
        ("response_type", "code"),
        ("client_id", client_id),
        ("redirect_uri", redirect),
        ("code_challenge", challenge),
        ("code_challenge_method", "S256"),
        ("state", state),
        ("resource", resource),
    ]
    if requested_scopes:
        params.append(("scope", " ".join(requested_scopes)))
    authorization_url = _append_query(authorization_endpoint, params)

    state_payload = {
        "schema_version": "1.0",
        "created_at": created_at,
        "expires_at": expires_at,
        "resource": resource,
        "authorization_server": issuer,
        "token_endpoint": token_endpoint,
        "client_id": client_id,
        "redirect_uri": redirect,
        "code_verifier": verifier,
        "state": state,
        "scopes": requested_scopes,
    }
    _create_private_json(state_file, state_payload)
    return {
        "authorization_url": authorization_url,
        "authorization_server": issuer,
        "resource": resource,
        "expires_at": expires_at,
        "state_file": str(Path(state_file).expanduser().resolve()),
    }


def complete_authorization(
    *,
    state_file: str | Path,
    callback_url: str,
    token_file: str | Path,
    timeout: float = 10.0,
    allow_private_network: bool = False,
    allow_insecure_http: bool = False,
    ca_bundle: str | None = None,
    proxy_url: str | None = None,
    client_cert: str | None = None,
    client_key: str | None = None,
) -> dict[str, Any]:
    """Validate an OAuth callback, exchange its code, and write a private token file."""

    request_timeout = _validate_timeout(timeout)
    lock_path = _acquire_state_lock(state_file)
    try:
        state = _read_private_json(state_file)
        _validate_state_payload(state)
        now = int(time.time())
        if state["expires_at"] < now:
            raise OAuthError("OAuth authorization state has expired")
        code = _validate_callback(callback_url, state)
        token_endpoint = _metadata_url(str(state["token_endpoint"]))
        _validate_network_url(
            token_endpoint,
            allow_private_network=allow_private_network,
            allow_insecure_http=allow_insecure_http,
            label="OAuth token endpoint",
        )
        form = urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "code": code,
                "client_id": state["client_id"],
                "redirect_uri": state["redirect_uri"],
                "code_verifier": state["code_verifier"],
                "resource": state["resource"],
            }
        ).encode("ascii")
        request = urllib.request.Request(
            token_endpoint,
            data=form,
            method="POST",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": f"mcp-tool-card-linter/{__version__}",
            },
        )
        http = _oauth_opener(
            ca_bundle=ca_bundle,
            proxy_url=proxy_url,
            client_cert=client_cert,
            client_key=client_key,
        )
        payload = _read_json_request(
            http,
            request,
            timeout=request_timeout,
            max_bytes=MAX_OAUTH_TOKEN_BYTES,
            label="OAuth token endpoint",
        )
        token_type = payload.get("token_type")
        if not isinstance(token_type, str) or token_type.lower() != "bearer":
            raise OAuthError("OAuth token response token_type must be Bearer")
        raw_access_token = payload.get("access_token")
        if not isinstance(raw_access_token, str):
            raise OAuthError("OAuth token response access_token must be a string")
        access_token = _validate_token(raw_access_token)
        _replace_private_text(token_file, access_token + "\n")
        _remove_file(state_file)
        return {
            "token_file": str(Path(token_file).expanduser().resolve()),
            "token_type": "Bearer",
            "expires_in": _optional_nonnegative_int(payload.get("expires_in")),
            "scope": _safe_response_scope(payload.get("scope")),
        }
    finally:
        _release_state_lock(lock_path)


def _probe_protected_resource_metadata(
    opener: Any,
    server_url: str,
    *,
    timeout: float,
    allow_private_network: bool,
    allow_insecure_http: bool,
) -> tuple[str | None, list[str] | None]:
    _validate_network_url(
        server_url,
        allow_private_network=allow_private_network,
        allow_insecure_http=allow_insecure_http,
        label="MCP server URL",
        oauth_https=False,
    )
    payload = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "mcp-tool-card-linter", "version": __version__},
            },
        },
        separators=(",", ":"),
    ).encode("utf-8")
    request = urllib.request.Request(
        server_url,
        data=payload,
        method="POST",
        headers={
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "MCP-Protocol-Version": MCP_PROTOCOL_VERSION,
            "User-Agent": f"mcp-tool-card-linter/{__version__}",
        },
    )
    try:
        with opener.open(request, timeout=timeout) as response:
            response.read(1)
            return None, None
    except urllib.error.HTTPError as exc:
        header = exc.headers.get("WWW-Authenticate", "")
        try:
            exc.read(MAX_HTTP_ERROR_BYTES + 1)
        finally:
            exc.close()
        if exc.code != 401:
            raise OAuthError(f"MCP authorization probe returned HTTP {exc.code}") from exc
        if not re.search(r"(?i)(?:^|,)\s*Bearer(?:\s|$)", header):
            return None, None
        metadata_url = _quoted_challenge_parameter(header, "resource_metadata")
        scope_value = _quoted_challenge_parameter(header, "scope")
        challenged_scopes = _validate_scopes(scope_value.split()) if scope_value else None
        return metadata_url, challenged_scopes
    except urllib.error.URLError as exc:
        raise OAuthError(
            f"MCP authorization probe failed: {safe_log_text(exc.reason)}"
        ) from exc


def _discover_protected_resource_metadata(
    opener: Any,
    resource: str,
    *,
    hint: str | None,
    timeout: float,
    allow_private_network: bool,
    allow_insecure_http: bool,
) -> dict[str, Any]:
    candidates = [hint] if hint else []
    candidates.extend(_protected_resource_metadata_candidates(resource))
    last_error: OAuthError | None = None
    for candidate in _unique(item for item in candidates if item is not None):
        try:
            url = _metadata_url(candidate)
            _validate_network_url(
                url,
                allow_private_network=allow_private_network,
                allow_insecure_http=allow_insecure_http,
                label="protected resource metadata URL",
            )
            payload = _get_json(opener, url, timeout=timeout, label="protected resource metadata")
            declared_resource = payload.get("resource")
            if not isinstance(declared_resource, str):
                raise OAuthError("Protected resource metadata must declare resource")
            if declared_resource != resource:
                raise OAuthError("Protected resource metadata resource does not match MCP server")
            return payload
        except OAuthError as exc:
            last_error = exc
    raise OAuthError(
        "Could not discover valid protected resource metadata"
        + (f": {safe_log_text(last_error)}" if last_error else "")
    )


def _discover_authorization_server_metadata(
    opener: Any,
    issuers: list[str],
    *,
    timeout: float,
    allow_private_network: bool,
    allow_insecure_http: bool,
) -> tuple[dict[str, Any], str]:
    last_error: OAuthError | None = None
    for issuer in issuers:
        for candidate in _authorization_metadata_candidates(issuer):
            try:
                _validate_network_url(
                    candidate,
                    allow_private_network=allow_private_network,
                    allow_insecure_http=allow_insecure_http,
                    label="authorization server metadata URL",
                )
                payload = _get_json(
                    opener,
                    candidate,
                    timeout=timeout,
                    label="authorization server metadata",
                )
                declared = payload.get("issuer")
                if not isinstance(declared, str) or declared != issuer:
                    raise OAuthError("Authorization metadata issuer mismatch")
                return payload, issuer
            except OAuthError as exc:
                last_error = exc
    raise OAuthError(
        "Could not discover valid authorization server metadata"
        + (f": {safe_log_text(last_error)}" if last_error else "")
    )


def _get_json(opener: Any, url: str, *, timeout: float, label: str) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": f"mcp-tool-card-linter/{__version__}"},
    )
    return _read_json_request(
        opener,
        request,
        timeout=timeout,
        max_bytes=MAX_OAUTH_METADATA_BYTES,
        label=label,
    )


def _read_json_request(
    opener: Any,
    request: urllib.request.Request,
    *,
    timeout: float,
    max_bytes: int,
    label: str,
) -> dict[str, Any]:
    try:
        with opener.open(request, timeout=timeout) as response:
            media_type = response.headers.get("Content-Type", "").split(";", 1)[0].lower()
            if media_type != "application/json" and not media_type.endswith("+json"):
                raise OAuthError(f"{label} returned unsupported Content-Type")
            length = response.headers.get("Content-Length")
            if length is not None:
                try:
                    declared = int(length)
                except ValueError as exc:
                    raise OAuthError(f"{label} returned invalid Content-Length") from exc
                if declared < 0 or declared > max_bytes:
                    raise OAuthError(f"{label} exceeds the {max_bytes} byte limit")
            raw = response.read(max_bytes + 1)
    except OAuthError:
        raise
    except urllib.error.HTTPError as exc:
        try:
            raw_error = exc.read(MAX_HTTP_ERROR_BYTES + 1)
        finally:
            exc.close()
        detail = safe_log_text(raw_error[:MAX_HTTP_ERROR_BYTES].decode("utf-8", "replace"))
        raise OAuthError(f"{label} returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise OAuthError(f"{label} request failed: {safe_log_text(exc.reason)}") from exc
    except TimeoutError as exc:
        raise OAuthError(f"{label} request timed out") from exc
    if len(raw) > max_bytes:
        raise OAuthError(f"{label} exceeds the {max_bytes} byte limit")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise OAuthError(f"{label} is not valid UTF-8") from exc
    try:
        payload = strict_json_loads(text)
    except InputValidationError as exc:
        raise OAuthError(f"{label} is not valid JSON: {safe_log_text(exc)}") from exc
    if not isinstance(payload, dict):
        raise OAuthError(f"{label} JSON must be an object")
    return payload


def _protected_resource_metadata_candidates(resource: str) -> list[str]:
    parsed = urlsplit(resource)
    path = parsed.path if parsed.path != "/" else ""
    return _unique(
        [
            urlunsplit(
                (
                    parsed.scheme,
                    parsed.netloc,
                    "/.well-known/oauth-protected-resource" + path,
                    "",
                    "",
                )
            ),
            urlunsplit(
                (
                    parsed.scheme,
                    parsed.netloc,
                    "/.well-known/oauth-protected-resource",
                    "",
                    "",
                )
            ),
        ]
    )


def _authorization_metadata_candidates(issuer: str) -> list[str]:
    parsed = urlsplit(issuer)
    path = parsed.path if parsed.path != "/" else ""
    return _unique(
        [
            urlunsplit(
                (
                    parsed.scheme,
                    parsed.netloc,
                    "/.well-known/oauth-authorization-server" + path,
                    "",
                    "",
                )
            ),
            urlunsplit(
                (
                    parsed.scheme,
                    parsed.netloc,
                    "/.well-known/openid-configuration" + path,
                    "",
                    "",
                )
            ),
            issuer.rstrip("/") + "/.well-known/openid-configuration",
        ]
    )


def _authorization_servers(payload: dict[str, Any]) -> list[str]:
    values = payload.get("authorization_servers")
    if not isinstance(values, list) or not 1 <= len(values) <= MAX_AUTHORIZATION_SERVERS:
        raise OAuthError(
            "Protected resource metadata authorization_servers must be a bounded non-empty array"
        )
    result: list[str] = []
    for value in values:
        if not isinstance(value, str):
            raise OAuthError("Protected resource metadata authorization_servers must be strings")
        result.append(_validate_issuer(value))
    if len(result) != len(set(result)):
        raise OAuthError("Protected resource metadata contains duplicate authorization servers")
    return result


def _metadata_endpoint(
    payload: dict[str, Any],
    field: str,
    *,
    allow_private_network: bool,
    allow_insecure_http: bool,
) -> str:
    value = payload.get(field)
    if not isinstance(value, str):
        raise OAuthError(f"Authorization metadata must declare {field}")
    result = _metadata_url(value)
    _validate_network_url(
        result,
        allow_private_network=allow_private_network,
        allow_insecure_http=allow_insecure_http,
        label=field,
    )
    return result


def _metadata_url(value: str) -> str:
    _validate_text("metadata URL", value)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise OAuthError(f"Invalid metadata URL: {safe_log_text(exc)}") from exc
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise OAuthError("Metadata URL must be absolute HTTP(S)")
    if parsed.username is not None or parsed.password is not None:
        raise OAuthError("Credentials in metadata URLs are not allowed")
    if parsed.fragment or port is not None and not 1 <= port <= 65535:
        raise OAuthError("Metadata URL has an invalid fragment or port")
    return value


def _canonical_resource_uri(value: str) -> str:
    try:
        validated = validate_mcp_url(
            value,
            allow_private_network=True,
            allow_insecure_http=True,
            resolve_hostnames=False,
        )
        parsed = urlsplit(validated)
        port = parsed.port
    except InputValidationError as exc:
        raise OAuthError(str(exc)) from exc
    if parsed.query:
        raise OAuthError("OAuth MCP resource URI must not include a query")
    host = (parsed.hostname or "").lower().rstrip(".")
    default_port = 443 if parsed.scheme == "https" else 80
    authority = f"[{host}]" if ":" in host else host
    if port is not None and port != default_port:
        authority += f":{port}"
    path = parsed.path
    return urlunsplit((parsed.scheme.lower(), authority, path, "", ""))


def _validate_issuer(value: str) -> str:
    parsed_value = _metadata_url(value)
    parsed = urlsplit(parsed_value)
    if parsed.query:
        raise OAuthError("Authorization server issuer must not include a query")
    return parsed_value


def _validate_network_url(
    value: str,
    *,
    allow_private_network: bool,
    allow_insecure_http: bool,
    label: str,
    oauth_https: bool = True,
) -> None:
    try:
        validate_mcp_url(
            value,
            allow_private_network=allow_private_network,
            allow_insecure_http=allow_insecure_http,
            allow_loopback=True,
        )
    except InputValidationError as exc:
        raise OAuthError(f"Invalid {label}: {safe_log_text(exc)}") from exc
    if oauth_https and urlsplit(value).scheme != "https" and not allow_insecure_http:
        raise OAuthError(f"{label} must use HTTPS")


def _validate_redirect_uri(value: str) -> str:
    parsed_value = _metadata_url(value)
    parsed = urlsplit(parsed_value)
    if parsed.query:
        raise OAuthError("redirect_uri must not include a query")
    host = (parsed.hostname or "").lower().rstrip(".")
    localhost = host == "localhost"
    if parsed.scheme != "https" and not (parsed.scheme == "http" and localhost):
        raise OAuthError("redirect_uri must use HTTPS or HTTP on the exact localhost host")
    return parsed_value


def _validate_callback(callback_url: str, state: dict[str, Any]) -> str:
    parsed_url = _metadata_url(callback_url)
    parsed = urlsplit(parsed_url)
    callback_base = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    if callback_base != state["redirect_uri"]:
        raise OAuthError("OAuth callback URL does not match the registered redirect_uri")
    try:
        pairs = urllib.parse.parse_qsl(
            parsed.query,
            keep_blank_values=True,
            strict_parsing=True,
            max_num_fields=16,
        )
    except ValueError as exc:
        raise OAuthError(f"OAuth callback query is invalid: {safe_log_text(exc)}") from exc
    values: dict[str, str] = {}
    for key, value in pairs:
        if key in values:
            raise OAuthError(f"OAuth callback contains duplicate parameter: {safe_log_text(key)}")
        values[key] = value
    if not secrets.compare_digest(values.get("state", ""), str(state["state"])):
        raise OAuthError("OAuth callback state mismatch")
    if "error" in values:
        raise OAuthError(f"Authorization server returned error: {safe_log_text(values['error'])}")
    if "iss" in values and values["iss"] != state["authorization_server"]:
        raise OAuthError("OAuth callback issuer mismatch")
    return _validate_text("authorization code", values.get("code"))


def _validate_state_payload(payload: dict[str, Any]) -> None:
    required_strings = (
        "resource",
        "authorization_server",
        "token_endpoint",
        "client_id",
        "redirect_uri",
        "code_verifier",
        "state",
    )
    if payload.get("schema_version") != "1.0":
        raise OAuthError("Unsupported OAuth state schema version")
    for field in required_strings:
        _validate_text(f"OAuth state {field}", payload.get(field))
    for field in ("created_at", "expires_at"):
        if isinstance(payload.get(field), bool) or not isinstance(payload.get(field), int):
            raise OAuthError(f"OAuth state {field} must be an integer")
    now = int(time.time())
    if payload["created_at"] > now + 60:
        raise OAuthError("OAuth state creation time is in the future")
    lifetime = payload["expires_at"] - payload["created_at"]
    if not 0 <= lifetime <= AUTHORIZATION_STATE_TTL_SECONDS:
        raise OAuthError("OAuth state has an invalid lifetime")
    if _canonical_resource_uri(payload["resource"]) != payload["resource"]:
        raise OAuthError("OAuth state resource is not canonical")
    if _validate_issuer(payload["authorization_server"]) != payload["authorization_server"]:
        raise OAuthError("OAuth state authorization server is invalid")
    _metadata_url(payload["token_endpoint"])
    if _validate_redirect_uri(payload["redirect_uri"]) != payload["redirect_uri"]:
        raise OAuthError("OAuth state redirect URI is invalid")
    if not _PKCE_VERIFIER.fullmatch(payload["code_verifier"]):
        raise OAuthError("OAuth state PKCE verifier is invalid")
    scopes = payload.get("scopes")
    if not isinstance(scopes, list):
        raise OAuthError("OAuth state scopes must be an array")
    _validate_scopes(scopes)


def _validate_scopes(values: Iterable[str]) -> list[str]:
    if isinstance(values, (str, bytes)):
        raise OAuthError("OAuth scopes must be an iterable of individual tokens")
    result = list(values)
    if len(result) > MAX_OAUTH_SCOPES:
        raise OAuthError(f"OAuth scopes exceed the {MAX_OAUTH_SCOPES} item limit")
    for value in result:
        if not isinstance(value, str) or not _SCOPE_TOKEN.fullmatch(value):
            raise OAuthError("OAuth scope contains an invalid token")
    if len(result) != len(set(result)):
        raise OAuthError("OAuth scopes contain duplicates")
    return result


def _metadata_scopes(payload: dict[str, Any]) -> list[str]:
    values = payload.get("scopes_supported")
    if values is None:
        return []
    if not isinstance(values, list):
        raise OAuthError("Protected resource metadata scopes_supported must be an array")
    return _validate_scopes(values)


def _quoted_challenge_parameter(header: str, name: str) -> str | None:
    if not isinstance(header, str) or len(header) > 64 * 1024:
        raise OAuthError("WWW-Authenticate challenge is invalid or too large")
    pattern = re.compile(
        rf'(?i)(?:^|[,\s]){re.escape(name)}\s*=\s*"((?:[^"\\]|\\.)*)"'
    )
    matches = pattern.findall(header)
    if len(matches) > 1:
        raise OAuthError(
            f"WWW-Authenticate challenge contains duplicate {safe_log_text(name)} parameters"
        )
    if not matches:
        return None
    return re.sub(r"\\(.)", r"\1", matches[0])


def _validate_text(label: str, value: Any) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= MAX_OAUTH_FIELD_CHARS
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise OAuthError(f"{label} must be a bounded string without control characters")
    return value


def _validate_timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise OAuthError("OAuth timeout must be a number")
    result = float(value)
    if not 0.05 <= result <= 300 or result != result or result in {float("inf"), -float("inf")}:
        raise OAuthError("OAuth timeout must be finite and in 0.05..300")
    return result


def _append_query(url: str, params: list[tuple[str, str]]) -> str:
    parsed = urlsplit(url)
    query = urllib.parse.urlencode(params)
    combined = "&".join(item for item in (parsed.query, query) if item)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, combined, ""))


def _create_private_json(path: str | Path, payload: dict[str, Any]) -> None:
    raw = (
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"), allow_nan=False) + "\n"
    ).encode("utf-8")
    resolved = _resolved_file(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    created = False
    try:
        descriptor = os.open(resolved, flags, 0o600)
        created = True
        owned_descriptor = descriptor
        descriptor = None
        with os.fdopen(owned_descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        _fsync_directory(resolved.parent)
    except FileExistsError as exc:
        raise OAuthError("OAuth state file already exists; refusing to overwrite it") from exc
    except OSError as exc:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if created:
            try:
                resolved.unlink(missing_ok=True)
            except OSError:
                pass
        raise OAuthError(f"Failed to create OAuth state file: {safe_log_text(exc)}") from exc


def _read_private_json(path: str | Path) -> dict[str, Any]:
    resolved = _resolved_file(path)
    try:
        with resolved.open("rb") as stream:
            mode = os.fstat(stream.fileno()).st_mode
            if not stat.S_ISREG(mode):
                raise OAuthError("OAuth state path is not a regular file")
            if os.name == "posix" and stat.S_IMODE(mode) & 0o077:
                raise OAuthError("OAuth state file must have mode 0600")
            raw = stream.read(MAX_OAUTH_METADATA_BYTES + 1)
    except OAuthError:
        raise
    except OSError as exc:
        raise OAuthError(f"Failed to read OAuth state file: {safe_log_text(exc)}") from exc
    if len(raw) > MAX_OAUTH_METADATA_BYTES:
        raise OAuthError("OAuth state file exceeds its byte limit")
    try:
        payload = strict_json_loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, InputValidationError) as exc:
        raise OAuthError(f"OAuth state file is invalid: {safe_log_text(exc)}") from exc
    if not isinstance(payload, dict):
        raise OAuthError("OAuth state file must contain a JSON object")
    return payload


def _replace_private_text(path: str | Path, value: str) -> None:
    resolved = _resolved_file(path)
    parent = resolved.parent
    temporary = parent / f".{resolved.name}.{secrets.token_hex(8)}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(temporary, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(value.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, resolved)
        _fsync_directory(parent)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise OAuthError(f"Failed to write bearer token file: {safe_log_text(exc)}") from exc


def _acquire_state_lock(path: str | Path) -> Path:
    resolved = _resolved_file(path)
    lock = resolved.with_name(resolved.name + ".lock")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor: int | None = None
    try:
        descriptor = os.open(lock, flags, 0o600)
        os.close(descriptor)
        descriptor = None
    except FileExistsError as exc:
        raise OAuthError("OAuth state is already being completed by another process") from exc
    except OSError as exc:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass
        try:
            lock.unlink(missing_ok=True)
        except OSError:
            pass
        raise OAuthError(f"Failed to lock OAuth state: {safe_log_text(exc)}") from exc
    return lock


def _release_state_lock(path: Path) -> None:
    try:
        path.unlink(missing_ok=True)
    except OSError:
        pass


def _remove_file(path: str | Path) -> None:
    try:
        _resolved_file(path).unlink()
    except OSError as exc:
        raise OAuthError(f"Token was written but OAuth state cleanup failed: {safe_log_text(exc)}") from exc


def _resolved_file(path: str | Path) -> Path:
    try:
        return Path(path).expanduser().resolve()
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise OAuthError(f"Invalid OAuth file path: {safe_log_text(exc)}") from exc


def _fsync_directory(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor: int | None = None
    try:
        descriptor = os.open(path, os.O_RDONLY)
        os.fsync(descriptor)
    except OSError:
        # The file itself was already fsynced. Some filesystems do not allow
        # directory fsync, so durability hardening must remain best-effort.
        pass
    finally:
        if descriptor is not None:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _oauth_opener(
    *,
    ca_bundle: str | None,
    proxy_url: str | None,
    client_cert: str | None,
    client_key: str | None,
) -> Any:
    try:
        return _build_http_opener(
            ca_bundle=ca_bundle,
            proxy_url=proxy_url,
            client_cert=client_cert,
            client_key=client_key,
        )
    except DiscoveryError as exc:
        raise OAuthError(str(exc)) from exc


def _optional_nonnegative_int(value: Any) -> int | None:
    if value is None:
        return None
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value <= 2**63 - 1
    ):
        raise OAuthError("OAuth token response expires_in must be a non-negative integer")
    return int(value)


def _safe_response_scope(value: Any) -> str | None:
    if value is None:
        return None
    validated = _validate_text("OAuth token response scope", value)
    _validate_scopes(validated.split(" "))
    return validated


def _unique(values: Iterable[str]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result

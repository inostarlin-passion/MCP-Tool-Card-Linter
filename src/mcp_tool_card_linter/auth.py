from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Mapping, Protocol, Sequence

from .security import InputValidationError, safe_log_text

MAX_TOKEN_BYTES = 64 * 1024
MAX_TOKEN_CHARS = 64 * 1024
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


class CredentialError(InputValidationError):
    """Raised when credentials cannot be obtained without exposing them."""


class CredentialProvider(Protocol):
    def authorization_headers(
        self,
        endpoint: str,
        scopes: Sequence[str],
    ) -> Mapping[str, str]: ...


class BearerTokenProvider:
    """A minimal provider for pre-issued, endpoint-scoped bearer tokens.

    It deliberately does not validate token audience locally: opaque access tokens
    have no client-readable claims. The authorization server and MCP resource server
    remain responsible for audience validation.
    """

    def __init__(self, token: str) -> None:
        self._token = _validate_token(token)

    @classmethod
    def from_environment(cls, variable: str) -> "BearerTokenProvider":
        if not isinstance(variable, str) or not _ENV_NAME.fullmatch(variable):
            raise CredentialError("Bearer token environment name is invalid")
        token = os.environ.get(variable)
        if token is None:
            raise CredentialError(
                f"Bearer token environment variable is not set: {safe_log_text(variable)}"
            )
        return cls(token)

    @classmethod
    def from_file(cls, path: str | Path) -> "BearerTokenProvider":
        try:
            resolved = Path(path).expanduser().resolve()
            with resolved.open("rb") as stream:
                mode = os.fstat(stream.fileno()).st_mode
                if not stat.S_ISREG(mode):
                    raise CredentialError("Bearer token path is not a regular file")
                if os.name == "posix" and stat.S_IMODE(mode) & 0o077:
                    raise CredentialError(
                        "Bearer token file must not be readable or writable by group/others"
                    )
                raw = stream.read(MAX_TOKEN_BYTES + 1)
        except CredentialError:
            raise
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise CredentialError(f"Failed to read bearer token file: {safe_log_text(exc)}") from exc
        if len(raw) > MAX_TOKEN_BYTES:
            raise CredentialError(f"Bearer token file exceeds {MAX_TOKEN_BYTES} bytes")
        try:
            token = raw.decode("utf-8").strip()
        except UnicodeDecodeError as exc:
            raise CredentialError("Bearer token file is not valid UTF-8") from exc
        return cls(token)

    def authorization_headers(
        self,
        endpoint: str,
        scopes: Sequence[str],
    ) -> Mapping[str, str]:
        del endpoint, scopes
        return {"Authorization": f"Bearer {self._token}"}


def _validate_token(token: str) -> str:
    if not isinstance(token, str):
        raise CredentialError("Bearer token must be a string")
    if not 1 <= len(token) <= MAX_TOKEN_CHARS:
        raise CredentialError(f"Bearer token must contain 1..{MAX_TOKEN_CHARS} characters")
    if any(ord(character) < 0x21 or ord(character) > 0x7E for character in token):
        raise CredentialError("Bearer token must contain only visible ASCII without whitespace")
    return token

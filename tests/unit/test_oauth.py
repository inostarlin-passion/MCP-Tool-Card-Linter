from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from mcp_tool_card_linter.oauth import (
    AUTHORIZATION_STATE_TTL_SECONDS,
    OAuthError,
    _acquire_state_lock,
    _authorization_servers,
    _authorization_metadata_candidates,
    _canonical_resource_uri,
    _create_private_json,
    _metadata_scopes,
    _metadata_url,
    _optional_nonnegative_int,
    _protected_resource_metadata_candidates,
    _quoted_challenge_parameter,
    _read_private_json,
    _release_state_lock,
    _safe_response_scope,
    _validate_state_payload,
    _validate_timeout,
    _validate_redirect_uri,
    _validate_scopes,
    callback_url_from_environment,
    callback_url_from_file,
)


class OAuthUnitTests(unittest.TestCase):
    def test_authorization_metadata_candidates_follow_required_priority(self) -> None:
        self.assertEqual(
            _authorization_metadata_candidates("https://auth.example/tenant"),
            [
                "https://auth.example/.well-known/oauth-authorization-server/tenant",
                "https://auth.example/.well-known/openid-configuration/tenant",
                "https://auth.example/tenant/.well-known/openid-configuration",
            ],
        )

    def test_protected_resource_metadata_prefers_endpoint_path_then_root(self) -> None:
        self.assertEqual(
            _protected_resource_metadata_candidates("https://mcp.example/public/mcp"),
            [
                "https://mcp.example/.well-known/oauth-protected-resource/public/mcp",
                "https://mcp.example/.well-known/oauth-protected-resource",
            ],
        )

    def test_canonical_resource_preserves_semantic_path_and_omits_implicit_slash(self) -> None:
        self.assertEqual(_canonical_resource_uri("https://MCP.Example:443"), "https://mcp.example")
        self.assertEqual(
            _canonical_resource_uri("https://MCP.Example:443/tenant/mcp"),
            "https://mcp.example/tenant/mcp",
        )

    def test_redirect_uri_requires_https_or_exact_localhost(self) -> None:
        self.assertEqual(
            _validate_redirect_uri("http://localhost:8765/callback"),
            "http://localhost:8765/callback",
        )
        with self.assertRaisesRegex(OAuthError, "localhost"):
            _validate_redirect_uri("http://127.0.0.1:8765/callback")
        with self.assertRaisesRegex(OAuthError, "localhost"):
            _validate_redirect_uri("http://example.com/callback")

    def test_scope_and_challenge_parsing_reject_ambiguity(self) -> None:
        self.assertEqual(_validate_scopes(["tools.read", "records:read"]), ["tools.read", "records:read"])
        self.assertEqual(
            _quoted_challenge_parameter(
                'Bearer resource_metadata="https://mcp.example/prm", scope="tools.read"',
                "scope",
            ),
            "tools.read",
        )
        with self.assertRaisesRegex(OAuthError, "duplicate"):
            _quoted_challenge_parameter('Bearer scope="one", scope="two"', "scope")

    def test_callback_file_requires_owner_only_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "callback"
            path.write_text(
                "http://localhost:8765/callback?code=code&state=state\n",
                encoding="utf-8",
            )
            if os.name == "posix":
                path.chmod(0o644)
                with self.assertRaisesRegex(OAuthError, "0600"):
                    callback_url_from_file(path)
                path.chmod(0o600)
            self.assertIn("code=code", callback_url_from_file(path))

    def test_callback_environment_and_metadata_url_validation(self) -> None:
        with mock.patch.dict(
            os.environ,
            {"MCP_CALLBACK": "https://client.example/cb?code=one&state=two"},
            clear=True,
        ):
            self.assertIn("code=one", callback_url_from_environment("MCP_CALLBACK"))
            with self.assertRaisesRegex(OAuthError, "not set"):
                callback_url_from_environment("MISSING_CALLBACK")
        with self.assertRaisesRegex(OAuthError, "name"):
            callback_url_from_environment("bad-name")
        for value in (
            "relative/path",
            "https://user:password@example.com/metadata",
            "https://example.com/metadata#fragment",
        ):
            with self.subTest(value=value), self.assertRaises(OAuthError):
                _metadata_url(value)

    def test_oauth_scalar_and_scope_boundaries(self) -> None:
        for value in (True, float("nan"), 301):
            with self.subTest(timeout=value), self.assertRaises(OAuthError):
                _validate_timeout(value)
        with self.assertRaisesRegex(OAuthError, "individual tokens"):
            _validate_scopes("tools.read")
        with self.assertRaisesRegex(OAuthError, "item limit"):
            _validate_scopes([f"scope-{index}" for index in range(65)])
        with self.assertRaisesRegex(OAuthError, "invalid token"):
            _validate_scopes(["space separated"])
        with self.assertRaisesRegex(OAuthError, "duplicates"):
            _validate_scopes(["same", "same"])
        self.assertEqual(_metadata_scopes({}), [])
        self.assertEqual(_metadata_scopes({"scopes_supported": ["one"]}), ["one"])
        with self.assertRaisesRegex(OAuthError, "must be an array"):
            _metadata_scopes({"scopes_supported": "one"})
        self.assertIsNone(_optional_nonnegative_int(None))
        self.assertEqual(_optional_nonnegative_int(0), 0)
        with self.assertRaisesRegex(OAuthError, "non-negative"):
            _optional_nonnegative_int(-1)
        self.assertEqual(_safe_response_scope("one two"), "one two")
        with self.assertRaises(OAuthError):
            _safe_response_scope("one  two")

    def test_oauth_metadata_and_resource_boundaries(self) -> None:
        with self.assertRaisesRegex(OAuthError, "query"):
            _canonical_resource_uri("https://mcp.example/mcp?tenant=one")
        with self.assertRaisesRegex(OAuthError, "non-empty array"):
            _authorization_servers({"authorization_servers": []})
        with self.assertRaisesRegex(OAuthError, "strings"):
            _authorization_servers({"authorization_servers": [123]})
        with self.assertRaisesRegex(OAuthError, "duplicate"):
            _authorization_servers(
                {"authorization_servers": ["https://auth.example", "https://auth.example"]}
            )
        with self.assertRaisesRegex(OAuthError, "too large"):
            _quoted_challenge_parameter("x" * (64 * 1024 + 1), "scope")
        self.assertIsNone(_quoted_challenge_parameter("Bearer realm=example", "scope"))

    def test_private_state_file_lifecycle_and_locking(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "state.json"
            _create_private_json(path, {"schema_version": "test"})
            self.assertEqual(_read_private_json(path)["schema_version"], "test")
            with self.assertRaisesRegex(OAuthError, "already exists"):
                _create_private_json(path, {})
            lock = _acquire_state_lock(path)
            with self.assertRaisesRegex(OAuthError, "another process"):
                _acquire_state_lock(path)
            _release_state_lock(lock)
            self.assertFalse(lock.exists())
            if os.name == "posix":
                path.chmod(0o644)
                with self.assertRaisesRegex(OAuthError, "0600"):
                    _read_private_json(path)

    def test_state_payload_revalidates_security_invariants(self) -> None:
        now = int(time.time())
        payload = {
            "schema_version": "1.0",
            "created_at": now,
            "expires_at": now + AUTHORIZATION_STATE_TTL_SECONDS,
            "resource": "https://mcp.example/mcp",
            "authorization_server": "https://auth.example",
            "token_endpoint": "https://auth.example/token",
            "client_id": "client",
            "redirect_uri": "https://client.example/callback",
            "code_verifier": "a" * 43,
            "state": "state",
            "scopes": ["tools.read"],
        }
        _validate_state_payload(payload)
        mutations = [
            ("schema_version", "2.0", "schema"),
            ("created_at", True, "integer"),
            ("expires_at", now + AUTHORIZATION_STATE_TTL_SECONDS + 1, "lifetime"),
            ("resource", "https://MCP.example:443/mcp", "canonical"),
            ("code_verifier", "short", "verifier"),
            ("scopes", "tools.read", "array"),
        ]
        for field, value, message in mutations:
            malformed = dict(payload)
            malformed[field] = value
            with self.subTest(field=field), self.assertRaisesRegex(OAuthError, message):
                _validate_state_payload(malformed)


if __name__ == "__main__":
    unittest.main()

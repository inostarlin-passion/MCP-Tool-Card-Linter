from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mcp_tool_card_linter.auth import BearerTokenProvider, CredentialError


class AuthenticationTests(unittest.TestCase):
    def test_bearer_token_provider_reads_environment_without_cli_token(self) -> None:
        with mock.patch.dict(os.environ, {"MCP_TEST_TOKEN": "opaque-token-value"}):
            provider = BearerTokenProvider.from_environment("MCP_TEST_TOKEN")
        self.assertEqual(
            provider.authorization_headers("https://example.test/mcp", ()),
            {"Authorization": "Bearer opaque-token-value"},
        )

    def test_bearer_token_file_requires_private_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "token"
            path.write_text("opaque-token-value\n", encoding="utf-8")
            if os.name == "posix":
                path.chmod(0o644)
                with self.assertRaisesRegex(CredentialError, "group/others"):
                    BearerTokenProvider.from_file(path)
                path.chmod(0o600)
            provider = BearerTokenProvider.from_file(path)
        self.assertEqual(
            provider.authorization_headers("https://example.test/mcp", ())["Authorization"],
            "Bearer opaque-token-value",
        )

    def test_bearer_token_rejects_header_injection(self) -> None:
        with self.assertRaisesRegex(CredentialError, "visible ASCII"):
            BearerTokenProvider("token\r\nX-Evil: yes")


if __name__ == "__main__":
    unittest.main()

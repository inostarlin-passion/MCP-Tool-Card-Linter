from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from mcp_tool_card_linter.security import (
    DuplicateJsonKeyError,
    InputValidationError,
    load_json_file,
    redact_command,
    safe_log_text,
    strict_json_loads,
    validate_mcp_url,
)


class SecurityPrimitiveTests(unittest.TestCase):
    def test_strict_json_rejects_duplicate_keys_and_nonstandard_numbers(self) -> None:
        with self.assertRaises(DuplicateJsonKeyError):
            strict_json_loads('{"tool": 1, "tool": 2}')
        with self.assertRaises(InputValidationError):
            strict_json_loads('{"score": NaN}')
        with self.assertRaises(InputValidationError):
            strict_json_loads('{"value": ' + "9" * 5000 + "}")

    def test_file_reader_enforces_byte_limit_and_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            oversized = Path(tmpdir) / "large.json"
            oversized.write_bytes(b" " * 33)
            with self.assertRaises(InputValidationError):
                load_json_file(oversized, max_bytes=32)

            invalid_utf8 = Path(tmpdir) / "invalid.json"
            invalid_utf8.write_bytes(b"{\"x\":\xff}")
            with self.assertRaises(InputValidationError):
                load_json_file(invalid_utf8)

    def test_url_policy_allows_loopback_and_rejects_unsafe_destinations(self) -> None:
        self.assertEqual(
            validate_mcp_url(
                "http://127.0.0.1:8080/mcp",
                resolve_hostnames=False,
            ),
            "http://127.0.0.1:8080/mcp",
        )
        with self.assertRaises(InputValidationError):
            validate_mcp_url(
                "https://192.168.1.10/mcp",
                resolve_hostnames=False,
            )
        with self.assertRaises(InputValidationError):
            validate_mcp_url(
                "http://93.184.216.34/mcp",
                resolve_hostnames=False,
            )
        with self.assertRaises(InputValidationError):
            validate_mcp_url(
                "https://user:password@example.com/mcp",
                resolve_hostnames=False,
            )

    def test_url_policy_requires_separate_explicit_opt_ins(self) -> None:
        self.assertEqual(
            validate_mcp_url(
                "http://192.168.1.10/mcp",
                allow_private_network=True,
                allow_insecure_http=True,
                resolve_hostnames=False,
            ),
            "http://192.168.1.10/mcp",
        )

    def test_diagnostics_redact_secrets_and_control_characters(self) -> None:
        command = redact_command(
            [
                "server",
                "--api-key",
                "super-secret-value",
                "--password=hunter2",
                "https://example.com/mcp?token=secret",
            ]
        )
        rendered = " ".join(command)
        self.assertNotIn("super-secret-value", rendered)
        self.assertNotIn("hunter2", rendered)
        self.assertNotIn("token=secret", rendered)

        diagnostic = safe_log_text(
            "password=secret-value Bearer abcdefghijklmnopqrstuvwxyz\n\x1b[31m forged"
        )
        self.assertNotIn("secret-value", diagnostic)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz", diagnostic)
        self.assertNotIn("\n", diagnostic)
        self.assertNotIn("\x1b", diagnostic)


if __name__ == "__main__":
    unittest.main()

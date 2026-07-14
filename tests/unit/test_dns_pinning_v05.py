from __future__ import annotations

import socket
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from mcp_tool_card_linter.security import DnsPinningPolicy, InputValidationError


def records(address: str):
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    return [(family, socket.SOCK_STREAM, 6, "", (address, 443))]


class DnsPinningV05Tests(unittest.TestCase):
    def test_rejects_public_address_change_across_requests(self) -> None:
        policy = DnsPinningPolicy()
        with mock.patch(
            "mcp_tool_card_linter.security.socket.getaddrinfo",
            side_effect=[
                records("203.0.113.10"),
                records("203.0.113.10"),
                records("203.0.113.11"),
                records("203.0.113.11"),
            ],
        ):
            # TEST-NET is non-global in ipaddress, so this case explicitly opts
            # into private/reserved addresses while still exercising pinning.
            policy.allow_private_network = True
            policy.validate("https://mcp.example.test/mcp")
            with self.assertRaisesRegex(InputValidationError, "DNS resolution changed"):
                policy.validate("https://mcp.example.test/mcp")

    def test_rebinding_to_metadata_address_is_rejected_before_open(self) -> None:
        policy = DnsPinningPolicy()
        with mock.patch(
            "mcp_tool_card_linter.security.socket.getaddrinfo",
            side_effect=[
                records("8.8.8.8"),
                records("8.8.8.8"),
                records("169.254.169.254"),
            ],
        ):
            policy.validate("https://mcp.example.test/mcp")
            with self.assertRaisesRegex(InputValidationError, "non-public address"):
                policy.validate("https://mcp.example.test/mcp")

    def test_pin_set_is_bounded(self) -> None:
        policy = DnsPinningPolicy(allow_private_network=True, max_endpoints=1)
        with mock.patch(
            "mcp_tool_card_linter.security.socket.getaddrinfo",
            return_value=records("203.0.113.10"),
        ):
            policy.validate("https://one.example.test/mcp")
            with self.assertRaisesRegex(InputValidationError, "exceeded 1 endpoints"):
                policy.validate("https://two.example.test/mcp")


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import os
import sys
import threading
import unittest
from pathlib import Path

from mcp_tool_card_linter.discovery import discover_from_stdio_command
from mcp_tool_card_linter.execution import HostExecutor

ROOT = Path(__file__).resolve().parents[2]
SOAK_ENV = "MCP_LINTER_ENFORCE_SOAK"


class SoakV1SystemTests(unittest.TestCase):
    def test_repeated_stdio_lifecycle_does_not_accumulate_threads_or_descriptors(self) -> None:
        enforce = os.environ.get(SOAK_ENV, "0")
        self.assertIn(enforce, {"0", "1"})
        cycles = 40 if enforce == "1" else 2
        threads_before = threading.active_count()
        descriptors_before = _descriptor_count()
        fixture = ROOT / "tests" / "fixtures" / "mock_mcp_stdio_server.py"

        for index in range(cycles):
            result = discover_from_stdio_command(
                [sys.executable, str(fixture), "normal"],
                server_name=f"soak-{index}",
                timeout=5.0,
                max_tools=10,
                executor=HostExecutor(),
            )
            self.assertEqual(len(result.tools), 2)

        self.assertLessEqual(threading.active_count(), threads_before + 1)
        descriptors_after = _descriptor_count()
        if descriptors_before is not None and descriptors_after is not None:
            self.assertLessEqual(descriptors_after, descriptors_before + 2)


def _descriptor_count() -> int | None:
    for candidate in (Path("/dev/fd"), Path("/proc/self/fd")):
        try:
            return len(list(candidate.iterdir()))
        except OSError:
            continue
    return None


if __name__ == "__main__":
    unittest.main()

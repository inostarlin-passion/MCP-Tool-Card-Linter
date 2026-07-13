#!/usr/bin/env python3
"""Minimal adapter used by the official MCP client conformance runner.

The runner appends its scenario server URL to this command. The adapter only
performs the client lifecycle; ordinary linter discovery is tested separately.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from mcp_tool_card_linter.discovery import StreamableHttpMcpClient


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print("usage: client.py <conformance-server-url>", file=sys.stderr)
        return 2
    with StreamableHttpMcpClient(argv[0], timeout=10) as client:
        print(json.dumps(client.discovery_metadata(), sort_keys=True))
        # The official sse-retry fixture exposes a uniquely named inert tool.
        # Calling only that fixture tool lets the runner exercise the shared
        # POST-SSE -> delayed GET resumption code without broadening production
        # lint discovery into arbitrary tool execution.
        if (client.server_info or {}).get("name") == "sse-retry-test-server":
            tools = client.list_tools(max_tools=10, max_pages=2)
            if [tool.get("name") for tool in tools if isinstance(tool, dict)] != [
                "test_reconnection"
            ]:
                raise RuntimeError("Unexpected tool set from sse-retry conformance fixture")
            client._request(
                "tools/call",
                {"name": "test_reconnection", "arguments": {}},
                retryable=False,
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

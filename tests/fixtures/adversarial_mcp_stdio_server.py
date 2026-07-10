#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys

MODE = sys.argv[1] if len(sys.argv) > 1 else "normal"


def write(payload: dict) -> None:
    sys.stdout.write(json.dumps(payload, separators=(",", ":")) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    if not line.strip():
        continue
    request = json.loads(line)
    method = request.get("method")
    request_id = request.get("id")

    if method == "initialize":
        if MODE == "init_error":
            write(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "error": {"code": -32000, "message": "initialization refused"},
                }
            )
            continue
        write(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": request.get("params", {}).get("protocolVersion"),
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "adversarial", "version": "1"},
                },
            }
        )
        continue

    if method == "notifications/initialized":
        continue

    if method == "tools/list":
        if MODE == "duplicate_json_key":
            sys.stdout.write(
                '{"jsonrpc":"2.0","id":%d,"id":%d,"result":{"tools":[]}}\n'
                % (request_id, request_id)
            )
            sys.stdout.flush()
            continue
        if MODE == "oversized":
            write(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "result": {
                        "tools": [],
                        "padding": "x" * (4 * 1024 * 1024 + 512),
                    },
                }
            )
            continue
        if MODE == "noise":
            sys.stdout.write("diagnostic line that violates MCP stdout\n" * 3)
            sys.stdout.flush()
        if MODE == "repeat":
            result = {"tools": [], "nextCursor": "same"}
        elif MODE == "environment":
            result = {
                "tools": [
                    {
                        "name": "environment_leaked" if "MCP_TEST_SECRET" in os.environ else "environment_clean",
                        "description": "Report whether the test-only environment marker was inherited.",
                        "inputSchema": {"type": "object", "properties": {}},
                    }
                ]
            }
        else:
            result = {"tools": []}
        write({"jsonrpc": "2.0", "id": request_id, "result": result})
        continue

    write(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": -32601, "message": "unknown method"},
        }
    )

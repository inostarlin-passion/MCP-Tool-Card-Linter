#!/usr/bin/env python3
import json
import sys


PAGE_1 = [
    {
        "name": "search_customer_orders",
        "description": "Search customer orders by customer email or order status. Use for read-only order lookup only; it does not modify orders.",
        "annotations": {"readOnlyHint": True},
        "inputSchema": {
            "type": "object",
            "properties": {
                "email": {
                    "type": "string",
                    "description": "Customer email address",
                    "maxLength": 254,
                },
                "status": {
                    "type": "string",
                    "description": "Order status filter",
                    "enum": ["pending", "paid", "cancelled"],
                },
            },
            "required": [],
            "additionalProperties": False,
        },
        "outputSchema": {
            "type": "object",
            "properties": {"orders": {"type": "array", "items": {"type": "object"}}},
            "required": ["orders"],
            "additionalProperties": False,
        },
    }
]

PAGE_2 = [
    {
        "name": "delete_customer",
        "description": "Delete a customer record. This permanently removes data and requires explicit user confirmation before calling.",
        "annotations": {"destructiveHint": True},
        "inputSchema": {
            "type": "object",
            "properties": {
                "customer_id": {
                    "type": "string",
                    "description": "Internal customer ID to delete",
                    "maxLength": 64,
                }
            },
            "required": ["customer_id"],
            "additionalProperties": False,
        },
        "outputSchema": {
            "type": "object",
            "properties": {"deleted": {"type": "boolean"}},
            "required": ["deleted"],
            "additionalProperties": False,
        },
    }
]


def write(message):
    sys.stdout.write(json.dumps(message, separators=(",", ":")) + "\n")
    sys.stdout.flush()


for line in sys.stdin:
    if not line.strip():
        continue
    request = json.loads(line)
    method = request.get("method")
    request_id = request.get("id")
    if method == "initialize":
        write(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "result": {
                    "protocolVersion": request.get("params", {}).get("protocolVersion"),
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "mock-stdio", "version": "1.0.0"},
                },
            }
        )
    elif method == "notifications/initialized":
        continue
    elif method == "tools/list":
        cursor = request.get("params", {}).get("cursor")
        if cursor == "page-2":
            result = {"tools": PAGE_2}
        else:
            result = {"tools": PAGE_1, "nextCursor": "page-2"}
        write({"jsonrpc": "2.0", "id": request_id, "result": result})
    else:
        write(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "error": {"code": -32601, "message": f"unknown method {method}"},
            }
        )


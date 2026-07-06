# MCP Tool Card Linter

MCP Tool Card Linter is a CLI quality gate for MCP servers. It discovers exposed tools, checks tool names, descriptions, `inputSchema`, `outputSchema`, annotations, potential side effects, and tool-poisoning risks, then emits JSON/Markdown reports and CI-friendly exit codes.

In this project, a "Tool Card" is an engineering concept: a reviewable bundle of an MCP tool's name, description, input/output schemas, behavior annotations, risk level, and recommendations. It is not a standalone object in the MCP specification.

## Features

- Input sources: static tools JSON, `mcp.json`, stdio MCP servers, and Streamable HTTP MCP endpoints.
- Checks: description clarity, overly generic names, missing parameter descriptions, JSON Schema completeness, missing output schemas, side-effect labeling, risky annotation conflicts, and tool-poisoning / secret-exfiltration text.
- Reports: Markdown, JSON, allowed-tools recommendations, approval/block decisions, and CI exit codes.
- Engineering boundaries: no third-party runtime dependencies, stdio subprocess timeouts and cleanup, and bounded concurrency for multi-server config discovery.

## Quick Start

```bash
python3 -m pip install -e .
mcp-toolsmith lint --tools-file examples/bad-tools.json
```

Run without installing the package:

```bash
PYTHONPATH=src python3 -m mcp_tool_card_linter lint \
  --tools-file examples/bad-tools.json \
  --json-report docs/sample-bad-report.json \
  --markdown-report docs/sample-bad-report.md \
  --fail-on error
```

Example stdio MCP server:

```bash
PYTHONPATH=src python3 -m mcp_tool_card_linter lint \
  --stdio "python3 tests/fixtures/mock_mcp_stdio_server.py" \
  --server mock \
  --fail-on never
```

Example `mcp.json`:

```bash
PYTHONPATH=src python3 -m mcp_tool_card_linter lint \
  --config examples/mcp.json \
  --server mock \
  --fail-on never
```

Streamable HTTP:

```bash
mcp-toolsmith lint --server-url https://example.com/mcp --server example
```

## Input Format

Static JSON supports the common `tools` shape:

```json
{
  "tools": [
    {
      "name": "search_customer_orders",
      "description": "Search customer orders by customer email. Use for read-only lookup only.",
      "inputSchema": {
        "type": "object",
        "properties": {
          "email": {
            "type": "string",
            "description": "Customer email address"
          }
        },
        "required": [],
        "additionalProperties": false
      },
      "outputSchema": {
        "type": "object",
        "properties": {
          "orders": { "type": "array", "items": { "type": "object" } }
        }
      }
    }
  ]
}
```

It also supports the MCP `tools/list` response shape:

```json
{
  "result": {
    "tools": []
  }
}
```

## CI Exit Codes

- `0`: no finding reached the `--fail-on` threshold, or `--fail-on never` was used.
- `1`: at least one lint finding reached the configured severity threshold.
- `2`: input, discovery, network, stdio, or report-writing error.
- `130`: interrupted by the user.

The default threshold is `--fail-on error`. For production releases, use at least:

```bash
mcp-toolsmith lint --config ./mcp.json --json-report mcp-tool-report.json --fail-on error --format none
```

## Optimization Output

`optimize` generates tool-exposure policy suggestions from a JSON lint report:

```bash
PYTHONPATH=src python3 -m mcp_tool_card_linter optimize \
  --input-report docs/sample-bad-report.json \
  --output docs/sample-optimized.json
```

Each output `decision` is one of:

- `include_by_default`
- `require_approval`
- `block_until_review`

## Rule Boundaries

Facts:

- MCP tool definitions include `name`, `description`, and `inputSchema`; they may also include `outputSchema` and `annotations`.
- MCP uses JSON-RPC messages, and standard transports include stdio and Streamable HTTP.
- OpenAI's MCP documentation describes `allowed_tools` as a way to import only a subset of tools when a server exposes many tools, reducing tool payload cost and latency.

Inferences:

- Static checks for descriptions, schemas, side effects, and prompt-injection-like text can reduce review effort and catch common tool-card quality problems before an MCP server is connected to an agent.
- Tools whose metadata suggests write, destructive, financial, network, or secret-related behavior should be reviewed more strictly and should usually require human approval in production clients.

Uncertainties:

- "Tool Card" is this project's term, not a formal MCP specification object.
- A static linter cannot prove that an MCP server's runtime behavior matches its metadata.
- Different MCP clients may handle annotations, approvals, and tool filtering differently, so this report should complement sandboxing, permission controls, runtime audit logs, and human review.

## References

- [MCP tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [MCP transports specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [OpenAI MCP and connectors guide](https://developers.openai.com/api/docs/guides/tools-connectors-mcp)
- [MCP tool description smells paper](https://arxiv.org/abs/2602.14878)
- [MCP tool poisoning threat modeling paper](https://arxiv.org/abs/2603.22489)

## Project Documents

- [Research notes](docs/RESEARCH_NOTES.md)
- [Quality self-check](docs/QUALITY_SELF_CHECK.md)
- [Test report](docs/TEST_REPORT.md)
- [Sample Markdown report](docs/sample-bad-report.md)


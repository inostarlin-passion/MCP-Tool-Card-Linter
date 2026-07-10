# MCP Tool Card Linter

MCP Tool Card Linter is a CLI quality gate for MCP servers. It discovers exposed tools, checks tool names, descriptions, `inputSchema`, `outputSchema`, annotations, potential side effects, and tool-poisoning risks, then emits JSON/Markdown reports and CI-friendly exit codes.

In this project, a "Tool Card" is an engineering concept: a reviewable bundle of an MCP tool's name, description, input/output schemas, behavior annotations, risk level, and recommendations. It is not a standalone object in the MCP specification.

## Features

- Input sources: static tools JSON, `mcp.json`, stdio MCP servers, and Streamable HTTP MCP endpoints.
- Checks: full model-visible metadata scanning, tool poisoning, hidden Unicode, embedded credentials, cross-server tool shadowing, rug-pull fingerprints, dangerous command/URL/path/secret parameters, JSON Schema validity and resource bounds, side-effect labeling, annotation conflicts, and description quality.
- Reports: escaped Markdown, strict JSON, SHA-256 tool-card fingerprints, baseline change status, allowed-tools recommendations, approval/block decisions, and CI exit codes.
- Defensive discovery: strict duplicate-free JSON, bounded files/messages/responses/pages/concurrency, serialized JSON-RPC round trips, protocol negotiation checks, SSRF-aware URL policy, disabled redirects, bounded transient retries, minimal child environments, process cleanup, and atomic private report files.
- Runtime boundary: no third-party runtime dependencies.

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
  --allow-config-execution \
  --server mock \
  --fail-on never
```

Streamable HTTP:

```bash
mcp-toolsmith lint --server-url https://example.com/mcp --server example
```

## Secure Discovery Defaults

- `--config` never executes local `command` entries unless `--allow-config-execution` is present. Review the exact command first and prefer a sandbox for third-party configs.
- stdio servers receive a small allowlist of ordinary environment variables by default. `--inherit-env` is an explicit opt-in because a full parent environment often contains credentials.
- remote endpoints require HTTPS except for an explicitly supplied loopback `--server-url`. Private/reserved destinations and loopback URLs loaded indirectly from config require `--allow-private-network`; non-loopback plain HTTP additionally requires `--allow-insecure-http`.
- HTTP redirects are refused. Response bodies, stdio messages, stderr history, pagination, retries, server count, worker count, schemas, descriptions, and tool counts all have hard limits.
- reports are written through a same-directory temporary file and atomic replacement. New report files default to owner-only permissions on POSIX.

These controls reduce accidental exposure; they are not a sandbox. A reviewed stdio command still runs with the linter process's operating-system identity and can access resources permitted to that identity.

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

- `0`: no source error occurred and no finding reached the threshold (or findings were disabled with `--fail-on never`).
- `1`: at least one lint finding reached the configured severity threshold.
- `2`: input, discovery, network, stdio, or report-writing error.
- `130`: interrupted by the user.

The default threshold is `--fail-on error`. `--fail-on never` disables finding-based failure only; discovery/source errors still return `2`. For production releases, use at least:

```bash
mcp-toolsmith lint --config ./mcp.json --allow-config-execution \
  --json-report mcp-tool-report.json --fail-on error --format none
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

## Rug-pull Baselines

Every JSON report contains a deterministic `sha256:` fingerprint of each complete tool definition. Compare a fresh discovery with an approved report:

```bash
mcp-toolsmith lint \
  --tools-file current-tools.json \
  --server production \
  --baseline-report approved-report.json \
  --json-report current-report.json \
  --fail-on error \
  --format none
```

Changed cards emit `TOOL_CARD_CHANGED`, are marked `baseline_status: changed`, and are recommended for blocking until review. New and missing cards are summarized separately. Fingerprints provide change detection, not publisher authenticity; protect the approved baseline with repository controls or signing.

## Notable Security Rules

- Tool metadata: injection/coercion text across descriptions, titles, schemas, examples/defaults/enums and keys; hidden/bidirectional Unicode; opaque encoded blobs; credential-like literals.
- Multi-server integrity: duplicate names within a server, cross-server same-name shadowing, deterministic card fingerprints, and baseline change detection.
- Input schemas: external `$ref`, malformed types/composition/bounds/annotations, unrestricted extra properties, unbounded arrays/strings, permissive or nested-quantifier regexes, and unconstrained command/URL/path/secret fields.
- Behavior claims: write/destructive/financial/network/filesystem/code-execution risk, missing approval/side-effect boundaries, and contradictory or invalid MCP annotation hints.

## Rule Boundaries

Facts:

- MCP tool definitions include `name`, `description`, and `inputSchema`; they may also include `outputSchema` and `annotations`.
- MCP uses JSON-RPC messages, and standard transports include stdio and Streamable HTTP.
- MCP annotations are untrusted hints and are not proof of runtime behavior.
- OpenAI's MCP documentation describes `allowed_tools` as a way to import only a subset of tools when a server exposes many tools, reducing tool payload cost and latency.

Inferences:

- Static checks for all model-visible metadata, schemas, side effects, and prompt-injection-like text can reduce review effort and catch common tool-card quality problems before an MCP server is connected to an agent.
- Tools whose metadata suggests write, destructive, financial, network, or secret-related behavior should be reviewed more strictly and should usually require human approval in production clients.

Uncertainties:

- "Tool Card" is this project's term, not a formal MCP specification object.
- A static linter cannot prove that an MCP server's runtime behavior matches its metadata.
- A SHA-256 baseline detects change but does not authenticate the server or prevent a malicious first snapshot.
- DNS validation has an unavoidable resolution/use race in this standard-library client; redirects are disabled and private addresses are rechecked before each request, but high-assurance server deployments should also enforce egress policy outside the process.
- Different MCP clients may handle annotations, approvals, and tool filtering differently, so this report should complement sandboxing, permission controls, runtime audit logs, and human review.

## References

- [MCP tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [MCP transports specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
- [OpenAI MCP and connectors guide](https://developers.openai.com/api/docs/guides/tools-connectors-mcp)
- [MCP tool description smells paper](https://arxiv.org/abs/2602.14878)
- [MCP tool poisoning threat modeling paper](https://arxiv.org/abs/2603.22489)

## Project Documents

- [Research notes](docs/RESEARCH_NOTES.md)
- [Quality self-check](docs/QUALITY_SELF_CHECK.md)
- [Test report](docs/TEST_REPORT.md)
- [Sample Markdown report](docs/sample-bad-report.md)

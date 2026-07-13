# MCP Tool Card Linter

MCP Tool Card Linter is a CLI quality gate for MCP servers. It discovers exposed tools, checks tool names, descriptions, `inputSchema`, `outputSchema`, icons, annotations, potential side effects, and tool-poisoning risks, then emits versioned machine reports and CI-friendly exit codes.

In this project, a "Tool Card" is an engineering concept: a reviewable bundle of an MCP tool's name, description, input/output schemas, behavior annotations, risk level, and recommendations. It is not a standalone object in the MCP specification.

## Features

- Input sources: static tools JSON, `mcp.json`, stdio MCP servers, and Streamable HTTP MCP endpoints.
- Checks: complete JSON Schema 2020-12 metaschema validation plus bounded security/quality rules, icon validation, full model-visible metadata scanning, tool poisoning, hidden Unicode, embedded credentials, cross-server tool shadowing, rug-pull fingerprints, dangerous parameters, side-effect labeling, and annotation conflicts.
- Reports: report schema 1.0.0, deterministic JSON, Markdown, SARIF 2.1.0, JUnit XML, JSON Lines, GitHub annotations, stable rule metadata, SHA-256 card fingerprints, and approval/block suggestions.
- Policy: production/security/spec/strict/compatibility profiles, select/ignore, severity overrides, and suppressions that require a reason, owner, and expiry date.
- Defensive discovery: MCP 2025-11-25, 2025-06-18, and legacy 2025-03-26 negotiation, capability gating, strict stdio, bounded resumable Streamable HTTP/SSE, optional one-shot `tools/list_changed` refresh, bounded I/O/concurrency/retries, SSRF-aware URL policy, disabled redirects, minimal child environments, process cleanup, and atomic private report files.
- Remote credentials: pre-issued Bearer tokens from environment/private files, custom CA bundles, explicit proxies, and mTLS; or MCP OAuth protected-resource/authorization-server discovery with Authorization Code, S256 PKCE, Resource Indicators, private single-use state, and private token output for a pre-registered public client.

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

To wait for a declared `notifications/tools/list_changed` event and refresh the snapshot once:

```bash
mcp-toolsmith lint --server-url https://example.com/mcp --server example \
  --refresh-on-list-changed 5
```

Authenticated Streamable HTTP without putting token text in process arguments:

```bash
export MCP_AUDIT_TOKEN='short-lived-resource-scoped-token'
mcp-toolsmith lint --server-url https://example.com/mcp \
  --bearer-token-env MCP_AUDIT_TOKEN --server example
```

OAuth Authorization Code + PKCE for a pre-registered public client is a two-process-safe flow. The
callback URL is deliberately read from an environment variable or private file so the authorization
code is not placed in process arguments:

```bash
mcp-toolsmith authorize start \
  --server-url https://example.com/mcp \
  --client-id registered-public-client \
  --redirect-uri https://client.example/callback \
  --state-file ~/.config/mcp-toolsmith/oauth-state.json \
  --scope tools.read

export MCP_CALLBACK_URL='https://client.example/callback?code=...&state=...'
mcp-toolsmith authorize complete \
  --state-file ~/.config/mcp-toolsmith/oauth-state.json \
  --callback-url-env MCP_CALLBACK_URL \
  --token-file ~/.config/mcp-toolsmith/access-token

mcp-toolsmith lint --server-url https://example.com/mcp \
  --bearer-token-file ~/.config/mcp-toolsmith/access-token
```

`authorize start` requires S256 support, uses the challenge scope before metadata fallback, includes
the canonical MCP `resource` in both requests, and refuses non-HTTPS authorization endpoints by
default. Dynamic Client Registration and refresh-token management are intentionally outside v0.4;
register the public client and exact redirect URI with the authorization server first.

## Secure Discovery Defaults

- `--config` never executes local `command` entries unless `--allow-config-execution` is present. Review the exact command first and prefer a sandbox for third-party configs.
- stdio servers receive a small allowlist of ordinary environment variables by default. `--inherit-env` is an explicit opt-in because a full parent environment often contains credentials.
- stdio stdout is protocol-strict by default. `--compat-stdio-noise` is an explicit compatibility exception for reviewed legacy servers.
- remote endpoints require HTTPS except for an explicitly supplied loopback `--server-url`. Private/reserved destinations and loopback URLs loaded indirectly from config require `--allow-private-network`; non-loopback plain HTTP additionally requires `--allow-insecure-http`.
- HTTP redirects are refused. Response bodies, stdio messages, stderr history, pagination, retries, server count, worker count, schemas, descriptions, and tool counts all have hard limits.
- reports are written through a same-directory temporary file and atomic replacement. New report files default to owner-only permissions on POSIX.

These controls reduce accidental exposure; they are not a sandbox. A reviewed stdio command still runs with the linter process's operating-system identity and can access resources permitted to that identity.

## Policy and rule catalog

Use `list-rules --format json` and `explain RULE_ID` to inspect stable machine-readable rule metadata. A policy can be a dedicated TOML file or the corresponding section of `pyproject.toml`:

```toml
[tool.mcp-tool-card-linter]
profile = "production"
select = ["INVALID_*", "TOOL_POISONING_*"]
ignore = ["DESCRIPTION_TOO_SHORT"]
fail-on = "error"

[tool.mcp-tool-card-linter.rules.URL_PARAMETER_ALLOWLIST_MISSING]
severity = "error"

[[tool.mcp-tool-card-linter.suppressions]]
server = "internal-search"
tool = "search_records"
rule = "CROSS_SERVER_TOOL_SHADOWING"
reason = "Gateway namespaces the exported name"
owner = "platform-security"
expires = 2026-12-31
```

Apply it with `--policy pyproject.toml`. Expired suppressions do not hide findings and are recorded in the report.
See [`examples/policy.toml`](examples/policy.toml) for a standalone policy.

## Machine report contracts

JSON reports declare `report_schema_version: 1.0.0`, a `scan_id`, tool version, policy, and requested/negotiated protocol metadata. The bundled Draft 2020-12 schema is at `src/mcp_tool_card_linter/schemas/report.schema.json`.

```bash
mcp-toolsmith lint --tools-file tools.json --deterministic \
  --json-report report.json --sarif-report report.sarif \
  --junit-report report.xml --jsonl-report report.jsonl --format github
```

`--deterministic` fixes the timestamp and derives `scan_id` from content for reproducible output. Normal scans use a UTC timestamp and UUID. SARIF results include rule metadata, logical tool locations, JSON Pointer paths, and partial fingerprints.

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

## References

- [MCP tools specification](https://modelcontextprotocol.io/specification/2025-11-25/server/tools)
- [MCP transports specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
- [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [JSON Schema Draft 2020-12](https://json-schema.org/draft/2020-12)
- [GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support)
- [MCP security best practices](https://modelcontextprotocol.io/docs/tutorials/security/security_best_practices)
- [OWASP MCP Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/MCP_Security_Cheat_Sheet.html)
- [OpenAI MCP and connectors guide](https://developers.openai.com/api/docs/guides/tools-connectors-mcp)
- [MCP tool description smells paper](https://arxiv.org/abs/2602.14878)
- [MCP tool poisoning threat modeling paper](https://arxiv.org/abs/2603.22489)

## Project Documents

- [Research notes](docs/RESEARCH_NOTES.md)
- [Threat model](docs/THREAT_MODEL.md)
- [Protocol compatibility](docs/PROTOCOL_COMPATIBILITY.md)
- [Quality self-check](docs/QUALITY_SELF_CHECK.md)
- [Test report](docs/TEST_REPORT.md)
- [Sample Markdown report](docs/sample-bad-report.md)

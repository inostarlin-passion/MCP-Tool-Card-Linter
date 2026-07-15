# MCP Tool Card Linter

MCP Tool Card Linter is a CLI quality gate for MCP servers. It discovers exposed tools, checks tool names, descriptions, `inputSchema`, `outputSchema`, icons, annotations, potential side effects, and tool-poisoning risks, then emits versioned machine reports and CI-friendly exit codes.

In this project, a "Tool Card" is an engineering concept: a reviewable bundle of an MCP tool's name, description, input/output schemas, behavior annotations, risk level, and recommendations. It is not a standalone object in the MCP specification.

## Features

- Input sources: static tools JSON, `mcp.json`, stdio MCP servers, and Streamable HTTP MCP endpoints.
- Checks: complete JSON Schema 2020-12 metaschema validation plus bounded security/quality rules, icon validation, full model-visible metadata scanning, tool poisoning, hidden Unicode, embedded credentials, cross-server tool shadowing, rug-pull fingerprints, dangerous parameters, side-effect labeling, and annotation conflicts.
- Reports: report schema 1.1.0, deterministic JSON, Markdown, SARIF 2.1.0, JUnit XML, JSON Lines, GitHub annotations, stable rule metadata, RFC 8785 card fingerprints, field-level hash diffs, and approval/block suggestions.
- Policy: production/security/spec/strict/compatibility profiles, select/ignore, severity overrides, and suppressions that require a reason, owner, and expiry date.
- Defensive discovery: MCP 2025-11-25, 2025-06-18, and legacy 2025-03-26 negotiation, capability gating, strict stdio, bounded resumable Streamable HTTP/SSE, DNS rebinding detection, optional one-shot `tools/list_changed` refresh, bounded I/O/concurrency/retries, SSRF-aware URL policy, disabled redirects, minimal child environments, managed sandbox processes, and atomic private report files.
- Safe execution and trust: default-deny local commands; Docker, Bubblewrap, Windows Job Object, and explicit unsandboxed host backends; Ed25519-signed baselines bound to publisher/server/source identity; and signed hash-chained append-only approval logs.
- Remote credentials: pre-issued Bearer tokens from environment/private files, custom CA bundles, explicit proxies, and mTLS; or MCP OAuth protected-resource/authorization-server discovery with Authorization Code, S256 PKCE, Resource Indicators, private single-use state, and private token output for a pre-registered public client.
- v1 production contracts: machine-readable report/rule/exit-code/protocol commitments, 1.0.0/1.1.0 report readers, a public labelled accuracy corpus, deterministic fuzz/input-mutation/stdio-soak gates, bit-for-bit wheel/sdist rebuild checks, signed release attestations, and minimal hash-chained operational audit events.

## Quick Start

Install the CLI in an isolated environment:

```bash
pipx install mcp-tool-card-linter
mcp-toolsmith lint --tools-file path/to/tools.json
```

Alternatively, install it into an existing Python environment:

```bash
python3 -m pip install mcp-tool-card-linter
```

Run directly from a source checkout without installing the package:

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
  --executor host \
  --server mock \
  --fail-on never
```

Example `mcp.json`:

```bash
PYTHONPATH=src python3 -m mcp_tool_card_linter lint \
  --config examples/mcp.json \
  --allow-config-execution \
  --executor host \
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
default. Dynamic Client Registration and refresh-token management are intentionally outside v1.0;
register the public client and exact redirect URI with the authorization server first.

## Secure Discovery Defaults

- Local command execution defaults to `--executor none`. Config commands additionally require `--allow-config-execution`. Use `--executor docker --executor-image IMAGE`, Linux `--executor bubblewrap`, or Windows `--executor windows-job`; `--executor host` is an explicit compatibility choice without filesystem or network isolation.
- stdio servers receive a small allowlist of ordinary environment variables by default. `--inherit-env` is an explicit opt-in because a full parent environment often contains credentials.
- stdio stdout is protocol-strict by default. `--compat-stdio-noise` is an explicit compatibility exception for reviewed legacy servers.
- remote endpoints require HTTPS except for an explicitly supplied loopback `--server-url`. Private/reserved destinations and loopback URLs loaded indirectly from config require `--allow-private-network`; non-loopback plain HTTP additionally requires `--allow-insecure-http`. Resolved IPv4/IPv6 sets are pinned and changes across requests/retries are refused.
- HTTP redirects are refused. Response bodies, stdio messages, stderr history, pagination, retries, server count, worker count, schemas, descriptions, and tool counts all have hard limits.
- reports are written through a same-directory temporary file and atomic replacement. New report files default to owner-only permissions on POSIX.
- programmatic stdio discovery accepts an argument sequence, which avoids shell quoting ambiguity. The `--stdio` string uses POSIX shell tokenization on Unix and the native Windows command-line parser on Windows.
- OAuth state and token files use mode `0600` on POSIX. Windows uses the containing directory's inherited DACL, so keep those files in a directory restricted to the current user and administrators.

Docker uses no network, a read-only root, dropped capabilities, no-new-privileges, a bounded tmpfs, and CPU/memory/process limits. Bubblewrap uses an empty mount namespace, read-only runtime/workspace bindings, no network namespace, and `prlimit` where available. Windows Job Object applies process-tree lifetime, CPU, memory, and process-count limits, but does not provide filesystem or network isolation. Treat `host` as trusted-code-only.

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

JSON reports declare `report_schema_version: 1.1.0`, a `scan_id`, tool version, policy, requested/negotiated protocol metadata, per-field hashes, and bounded field diffs. The bundled Draft 2020-12 schema is at `src/mcp_tool_card_linter/schemas/report.schema.json`.

Inspect the frozen v1 machine contract or validate a current/legacy report:

```bash
mcp-tool-card-linter contract
mcp-tool-card-linter validate-report --input report.json
```

v1 produces schema 1.1.0 and reads 1.0.0/1.1.0. Rule IDs are not repurposed, and CLI exit meanings
are stable. See [the complete stability policy](docs/STABILITY_POLICY.md).

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
  --executor docker --executor-image registry.example/reviewed-mcp-server@sha256:DIGEST \
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

## Signed Rug-pull Baselines

Every JSON report contains an RFC 8785 + SHA-256 fingerprint of each complete tool definition and SHA-256 fingerprints for bounded JSON Pointer leaves. Create an Ed25519 trust root, approve a report, and append an independently reviewable hash-chain record:

```bash
mcp-toolsmith baseline keygen \
  --private-key baseline.key --public-key baseline.pub
mcp-toolsmith baseline approve \
  --report approved-report.json --output approved-baseline.json \
  --private-key baseline.key --publisher example-org \
  --server-identity example-org/production-mcp@1 \
  --approved-by security-reviewer --approval-log approvals.jsonl
mcp-toolsmith baseline verify \
  --baseline approved-baseline.json --public-key baseline.pub \
  --approval-log approvals.jsonl
```

Compare fresh discovery with that signed baseline:

```bash
mcp-toolsmith lint \
  --tools-file current-tools.json \
  --server production \
  --baseline-report approved-baseline.json \
  --baseline-public-key baseline.pub \
  --require-signed-baseline \
  --expected-publisher example-org \
  --expected-server-identity example-org/production-mcp@1 \
  --json-report current-report.json \
  --fail-on error \
  --format none
```

Changed cards emit `TOOL_CARD_CHANGED`, report added/removed/changed JSON Pointer paths without disclosing raw values, and are blocked pending review. Identity, endpoint/capability/server-info, or publisher drift has distinct `identity_changed`/`publisher_changed` states. Unsigned legacy reports remain readable for migration, but an otherwise unchanged match is marked `baseline_untrusted`; use `--require-signed-baseline` in production.

## Operational audit log

Lint and OAuth operations can append allowlisted, credential-free fields to a private hash-chained
JSONL log. Both options are required together; an audit write failure is an operational failure:

```bash
mcp-tool-card-linter lint --tools-file tools.json --fail-on error --format none \
  --audit-log audit.jsonl --audit-actor ci:production
mcp-tool-card-linter audit verify --log audit.jsonl
```

The log uses an exclusive cooperating-writer lock, `O_APPEND`, fsync and mode 0600 on POSIX. A local
hash chain detects modification but is not an authenticity or availability boundary against an
administrator who can rewrite, recompute or delete the file; forward it to WORM/transparent storage.

## Accuracy and adversarial testing

Run the public explicitly-labelled corpus and its production threshold:

```bash
mcp-tool-card-linter evaluate \
  --corpus evaluation/rule_accuracy_v1.jsonl \
  --min-precision 0.95 --min-recall 0.95
```

The v1 corpus has 12 cases and 21 labelled rule/case pairs. The current scoped precision, recall and
F1 are 1.0, with no missed or unexpected labelled result. This is a synthetic regression score, not
a claim about all rules or production prevalence; see [the accuracy report](docs/RULE_ACCURACY.md).

CI separately executes deterministic parser/tool fuzzing, security input mutations, a 40-cycle
stdio process-lifecycle soak, the uninstrumented performance budget and two byte-compared package
builds.

## Release verification

Release wheel/sdist artifacts have SHA-256 checksums, reproducible CycloneDX SBOMs, signed
GitHub/Sigstore provenance and PyPI Trusted Publisher attestations. Verification and local
reproduction commands are in [RELEASE_VERIFICATION.md](docs/RELEASE_VERIFICATION.md). A valid
signature establishes digest, publisher/build identity and provenance—not vulnerability freedom.

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
- [RFC 8785 JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785)
- [RFC 8032 Ed25519](https://www.rfc-editor.org/rfc/rfc8032)
- [Docker run security/resource flags](https://docs.docker.com/reference/cli/docker/container/run/)
- [Windows Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects)
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
- [v1 stability policy](docs/STABILITY_POLICY.md)
- [Rule accuracy report](docs/RULE_ACCURACY.md)
- [Supported and unsupported boundaries](docs/SUPPORT_BOUNDARIES.md)
- [Release verification](docs/RELEASE_VERIFICATION.md)
- [Sample Markdown report](docs/sample-bad-report.md)

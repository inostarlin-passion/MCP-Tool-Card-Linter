# Threat model

Review date: 2026-07-13. Scope: MCP Tool Card Linter 0.3.0.

## Security objective

The linter is a deterministic metadata admission aid. It should safely ingest hostile tool cards and
bounded discovery responses, surface reviewable facts, and produce tamper-evident change signals
without turning a scan into an implicit credential leak, internal-network request, unbounded resource
consumer, or silent host command execution.

It is not a runtime authorization gateway, malware sandbox, OAuth authorization agent, server
identity authority, or proof that implementation behavior matches metadata.

## Assets and trust boundaries

| Asset | Boundary and trust assumption |
| --- | --- |
| Developer/CI host files, environment and credentials | Must remain unavailable to static input and remote servers; a locally executed stdio server crosses this boundary and is therefore trusted only when externally sandboxed |
| Remote access token and mTLS key | Loaded from environment/private file or TLS context; never accepted as token text in CLI arguments, URLs, metadata, or reports |
| Approved baseline and policy | Administrative input; must be protected by repository approval/signing outside this process |
| JSON/SARIF/JUnit/JSONL reports | Security decision input; written atomically and owner-only by default on POSIX, but downstream storage controls remain required |
| CPU, memory, process/thread, file descriptor and network budgets | Shared host resources; attacker-controlled loops, buffers, schemas and concurrency must have hard upper bounds |

Untrusted inputs are tool/config JSON, TOML policy syntax, tool metadata at every nested key/value,
JSON Schema, endpoint and proxy URLs, DNS answers, HTTP status/headers/body/SSE, JSON-RPC messages,
stdio stdout/stderr, server capabilities/info, pagination cursors, baseline reports, and optimizer input.

## Threats, controls and residual risk

| Threat | In-process control | Residual/external control |
| --- | --- | --- |
| Parser ambiguity and type confusion | Duplicate-key/NaN rejecting JSON, UTF-8/type/shape checks, full Draft 2020-12 metaschema plus MCP-specific checks | Differential parser fuzzing remains desirable |
| Resource exhaustion | File/body/line/queue/tool/page/cursor/server/thread/retry/schema/depth/icon/text limits; repeated-cursor failure; total deadlines; cached metaschema results | Soak/fuzz/mutation tests and OS quotas add assurance |
| Tool poisoning and secret exposure | Recursive model-visible metadata scanning, bounded/redacted evidence, Markdown/XML/Actions escaping | Heuristics have false positives/negatives; runtime content needs separate controls |
| SSRF, redirect and DNS rebinding | HTTPS/public-address defaults, URL credential rejection, no redirect, validation before every open | DNS resolve/connect TOCTOU remains; enforce egress proxy/network namespace and metadata-address blocks |
| Credential theft/passthrough | Provider interface, environment/private file Bearer input, no literal token flag, no auth metadata reporting, redirect refusal | Full OAuth 2.1/PKCE/resource/audience lifecycle is not implemented; use short-lived resource-scoped tokens |
| Protocol downgrade or capability misuse | Supported-version allowlist, requested/negotiated recording, post-initialize negotiated header, tools capability gate | Full official conformance suite, GET SSE resumption and list-change subscriptions are future work |
| Malicious local config command | Default refusal, explicit consent flag, minimal environment, bounded stdio and process-group cleanup | Consent is not isolation; use container/VM/bubblewrap/Job Object and default-deny network |
| Partial/corrupted report | Same-directory temporary file, fsync, atomic replace, schema version and deterministic mode | Filesystem/branch signing and append-only approval logs are external |
| Rug pull or malicious first snapshot | Complete-card SHA-256 change signal, changed/new/missing states | Baseline is unsigned and does not authenticate publisher/server; protect or attest it externally |
| Policy exception abuse | Bounded TOML, exact/prefix rule selection, known-rule severity overrides, suppression reason/owner/expiry, expired exceptions fail open to findings and are reported | Approval workflow and ownership validation are organizational controls |

## Abuse cases explicitly rejected

- Credentials in MCP endpoint or proxy URLs.
- Bearer token text as a CLI argument.
- Config-sourced local command execution without the independent CLI flag.
- Config self-authorization of full environment inheritance.
- Calling `tools/list` when the initialized server did not declare `tools`.
- Unsupported negotiated protocol versions.
- Non-JSON stdio stdout unless the operator explicitly enables bounded compatibility mode.
- Redirect following, duplicate JSON keys, non-finite JSON numbers, repeated cursors, oversized bodies,
  and report output overwriting any declared input.

## Production deployment requirements

For third-party stdio servers, run the linter worker in a disposable, unprivileged sandbox with a
read-only root, isolated temporary directory, no host home/SSH/cloud credentials/Docker socket,
default-deny network, CPU/memory/process/file-descriptor limits, and explicit mounts. For remote
servers, use an egress proxy that pins allowed destinations, a short-lived resource-scoped token,
trusted CA policy, and audit logs. Treat static allow/block output as a policy recommendation that
still requires runtime least privilege and human confirmation for consequential actions.

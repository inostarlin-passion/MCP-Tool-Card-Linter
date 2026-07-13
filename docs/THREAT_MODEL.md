# Threat model

Review date: 2026-07-13. Scope: MCP Tool Card Linter 0.4.0.

## Security objective

The linter is a deterministic metadata admission aid. It should safely ingest hostile tool cards and
bounded discovery responses, surface reviewable facts, and produce tamper-evident change signals
without turning a scan into an implicit credential leak, internal-network request, unbounded resource
consumer, or silent host command execution.

It is not a runtime authorization gateway, malware sandbox, general OAuth client SDK, server
identity authority, or proof that implementation behavior matches metadata. Its OAuth role is
limited to a pre-registered public-client Authorization Code + PKCE bootstrap.

## Assets and trust boundaries

| Asset | Boundary and trust assumption |
| --- | --- |
| Developer/CI host files, environment and credentials | Must remain unavailable to static input and remote servers; a locally executed stdio server crosses this boundary and is therefore trusted only when externally sandboxed |
| Remote access token and mTLS key | Loaded from environment/private file or TLS context; never accepted as token text in CLI arguments, URLs, metadata, or reports |
| OAuth authorization code, PKCE verifier and state | Callback comes only from environment/private file; verifier/state live in an expiring owner-only file; exact callback/state/optional issuer are verified before exchange |
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
| Resource exhaustion | File/body/SSE-line/event/queue/tool/page/cursor/server/thread/retry/reconnect/schema/depth/icon/text limits; repeated-cursor failure; total deadlines; cached metaschema results | Soak/fuzz/mutation tests and OS quotas add assurance |
| Tool poisoning and secret exposure | Recursive model-visible metadata scanning, bounded/redacted evidence, Markdown/XML/Actions escaping | Heuristics have false positives/negatives; runtime content needs separate controls |
| SSRF, redirect and DNS rebinding | HTTPS/public-address defaults, URL credential rejection, no redirect, validation before every open | DNS resolve/connect TOCTOU remains; enforce egress proxy/network namespace and metadata-address blocks |
| OAuth code interception, CSRF, mix-up or wrong audience | Mandatory S256, random state, exact redirect, optional `iss` equality, canonical resource in authorization/token requests, metadata issuer/resource equality, private single-use state and completion lock | User/browser and AS still enforce consent/client registration; resource server must validate token audience; DCR/refresh/step-up are not implemented |
| Credential theft/passthrough | Provider interface, environment/private file Bearer input, callback secret absent from argv, token absent from URI/output/report, redirect refusal | Use short-lived resource-scoped tokens and protected CI secret/file storage |
| Protocol downgrade or capability misuse | Supported-version allowlist, requested/negotiated recording, post-initialize negotiated header, tools/listChanged capability gates, official initialize conformance vector | General SDK capabilities and the complete official scenario suite are outside this linter's declared surface |
| SSE loss, replay or reconnect loop | Incremental strict parser, exact JSON-RPC ID/notification checks, event cursor, `Last-Event-ID`, retry/deadline/reconnect caps, exactly-once re-list | Server event persistence determines how far resumption can recover; output remains a point-in-time snapshot |
| Malicious local config command | Default refusal, explicit consent flag, minimal environment, bounded stdio and process-group cleanup | Consent is not isolation; use container/VM/bubblewrap/Job Object and default-deny network |
| Partial/corrupted report | Same-directory temporary file, fsync, atomic replace, schema version and deterministic mode | Filesystem/branch signing and append-only approval logs are external |
| Rug pull or malicious first snapshot | Complete-card SHA-256 change signal, changed/new/missing states | Baseline is unsigned and does not authenticate publisher/server; protect or attest it externally |
| Policy exception abuse | Bounded TOML, exact/prefix rule selection, known-rule severity overrides, suppression reason/owner/expiry, expired exceptions fail open to findings and are reported | Approval workflow and ownership validation are organizational controls |

## Abuse cases explicitly rejected

- Credentials in MCP endpoint or proxy URLs.
- Bearer token text as a CLI argument.
- OAuth callback URL/code as a CLI argument, non-S256 PKCE, mismatched state/resource/issuer, or
  concurrent completion of one state file.
- Config-sourced local command execution without the independent CLI flag.
- Config self-authorization of full environment inheritance.
- Calling `tools/list` when the initialized server did not declare `tools`.
- Unsupported negotiated protocol versions.
- Non-JSON stdio stdout unless the operator explicitly enables bounded compatibility mode.
- Waiting for `tools/list_changed` unless the server declared that capability.
- Redirect following, duplicate JSON keys, non-finite JSON numbers, repeated cursors, oversized bodies,
  and report output overwriting any declared input.

## Production deployment requirements

For third-party stdio servers, run the linter worker in a disposable, unprivileged sandbox with a
read-only root, isolated temporary directory, no host home/SSH/cloud credentials/Docker socket,
default-deny network, CPU/memory/process/file-descriptor limits, and explicit mounts. For remote
servers, use an egress proxy that pins allowed destinations, a short-lived resource-scoped token,
trusted CA policy, and audit logs. Treat static allow/block output as a policy recommendation that
still requires runtime least privilege and human confirmation for consequential actions.

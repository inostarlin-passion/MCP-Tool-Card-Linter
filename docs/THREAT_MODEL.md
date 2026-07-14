# Threat model

Review date: 2026-07-14. Scope: MCP Tool Card Linter 0.5.0.

## Security objective

The linter is a deterministic metadata admission aid. It should safely ingest hostile tool cards and
bounded discovery responses, surface reviewable facts, and produce authenticated change signals
without turning a scan into an implicit credential leak, internal-network request, unbounded resource
consumer, or silent host command execution.

It is not a runtime authorization gateway, complete malware sandbox, general OAuth client SDK,
public server-identity authority, or proof that implementation behavior matches metadata. Its OAuth role is
limited to a pre-registered public-client Authorization Code + PKCE bootstrap.

## Assets and trust boundaries

| Asset | Boundary and trust assumption |
| --- | --- |
| Developer/CI host files, environment and credentials | Must remain unavailable to static input and remote servers; local execution defaults off and should use Docker/Bubblewrap or an independently hardened worker |
| Remote access token and mTLS key | Loaded from environment/private file or TLS context; never accepted as token text in CLI arguments, URLs, metadata, or reports |
| OAuth authorization code, PKCE verifier and state | Callback comes only from environment/private file; verifier/state live in an expiring owner-only file; exact callback/state/optional issuer are verified before exchange |
| Baseline signing key, public trust root, approved baseline and policy | Private Ed25519 key is owner-only administrative input; verifier trust comes from out-of-band public-key distribution, not from the bundle's self-asserted key ID |
| Approval log | Owner-only JSONL whose records are signed and chained; append locking prevents cooperating writers from interleaving but storage ACL/WORM controls remain external |
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
| SSRF, redirect and DNS rebinding | HTTPS/public-address defaults, URL credential rejection, no redirect, IPv4/IPv6 validation before every open, cross-request DNS-set pinning | Standard-library resolve/connect TOCTOU remains; high-assurance deployments still require egress proxy/network namespace and metadata-address blocks |
| OAuth code interception, CSRF, mix-up or wrong audience | Mandatory S256, random state, exact redirect, optional `iss` equality, canonical resource in authorization/token requests, metadata issuer/resource equality, private single-use state and completion lock | User/browser and AS still enforce consent/client registration; resource server must validate token audience; DCR/refresh/step-up are not implemented |
| Credential theft/passthrough | Provider interface, environment/private file Bearer input, callback secret absent from argv, token absent from URI/output/report, redirect refusal | Use short-lived resource-scoped tokens and protected CI secret/file storage |
| Protocol downgrade or capability misuse | Supported-version allowlist, requested/negotiated recording, post-initialize negotiated header, tools/listChanged capability gates, official initialize conformance vector | General SDK capabilities and the complete official scenario suite are outside this linter's declared surface |
| SSE loss, replay or reconnect loop | Incremental strict parser, exact JSON-RPC ID/notification checks, event cursor, `Last-Event-ID`, retry/deadline/reconnect caps, exactly-once re-list | Server event persistence determines how far resumption can recover; output remains a point-in-time snapshot |
| Malicious local config command | Independent consent plus default-deny executor; Docker no-network/read-only/cap/resource policy; Bubblewrap namespace/read-only policy; Job Object resource/tree policy; minimal environment and bounded stdio | Host backend is unsandboxed; Job Object lacks filesystem/network isolation; container/runtime/kernel and explicit mounts remain trusted boundaries |
| Partial/corrupted report | Same-directory temporary file, fsync, atomic replace, schema version and deterministic mode | Filesystem failure after baseline write but before log append is reported but cannot be a cross-file transaction |
| Rug pull or malicious first snapshot | RFC 8785 complete-card/field hashes; Ed25519 bundle signature; publisher/server/source binding; distinct changed/identity/publisher/untrusted states | First approval and public-key distribution remain human/organizational trust decisions; a stolen signing key defeats authentication |
| Approval history deletion/reordering/forgery | Exact schema, sequence, previous-record hash, Ed25519 signature, full-chain verification, `O_EXCL` writer lock | Local file can still be truncated or replaced by an actor with filesystem access; use protected repository/WORM transparency storage for independent availability |
| Policy exception abuse | Bounded TOML, exact/prefix rule selection, known-rule severity overrides, suppression reason/owner/expiry, expired exceptions fail open to findings and are reported | Approval workflow and ownership validation are organizational controls |

## Abuse cases explicitly rejected

- Credentials in MCP endpoint or proxy URLs.
- Bearer token text as a CLI argument.
- OAuth callback URL/code as a CLI argument, non-S256 PKCE, mismatched state/resource/issuer, or
  concurrent completion of one state file.
- Config-sourced local command execution without the independent CLI flag.
- Any CLI local command execution without an explicit executor; Docker execution without an image.
- Config self-authorization of full environment inheritance.
- Calling `tools/list` when the initialized server did not declare `tools`.
- Unsupported negotiated protocol versions.
- Non-JSON stdio stdout unless the operator explicitly enables bounded compatibility mode.
- Waiting for `tools/list_changed` unless the server declared that capability.
- Redirect following, duplicate JSON keys, non-finite JSON numbers, repeated cursors, oversized bodies,
  and report output overwriting any declared input.
- Signed baselines with unknown fields, wrong key IDs, invalid signatures/digests, publisher/server
  mismatch, or malformed approval chains.

## Production deployment requirements

For third-party stdio servers, prefer the Docker executor with a digest-pinned reviewed image or run
the entire linter worker in a disposable unprivileged sandbox. Keep a read-only root, isolated
temporary directory, no host home/SSH/cloud credentials/Docker socket, default-deny network,
CPU/memory/process/file-descriptor limits, and explicit mounts. Treat Bubblewrap availability and
kernel user-namespace policy as deployment prerequisites; combine Windows Job Object with a
separate network/filesystem sandbox. For remote
servers, use an egress proxy that pins allowed destinations, a short-lived resource-scoped token,
trusted CA policy, and audit logs. Distribute the baseline public key separately from the bundle,
keep the private key outside routine scan workers, and replicate approval logs to protected/WORM
storage. Treat static allow/block output as a policy recommendation that
still requires runtime least privilege and human confirmation for consequential actions.

# Threat model

Review date: 2026-07-14. Scope: MCP Tool Card Linter 1.0.0.

## Security objective

The linter is a deterministic metadata admission aid. It should safely ingest hostile tool cards and
bounded discovery responses, surface reviewable facts, and produce authenticated change signals
without turning a scan into an implicit credential leak, internal-network request, unbounded resource
consumer, or silent host command execution.

It is not a runtime authorization gateway, complete malware sandbox, general OAuth client SDK,
public server-identity authority, or proof that implementation behavior matches metadata. Its OAuth role is
limited to a pre-registered public-client Authorization Code + PKCE bootstrap.

## Actors, entry points and data flow

Actors are the operator/CI workload, MCP server or config publisher, remote authorization/resource
servers, enterprise proxy/PKI administrators, baseline approver/signing-key custodian, report/audit
consumer, package publisher, and an attacker controlling any untrusted input or one of those
services. The local OS/container runtime, Python interpreter, pinned dependencies, GitHub Actions,
PyPI Trusted Publisher identity and out-of-band public-key channel form explicit trusted computing
bases rather than attacker-controlled inputs.

```text
static JSON/config ─┐
stdio sandbox ──────┼─> bounded normalized ToolCard ─> schema/rules/policy ─> reports
HTTPS MCP/OAuth ────┘              │                         │                 │
                                  │                         └─> audit chain ─> SIEM/WORM
signed baseline + public key ─────┴─> identity/change decision
tagged source ─> reproducible build ─> signed provenance/SBOM ─> PyPI/GitHub consumer
```

No data flows from a report back into a tool invocation. The linter does not execute MCP tools.
Local server startup is a separate, consented and executor-controlled flow.

## Assets and trust boundaries

| Asset | Boundary and trust assumption |
| --- | --- |
| Developer/CI host files, environment and credentials | Must remain unavailable to static input and remote servers; local execution defaults off and should use Docker/Bubblewrap or an independently hardened worker |
| Remote access token and mTLS key | Loaded from environment/private file or TLS context; never accepted as token text in CLI arguments, URLs, metadata, or reports |
| OAuth authorization code, PKCE verifier and state | Callback comes only from environment/private file; verifier/state live in an expiring owner-only file; exact callback/state/optional issuer are verified before exchange |
| Baseline signing key, public trust root, approved baseline and policy | Private Ed25519 key is owner-only administrative input; verifier trust comes from out-of-band public-key distribution, not from the bundle's self-asserted key ID |
| Approval log | Owner-only JSONL whose records are signed and chained; append locking prevents cooperating writers from interleaving but storage ACL/WORM controls remain external |
| Operational audit log | Minimal allowlisted event fields; owner-only, append-mode, locked and hash-chained. It deliberately excludes endpoint paths, raw cards, tokens, codes and credentials; authenticity/availability require external collection |
| JSON/SARIF/JUnit/JSONL reports | Security decision input; written atomically and owner-only by default on POSIX, but downstream storage controls remain required |
| CPU, memory, process/thread, file descriptor and network budgets | Shared host resources; attacker-controlled loops, buffers, schemas and concurrency must have hard upper bounds |

Untrusted inputs are accuracy corpus JSONL, tool/config JSON, TOML policy syntax, tool metadata at every nested key/value,
JSON Schema, endpoint and proxy URLs, DNS answers, HTTP status/headers/body/SSE, JSON-RPC messages,
stdio stdout/stderr, server capabilities/info, pagination cursors, baseline reports, and optimizer input.

## Threats, controls and residual risk

| Threat | In-process control | Residual/external control |
| --- | --- | --- |
| Parser ambiguity and type confusion | Duplicate-key/NaN rejecting JSON, UTF-8/type/shape checks, full Draft 2020-12 metaschema plus MCP-specific checks; 500-value deterministic parser fuzz gate | Coverage-guided native/TLS/parser fuzzing remains desirable |
| Resource exhaustion | File/body/SSE-line/event/queue/tool/page/cursor/server/thread/retry/reconnect/schema/depth/icon/text/corpus/audit limits; repeated-cursor failure; total deadlines; cached metaschema results; stdio soak and performance gates | OS quotas and longer environment-specific soak add assurance |
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
| Audit repudiation or secret leakage | Exact record fields, allowlisted detail keys, redaction, sequence/previous hash, full-chain verify, `O_EXCL` lock, `O_APPEND`, fsync and 0600 | Local admin can recompute/delete the unsigned chain; export over authenticated transport to restricted WORM/SIEM storage |
| Rule/report/CLI contract drift | Machine-readable v1 contract, immutable schema version, legacy 1.0 reader, rule ID-set digest/literal-ID test, stable exit constants and integration tests | Human-readable text and private Python APIs are not stable interfaces |
| Supply-chain substitution | Exact Action SHAs, Trusted Publishing, reproducible wheel/sdist gate, SHA-256, CycloneDX, signed provenance and SBOM attestation | Signatures prove identity/provenance, not benign code; branch/tag/environment and dependency governance remain external |

## STRIDE coverage

| Category | Principal abuse case | Primary control/evidence |
| --- | --- | --- |
| Spoofing | Counterfeit publisher/server/authorization endpoint/build | External baseline key plus publisher/server/source binding; issuer/resource checks; signed build identity |
| Tampering | Card rug pull, report/log/package modification | RFC 8785 hashes, Ed25519 baseline/approval chain, atomic reports, operational hash chain, reproducible hashes and attestations |
| Repudiation | Unattributed approval, scan or OAuth bootstrap | Required approver/audit actor, timestamp/sequence, signed approval records, minimal operational events; external retention required |
| Information disclosure | Tokens/codes/private paths/cards in argv, URL, logs or reports | Environment/private-file secret ingress, URL credential rejection, allowlisted audit fields, bounded redaction and output escaping |
| Denial of service | Oversized/deep inputs, pagination/retry/SSE loops, process/thread leaks | Allocation-before-use bounds, total deadlines, repeated-cursor detection, executor quotas, performance/fuzz/soak regression gates |
| Elevation of privilege | Config starts arbitrary code with host credentials/network | Independent consent, default-deny executor, minimal environment, Docker/Bubblewrap isolation; host and Job limitations explicit |

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
- Audit use without an actor, unknown audit detail fields, concurrent cooperating writers, modified
  audit records, report/audit path overlap, unsupported report schemas, or accuracy corpora with
  unknown/overlapping labels.

## Assurance and verification ownership

| Control owner | Required verification |
| --- | --- |
| Project CI | 3 OS × Python 3.11..3.14 tests, branch coverage, strict typing, static checks, official MCP scenarios, accuracy/fuzz/mutation/soak/performance/reproducibility jobs |
| Release workflow | tag/version equality, fixed source epoch, wheel/sdist, clean install, checksums, SBOM, signed provenance/SBOM attestation and Trusted Publishing |
| Deployment operator | branch protection, immutable releases, digest-pinned sandbox image, enterprise proxy/CA policy, token audience/scope, OS ACLs, centralized audit retention and alerting |
| Security reviewer | review baseline source identity and field diff, protect/distribute signing keys, approve suppressions with expiry, investigate accuracy regressions and high-risk findings |
| Runtime platform | enforce tool-call authorization, user confirmation, output validation, data-loss prevention and post-call audit; these are outside this metadata linter |

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

# Changelog

This project follows semantic versioning for its CLI, rule IDs, and versioned report contract while
it moves toward 1.0. Deprecations are documented here before removal where security permits.

## [Unreleased]

## [1.0.0] - 2026-07-14

### Added

- A machine-readable v1 compatibility contract for readable report schemas, stable rule IDs,
  stable CLI exit meanings, and current/previous MCP protocol support.
- `validate-report` with full 1.1.0 Schema validation and a retained 1.0.0 migration reader.
- A bounded public JSONL accuracy evaluator and 12-case/21-labelled-pair v1 corpus with CI precision
  and recall gates.
- Deterministic parser/tool-card fuzzing, security input-mutation operators, repeated stdio process
  lifecycle soak testing, and dedicated CI jobs.
- Minimal allowlisted lint/OAuth operational audit records with owner-only append, fsync,
  cooperating-writer lock, record hashes, previous-hash chain, and full-chain verification.
- Stability, accuracy, release-verification, production-support-boundary, and expanded STRIDE/data-flow
  threat-model documentation.

### Changed

- Package maturity is now Production/Stable and the version is 1.0.0; report output remains schema
  1.1.0 to preserve the already published machine contract.
- MCP version constants and CLI exit codes are centralized as public compatibility data.
- Rule catalog now includes the previously emitted `BASELINE_SIGNATURE_MISSING` ID and rejects
  unregistered IDs instead of silently manufacturing metadata.
- The build backend is pinned to `setuptools-reproducible==0.1`; CI builds wheel and sdist twice with
  the same source epoch and requires byte equality.

### Security

- Audit detail keys are a closed allowlist and exclude endpoint/card/token/code/path material.
- Release workflow uses commit-SHA-pinned GitHub attestation actions, binds the CycloneDX SBOM to
  artifacts, explicitly enables PyPI attestations, and publishes GitHub assets as a draft before
  finalization for immutable-release compatibility.
- Documentation distinguishes cryptographic provenance from code safety, a local hash chain from
  authenticated/WORM logging, and synthetic accuracy from production prevalence.

## [0.5.0] - 2026-07-14

### Added

- Pluggable stdio execution boundaries with default-deny CLI behavior, explicit host compatibility,
  hardened Docker, Linux Bubblewrap, and Windows Job Object backends.
- Cross-request DNS address pinning with IPv4/IPv6 policy revalidation and DNS rebinding tests.
- RFC 8785 JSON canonicalization and Ed25519-signed baseline bundles bound to publisher, explicit
  server identity, endpoint/source metadata, protocol, capabilities, server info, and executor.
- Bounded per-field SHA-256 maps and added/removed/changed JSON Pointer diffs without raw-value
  disclosure.
- Owner-only, signed, hash-chained append-only approval logs with concurrency locking and full-chain
  verification.
- Unit, integration, and system coverage for execution boundaries, DNS rebinding, signature
  tampering, identity/publisher drift, field diffs, approval chains, and signed-baseline CLI flows.

### Changed

- Version increased from 0.4.0 to 0.5.0 and report schema from 1.0.0 to 1.1.0.
- CLI `--stdio` and config command execution now require an explicit `--executor`; config commands
  continue to require the independent `--allow-config-execution` consent flag.
- Unsigned legacy reports remain readable for migration but unchanged matches are marked
  `baseline_untrusted`; production can require signatures with `--require-signed-baseline`.

### Security

- Docker defaults to no network, read-only root, dropped capabilities, no-new-privileges, bounded
  tmpfs, and CPU/memory/process limits; Bubblewrap uses an unshared network/mount namespace and
  read-only bindings.
- Windows Job Objects kill the associated process tree when the job closes and enforce CPU, memory,
  and active-process limits.
- Baseline signatures and approval records use domain-separated Ed25519 messages over RFC 8785
  canonical JSON; private keys and logs require owner-only permissions on POSIX.

### Fixed

- Use buffered stdio pipes so bounded `readline` detects oversized JSON-RPC messages
  deterministically instead of timing out on raw short reads.
- Select POSIX process-group signaling at module load so strict mypy also passes with Windows
  platform stubs.
- Run the 2,000-card time and memory budget in a dedicated uninstrumented CI job; coverage keeps
  the same system workflow but no longer treats tracer overhead as product latency.

## [0.4.0] - 2026-07-13

### Added

- Incremental Streamable HTTP SSE parsing, bounded reconnects, `retry` handling, GET resumption,
  and `Last-Event-ID` propagation across interrupted POST responses.
- Capability-gated `notifications/tools/list_changed` waiting and exactly-once snapshot refresh for
  both stdio and Streamable HTTP discovery.
- MCP OAuth protected-resource and authorization-server metadata discovery, Authorization Code
  flow with mandatory S256 PKCE, RFC 8707 Resource Indicators, challenge-aware scope selection,
  exact callback state/issuer checks, owner-only state/token files, and process-safe completion lock.
- Integrity-locked official MCP conformance `initialize` and `sse-retry` scenarios in CI with a
  dedicated fixture-restricted client adapter.
- Unit, integration, and system coverage for v0.4 transport and OAuth workflows.

### Changed

- Version increased from 0.3.0 to 0.4.0 while report schema compatibility remains 1.0.0.
- README now documents v0.4 discovery/OAuth usage and no longer contains the `Rule Boundaries`
  section.

### Security

- OAuth authorization endpoints require HTTPS by default; callbacks require HTTPS or exact
  `localhost`, credentials are never accepted in callback process arguments, and state is
  single-use, expiring, owner-only, and concurrency locked.
- SSE line, stream, event, reconnect, retry, and notification refresh work are all bounded.

## [0.3.0] - 2026-07-13

### Added

- Versioned report schema 1.0.0 with scan IDs, policy and negotiated protocol metadata.
- SARIF 2.1.0, JUnit XML, JSON Lines, GitHub annotation, and deterministic JSON output.
- TOML policy profiles, rule selection/ignore, severity overrides, and expiring audited suppressions.
- MCP 2025-11-25/2025-06-18 negotiation, tools capability gating, and strict stdio mode.
- Complete JSON Schema 2020-12 metaschema validation and MCP icon validation.
- Bearer token providers using environment/private files, custom CA, explicit proxy, and mTLS.
- Cross-platform CI, coverage/type/static gates, clean artifact installation, trusted publishing,
  checksums, SBOM, and build provenance.

### Changed

- Non-JSON stdio stdout now fails by default; reviewed legacy servers require
  `--compat-stdio-noise`.
- Package version now has a single source in `mcp_tool_card_linter.__version__`.
- Version increased from 0.2.0 to 0.3.0.

### Security

- Unexpected CLI exceptions are converted to bounded diagnostics unless `--debug` is requested.
- Credentials are rejected in endpoint/proxy URLs and bearer token text is never accepted as a CLI
  argument.
- Environment proxy variables are not inherited implicitly; proxy routing requires `--proxy`.
- Per-tool findings and SARIF results have explicit truncation limits and machine-readable markers.

[Unreleased]: https://github.com/inostarlin-passion/MCP-Tool-Card-Linter/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/inostarlin-passion/MCP-Tool-Card-Linter/compare/v0.5.0...v1.0.0
[0.5.0]: https://github.com/inostarlin-passion/MCP-Tool-Card-Linter/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/inostarlin-passion/MCP-Tool-Card-Linter/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/inostarlin-passion/MCP-Tool-Card-Linter/compare/v0.2.0...v0.3.0

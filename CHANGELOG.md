# Changelog

This project follows semantic versioning for its CLI, rule IDs, and versioned report contract while
it moves toward 1.0. Deprecations are documented here before removal where security permits.

## [Unreleased]

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

[Unreleased]: https://github.com/inostarlin-passion/MCP-Tool-Card-Linter/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/inostarlin-passion/MCP-Tool-Card-Linter/compare/v0.2.0...v0.3.0

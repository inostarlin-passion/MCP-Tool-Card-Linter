# v1 stability policy

Effective from version 1.0.0. The machine-readable form is emitted by
`mcp-tool-card-linter contract`.

## Report contract

- v1 produces report schema 1.1.0 and reads report schemas 1.0.0 and 1.1.0.
- A published schema version is immutable. Adding a required field, changing a field type or
  narrowing an accepted value requires a new report schema version.
- A new minor report schema may add fields. v1 readers retain the prior supported schema reader;
  a schema major may remove fields only with a product major release.
- The deprecated top-level `version` alias remains alongside `tool_version` for v1.
- Consumers should select behavior from `report_schema_version`, validate against the matching
  published schema, and reject unknown schema majors.

## Rule contract

- Rule IDs are semantic identifiers, not display strings. An ID is never repurposed for another
  condition.
- New IDs may be added in minor releases. Removal requires documented deprecation before a product
  major release, except where preserving the rule would create a security vulnerability.
- Severity, confidence and recommendation text may be corrected in minor releases and are recorded
  in `CHANGELOG.md`. Policies should select by rule ID, not message text.
- `rule_catalog_version` and the ordered ID-set digest in `contract` make catalog drift explicit.

## CLI contract

The stable exit meanings are:

| Code | Meaning |
| ---: | --- |
| 0 | Completed and no finding reached the threshold, or finding failure was disabled |
| 1 | At least one finding reached the configured threshold |
| 2 | Input, discovery, trust, network, audit, report or other operational failure |
| 130 | User/process interruption |

Existing command/option removal requires deprecation before a product major release. New optional
commands and options may be added. Security-sensitive defaults may become stricter in a minor
release when the previous behavior would expose credentials, execute code or bypass a trust check;
such changes are documented prominently.

## Protocol support

As of 2026-07-14 the current final MCP protocol is 2025-11-25 and the immediately previous final
version is 2025-06-18. Both are tested. 2025-03-26 remains a legacy negotiation path. Draft or
release-candidate specifications are not advertised as production support until final.

## Support lifecycle

Security fixes are issued for the latest v1 minor release. A deprecated interface remains for at
least one minor release when security permits. The repository does not promise compatibility with
private Python functions, human-readable Markdown wording or undocumented metadata fields.

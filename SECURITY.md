# Security Policy

## Supported versions

Security fixes are provided for the latest v1 minor release. Published report schemas, rule IDs and
CLI exit meanings follow `docs/STABILITY_POLICY.md`. Security hardening may tighten a default when
preserving it would expose credentials, execute code or bypass trust; such changes are documented.

## Private vulnerability reporting

Do not open a public issue for a suspected vulnerability. Use GitHub's **Report a vulnerability**
button under the repository Security tab (GitHub Private Vulnerability Reporting). Include affected
versions, reproduction steps, impact, and any suggested mitigation. If that channel is unavailable,
contact the repository owner through the private contact method on the owner's GitHub profile.

We aim to acknowledge reports within 3 business days, complete initial triage within 7 days, and
publish or communicate a remediation plan for confirmed high-severity issues within 14 days. These
are response targets, not contractual service levels.

## Security boundaries

This linter statically assesses untrusted MCP metadata. It does not prove that runtime server
behavior matches a tool card. Config command execution remains host code execution even when the
CLI confirmation flag is present; run untrusted servers only in an external OS/container sandbox.
DNS validation is also subject to resolution/connect TOCTOU, so high-assurance deployments need an
egress proxy or network policy. See `docs/THREAT_MODEL.md` for the complete boundary.
The local operational audit hash chain is tamper-evident, not administrator-authenticated or
deletion-resistant; export it to restricted WORM/centralized storage where those properties matter.

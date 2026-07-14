# MCP Tool Card Linter Report

- Report schema: `1.1.0`
- Scan ID: `urn:sha256:07b3046427d61aa58f88edc08aac38f3d5282917d0bc58b3ccfb66f9c7679a53`
- Generated: `1970-01-01T00:00:00+00:00`
- Linter version: `1.0.0`
- Policy profile: `production`
- Sources scanned: `1`
- Tools scanned: `2`
- Average score: `50.5/100`
- Source errors: `0`

## Issue Summary

| Severity | Count |
| --- | ---: |
| critical | 1 |
| error | 0 |
| warning | 12 |
| info | 4 |

## Risk Summary

| Risk | Tool count |
| --- | ---: |
| critical | 1 |
| high | 0 |
| medium | 1 |
| low | 0 |

## Allowed Tools Recommendation

- Include by default: `none`
- Require approval: `send`
- Block until review: `summarize_issue`

## Sources

| Server | Type | Tools | Errors |
| --- | --- | ---: | --- |
| static | tools-file | 2 |  |

## Tool Findings

### `static` / `summarize_issue`

- Score: `44/100`
- Risk: `critical`
- Categories: `network, secret`
- Estimated card size: `325` chars
- Fingerprint: `sha256:993476025cf09f497da264aac7eff74ce59b43e466f0945de4092959307dbffb`
- Baseline status: `not_checked`

| Severity | Code | Path | Finding | Recommendation |
| --- | --- | --- | --- | --- |
| warning | `MISSING_SIDE_EFFECT_WARNING` | `description` | Tool appears to have side effects but the description does not state them clearly. | State whether the tool writes, sends, deletes, charges, calls external systems, and whether user confirmation is required. |
| warning | `MISSING_USAGE_BOUNDARY` | `description` | Risky tool lacks a clear usage boundary. | Add when-to-use and when-not-to-use guidance, especially for drafting versus sending or read-only versus write operations. |
| critical | `TOOL_POISONING_SECRET_EXFILTRATION` | `description` | Model-visible metadata contains instruction-like or secret-seeking text that may poison tool selection. Evidence: `read ~/.ssh/id_rsa` | Block this tool until reviewed; tool metadata appears to request unrelated secrets. |
| info | `STRING_BOUND_RECOMMENDED` | `inputSchema.properties.issue_url` | Free-form string parameter &#x27;issue_url&#x27; has no maxLength. | Add maxLength when large strings could increase latency, cost, or injection risk. |
| warning | `URL_PARAMETER_ALLOWLIST_MISSING` | `inputSchema.properties.issue_url` | URL-like parameter &#x27;issue_url&#x27; has no allowlist constraint. | Constrain schemes and destinations with an allowlist and enforce SSRF protections server-side; format alone is not an allowlist. |
| warning | `MISSING_OUTPUTSCHEMA` | `outputSchema` | outputSchema is missing. | Provide outputSchema when the client should parse structured results reliably. |

Recommendations:

- Add outputSchema for structured outputs when callers need deterministic parsing.
- Require human approval before calling this tool in production clients.
- Block this tool until the server owner removes instruction-like or secret-seeking metadata.
- Replace dangerous free-form inputs with bounded structured values and enforce the same policy server-side.

### `static` / `send`

- Score: `57/100`
- Risk: `medium`
- Categories: `write`
- Estimated card size: `138` chars
- Fingerprint: `sha256:55775a2a0e3403cc1e377112e224a32a6f1e6a68d632b02bc53b5492c3e0e53f`
- Baseline status: `not_checked`

| Severity | Code | Path | Finding | Recommendation |
| --- | --- | --- | --- | --- |
| warning | `GENERIC_TOOL_NAME` | `name` | Tool name &#x27;send&#x27; is too generic for reliable tool selection. | Rename the tool to include the target domain and action, for example send_email or search_customer_orders. |
| warning | `DESCRIPTION_TOO_SHORT` | `description` | Tool description is too short to guide reliable tool selection. Evidence: `Send message` | Add purpose, usage boundary, important inputs, output shape, and side effects. |
| warning | `MISSING_SIDE_EFFECT_WARNING` | `description` | Tool appears to have side effects but the description does not state them clearly. | State whether the tool writes, sends, deletes, charges, calls external systems, and whether user confirmation is required. |
| warning | `MISSING_USAGE_BOUNDARY` | `description` | Risky tool lacks a clear usage boundary. | Add when-to-use and when-not-to-use guidance, especially for drafting versus sending or read-only versus write operations. |
| warning | `MISSING_REQUIRED_FIELDS` | `inputSchema.required` | Object schema has properties but no required list. | Declare required parameters explicitly; use an empty list if every field is optional. |
| warning | `ADDITIONAL_PROPERTIES_UNSPECIFIED` | `inputSchema.additionalProperties` | Object schema does not state whether extra parameters are allowed. | Set additionalProperties to false for strict tool arguments unless arbitrary keys are intentional. |
| info | `PARAMETER_DESCRIPTION_MISSING` | `inputSchema.properties.to.description` | Parameter &#x27;to&#x27; has no description. | Explain accepted format, units, identifiers, and whether the parameter is optional. |
| info | `STRING_BOUND_RECOMMENDED` | `inputSchema.properties.to` | Free-form string parameter &#x27;to&#x27; has no maxLength. | Add maxLength when large strings could increase latency, cost, or injection risk. |
| warning | `PARAMETER_DESCRIPTION_MISSING` | `inputSchema.properties.msg.description` | Parameter &#x27;msg&#x27; has no description. | Explain accepted format, units, identifiers, and whether the parameter is optional. |
| info | `STRING_BOUND_RECOMMENDED` | `inputSchema.properties.msg` | Free-form string parameter &#x27;msg&#x27; has no maxLength. | Add maxLength when large strings could increase latency, cost, or injection risk. |
| warning | `MISSING_OUTPUTSCHEMA` | `outputSchema` | outputSchema is missing. | Provide outputSchema when the client should parse structured results reliably. |

Recommendations:

- Rename the tool to an action_domain form such as send_email or search_orders.
- Expand the description with purpose, usage boundary, important inputs, outputs, and side effects.
- Add outputSchema for structured outputs when callers need deterministic parsing.
- Require human approval before calling this tool in production clients.

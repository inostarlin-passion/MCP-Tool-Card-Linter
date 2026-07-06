# MCP Tool Card Linter Report

- Generated: `2026-07-06T13:07:32.761978+00:00`
- Linter version: `0.1.0`
- Sources scanned: `1`
- Tools scanned: `2`
- Average score: `56.0/100`
- Source errors: `0`

## Issue Summary

| Severity | Count |
| --- | ---: |
| critical | 1 |
| error | 0 |
| warning | 10 |
| info | 3 |

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

- Score: `50/100`
- Risk: `critical`
- Categories: `network, secret`
- Estimated card size: `297` chars

| Severity | Code | Path | Finding | Recommendation |
| --- | --- | --- | --- | --- |
| critical | `TOOL_POISONING_SECRET_EXFILTRATION` | `description` | Description contains instruction-like or secret-seeking text that may poison tool selection. Evidence: `read ~/.ssh/id_rsa` | Block this tool until reviewed; tool metadata appears to request unrelated secrets. |
| warning | `MISSING_SIDE_EFFECT_WARNING` | `description` | Tool appears to have side effects but the description does not state them clearly. | State whether the tool writes, sends, deletes, charges, calls external systems, and whether user confirmation is required. |
| warning | `MISSING_USAGE_BOUNDARY` | `description` | Risky tool lacks a clear usage boundary. | Add when-to-use and when-not-to-use guidance, especially for drafting versus sending or read-only versus write operations. |
| warning | `MISSING_OUTPUTSCHEMA` | `outputSchema` | outputSchema is missing. | Provide outputSchema when the client should parse structured results reliably. |

Recommendations:

- Add outputSchema for structured outputs when callers need deterministic parsing.
- Require human approval before calling this tool in production clients.
- Block this tool until the server owner removes instruction-like or secret-seeking metadata.

### `static` / `send`

- Score: `62/100`
- Risk: `medium`
- Categories: `write`
- Estimated card size: `107` chars

| Severity | Code | Path | Finding | Recommendation |
| --- | --- | --- | --- | --- |
| warning | `GENERIC_TOOL_NAME` | `name` | Tool name 'send' is too generic for reliable tool selection. | Rename the tool to include the target domain and action, for example send_email or search_customer_orders. |
| warning | `DESCRIPTION_TOO_SHORT` | `description` | Tool description is too short to guide reliable tool selection. Evidence: `Send message` | Add purpose, usage boundary, important inputs, output shape, and side effects. |
| warning | `MISSING_SIDE_EFFECT_WARNING` | `description` | Tool appears to have side effects but the description does not state them clearly. | State whether the tool writes, sends, deletes, charges, calls external systems, and whether user confirmation is required. |
| warning | `MISSING_USAGE_BOUNDARY` | `description` | Risky tool lacks a clear usage boundary. | Add when-to-use and when-not-to-use guidance, especially for drafting versus sending or read-only versus write operations. |
| warning | `MISSING_REQUIRED_FIELDS` | `inputSchema.required` | Object schema has properties but no required list. | Declare required parameters explicitly; use an empty list if every field is optional. |
| info | `ADDITIONAL_PROPERTIES_UNSPECIFIED` | `inputSchema.additionalProperties` | Object schema does not state whether extra parameters are allowed. | Set additionalProperties to false for strict tool arguments unless arbitrary keys are intentional. |
| info | `PARAMETER_DESCRIPTION_MISSING` | `inputSchema.properties.to.description` | Parameter 'to' has no description. | Explain accepted format, units, identifiers, and whether the parameter is optional. |
| warning | `PARAMETER_DESCRIPTION_MISSING` | `inputSchema.properties.msg.description` | Parameter 'msg' has no description. | Explain accepted format, units, identifiers, and whether the parameter is optional. |
| info | `STRING_BOUND_RECOMMENDED` | `inputSchema.properties.msg` | Free-form string parameter 'msg' has no maxLength. | Add maxLength when large strings could increase latency, cost, or injection risk. |
| warning | `MISSING_OUTPUTSCHEMA` | `outputSchema` | outputSchema is missing. | Provide outputSchema when the client should parse structured results reliably. |

Recommendations:

- Rename the tool to an action_domain form such as send_email or search_orders.
- Expand the description with purpose, usage boundary, important inputs, outputs, and side effects.
- Add outputSchema for structured outputs when callers need deterministic parsing.
- Require human approval before calling this tool in production clients.

## Facts, Inferences, And Uncertainties

Facts:

- MCP tools are model-callable capabilities described by metadata such as name, description, and input schema.
- MCP uses JSON-RPC messages over transports such as stdio and Streamable HTTP.
- Tool metadata quality affects how an agent discovers, selects, and fills arguments for tools.

Inferences:

- Side-effect, schema, and prompt-injection checks are static heuristics; they reduce review effort but do not prove runtime safety.
- Tools with write, destructive, financial, network, or secret-related wording should require stricter human review by default.

Uncertainties:

- Tool Card is an engineering term in this project, not a formal MCP specification object.
- A static linter cannot verify whether server implementation behavior matches its metadata.

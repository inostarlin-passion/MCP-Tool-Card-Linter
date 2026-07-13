# MCP protocol compatibility

Review date: 2026-07-13. The matrix describes tested claims, not full SDK conformance.

| Capability | 2025-11-25 | 2025-06-18 | Notes |
| --- | --- | --- | --- |
| Initialize/version negotiation | Tested | Tested | Client requests configured version (latest by default), accepts either supported version, records both |
| Capability negotiation | Tested | Tested | `tools/list` is rejected with `unsupported_feature` unless `capabilities.tools` is declared |
| stdio request/notification | Tested | Tested through shared JSON-RPC path | Strict newline-delimited JSON; bounded compatibility exception for legacy stdout noise |
| Streamable HTTP POST JSON | Tested | Tested through shared path | JSON response, session header, initialized notification and DELETE cleanup |
| Streamable HTTP POST SSE response | Tested | Tested through shared path | Bounded finite response parsing; not a persistent streaming implementation |
| Pagination | Tested | Tested through shared path | Tool/page caps and repeated cursor rejection |
| Protocol version request header | Tested | Tested | Subsequent HTTP requests use the negotiated version |
| Tool `icons` metadata | Tested | Not defined in this version | Structural URI/MIME/size/theme checks; icons are never fetched |
| JSON Schema dialect | Draft 2020-12 metaschema | Draft 2020-12 validator used as project policy | External `$ref` remains blocked from network resolution |
| Bearer token, CA, proxy, mTLS | Tested provider/header primitives | Same HTTP path | Pre-issued token support only; no interactive OAuth flow |
| OAuth metadata, Authorization Code + PKCE | Not implemented | Not implemented | Do not claim MCP OAuth conformance |
| GET SSE listener/resumption/Last-Event-ID | Not implemented | Not implemented | Current client is a bounded discovery snapshot |
| `notifications/tools/list_changed` refresh | Not implemented | Not implemented | One-shot scan only |
| Tasks | Not implemented | Not applicable | 2025-11-25 tasks are experimental and outside tool-card scan scope |

The official MCP lifecycle requires version negotiation and capability-aware operation; the
transport specification additionally requires stdout purity for stdio and supports both JSON and SSE
responses for Streamable HTTP. This project tests those bounded discovery paths but does not label
itself a complete MCP SDK. Official conformance vectors should be pinned and added once the project
implements the remaining transport lifecycle.

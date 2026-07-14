# MCP protocol compatibility

Review date: 2026-07-14. Version: 0.5.0. The matrix describes tested tool-discovery
claims, not a claim that this focused linter is a general-purpose MCP SDK.
The columns focus on the current and immediately previous release. The allowlist also accepts
2025-03-26 for base lifecycle/transport compatibility; the official `sse-retry` fixture negotiates
that version and passes, but fields introduced in later versions are not projected backward.

| Capability | 2025-11-25 | 2025-06-18 | Notes |
| --- | --- | --- | --- |
| Initialize/version negotiation | Tested | Tested | Client requests configured version (latest by default), accepts any of the three allowlisted versions, records requested/negotiated |
| Capability negotiation | Tested | Tested | `tools/list` is rejected with `unsupported_feature` unless `capabilities.tools` is declared |
| stdio request/notification | Tested | Tested through shared JSON-RPC path | Strict newline-delimited JSON; bounded compatibility exception; CLI executor is default-deny with host/Docker/Bubblewrap/Job Object choices |
| Streamable HTTP POST JSON | Tested | Tested through shared path | JSON response, session header, initialized notification, DELETE cleanup, and cross-request DNS-set pinning |
| Streamable HTTP POST SSE response | Tested | Tested through shared path | Incremental UTF-8/event parser; empty priming events; hard line/body/event limits |
| GET SSE listener/resumption/Last-Event-ID | Tested | Tested through shared path | Optional listener, POST response resumption, `retry` delay cap and three-reconnect cap |
| `notifications/tools/list_changed` refresh | Tested | Tested through shared path | Explicit timeout, capability gate, stdio/HTTP event handling and exactly one re-list |
| Pagination | Tested | Tested through shared path | Tool/page caps and repeated cursor rejection |
| Protocol version request header | Tested | Tested | Subsequent HTTP requests use the negotiated version |
| Tool `icons` metadata | Tested | Not defined in this version | Structural URI/MIME/size/theme checks; icons are never fetched |
| Tool `execution.taskSupport` metadata | Tested | Not defined in this version | Validates `forbidden`/`optional`/`required`; linter never invokes tools |
| JSON Schema dialect | Draft 2020-12 metaschema | Draft 2020-12 validator used as project policy | External `$ref` remains blocked from network resolution |
| Bearer token, CA, proxy, mTLS | Tested provider/header primitives | Same HTTP path | Token only in header; env/private-file ingress; explicit network configuration |
| Protected Resource Metadata discovery | Tested | Same authorization path | `WWW-Authenticate` hint, endpoint-path then root fallback, exact resource binding |
| Authorization Server Metadata discovery | Tested | Same authorization path | RFC 8414 then two OIDC candidates in required priority; issuer equality enforced |
| Authorization Code + PKCE + Resource Indicators | Tested | Same authorization path | Pre-registered public client; mandatory S256; `resource` in authorization/token requests; exact state/callback/optional issuer checks |
| Official MCP conformance runner | `initialize` + `sse-retry` passed locally | Adapter accepts negotiated previous/legacy versions | Integrity-locked `@modelcontextprotocol/conformance@0.1.15`; 2/2 scenarios and 4/4 normative checks; CI gate configured |
| Tasks | Not implemented | Not applicable | 2025-11-25 tasks are experimental and outside tool-card scan scope |

The official MCP lifecycle requires version negotiation and capability-aware operation; the
transport specification additionally requires stdout purity for stdio and defines JSON/SSE POST,
optional GET listeners, session headers, resumability and event IDs for Streamable HTTP. v0.5 tests
these bounded discovery paths and the official initialization vector. It does not declare client
capabilities for sampling, roots or elicitation, so server-to-client requests for those features are
outside the negotiated behavior rather than silently accepted.

OAuth v0.5 intentionally supports pre-registered public clients. Dynamic Client Registration,
Client ID Metadata Documents, refresh-token rotation, browser automation and automatic
insufficient-scope step-up are separate lifecycle features and are not claimed here.

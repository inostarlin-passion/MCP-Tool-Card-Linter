# Supported and unsupported boundaries

Review date: 2026-07-14. Version: 1.0.0.

## Supported production gate

| Area | Supported claim |
| --- | --- |
| Input | Static tool JSON, bounded MCP config, stdio and Streamable HTTP tool discovery |
| MCP | Current final 2025-11-25 and previous final 2025-06-18; legacy 2025-03-26 negotiation |
| Schema | JSON Schema Draft 2020-12 metaschema validation plus bounded MCP/security heuristics |
| Auth | Pre-issued Bearer provider, enterprise CA, explicit HTTP(S) proxy, mTLS; pre-registered public-client Authorization Code + S256 PKCE + Resource Indicators |
| Execution | Default deny; Docker/Bubblewrap sandbox policies; Windows Job Object resource/tree policy; explicit trusted host compatibility |
| Trust | RFC 8785 fingerprints, externally trusted Ed25519 signed baseline, publisher/server/source binding, signed approval chain |
| Audit | Minimal allowlisted lint/OAuth event fields in owner-only, locked, append-mode, hash-chained JSONL; verification command |
| Reports | Schema 1.1.0 output; 1.0.0/1.1.0 reader; JSON/Markdown/SARIF/JUnit/JSONL/GitHub output |
| Quality evidence | Cross-platform Python matrix, official MCP scenarios, deterministic fuzz/input-mutation/soak, public labelled-pair accuracy gate, performance and reproducible-build gates |

## Explicitly unsupported

- Proving that server runtime behavior matches metadata, runtime tool authorization, runtime output
  validation, malware detection, SAST/SCA or container-escape resistance.
- MCP prompts, resources, sampling, roots, elicitation, draft extensions, MCP Apps, multi-step toxic
  flow or arbitrary tool invocation.
- Dynamic Client Registration, Client ID Metadata Documents, confidential-client secret handling,
  refresh-token rotation, DPoP, automated browser consent or automatic scope escalation.
- A network-security guarantee from application DNS checks alone. DNS resolver-to-socket TOCTOU
  remains; high-assurance installations need an egress proxy/network policy.
- Filesystem/network isolation from Windows Job Object or `--executor host`.
- Audit-log authenticity against an administrator who can rewrite and recompute the local chain, or
  availability against deletion/truncation. Forward logs to access-controlled WORM/transparent
  storage for that property.
- A universal accuracy claim. The published evaluation covers only explicitly labelled pairs in its
  versioned corpus.
- Bit-identical archives across arbitrary OS/Python/compression versions; the enforced claim is two
  builds in the same declared CI environment.

## Operator responsibilities

Pin reviewed container images by digest; keep signing and mTLS private keys outside routine scan
workers; distribute baseline public keys independently; enforce token audience/scope/expiry at the
authorization and resource servers; protect proxy and CA configuration; archive audit/approval logs;
enable immutable GitHub releases; apply branch protection; and require human confirmation plus
runtime least privilege for consequential tools.

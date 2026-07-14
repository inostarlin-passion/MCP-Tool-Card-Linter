# Release integrity and reproducibility

Version 1.0.0 uses a tag-triggered, least-permission release workflow. GitHub Actions are pinned to
full commit SHAs. The workflow builds wheel and sdist with the commit timestamp as
`SOURCE_DATE_EPOCH`, emits SHA-256 checksums and a reproducible CycloneDX SBOM, creates signed
GitHub/Sigstore provenance plus an SBOM attestation, and publishes through PyPI Trusted Publishing
with PEP 740 attestations enabled.

## Consumer verification

Verify a downloaded GitHub artifact against repository/workflow identity:

```bash
gh attestation verify mcp_tool_card_linter-1.0.0-py3-none-any.whl \
  --repo inostarlin-passion/MCP-Tool-Card-Linter
sha256sum -c SHA256SUMS
```

If immutable releases are enabled in repository settings, also verify the release and asset:

```bash
gh release verify v1.0.0 --repo inostarlin-passion/MCP-Tool-Card-Linter
gh release verify-asset v1.0.0 mcp_tool_card_linter-1.0.0-py3-none-any.whl \
  --repo inostarlin-passion/MCP-Tool-Card-Linter
```

PyPI displays and serves the Trusted Publisher attestations associated with each distribution.
Verification establishes artifact digest, build/publisher identity and provenance; it does not prove
that the source or artifact is vulnerability-free.

## Reproduce locally

Use the same Python/build-backend versions and source epoch, then compare bytes:

```bash
export SOURCE_DATE_EPOCH="$(git show -s --format=%ct v1.0.0)"
python -m build --outdir /tmp/build-a
python -m build --outdir /tmp/build-b
cmp /tmp/build-a/*.whl /tmp/build-b/*.whl
cmp /tmp/build-a/*.tar.gz /tmp/build-b/*.tar.gz
```

The CI claim is bit-for-bit reproducibility on its pinned Ubuntu/Python build environment. It is not
a promise that archives built with arbitrary Python, compression-library or platform versions have
the same bytes.

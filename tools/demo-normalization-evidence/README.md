# Normalization evidence

Requires Python 3.9+ and an installed Rio v0.7.0+ release. No Go toolchain, server, credentials or network is used.

```sh
RIO_BIN=/absolute/path/to/rio python3 tools/demo-normalization-evidence/run.py
```

The committed synthetic SBOM and mapping assertion demonstrate spec uplift, an external table
repair, a preserved Eclipse qualifier, and an unresolved mapping. The script verifies the digest
of the loaded mapping, categorical provenance, one rewrite count per component, unchanged input
and deterministic output. It checks two isolated runs produce identical index and SBOM bytes, retains each invocation’s
automatic compact receipt separately, removes only its own source workspace, and inspects both
receipts offline. The receipts preserve spec from/to and bulk repair counts, not the detailed
component ledger available in the local index. The printed directory retains the result.

The mapping's `manifest-proven` label is synthetic upstream assertion data, not measured confidence.
This example does not establish authenticity, full-input retention or delivery acceptance.

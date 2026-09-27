# Normalization evidence

Requires Python 3.9+ and an installed Rio release containing normalization evidence (v0.6.0
planned). No Go toolchain, server, credentials or network is used.

```sh
python3 tools/demo-normalization-evidence/run.py /absolute/path/to/rio
```

The committed synthetic SBOM and mapping assertion demonstrate spec uplift, an external table
repair, a preserved Eclipse qualifier, and an unresolved mapping. The script verifies the digest
of the loaded mapping, categorical provenance, one rewrite count per component, unchanged input
and deterministic output. It collects one portable record, removes only its own source workspace,
and inspects the retained JSON offline. The printed directory retains the result.

The mapping's `manifest-proven` label is synthetic upstream assertion data, not measured confidence.
This example does not establish authenticity, full-input retention or delivery acceptance.

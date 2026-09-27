# A complete client evidence handoff

**Start with the simple delivery story:** [full record.json](example/record.json) ·
[HTML report](example/report.html) (download and open locally) ·
[reproduce the two-SBOM pipeline/delivery example](example/README.md).
It records the consumed SBOMs, added build URL/ID, destination URL, TLS facts and server receipts.
The broader walkthrough below also exercises specialized repairs and failure cases.

Requires Python 3.9+ and an installed Rio release containing client evidence (v0.6.0 or newer).
No Go toolchain, container or production credentials are needed:

```sh
python3 tools/demo-client-record/run.py /absolute/path/to/rio
# Windows:
python tools/demo-client-record/run.py C:\path\rio.exe
```

The script copies the committed synthetic fixtures, starts a loopback HTTPS receiver and supplies
the existing clearly labelled synthetic test CA. `rio.yaml` uses JSON syntax (valid YAML), allowing
the Python standard library to update only the disposable endpoint and CA reference.

The main story uses two artifact-set modules, CycloneDX 1.4 → 1.6 uplift, a coordinate/version repair,
an unresolved mapping, inherited producer/supplier/license enrichment, two delivery targets and an
explicit exclusion. It executes the two-command flow, stopping if normalization fails:

```sh
rio normalize --gate fail &&
  rio deliver --evidence client.json
```

A separate destination records explicit TLS verification bypass; it is not a policy-changing retry
of the verified destination. Reconciliation retains processing, no processing observed, and a later
unavailable query without rewriting the acknowledgment. The original successful snapshot stays
byte-identical. Separate examples cover a partial/lost response, an enforced failed gate exported
without delivery, and an explicitly authorized failed-gate delivery override.

After stopping the receiver, the script replaces the working index and collects from immutable
batch/index snapshots. It removes only its test-created source workspace, relocates one final JSON,
inspects it, and renders HTML offline. Edits to repair, receipt and coverage projections each refuse.
Runtime secret canaries must be absent from records, reports and CLI output.

The printed directory contains:

- `recipient/record.json` and `recipient/report.html`: the standalone client handoff after reconciliation.
- `success.json` / `.html`: the original verified-HTTPS snapshot.
- `partial.json` / `.html`: unknown acknowledgment and an unattempted suffix.
- `failed-gate.json` / `.html` and `explicit-override.json` / `.html`: separate gate outcomes.
- `walkthrough.json`: commands, exits, request count and original snapshot digest.

All receiver responses are synthetic. Receipts/activity are not ingestion or content-retention proof.
For real-server observations, use the separately provisioned
[disposable Dependency-Track integration](../demo-delivery/integration/README.md).

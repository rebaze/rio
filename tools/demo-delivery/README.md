# Installed-binary verified delivery demo

Run `python3 tools/demo-delivery/run.py /absolute/path/to/rio` with Python 3.9+.
On Windows use `python tools/demo-delivery/run.py C:\path\rio.exe`.
Only an installed Rio v0.7.0 or newer binary and the Python standard library are needed. The demo never builds Rio.

The normal path runs `rio --json` once using one `rio.yaml`. Its compact receipt identifies the
normalized bytes, HTTP transport, destination projects and synthetic server event tokens. Three
synthetic artifact-set modules feed two loopback receivers. Subsequent specialist scenarios use
the returned run directory’s `index.json` and explicit delivery journals. The demo
retains its temporary directory and demonstrates:

- Index membership remains authoritative after source modules change.
- Default subject projects, target fan-out, overrides/exclusions, unused rules and exact upload bytes.
- Duplicate project and later missing-credential refusal before any upload.
- Isolated run directories, automatic internal journal paths, and duplicate stage-delivery refusal.
- Partial acceptance followed by a lost response, unattempted work, filtered completion and deliberate retry.
- Journal inspection and activity reconciliation without upload replay.
- Explicit UUID, digest tampering, failed-gate refusal/override, malformed receipt and skipped schema validation.

All receiver receipts/statuses are explicitly **synthetic**. They prove the demo behavior and do
not establish Dependency-Track compatibility, ingestion or content retention. The separately
retained [real 5.1.1 integration evidence](integration/README.md) describes historical adapter
observations; this demo does not relabel or refresh that evidence. The updated real-server harness
can verify the v0.7 compact receipt contract against an owned disposable fixture.

See [configuration, limits and recovery semantics](../README.md#native-verified-delivery).

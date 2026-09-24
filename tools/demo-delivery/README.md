# Installed-binary verified delivery demo

Run `python3 tools/demo-delivery/run.py /absolute/path/to/rio` with Python 3.9+.
On Windows use `python tools/demo-delivery/run.py C:\path\rio.exe`.
Only the installed Rio binary and Python standard library are needed; no Go invocation occurs.

A temporary local HTTP receiver emits explicitly **synthetic** receipts/status. The demo retains
its output directory, verifies exact uploaded bytes, shows direct name/version, UUID and subject
selection, failed-gate refusal/override, digest tampering, malformed/lost receipts, offline
inspection and read-only reconciliation. Missing version and unmapped p2 examples retain the
index and unsigned statements. A future CycloneDX spec demonstrates skipped schema validation;
that fact stays visible and is not a claim of valid schema or ingestion.

See [configuration and evidence semantics](../README.md#native-verified-delivery).

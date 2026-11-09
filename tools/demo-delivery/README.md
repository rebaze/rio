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

## Tags, parent and latest version

`python3 tools/demo-delivery/project-fields.py /absolute/path/to/rio` needs Rio v0.10.0 or newer.
One `rio.yaml` sets `tags`, `parent` and `isLatest` on a Dependency-Track target, with an
artifact override for `agent` (its own tags and a parent by UUID). Six root runs show, per artifact,
each requested value and its receipt state:

1. A new version with a key that may create and read projects: all `observed`.
2. Changed tags on that version with a key lacking `PORTFOLIO_MANAGEMENT_UPDATE`: the receiver answers
   200 and keeps the old tags, recorded as `different` with the observed tags.
3. The same without `VIEW_PORTFOLIO`: `readBack=forbidden`, every value `unknown`.
4. With `PORTFOLIO_MANAGEMENT_UPDATE`: the tag set is replaced, `observed`.
5. A newer version with `isLatest`: it becomes the latest; the earlier version loses the flag.
6. A parent that does not exist: 404, delivery `rejected` with `parent_not_found`, exit 5.

Its loopback receiver imitates the upload rules of Dependency-Track 5.2.1 and is **synthetic**.
The same matrix against a real 5.2.1 server is in [integration](integration/README.md#project-tags-parent-and-latest-version-on-521).

All receiver receipts/statuses are explicitly **synthetic**. They prove the demo behavior and do
not establish Dependency-Track compatibility, ingestion or content retention. The separately
retained [real 5.1.1 integration evidence](integration/README.md) describes historical adapter
observations; this demo does not relabel or refresh that evidence. The updated real-server harness
can verify the v0.7 compact receipt contract against an owned disposable fixture.

See [configuration, limits and recovery semantics](../README.md#native-verified-delivery).

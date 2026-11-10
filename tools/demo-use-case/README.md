# The README's use case

One `rio.yaml`, one `rio` invocation: a build's CycloneDX 1.4 SBOM is raised to 1.6, enriched
with the supplier, security contact and fact-sheet link, checked, delivered to Dependency-Track
with an owner tag, and read back.

**The data is synthetic, and so is the receiver:** a loopback server imitating Dependency-Track
5.2.1's upload and project-read rules for a key with `BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD` and
`VIEW_PORTFOLIO`. Its acknowledgment is synthetic; acceptance is not ingestion. Real-server
evidence for the same fields is in [`demo-delivery/integration`](../demo-delivery/integration/README.md#project-tags-parent-and-latest-version-on-521).

```sh
python3 tools/demo-use-case/run.py [rio] [new-output-directory]
```

It needs an installed Rio v0.10.0 or newer and Python 3.9+, and no network, Go toolchain or
account. It copies [`inputs/bom.json`](inputs/bom.json) to `target/bom.json` and
[`rio.yaml`](rio.yaml) next to it, pointing the target's `url` at the receiver (with
`allowHTTP: true`, for loopback only), and runs `rio`. It checks that the receiver got exactly the
bytes Rio wrote, that the receipt holds no API key, and that the tag reads back as `observed`. It then prints the output tree and `rio record inspect`, and writes `report.html`.
Everything stays in the output directory.

[`example/`](example/) holds one such run by Rio v0.10.0: [`rio.yaml`](example/rio.yaml) as run,
[`record.json`](example/record.json), the delivered [`payments-api.cdx.json`](example/payments-api.cdx.json),
[`index.json`](example/index.json), [`report.html`](example/report.html) and the
[console output](example/output.txt), with the output path replaced by `<output>`. The README's
example is this run.

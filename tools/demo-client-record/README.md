# One command, one compact receipt

Run `rio` once. The synthetic example consumes `api.cdx.json` and `worker.cdx.json`, adds a build URL and ID, submits the resulting bytes to two projects on a local HTTPS receiver, and records HTTP responses and event tokens.

See the result immediately: [complete receipt](example/record.json), [offline HTML](example/report.html), or [download the runnable example](example/example.zip). The server, SBOMs and tokens are synthetic. The URL in the receipt identifies the receiver used for that run, not a product website. HTTP acceptance does not establish ingestion.

With Rio 0.7.0+ installed and Python 3.9+:

```sh
python3 tools/demo-client-record/run.py "$(command -v rio)"
```

The runner exercises success and a lost second response, each as its own single pipeline invocation. It verifies the input/output hashes, exact multipart SBOM bytes and project fields, exact build metadata, certificate verification, HTTP status and returned token, the 8 KiB readable-JSON budget, and secret-canary absence. It stops the receiver and deletes the source workspace before inspecting and rendering a receipt-only copy.

To regenerate a single example in a **new** directory:

```sh
python3 tools/demo-client-record/example/generate.py "$(command -v rio)" /tmp/rio-example
python3 tools/demo-client-record/example/generate.py "$(command -v rio)" /tmp/rio-partial --partial
```

The output includes complete `rio.yaml`, `pipeline.json`, input and normalized SBOMs, a standalone Python runner, synthetic TLS material, JSON/HTML, and a downloadable ZIP. Neither the runner nor Rio needs a Go toolchain. Each receipt describes only its own invocation; no collection or bundle export is involved.

For native adapter failure matrices and explicit stage operations, see the [Dependency-Track](../demo-delivery/README.md), [TLS policy](../demo-dtrack-tls/README.md), [OCI](../demo-oci/README.md), and [batch recovery](../demo-batch-evidence/README.md) examples. Artifact-set and normalization fixtures remain specialist examples in [tools/README.md](../README.md).

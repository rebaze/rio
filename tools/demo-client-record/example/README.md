# Two SBOMs, pipeline context, and delivery receipts

[Read the complete record.json](record.json) or download [report.html](report.html) and open it locally.
These are actual outputs from the released Rio v0.6.0 binary. The receiver is a synthetic HTTPS
implementation of the Dependency-Track upload API; its loopback URL is recorded honestly.

The example consumes `api.cdx.json` and `worker.cdx.json`, adds the supplied build URL
`https://ci.example.org/runs/42` and build ID `42`, and sends each enriched SBOM to its own
Dependency-Track project (`api` / `1.0.0` and `worker` / `1.0.0`). Both uploads use TLS with
certificate verification enforced. Each response is HTTP 200 with an event token.
No coordinate repair or spec uplift is needed.

## Reproduce with an installed Rio

Requires Rio v0.6.0 or newer and Python 3.9+; no Go toolchain, container, external server or real
credentials are needed. From the repository root, choose a new output directory:

```sh
python3 tools/demo-client-record/example/generate.py /absolute/path/to/rio /tmp/rio-delivery-example
rio record inspect --file /tmp/rio-delivery-example/record.json
```

The script creates two small input SBOMs and a digest-bound `pipeline.json`, then executes
`rio normalize --gate fail` and `rio deliver --evidence record.json`. It checks that the submitted
bytes match the normalized files, that pipeline values are retained, and that the record contains
the destination URL, TLS facts, HTTP statuses and event tokens. It stops the receiver, removes its
source workspace, and inspects/renders only the retained JSON. Receiver ports and timestamps vary
between runs; the checked-in sample preserves one complete run without editing the record.

The HTML report binds this exact JSON SHA-256:
`448ccc8db53b7ef094b29ac193e21c0a868e4566037355dadf256c35ec7dc3d7`.

## Where the facts live

| Question | Record field |
| --- | --- |
| Which SBOMs were consumed? | `normalization.index.artifacts[].input` (path and digest) |
| Which pipeline values were added? | `normalization.index.artifacts[].context.effective.build` and `.context.changes` |
| Which bytes were delivered? | `deliveries[].intent.payloads[]` (digest and size) |
| Which server and project? | `deliveries[].intent.destination.identity` (URL and project) |
| Was TLS used and verified? | Submission observation `.details.tls` (`observed`, `certificateVerification`) |
| What did the server return? | Submission observation `.httpStatus`, `.value`, and `.references[]` (event token) |

`build.url` becomes a native SBOM build-system reference; both build fields are also retained in
Rio's SBOM context property. Pipeline context is a producer assertion. HTTP acceptance is not
proof of ingestion, and the portable record is unsigned consistency evidence.

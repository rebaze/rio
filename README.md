# rio

**One `rio` invocation → the pipeline in `rio.yaml` → one compact receipt.**

```sh
rio
```

Rio consumes your SBOMs, adds configured product/build metadata, checks quality, and delivers the resulting bytes to your receivers. Here is an excerpt from the **actual generated v0.7.0 example** (synthetic SBOMs, HTTPS receiver and tokens; digests shortened only in this excerpt):

```text
Consumed → enriched → delivered → acknowledged

api.cdx.json     1d2b04c0df45… → 55e46a63a8b3…  (2307 output bytes)
worker.cdx.json  721bd8311e64… → 085265392b20…  (2316 output bytes)

Added to both: build.url = https://ci.example.org/runs/42
               build.id  = 42
Destination:   https://127.0.0.1:53946
Projects:      api / 1.0.0, worker / 1.0.0
TLS:           observed; certificate verification enforced

api:     HTTP 200, accepted; token 11111111-1111-4111-8111-111111111111
worker:  HTTP 200, accepted; token 22222222-2222-4222-8222-222222222222
```

**[Complete JSON receipt — 5,791 bytes](tools/demo-client-record/example/record.json)** · **[Download offline HTML](https://raw.githubusercontent.com/rebaze/rio/main/tools/demo-client-record/example/report.html)** · **[Download the runnable example](https://raw.githubusercontent.com/rebaze/rio/main/tools/demo-client-record/example/example.zip)**

The URL identifies the **destination server**, not a product website. This capture used a local synthetic receiver; your receipt contains your configured Dependency-Track instance or OCI registry. It retains full input/output digests, byte sizes, exact metadata changes, effective checks, projects, transport facts, response times and receiver references. HTTP acceptance is distinct from ingestion or content verification.

[Complete quick start](docs/quick-start.md) · [Manifest](docs/manifest.md) · [CLI](docs/cli.md) · [Receipt field guide](docs/output.md) · [Installed-binary demos](tools/README.md#client-evidence-demos)

## Install

Rio is one self-contained binary for Linux, macOS and Windows. No Go toolchain or external runtime is needed to run it.

```sh
brew install rebaze/tap/rio
```

Or use the installer:

```sh
curl -sSL https://raw.githubusercontent.com/rebaze/rio/main/install.sh | sh
```

[Release downloads](https://github.com/rebaze/rio/releases/latest) include checksums, signatures and attestations. Use **v0.7.0 or newer** for this workflow. The [installation reference](docs/cli.md#install) covers version pinning and custom directories.

## Configure your pipeline

For a build that produces `target/bom.json`, save this as `rio.yaml`:

```yaml
version: 1
artifacts:
  - id: app
    sbom: target/bom.json
delivery:
  targets:
    security:
      type: dependency-track
      url: https://dtrack.example.org
      apiKeyEnv: DTRACK_API_KEY
      autoCreate: true
```

Inject `DTRACK_API_KEY` through your shell or CI secret store, then run `rio`. The destination project name/version come from the SBOM subject. `security` is a target label you choose; `app` is Rio's artifact ID. The URL is your receiver's base URL before `/api/v1`. Omit `autoCreate` if projects are provisioned separately.

Add [pipeline context](docs/context.md) or [product metadata](docs/enrichment.md) in the same manifest. The [complete quick start](docs/quick-start.md) includes both SBOMs, their digest-bound context and full configuration from the example above. Native destinations are [Dependency-Track and OCI registries](docs/delivery.md).

## Run and inspect

```sh
rio plan --json                 # preview wiring, effective policy and routing offline
rio                             # execute the configured pipeline once
rio --manifest release.yaml --out build/evidence
rio --receipt receipts/build-42.json
rio --artifact app --target security
rio --skip-delivery             # local stages only
```

Every execution gets a fresh `target/rio/runs/<run-id>/` directory containing its `record.json`, generated SBOMs and `index.json`. The terminal and `--json` output expose the receipt path. There is no mutable `latest` file and no collection step. `--receipt` changes only the public receipt destination; its parent must exist and Rio refuses to replace a file.

```sh
rio record inspect --file receipts/build-42.json
rio record report --file receipts/build-42.json --output receipts/build-42.html
```

Inspection and rendering are offline. They never fetch receipt URLs or source paths. The HTML contains embedded styles, no scripts or remote assets, and the exact JSON digest.

## Failures stay visible

Root execution defaults to `gate: fail`: any enforced failure blocks all selected uploads. An explicit `gate.mode: warn` or `--gate warn` can continue while retaining the failed checks and effective policy. Missing inputs never cause stale outputs from a prior run to be uploaded. With no delivery targets, Rio completes local work and records delivery as not configured.

Partial delivery preserves accepted, rejected, unknown and unattempted outcomes. A lost response is not a rejection. Rio does not automatically retry to obtain a receipt. Committed local checkpoints and journals support [offline crash recovery](docs/output.md#interruption-and-recovery), including when public-receipt publication fails after a request.

Receipts are **unsigned recorded assertions and observations**. Hashes identify bytes; they do not authenticate the producer or prove what a server retained. Validation checks schema and internal consistency, and cannot detect every coherently forged unsigned receipt.

## Optional stage-by-stage work

`rio normalize` and `rio deliver` remain available for intentional separate invocations. Each has its own receipt. A standalone delivery receipt describes consuming already-normalized bytes; it does not claim the earlier normalization happened again. Explicit retry and reconciliation create new receipts referencing prior attempts. [Stage commands and exit codes](docs/cli.md).

Normalization includes spec-version leveling, product enrichment, build context and optional P2 coordinate repair. These are pipeline steps; their specialist details are in the [manifest reference](docs/manifest.md), [P2 repair guide](docs/p2-repair.md), and [supporting tools](tools/README.md). [Agent/CI integration](docs/agent-integration.md) uses the same one-command workflow.

## Project

[Architecture and development](docs/project.md) · [License](LICENSE) · [Issues](https://github.com/rebaze/rio/issues)

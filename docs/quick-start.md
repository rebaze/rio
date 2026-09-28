# One-command quick start

[See the generated receipt first](../tools/demo-client-record/example/record.json) · [Offline HTML](../tools/demo-client-record/example/report.html) · [Complete runnable ZIP](../tools/demo-client-record/example/example.zip)

Use Rio 0.7.0+ and run it after your build produces SBOMs. The example consumes ordinary CycloneDX 1.6 documents, adds a supplied build URL/ID, checks quality, and delivers once to each Dependency-Track project. All downloadable data and responses are synthetic.

## Complete inputs and context

Download [api.cdx.json](../tools/demo-client-record/example/api.cdx.json), [worker.cdx.json](../tools/demo-client-record/example/worker.cdx.json), and [pipeline.json](../tools/demo-client-record/example/pipeline.json) into one directory. The context binds each assertion to the exact input bytes:

```json
{
  "contextVersion": 1,
  "artifacts": [
    {
      "id": "api",
      "sbom": {"sha256": "1d2b04c0df452a4c2c34d84a6c195bb2805c3f208cf8f6c0bbe90ec54970dc01"},
      "build": {"url": "https://ci.example.org/runs/42", "id": "42"}
    },
    {
      "id": "worker",
      "sbom": {"sha256": "721bd8311e643571b9e6fef197a8ffb41e8ff1cbde641d1c03bdd0cba2e012ef"},
      "build": {"url": "https://ci.example.org/runs/42", "id": "42"}
    }
  ]
}
```

For your own build, use its actual SBOM digests and pipeline facts. A stale context digest is refused. [Context semantics and producer integration](context.md).

## One manifest

Save this complete configuration as `rio.yaml` and replace the receiver URL with your server's base URL, before `/api/v1`:

```yaml
version: 1
artifacts:
  - id: api
    sbom: api.cdx.json
    context:
      file: pipeline.json
      require: [build.url, build.id]
  - id: worker
    sbom: worker.cdx.json
    context:
      file: pipeline.json
      require: [build.url, build.id]
output:
  directory: target/rio
gate:
  mode: fail
  require: [name, version, purl]
delivery:
  targets:
    security:
      type: dependency-track
      url: https://dtrack.example.org
      apiKeyEnv: DTRACK_API_KEY
      autoCreate: true
```

Set `DTRACK_API_KEY` through your shell or CI secret manager, then:

```sh
rio plan --json
rio
```

The project names/versions are `api / 1.0.0` and `worker / 1.0.0`, from the normalized SBOM subjects. `autoCreate: true` permits project creation by the receiver; omit it if you provision projects separately. For a private CA, add `caFile: certs/receiver-ca.pem`; that path is manifest-relative and certificate/hostname verification stays enabled.

No server or account is needed for the [installed-binary synthetic demo](../tools/README.md#client-evidence-demos). Its supplied certificate/key are public fixture material for a loopback receiver. The downloaded capture's `rio.yaml` contains the actual temporary URL used for that capture; the included runner creates a new local receiver on every execution.

## Find and use the receipt

Rio prints the fresh run ID and receipt path. `rio --json` exposes `runDirectory` and `receipt.path` programmatically. Generated SBOMs and `index.json` are under that run directory. A typical layout is:

```text
target/rio/runs/run-<random-id>/
  record.json
  api.cdx.json
  worker.cdx.json
  index.json
  .internal/          # recovery checkpoints, not a client export
  deliveries/         # internal immutable attempt journals
```

Use the reported path:

```sh
rio record inspect --file target/rio/runs/RUN_ID/record.json
rio record report --file target/rio/runs/RUN_ID/record.json --output report.html
```

`RUN_ID` stands for the actual generated directory name. Reports and receipts refuse existing destinations. To select a public receipt path directly, first create its parent directory, then run `rio --receipt receipts/build-42.json`. This does not move the run's normalized outputs or recovery state.

Explicit flags override manifest settings; omitted flags do not. `--artifact` and `--target` select scope, `--gate warn` deliberately permits failed quality checks, and `--skip-delivery` performs only local work. With no configured targets, local work succeeds and delivery is `not-configured`. An enforced gate failure blocks every selected upload and leaves a failed receipt.

[Failure/recovery semantics](output.md#interruption-and-recovery) · [Native delivery](delivery.md) · [Optional stage commands](cli.md#stage-commands)

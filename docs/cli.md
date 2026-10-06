# Command reference

[One-command quick start](quick-start.md) · [Manifest](manifest.md) · [Receipt contract](output.md)

Rio 0.7.0 uses one invocation owner and one compact receipt. Root execution, native delivery and reconciliation may use the network. Normalize, plan, inspect, report and recovery are offline. Read-only commands do not create execution receipts.

## Install

```sh
brew install rebaze/tap/rio
```

Or install a release binary with a pinned version and chosen directory:

```sh
curl -sSL https://raw.githubusercontent.com/rebaze/rio/main/install.sh \
  | RIO_VERSION=v0.7.0 RIO_INSTALL_DIR="$HOME/.local/bin" sh
```

The installer variables belong on `sh`, after the pipe. Without them it uses the latest release and chooses a writable installation directory. Add the selected directory to `PATH`. [Platform downloads](https://github.com/rebaze/rio/releases/latest) also include Windows archives. Rio itself has no external runtime dependencies; supporting demos use Python 3.9+ where documented.

## Root execution

```text
rio [flags]
  --manifest PATH       default rio.yaml
  --out DIR             output root; flag > output.directory > target/rio
  --receipt PATH        new public receipt destination; default <runDirectory>/record.json
  --artifact ID         repeatable artifact selection; default all
  --target ID           repeatable target selection; default all
  --gate fail|warn      flag > gate.mode > fail
  --skip-delivery       local stages only
  --json                structured result with runId, outcome, runDirectory and receipt metadata
  --quiet               suppress optional progress
```

Bare `rio` runs intake, normalization/enrichment/context, schema/quality checks, then configured delivery. It does not prompt before configured uploads. No targets means successful local work with delivery `not-configured`. An enforced gate failure blocks every selected upload. A deliberate warn policy retains failed checks and the override while permitting continuation.

`--manifest`, `--out` and `--receipt` are relative to the caller's working directory. Paths inside the manifest, including `output.directory`, are relative to the manifest. Explicit flags override manifest values; omitted flags do not. A receipt override changes only the public receipt destination. Its parent must exist. Existing files, locks or unsafe collisions are refused before requests.

Each execution owns a collision-resistant `runs/<run-id>/` directory. Never infer the current run from old files or a mutable `latest` alias; use the printed path or structured result. Inputs, metadata assertions, checks, byte identities, selected/excluded scope and overrides are recorded compactly.

## `rio plan`

```sh
rio plan --json
rio plan --artifact app --target security --gate warn --out release-output
```

Plan accepts the root manifest/output/receipt/gate/artifact/target/skip settings and previews their effective values. It resolves input wiring and describes transforms without constructing them, opening SBOM/context contents, loading CA files, resolving credentials or making requests. Projects derived from normalized subjects are explicitly marked `projectSource: "normalized-subject"`; final identity is resolved during execution.

The additive `planVersion: 1` JSON contract retains `manifest`, `out`, `builtinTable`, `artifacts`, transform options and gate requirements. It also includes `runDirectory` and `receipt` templates containing `<run-id>`, effective `gate.mode`, delivery mode/targets/pairs, and compact exclusions. `artifacts[].input.path` is manifest-relative; `artifacts[].output.path` is relative to the eventual run directory. Supporting tools can keep harvesting declared inputs without requiring the transform's mapping table to exist.

Plan writes nothing and creates no run receipt. It is a preview of configured work, not evidence that checks or uploads succeeded.

## Stage commands

Use stages separately only when that is the intended workflow:

```sh
rio normalize --json --attest
rio deliver --index PATH_FROM_NORMALIZE/index.json --json
```

`normalize` supports `--manifest`, `--out`, `--receipt`, `--artifact`, `--gate`, `--attest`, `--json`, and `--quiet`. Its historical default gate policy is `warn` when neither manifest nor flags select a mode. It never delivers. Generated SBOMs, index and optional unsigned in-toto statements share its fresh run directory.

`deliver` consumes already-normalized index members, verifies their captured bytes, and produces its own receipt. It does not attribute earlier normalization/context additions to this invocation. Use explicit `--index`; its conventional default is `target/rio/index.json`, which is not the new normalization run path. Artifact/target filters are repeatable. `--allow-failed-gate` is the explicit standalone override; root's warn policy does not silently change standalone refusal.

Delivery JSON exposes the batch result and automatic receipt metadata. Its `items[].record` paths identify internal attempt journals for specialist inspection, retry and reconciliation. An explicit fresh `--record DIR` requires one selected artifact/target pair. Reusing a journal is refused.

```sh
rio delivery plan --index RUN_DIRECTORY/index.json --json
rio delivery inspect --record JOURNAL_DIRECTORY --json
rio deliver --index RUN_DIRECTORY/index.json --artifact app --target security \
  --retry-of PRIOR_JOURNAL --record FRESH_JOURNAL --json
rio delivery reconcile --record JOURNAL_DIRECTORY --json
```

`delivery plan` verifies current index members offline. `delivery inspect` reads the selected internal journal offline. Neither creates an execution receipt. Explicit retry authorizes possible duplicate delivery only when source/target/policies match and a fresh journal is selected. Reconciliation performs supported read-only receiver observations; it creates a new receipt referencing the prior attempt and includes only observations made in that invocation. Earlier public receipts stay unchanged. DTrack `--wait DURATION` may poll for up to 10 minutes; OCI content observations do not poll. Acceptance, processing activity and content verification remain distinct.

## Inspect, report and recover

```sh
rio record inspect --file record.json
rio record inspect --file record.json --json
rio record report --file record.json --output report.html
rio record recover --run INTERRUPTED_RUN_DIRECTORY --output recovered.json
```

Inspection validates the compact schema, references and internal consistency; it does not replay absent source documents or authenticate unsigned claims. Reporting uses the exact inspected JSON digest, escapes supplied text and embeds all styles. Neither follows receipt URLs or workspace paths. Existing report files are refused.

Recovery is an exceptional offline operation on explicitly selected local checkpoints/journals, not a normal assembly step. Choose a fresh output outside the recovery sources. It never uploads, resolves credentials, removes crash locks or declares an interrupted run completed. [Detailed recovery semantics](output.md#interruption-and-recovery).

The v0.6 client bundle and collection contracts are unsupported. There is no `record --index`, `--delivery-record`, `--batch`, `--schema-version`, or `deliver --evidence` mode.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Requested execution/read operation succeeded; not proof of server ingestion |
| 1 | Enforced quality gate failed; selected delivery blocked |
| 2 | Usage, configuration, input or preflight refusal |
| 3 | Internal or persistence failure; a request may already have occurred |
| 4 | Delivery outcome/observation unknown or unavailable |
| 5 | Supported receiver rejection |

Ordinary failed or partial executions still attempt to publish their receipt. Initial invalid CLI/configuration or an unwritable/occupied destination may prevent receipt creation; no request is made. After a request, a persistence error reports possible output and the run directory for local recovery. Never retry automatically merely to obtain a receipt. `record inspect` can return 0 for a structurally valid receipt describing a failed or incomplete run.

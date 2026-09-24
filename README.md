# rio

[![CI](https://github.com/rebaze/rio/actions/workflows/ci.yaml/badge.svg)](https://github.com/rebaze/rio/actions/workflows/ci.yaml)
[![Release](https://github.com/rebaze/rio/actions/workflows/release.yaml/badge.svg)](https://github.com/rebaze/rio/actions/workflows/release.yaml)
[![GitHub Release](https://img.shields.io/github/v/release/rebaze/rio)](https://github.com/rebaze/rio/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/github/go-mod/go-version/rebaze/rio)](go.mod)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/rebaze/rio/badge)](https://scorecard.dev/viewer/?uri=github.com/rebaze/rio)

**Rio normalizes CycloneDX SBOMs, delivers verified outputs, and records the evidence for both.**

Set a spec-version floor, attach product and pipeline metadata, and get normalized SBOMs plus an
`index.json` linking original inputs, output digests, the manifest and check results.

Native delivery checks that the SBOM matches that record, sends the exact verified bytes, and
keeps a separate **delivery journal**: what Rio attempted, what the destination acknowledged,
and what later checks observed. Lost responses remain visible as uncertainty, with no automatic
resubmission. Normalization stays offline; delivery uses the network explicitly. Both run in one
binary, on your workstation or in CI.

Delivery destinations include analysis platforms and artifact registries. **Dependency-Track is
implemented today; [OCI registry delivery is planned](https://github.com/rebaze/rio/issues/83).**

[Quick start](#quick-start) · [Verified delivery](#deliver-to-dependency-track) · [Configuration](#configure-your-project) · [For agents](#for-agents) · [Reference](#reference)

## When to use Rio

- **Normalize versions and check quality.** Raise older SBOMs to your chosen CycloneDX floor,
  preserve dependency membership, and check required names, versions and package URLs.
- **Keep lineage and pipeline context.** Record input/output digests and normalization details;
  attach supplied product, source, build and generator metadata with its origins and changes.
  Source/build details remain labeled as producer assertions.
- **Deliver verified SBOMs with an inspectable history.** Upload directly to Dependency-Track by
  project name/version or UUID. Retain the intended destination, payload digest, acknowledgment
  and later activity observations in a delivery journal, including unknown outcomes.
- **Cover every selected module.** Include each qualifying module's SBOM automatically, with a
  failure when a selected module has not produced its output.
- **Optionally repair Eclipse/OSGi p2 coordinates.** Convert eligible package URLs to Maven
  coordinates using explicit coordinate evidence and maintained mappings.
  [Repair reference](docs/p2-repair.md) · [Focused example](tools/README.md#first-repair-sample).

The records provide evidence for later release controls: which SBOM was processed, what changed,
which supplied build assertions belong to it, and what is known about each delivery attempt.
Rio's gate checks SBOM fields; broader
[release-rule evaluation is planned](docs/project.md#direction). SBOM generation and vulnerability
scanning remain separate steps.

### Where the evidence lives

| Record | What it captures |
|---|---|
| `index.json` | Normalization inputs, output digests, transforms and gate results |
| `<artifact>.intoto.json`, with `rio normalize --attest` | An **unsigned in-toto Statement** describing the normalization |
| The directory passed to `rio deliver --record` | Separate journal events for delivery intent, receipt when available, and later reconciliation observations |

Delivery history is not added to `index.json` or the normalization statements. These records
support traceability; they do not authenticate the producer or prove successful ingestion.
`rio delivery inspect` reads a journal offline; `rio delivery reconcile` queries the destination
and appends new observations without uploading again.

## Install

With Homebrew:

```sh
brew install rebaze/tap/rio
```

Or use the installer:

```sh
curl -sSL https://raw.githubusercontent.com/rebaze/rio/main/install.sh | sh
```

You can also [download a release binary](https://github.com/rebaze/rio/releases).
See [installation options](docs/cli.md#install) to pin a version or choose the install directory.
Documentation follows `main`; check feature prerequisites when using an older release.

## Quick start

With **Rio v0.4.0 or newer** installed, try this synthetic CycloneDX 1.5 input. It needs no project
build or account. Download the existing sample and manifest, then normalize and inspect the index:

```sh
demo_dir=$(mktemp -d "${TMPDIR:-/tmp}/rio-sample.XXXXXXXX") &&
sample_url=https://raw.githubusercontent.com/rebaze/rio/v0.4.0/tools/demo-agent-integration &&
mkdir -p "$demo_dir/desktop/target" &&
curl -fsSL "$sample_url/projects/explicit/seed.cdx.json" -o "$demo_dir/desktop/target/bom.json" &&
curl -fsSL "$sample_url/examples/explicit.yaml" -o "$demo_dir/rio.yaml" &&
rio normalize --manifest "$demo_dir/rio.yaml" --out "$demo_dir/out" --gate fail --quiet &&
cat "$demo_dir/out/index.json" &&
printf 'Inspect the input and results in: %s\n' "$demo_dir"
```

The index shows the version change (excerpt):

```json
"specVersion": {
  "input": "1.5",
  "output": "1.6"
}
```

It also records the input and output SHA-256 digests, manifest digest, tool version and `gate: "ok"`.
Compare `desktop/target/bom.json` with `out/desktop.cdx.json`: the spec version is normalized and
the dependency inventory is preserved. The original file stays unchanged.

To carry pipeline lineage alongside those records, bind a producer-supplied [context file](docs/context.md)
by artifact ID and original SBOM digest. The [context example](tools/README.md#ci-build-context-demo)
shows source/build metadata appearing in the SBOM and index; Rio does not infer it from this sample.

If `rio` is not found, use its installed path or [add its directory to PATH](docs/cli.md#install).
The [offline onboarding examples](tools/README.md#agent-integration-examples) run from a checkout.

## Deliver to Dependency-Track

Native delivery requires a Rio build with `rio deliver` available; it is not included in the
v0.4.0 sample release above. To deliver the normalized quick-start sample, save this as
`$demo_dir/delivery.yaml`, replacing the server URL and project name/version with an existing
test project:

```yaml
version: 1
destinations:
  security:
    type: dependency-track
    options:
      url: https://dtrack.example.com
      apiKeyEnv: DTRACK_API_KEY
deliveries:
  application-security:
    artifact: desktop
    destination: security
    options:
      project:
        name: acme-desktop
        version: "1.0.0"
      autoCreate: false
```

Inject `DTRACK_API_KEY` into the environment through your secret manager or CI, then upload:

```sh
rio deliver --index "$demo_dir/out/index.json" \
  --config "$demo_dir/delivery.yaml" --delivery application-security \
  --record "$demo_dir/delivery-record" --json
rio delivery inspect --record "$demo_dir/delivery-record"
```

Rio checks the recorded gate and output digest, then sends the exact verified SBOM bytes directly
by project name/version. The upload replaces that project's component inventory. Project creation
is disabled by default, and each attempt needs a new journal directory. An accepted receipt means
submission was acknowledged; it does not prove successful ingestion. The directory at
`$demo_dir/delivery-record` retains the delivery history independently of the normalized files.

Use `rio delivery plan` to preview offline and `rio delivery reconcile` to query saved receipt
activity without resubmitting. See [delivery configuration and the runnable demo](tools/README.md#native-verified-delivery)
for UUID/subject targeting, optional creation, TLS, retry behavior and the tested server version.

## Configure your project

Once the sample works, point Rio at an SBOM your own build produces. For a project with
`target/bom.json`, create or adapt `rio.yaml`:

```yaml
version: 1
artifacts:
  - id: app
    sbom: target/bom.json
```

This minimal manifest uses the default 1.6 spec floor and checks the input. Add
[enrichment](docs/enrichment.md) for supplied product metadata and [context](docs/context.md) for
producer-provided source/build assertions. Their source and change records travel with the outputs.

Preview the selection, then normalize into a fresh directory:

```sh
rio plan
out_dir=$(mktemp -d "${TMPDIR:-/tmp}/rio.XXXXXXXX")
rio normalize --out "$out_dir" --gate fail
printf 'Results: %s\n' "$out_dir"
```

You get `app.cdx.json` and `index.json`. Explicit artifact paths are relative to `rio.yaml`, and
each must resolve to exactly one SBOM. `--gate fail` returns exit **1** for failed requirements,
with results still available for inspection. Missing inputs or invalid configuration return exit
**2** with no new outputs. See [exit codes](docs/cli.md#exit-codes) and [what the gate checks](docs/manifest.md#output-version-and-gate).

Use **`artifactSets`** when a directory convention defines your deliverable modules:

```yaml
version: 1
artifactSets:
  - modules: "services/*server/pom.xml"
    sbom: "target/bom.json"
    idFrom: module-directory
```

This selects module markers first. `services/orders-server/pom.xml` produces an `orders-server`
artifact from that module's `target/bom.json`; a selected module without an SBOM fails the run.
Rio matches marker paths, not Maven artifact IDs. Explicit artifacts and sets can share a manifest.
Module discovery, enrichment and context are available in v0.4.0 and newer.

[Manifest reference](docs/manifest.md) covers exclusions, naming rules, paths, transforms and
shared settings. [Module discovery](docs/manifest.md#discovering-module-artifacts) explains the full
selection contract. [CI examples](tools/README.md#agent-integration-examples) show build → plan →
normalize → collect. Use fresh output directories: `index.json` defines the current run, while
reused directories can retain older files.

## For agents

Paste this into your project's coding-agent session:

```text
Integrate Rio into this project. Read
https://raw.githubusercontent.com/rebaze/rio/main/docs/agent-integration.md
first. Inspect our build and existing configuration, ask only about unresolved
decisions, then configure and validate Rio. Report anything still needed.
```

The [integration guide](docs/agent-integration.md) works with any harness; provide the guide and its references locally if
the agent cannot fetch them. Use `rio plan --json` to inspect resolved inputs and settings.
[AGENTS.md](AGENTS.md) is for developing Rio itself.

## Reference

Reading an extracted release archive? [Open these references on GitHub](https://github.com/rebaze/rio#reference).

<!-- Keep previously linked README fragments useful after moving the reference. -->
<a id="usage"></a><a id="rio-plan"></a><a id="the-plan-json"></a><a id="exit-codes"></a>
<a id="the-manifest"></a><a id="discovering-module-artifacts"></a>
<a id="build-and-source-context"></a><a id="walkthrough-recording"></a>
<a id="manifest-enrichment"></a><a id="existing-values-and-explicit-replacement"></a><a id="enrichment-provenance-and-compatibility"></a>
<a id="normalization-attestations"></a><a id="what-rio-writes-into-the-output-sbom"></a><a id="reading-the-repair-records"></a><a id="what-a-record-establishes"></a>
<a id="repaired-unmapped-skipped"></a>

| I want to… | Read |
|---|---|
| Look up CLI flags, exit codes or the plan JSON contract | [Commands](docs/cli.md) |
| Configure explicit artifacts or module discovery | [Manifest](docs/manifest.md) |
| Supply product and organization metadata | [Enrichment](docs/enrichment.md) |
| Attach supplied source/build context | [Context](docs/context.md) |
| Read the index, repair records or unsigned statements | [Output records](docs/output.md) |
| Deliver verified SBOMs and inspect delivery journals | [Native delivery](tools/README.md#native-verified-delivery) |
| Repair Eclipse p2 package URLs | [p2 repair](docs/p2-repair.md) |
| Run demos, prepare mapping tables or upload to DependencyTrack | [Tools and examples](tools/README.md) |
| Integrate a project with a coding agent | [Agent integration](docs/agent-integration.md) |

<a id="why-it-exists"></a><a id="the-case-it-was-built-for"></a><a id="what-works-today"></a>
<a id="direction"></a><a id="rio-and-rebaze"></a><a id="out-of-scope"></a><a id="no-network-calls"></a><a id="build-from-source"></a>

Maintained by [rebaze](https://www.rebaze.de/), licensed under [Apache-2.0](LICENSE).
[Roadmap, scope and contributing](docs/project.md) · [Report an issue](https://github.com/rebaze/rio/issues)

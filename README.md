# rio

[![CI](https://github.com/rebaze/rio/actions/workflows/ci.yaml/badge.svg)](https://github.com/rebaze/rio/actions/workflows/ci.yaml)
[![Release](https://github.com/rebaze/rio/actions/workflows/release.yaml/badge.svg)](https://github.com/rebaze/rio/actions/workflows/release.yaml)
[![GitHub Release](https://img.shields.io/github/v/release/rebaze/rio)](https://github.com/rebaze/rio/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/github/go-mod/go-version/rebaze/rio)](go.mod)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/rebaze/rio/badge)](https://scorecard.dev/viewer/?uri=github.com/rebaze/rio)

**Rio takes the CycloneDX SBOM your build writes, fixes it up, checks it, delivers it to
Dependency-Track or an OCI registry, and keeps a receipt of what happened.**

## Example

In this synthetic payments build, Rio raised the SBOM to CycloneDX 1.6, added the supplier
and security contact, checked the components, and sent it to Dependency-Track. These lines
from the Rio v0.10.0 receipt show that the synthetic receiver accepted the upload and Rio read back
the requested project tag:

```text
  spec 1.4 → 1.6
  gate=pass mode=fail schema=pass findings=0

payments-api → security (http://127.0.0.1:49853): accepted
    tags requested=["owner:payments"] state=observed
```

[Inspect the receipt](tools/demo-use-case/example/record.json) · [Delivered SBOM](tools/demo-use-case/example/payments-api.cdx.json) · [Download the HTML report](https://raw.githubusercontent.com/rebaze/rio/main/tools/demo-use-case/example/report.html) · [Full console output](tools/demo-use-case/example/output.txt)

## Get your first local receipt

With Rio installed and your build’s CycloneDX JSON at `target/bom.json`, run from the project root:

```sh
rio init --write       # create a starter rio.yaml
rio --skip-delivery    # check the SBOM locally and print the receipt path
```

Run `rio init` alone to preview the YAML. If your build writes the SBOM elsewhere, use
`rio init --sbom dist/app.cdx.json --write`. Already have a manifest? Start with `rio plan`
to review its inputs and checks. Open the printed `record.json` to see your result.

Using Rio v0.10.2? Save the [starter rio.yaml](tools/demo-first-run/rio.yaml) in your
project root and run the second command. [Install Rio](#install) · [Configure init](docs/cli.md#preview-a-starter-manifest) · [Try the synthetic example](tools/README.md#first-local-receipt)

## Add enrichment and delivery

To get the delivery receipt shown above, extend your starter manifest with the metadata
and receiver details for your project. Here is the payments example:

```yaml
version: 1
artifacts:
  - id: payments-api
    sbom: target/bom.json

enrichment:                        # what the SBOM generator doesn't know
  subject:
    supplier: {name: Example Payments GmbH}
    securityContact: mailto:security@payments.example.com
    links:
      - label: Fact sheet
        url: https://ea.example.com/factsheet/Application/payments-api

delivery:
  targets:
    security:
      type: dependency-track
      url: https://dtrack.example.com
      apiKeyEnv: DTRACK_API_KEY
      autoCreate: true
      tags: [owner:payments]       # route findings to the owning team
```

Set `DTRACK_API_KEY` via your secret manager, then run `rio` to deliver the checked SBOM.
To reproduce the example with a synthetic receiver on your machine, [run the delivery demo](tools/demo-use-case/README.md).

## Install

```sh
brew install rebaze/tap/rio
```

Or `curl -sSL https://raw.githubusercontent.com/rebaze/rio/main/install.sh | sh`, or download a
[release binary](https://github.com/rebaze/rio/releases/latest) for Linux, macOS or Windows. Rio is
a single binary with no runtime dependencies. Releases are signed, and the macOS binaries are
notarized. [More install options](docs/cli.md#install).

## Usage

| Command | What it does |
|---|---|
| `rio init` | Previews a starter manifest for an existing SBOM; `--write` saves it |
| `rio` | Runs `rio.yaml`: normalize, enrich, check, deliver, write the receipt |
| `rio plan` | Shows what `rio` would do, without doing it; `--json` for scripts and agents |
| `rio --skip-delivery` | Everything except the upload |
| `rio record inspect --file record.json` | Reads a receipt, offline |
| `rio record report --file record.json --output report.html` | Renders a receipt as one self-contained HTML page |
| `rio delivery reconcile --record DIR` | Asks the server about an earlier delivery, without uploading again |

Exit code 0 is success, 1 a failed check (nothing was delivered), 2 a configuration or input error,
and 3 to 5 a delivery that failed, was rejected or has an unknown outcome.
[All commands and exit codes](docs/cli.md).

## What Rio does

- **Normalizes.** Raises older SBOMs to CycloneDX 1.6 (or 1.5) and keeps the dependency graph intact.
- **Enriches.** Adds supplier, manufacturer, security contact, issue tracker, release notes and
  labelled links from `rio.yaml`, and build and source facts from a [context file](docs/context.md).
  Each added value records where it came from. [Enrichment](docs/enrichment.md)
- **Checks.** Refuses to deliver when a component lacks a name, version or package URL, or the SBOM
  misses what you require, such as a security contact or the
  [BSI TR-03183-2 profile](docs/manifest.md#requirement-profiles). Each failure says how to fix it.
- **Delivers.** To [Dependency-Track](docs/delivery.md#dependency-track), with project tags, parent
  and latest-version flag, or to an [OCI registry](docs/delivery.md#oci-registries), standalone or
  attached to an image. Rio sends exactly the bytes it checked.
- **Keeps a receipt.** Digests of every input and output, each change, the check results and what the
  server answered. A lost response stays recorded as unknown; Rio never retries it blindly.
  [Reading a receipt](docs/output.md)
- **Covers multi-module builds.** [`artifactSets`](docs/manifest.md#discovering-module-artifacts)
  picks up every module's SBOM and fails when one is missing.

Rio doesn't generate SBOMs or scan for vulnerabilities: it works on the SBOM your build already
produces, and it uses the network only to deliver.

## Use it with a coding agent

Paste this into your project's agent session:

```text
Integrate Rio into this project. Read
https://raw.githubusercontent.com/rebaze/rio/main/docs/agent-integration.md
first. Inspect our build and existing configuration, ask only about unresolved
decisions, then configure and validate Rio. Report anything still needed.
```

## Documentation

| I want to… | Read |
|---|---|
| Set up a first delivery, step by step | [Quick start](docs/quick-start.md) |
| Configure artifacts, module discovery, checks and output | [Manifest](docs/manifest.md) |
| Add product and organization metadata | [Enrichment](docs/enrichment.md) |
| Attach build and source facts | [Context](docs/context.md) |
| Configure Dependency-Track or OCI delivery, credentials and TLS | [Delivery](docs/delivery.md) |
| Look up commands, flags, exit codes and the plan JSON | [Commands](docs/cli.md) |
| Read a receipt, the index or the attestations | [Output records](docs/output.md) |
| Recover from an interrupted run | [Recovery](docs/recovery.md) |
| Repair Eclipse p2 package URLs | [p2 repair](docs/p2-repair.md) |
| Run the demos | [Tools and examples](tools/README.md) |
| See how Rio monitors its own dependencies | [Self-SBOM monitoring](tools/README.md#self-sbom-monitoring) |
| Integrate with a coding agent | [Agent integration](docs/agent-integration.md) |

<!-- Keep previously linked README fragments useful after the README was shortened. -->
<a id="see-what-your-client-receives"></a><a id="deliver-your-first-sbom"></a><a id="send-to-dependency-track"></a>
<a id="store-in-an-oci-registry"></a><a id="keep-the-delivery-evidence"></a><a id="when-to-use-rio"></a>
<a id="where-the-evidence-lives"></a><a id="quick-start"></a><a id="deliver-to-dependency-track"></a>
<a id="deliver-to-an-oci-registry"></a><a id="one-evidence-record"></a><a id="configure-your-project"></a>
<a id="for-agents"></a><a id="reference"></a>
<a id="rio-plan"></a><a id="the-plan-json"></a><a id="exit-codes"></a>
<a id="the-manifest"></a><a id="discovering-module-artifacts"></a>
<a id="build-and-source-context"></a>
<a id="manifest-enrichment"></a><a id="existing-values-and-explicit-replacement"></a><a id="enrichment-provenance-and-compatibility"></a>
<a id="normalization-attestations"></a><a id="what-rio-writes-into-the-output-sbom"></a><a id="reading-the-repair-records"></a><a id="what-a-record-establishes"></a>
<a id="repaired-unmapped-skipped"></a>
<a id="why-it-exists"></a><a id="the-case-it-was-built-for"></a><a id="what-works-today"></a>
<a id="direction"></a><a id="rio-and-rebaze"></a><a id="out-of-scope"></a><a id="no-network-calls"></a><a id="build-from-source"></a>

Maintained by [rebaze](https://www.rebaze.de/), licensed under [Apache-2.0](LICENSE).
[Roadmap, scope and contributing](docs/project.md) · [Report an issue](https://github.com/rebaze/rio/issues)

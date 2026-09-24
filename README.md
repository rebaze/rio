# rio

[![CI](https://github.com/rebaze/rio/actions/workflows/ci.yaml/badge.svg)](https://github.com/rebaze/rio/actions/workflows/ci.yaml)
[![Release](https://github.com/rebaze/rio/actions/workflows/release.yaml/badge.svg)](https://github.com/rebaze/rio/actions/workflows/release.yaml)
[![GitHub Release](https://img.shields.io/github/v/release/rebaze/rio)](https://github.com/rebaze/rio/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/github/go-mod/go-version/rebaze/rio)](go.mod)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/rebaze/rio/badge)](https://scorecard.dev/viewer/?uri=github.com/rebaze/rio)

**Rio normalizes and checks the CycloneDX SBOMs your build produces.**

Give it a `rio.yaml` and local SBOM files. It writes one normalized SBOM per artifact and an
`index.json` with hashes and check results. Rio runs offline as a single binary,
on your workstation or in CI.

For example, the built-in mapping repairs this package URL and records the original:

```text
pkg:p2/com.google.gson@2.8.9?classifier=osgi.bundle
  → pkg:maven/com.google.code.gson/gson@2.8.9
```

[Quick start](#quick-start) · [Configuration](#configure-your-project) · [For agents](#for-agents) · [Reference](#reference)

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

With Rio installed, try this **synthetic sample**. No project build, account or custom mapping table
is needed. These commands download two sample files; Rio's processing is offline.

```sh
demo_dir=$(mktemp -d "${TMPDIR:-/tmp}/rio-sample.XXXXXXXX") &&
sample_url=https://raw.githubusercontent.com/rebaze/rio/main/tools/demo-repair &&
curl -fsSL "$sample_url/bom.json" -o "$demo_dir/bom.json" &&
curl -fsSL "$sample_url/rio.yaml" -o "$demo_dir/rio.yaml" &&
rio normalize --manifest "$demo_dir/rio.yaml" --out "$demo_dir/out" --gate fail &&
sed -n '/"purl":/p' "$demo_dir/out/sample.cdx.json" &&
printf 'Inspect the input and results in: %s\n' "$demo_dir"
```

Expected output from v0.3.0:

```text
sample  1 components   repaired 1    unmapped 0    gate ok
1 artifact, no gate failures
      "purl": "pkg:maven/com.google.code.gson/gson@2.8.9",
```

Compare `bom.json` with `out/sample.cdx.json`: Gson now has the Maven URL shown above, and the
repair record preserves the before/after values. The input is unchanged. `out/index.json` records
file hashes and the result. The sample demonstrates coordinate repair, not vulnerability scanning.

If `rio` is not found, use its installed path or [add its directory to PATH](docs/cli.md#install).
For an offline run from a checkout, use the [sample runner](tools/README.md#first-repair-sample).

## When to use Rio

- Your Eclipse/Tycho SBOMs need p2 package URLs repaired to Maven coordinates.
- You want a consistent CycloneDX version and checks for missing names, versions or package URLs.
- You need to supply product metadata or bind explicit build context while recording changes.
- You want every qualifying module's SBOM included, with a failure when a selected module's output is missing.

Rio fits between your SBOM generator and downstream tools such as DependencyTrack. SBOM generation
and vulnerability scanning remain separate steps. Each input inventory stays separate, and its
component membership is preserved.

## Configure your project

Once the sample works, point Rio at an SBOM your own build produces. For a project with
`target/bom.json`, create or adapt `rio.yaml`:

```yaml
version: 1
artifacts:
  - id: app
    sbom: target/bom.json
```

This minimal manifest normalizes and checks the input. To apply the demonstrated p2 repair,
keep the sample's `transforms` block too; see [p2 repair](docs/p2-repair.md). Ordinary Maven
package URLs do not need that transform.

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
Module discovery requires an `artifactSets`-capable release; it is not available in v0.3.0.

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
| Repair Eclipse p2 package URLs | [p2 repair](docs/p2-repair.md) |
| Supply product and organization metadata | [Enrichment](docs/enrichment.md) |
| Attach supplied source/build context | [Context](docs/context.md) |
| Read the index, repair records or unsigned statements | [Output records](docs/output.md) |
| Run demos, prepare mapping tables or upload to DependencyTrack | [Tools and examples](tools/README.md) |
| Integrate a project with a coding agent | [Agent integration](docs/agent-integration.md) |

<a id="why-it-exists"></a><a id="the-case-it-was-built-for"></a><a id="what-works-today"></a>
<a id="direction"></a><a id="rio-and-rebaze"></a><a id="out-of-scope"></a><a id="no-network-calls"></a><a id="build-from-source"></a>

Maintained by [rebaze](https://www.rebaze.de/), licensed under [Apache-2.0](LICENSE).
[Roadmap, scope and contributing](docs/project.md) · [Report an issue](https://github.com/rebaze/rio/issues)

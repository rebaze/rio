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
implemented on `main`; [OCI registry delivery is in review](https://github.com/rebaze/rio/issues/83).**

[First delivery](#deliver-your-first-sbom) · [Try without a server](#quick-start) · [Verified delivery](#deliver-to-dependency-track) · [OCI registries](#deliver-to-an-oci-registry) · [One evidence record](#one-evidence-record) · [Configuration](#configure-your-project) · [For agents](#for-agents) · [Reference](#reference)

## Deliver your first SBOM

Already generating `target/bom.json`? Choose one destination below, save its configuration as
**`rio.yaml`**, and deliver the normalized SBOM in two commands. Intake and delivery share this one file.
No server yet? Start with the [released, account-free normalization example](#quick-start).

**Availability:** these delivery examples are unreleased. Dependency-Track delivery and `rio record`
are merged on `main`; OCI delivery is implemented in [#83](https://github.com/rebaze/rio/issues/83)
and awaiting review/integration. The latest release, v0.4.0, supports the normalization quick start
but does not contain these delivery or record commands. Use a build containing the chosen feature.

With either configuration below:

```sh
rio normalize --gate fail && rio deliver
```

### Send to Dependency-Track

Here is a complete local layout for macOS/Linux. Commit `rio.yaml` and include `target/` in your
`.gitignore`; keep the API key outside the project:

```text
~/.config/rio/dtrack.env          # private local credential file

my-app/                         # run Rio from this directory
├── rio.yaml                    # configuration below
├── .gitignore                  # includes target/
├── certs/dtrack-ca.pem          # optional public company CA certificate
└── target/
    ├── bom.json                # CycloneDX SBOM produced by your build
    └── rio/                    # Rio creates this output directory
        ├── app.cdx.json        # normalized SBOM
        ├── index.json         # normalization evidence
        ├── deliveries/<hash>/ # automatic delivery journal
        └── record.json        # created by rio record below
```

Save this as `my-app/rio.yaml`:

```yaml
version: 1
artifacts:
  - id: app
    sbom: target/bom.json
delivery:
  targets:
    security:                   # a target name you choose
      type: dependency-track
      url: https://dtrack.example.com
      apiKeyEnv: DTRACK_API_KEY  # environment variable name, never the key itself
      autoCreate: true
```

**`security` is a local target label.** You could name it `company-dtrack` instead. It appears in
`rio delivery plan`, in the `--target security` filter, and as `destinationName` in journal evidence.
The journal directory uses a generated hash. The API key determines access rights; the
Dependency-Track project name/version come from the SBOM's subject. Separately, `app` is Rio's
artifact ID and names the output `app.cdx.json`.

Replace the URL with your server. Create a private directory for local credentials:

```sh
mkdir -p "$HOME/.config/rio"
chmod 700 "$HOME/.config/rio"
```

Using your editor, save `~/.config/rio/dtrack.env` with this content:

```sh
export DTRACK_API_KEY='replace-with-your-dependency-track-api-key'
```

Restrict that private file to your account, then load it and run from `my-app`:

```sh
chmod 600 "$HOME/.config/rio/dtrack.env"
. "$HOME/.config/rio/dtrack.env"
rio normalize --gate fail && rio deliver
```

Your shell loads the credential into Rio's environment; Rio does not automatically read this file.
For CI, store the value in a CI secret named `DTRACK_API_KEY` and inject it as an environment variable.
Rio retains the variable name in evidence, never the API-key value.

For an internal CA, obtain its public certificate from your administrator, save it as
`certs/dtrack-ca.pem`, and add `caFile: certs/dtrack-ca.pem` under `security`. The path is relative to
`rio.yaml`; certificate and hostname verification remain enabled. This is the preferred option.
The unreleased [#83 candidate](https://github.com/rebaze/rio/issues/83) also implements
`insecureSkipVerify: true` under `security` for explicitly skipping certificate-chain and hostname
verification. It requires HTTPS and cannot be combined with `caFile`. The choice is saved in the
journal and portable record alongside observed TLS facts; it does not imply the certificate was
invalid. Protocol failures still fail, with no fallback or automatic replay. This option is awaiting
review/integration and is not in v0.4.0. [TLS policy and synthetic demo](tools/README.md#native-verified-delivery).

This example explicitly enables project creation; omit `autoCreate` when you provision projects
yourself. [Permissions and options](tools/README.md#native-verified-delivery).

### Store in an OCI registry — preview

Use this alternative `rio.yaml` to retain the same SBOM in a writable OCI repository:

```yaml
version: 1
artifacts:
  - id: app
    sbom: target/bom.json
delivery:
  targets:
    release-registry:           # another target name you choose
      type: oci
      registry: registry.example.com
      repository: acme/app-sbom
      auth:
        usernameEnv: OCI_USERNAME
        passwordEnv: OCI_PASSWORD
```

Set the registry host and repository. `release-registry` is the label used by
`--target release-registry`; the inner `registry` field is the server address.
For local use, put these assignments in a separate private `~/.config/rio/registry.env`:

```sh
export OCI_USERNAME='replace-with-your-registry-user'
export OCI_PASSWORD='replace-with-your-registry-password-or-token'
```

Apply the same private-file permissions, then load it with `. "$HOME/.config/rio/registry.env"`
before running Rio. In CI, inject the two variables from CI secrets.
This publishes a **standalone SBOM** and returns an immutable manifest reference. To attach it to
an existing image or image index, use that image's repository and add its exact `subject` descriptor
(`digest`, `mediaType`, `size`); Rio leaves the image unchanged and requires Referrers API support.
[Attachment configuration and current registry scope](tools/README.md#oci-registry-delivery).

### Keep the delivery evidence

You get normalized bytes, their digest, the receiver's acknowledgment, and an automatic journal path.
To preview destinations before sending, run `rio delivery plan`. To use both destinations, put both
target entries under `delivery.targets`; plain `rio deliver` sends every indexed artifact to each target.

Replace `JOURNAL_PATH` with the path printed by `rio deliver` to produce one portable evidence file:

```sh
rio record --delivery-record JOURNAL_PATH --output target/rio/record.json
rio record inspect --file target/rio/record.json
```

The recipient can inspect `record.json` without your workspace or credentials.
[What the record establishes](docs/output.md#consolidated-recordjson-v1).

## When to use Rio

- **Normalize versions and check quality.** Raise older SBOMs to your chosen CycloneDX floor,
  preserve dependency membership, and check required names, versions and package URLs.
- **Keep lineage and pipeline context.** Record input/output digests and normalization details;
  attach supplied product, source, build and generator metadata with its origins and changes.
  Source/build details remain labeled as producer assertions.
- **Deliver verified SBOMs with an inspectable history.** Upload directly to Dependency-Track by
  project name/version or UUID. Retain the intended destination, payload digest, acknowledgment
  and later activity observations in a delivery journal, including unknown outcomes. Publish unchanged
  SBOM bytes to OCI registries with immutable manifest references and independent read-back evidence.
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
| `record.json` (explicit `rio record`) | Complete index and selected committed delivery events, exact source bytes, readable facts and coverage |
| `target/rio/deliveries/<pair-key>/`, or an explicit `--record` directory | Separate journal events for delivery intent, receipt when available, and later reconciliation observations |

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
v0.4.0 sample release above. Add targets to the existing `rio.yaml`:

```yaml
delivery:
  targets:
    security:
      type: dependency-track
      url: https://dtrack.example.com
```

Inject `DTRACK_API_KEY` through your secret manager or CI, then run the normal pipeline:

```sh
rio normalize --gate fail
rio delivery plan
rio deliver
```

Every indexed artifact goes to every eligible target, using its verified SBOM subject name and
version as the Dependency-Track project. Project creation is disabled by default; opt in with
`autoCreate: true` on the target. Rio refuses duplicate project routing and preflights the complete
batch before uploading. Each attempt receives an automatic journal under `target/rio/deliveries/`.
An unchanged rerun refuses existing journals. An accepted receipt acknowledges submission only;
it does not prove ingestion. A partially completed batch retains each attempt independently.

For the quick-start sample's custom output location, use
`rio deliver --manifest "$demo_dir/rio.yaml" --index "$demo_dir/out/index.json"`.
Changing only delivery settings after normalization is supported; the index retains its original
manifest digest, while each delivery records the current manifest digest.

Use the reported journal path with `rio delivery inspect --record PATH` or
`rio delivery reconcile --record PATH` to query saved receipt activity without resubmitting.
See [delivery configuration and the runnable demo](tools/README.md#native-verified-delivery)
for filters, overrides, UUID selectors, deliberate retries, and tested server versions.

## Deliver to an OCI registry

With a build that includes OCI delivery, add a registry target to the same `rio.yaml`:

```yaml
delivery:
  targets:
    release-registry:
      type: oci
      registry: registry.example.com
      repository: acme/application-sbom
      auth:
        usernameEnv: OCI_USERNAME
        passwordEnv: OCI_PASSWORD
```

Inject the named credentials through your secret manager, normalize, then preview or deliver:

```sh
rio normalize --gate fail
rio delivery plan --target release-registry --json
rio deliver --target release-registry --json
```

Rio uploads the exact verified CycloneDX bytes with a deterministic OCI manifest. It reports a
consumer reference such as `registry.example.com/acme/application-sbom@sha256:<manifest-digest>`
and uses the generated tag `rio-sbom-sha256-<manifest-digest>`. A valid persisted receipt is exit 0;
normal publication does not claim that a later read-back has already succeeded.

To attach the SBOM to an existing image, use **that image's repository** and add its exact
`subject` descriptor to the target. This example is illustrative; replace all descriptor values
with those from your image-producing pipeline:

```yaml
repository: acme/application
subject:
  digest: sha256:1111111111111111111111111111111111111111111111111111111111111111
  mediaType: application/vnd.oci.image.manifest.v1+json
  size: 527
```

Rio verifies that subject before writing and requires the OCI Referrers API for attachment.
Choose the image index or a specific platform manifest explicitly. The **SBOM blob digest**,
**Rio wrapper manifest digest**, and **subject image digest** are different identities. Attachment
does not change the subject, prove executable-to-SBOM correspondence, or trigger security analysis.

Use the reported journal with `rio delivery reconcile --record PATH` for a bounded read-only
content/discovery check. Reconciliation needs no original SBOM or index files. After a lost response
it can report `verification: verified` while the historical acknowledgment remains `unknown`.
`rio delivery inspect` and `rio record` remain offline. Server tag immutability and retention policy
matter: generated tags avoid human release aliases but are not an atomic protection against racing
external writers. See [OCI configuration, recovery, demos and tested registry scope](tools/README.md#native-oci-delivery).

## One evidence record

With a build containing `rio record` (not v0.4.0), collect current evidence from an index and explicitly
selected delivery attempts. Replace `JOURNAL_PATH` with the path printed by `rio deliver`:

```sh
rio record --delivery-record JOURNAL_PATH --output record.json
rio record inspect --file record.json
```

Both commands are offline. The file retains the complete index, original committed event bytes,
readable delivery facts and explicit coverage; inspection works after the source workspace is gone.
New observations need a new output path. This checks evidence consistency, without authenticating
producers, checking external SBOM bytes, or proving ingestion. Signing and full file retention are
separate. See the [record schema](docs/output.md#consolidated-recordjson-v1) and
[installed-binary demo](tools/README.md#consolidated-record-demo).

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

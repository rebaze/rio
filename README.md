# rio

[![CI](https://github.com/rebaze/rio/actions/workflows/ci.yaml/badge.svg)](https://github.com/rebaze/rio/actions/workflows/ci.yaml)
[![Release](https://github.com/rebaze/rio/actions/workflows/release.yaml/badge.svg)](https://github.com/rebaze/rio/actions/workflows/release.yaml)
[![GitHub Release](https://img.shields.io/github/v/release/rebaze/rio)](https://github.com/rebaze/rio/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/github/go-mod/go-version/rebaze/rio)](go.mod)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/rebaze/rio/badge)](https://scorecard.dev/viewer/?uri=github.com/rebaze/rio)

**Rio normalizes CycloneDX SBOMs, delivers verified outputs, and records the evidence for both.**

## See what your client receives

**Two SBOMs consumed → pipeline evidence added → delivered to Dependency-Track → receipts retained.**

Here is a JSON excerpt from the actual Rio v0.7.0 record, produced with a synthetic HTTPS receiver
speaking the Dependency-Track upload API. This shows the `api` artifact; the second artifact,
checks and run details are omitted here. Values and full digests match the complete file.

```json
{
  "kind": "rio-run-receipt",
  "schemaVersion": 1,
  "rioVersion": "0.7.0",
  "run": {
    "operation": "pipeline",
    "outcome": "success"
  },
  "artifacts": [
    {
      "id": "api",
      "input": {
        "path": "api.cdx.json",
        "sha256": "1d2b04c0df452a4c2c34d84a6c195bb2805c3f208cf8f6c0bbe90ec54970dc01",
        "size": 376
      },
      "output": {
        "path": "api.cdx.json",
        "sha256": "55e46a63a8b30ad6082b6c35dd43f0e5bc65d5cdd5ecd91126c09d0327f3d3e4",
        "size": 2307
      },
      "changes": {
        "metadata": [
          {
            "field": "build.id",
            "operation": "add",
            "before": null,
            "after": "42",
            "assertion": "producer",
            "source": "context-file"
          },
          {
            "field": "build.url",
            "operation": "add",
            "before": null,
            "after": "https://ci.example.org/runs/42",
            "assertion": "producer",
            "source": "context-file"
          }
        ]
      }
    }
  ],
  "targets": {
    "security": {
      "type": "dependency-track",
      "url": "https://127.0.0.1:53946"
    }
  },
  "deliveries": [
    {
      "artifactId": "api",
      "target": "security",
      "project": {
        "name": "api",
        "version": "1.0.0"
      },
      "submitted": [
        {
          "artifactOutput": "api",
          "mediaType": "application/vnd.cyclonedx+json",
          "role": "sbom"
        }
      ],
      "transport": {
        "scheme": "https",
        "tlsObserved": true,
        "certificateVerification": "enforced"
      },
      "responses": [
        {
          "tlsObserved": true,
          "kind": "acknowledgment",
          "value": "accepted",
          "httpStatus": 200,
          "observedAt": "2026-09-27T23:54:37.014772Z",
          "code": "accepted",
          "references": [
            {
              "kind": "dependency-track:event-token",
              "value": "11111111-1111-4111-8111-111111111111"
            }
          ]
        }
      ]
    }
  ]
}
```

**[Read the full record.json — 5,791 bytes](tools/demo-client-record/example/record.json)** ·
**[Download the HTML report](https://raw.githubusercontent.com/rebaze/rio/main/tools/demo-client-record/example/report.html)** (open locally) ·
[Download the runnable example](https://raw.githubusercontent.com/rebaze/rio/main/tools/demo-client-record/example/example.zip) ·
[Reproduce this example](tools/demo-client-record/example/README.md)

The URL is the **destination server**, not the Dependency-Track project website. This demo used a
local receiver; your record contains your configured instance URL, such as `https://dtrack.example.org`.
It also retains the original and delivered SBOM digests, exact payload sizes, project identities,
and response timestamps. Pipeline values are supplied by your build; HTTP 200 records acceptance,
not proof of ingestion.

With intake, [pipeline context](docs/context.md), and delivery configured in `rio.yaml`:

```sh
rio --receipt record.json
rio record inspect --file record.json
rio record report --file record.json --output report.html
```

Set a spec-version floor, attach product and pipeline metadata, and get normalized SBOMs plus an
`index.json` linking original inputs, output digests, the manifest and check results.

Native delivery checks that the SBOM matches that record, sends the exact verified bytes, and
keeps a separate **delivery journal**: what Rio attempted, what the destination acknowledged,
and what later checks observed. Lost responses remain visible as uncertainty, with no automatic
resubmission. Normalization stays offline; delivery uses the network explicitly. Both run in one
binary, on your workstation or in CI.

Delivery destinations include **Dependency-Track** and **OCI artifact registries**, with separate
delivery acknowledgments, transport facts and content verification.

[First delivery](#deliver-your-first-sbom) · [Try without a server](#quick-start) · [Verified delivery](#deliver-to-dependency-track) · [OCI registries](#deliver-to-an-oci-registry) · [One evidence record](#one-evidence-record) · [Configuration](#configure-your-project) · [For agents](#for-agents) · [Reference](#reference)

## Deliver your first SBOM

Already generating `target/bom.json`? Choose one destination below, save its configuration as
**`rio.yaml`**, and run `rio` to normalize and deliver the SBOM. Intake and delivery share this one file.
No server yet? Start with the [released, account-free normalization example](#quick-start).

**Availability:** use Rio **v0.7.0 or newer** for the one-command pipeline and compact receipts.

With either configuration below:

```sh
rio
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
        └── runs/<run-id>/     # fresh directory for each invocation
            ├── app.cdx.json   # normalized SBOM
            ├── index.json    # normalization evidence
            ├── deliveries/   # internal delivery journals
            └── record.json   # automatic compact receipt
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
`rio plan`, in the `--target security` filter, and as `destinationName` in journal evidence.
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
rio
```

Your shell loads the credential into Rio's environment; Rio does not automatically read this file.
For CI, store the value in a CI secret named `DTRACK_API_KEY` and inject it as an environment variable.
Rio retains the variable name in evidence, never the API-key value.

For an internal CA, obtain its public certificate from your administrator, save it as
`certs/dtrack-ca.pem`, and add `caFile: certs/dtrack-ca.pem` under `security`. The path is relative to
`rio.yaml`; certificate and hostname verification remain enabled. This is the preferred option.
Rio v0.5.0 also provides
`insecureSkipVerify: true` under `security` for explicitly skipping certificate-chain and hostname
verification. It requires HTTPS and cannot be combined with `caFile`. The choice is saved in the
journal and portable record alongside observed TLS facts; it does not imply the certificate was
invalid. Protocol failures still fail, with no fallback or automatic replay.
[TLS policy and synthetic demo](tools/README.md#native-verified-delivery).

This example explicitly enables project creation; omit `autoCreate` when you provision projects
yourself. [Permissions and options](tools/README.md#native-verified-delivery).

### Store in an OCI registry

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
[Attachment configuration and current registry scope](tools/README.md#native-oci-delivery).

### Keep the delivery evidence

You get normalized bytes, their digest, the receiver's acknowledgment, and an automatic compact
receipt. To preview destinations before sending, run `rio plan`. To use both destinations, put both
target entries under `delivery.targets`; plain `rio` sends each selected artifact to every eligible target.

Each invocation writes its receipt under `target/rio/runs/<run-id>/record.json` and prints its path.
To choose a public receipt path instead, use a fresh filename:

```sh
rio --receipt record.json
rio record inspect --file record.json
rio record report --file record.json --output report.html
```

The receipt retains scope, meaningful changes, effective checks, selected attempts and missing-evidence
gaps. Ordinary failures also retain a receipt; an enforced gate failure blocks delivery. Its parent
must exist, and Rio refuses to overwrite an existing receipt. See the [client evidence workflow](docs/cli.md#inspect-report-and-recover) and
[installed-binary examples](tools/README.md#client-evidence-demos), including a complete client handoff.

The recipient can inspect `record.json` without your workspace or credentials, or read the optional
self-contained HTML report. Keep the JSON alongside the report for machine inspection.
[What the record establishes](docs/output.md).

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
| `record.json` (automatic for each invocation) | Compact input/output identities, meaningful changes, checks, delivery facts and coverage |
| `<run-directory>/deliveries/<pair-key>/`, or an explicit `--record` directory | Separate journal events for delivery intent, receipt when available, and later reconciliation observations |

Optional [signing and recipient verification](tools/README.md#signing-and-verifying-normalization-attestations)
adds a per-artifact bundle outside Rio, using a local key with public-log upload disabled.

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

Testing a fix on Linux? [Build and download a temporary test binary](tools/README.md#temporary-linux-test-binaries)
from GitHub Actions, including a runnable example, without creating a release.

## Quick start

With **Rio v0.7.0 or newer** installed, try this synthetic CycloneDX 1.5 input. It needs no project
build or account. Download the existing sample and manifest, then normalize and inspect the receipt:

```sh
demo_dir=$(mktemp -d "${TMPDIR:-/tmp}/rio-sample.XXXXXXXX") &&
sample_url=https://raw.githubusercontent.com/rebaze/rio/v0.4.0/tools/demo-agent-integration &&
mkdir -p "$demo_dir/desktop/target" &&
curl -fsSL "$sample_url/projects/explicit/seed.cdx.json" -o "$demo_dir/desktop/target/bom.json" &&
curl -fsSL "$sample_url/examples/explicit.yaml" -o "$demo_dir/rio.yaml" &&
rio normalize --manifest "$demo_dir/rio.yaml" --out "$demo_dir/out" --gate fail --receipt "$demo_dir/record.json" &&
rio record inspect --file "$demo_dir/record.json" &&
printf 'Inspect the input and results in: %s\n' "$demo_dir"
```

The `index.json` in the printed run directory shows the version change (excerpt):

```json
"specVersion": {
  "input": "1.5",
  "output": "1.6"
}
```

It also records the input and output SHA-256 digests, manifest digest, tool version and `gate: "ok"`.
Compare `desktop/target/bom.json` with `out/runs/<run-id>/desktop.cdx.json`: the spec version is normalized and
the dependency inventory is preserved. The original file stays unchanged.

To carry pipeline lineage alongside those records, bind a producer-supplied [context file](docs/context.md)
by artifact ID and original SBOM digest. The [context example](tools/README.md#ci-build-context-demo)
shows source/build metadata appearing in the SBOM and index; Rio does not infer it from this sample.

If `rio` is not found, use its installed path or [add its directory to PATH](docs/cli.md#install).
The [offline onboarding examples](tools/README.md#agent-integration-examples) run from a checkout.

## Deliver to Dependency-Track

Add targets to the existing `rio.yaml` to include native delivery in the pipeline:

```yaml
delivery:
  targets:
    security:
      type: dependency-track
      url: https://dtrack.example.com
```

Inject `DTRACK_API_KEY` through your secret manager or CI, then run the normal pipeline:

```sh
rio plan
rio
```

Every selected artifact goes to every eligible target, using its verified SBOM subject name and
version as the Dependency-Track project. Project creation is disabled by default; opt in with
`autoCreate: true` on the target. Rio refuses duplicate project routing and preflights the complete
batch before uploading. Each attempt receives an automatic journal under the current run directory.
A standalone `rio deliver --index PATH` refuses to reuse existing journals for that indexed output.
A new root `rio` invocation creates new outputs and may upload them again. An accepted receipt acknowledges submission only;
it does not prove ingestion. A partially completed batch retains each attempt independently.

For the quick-start sample's custom output location, use
`rio deliver --manifest "$demo_dir/rio.yaml" --index "$demo_dir/out/runs/RUN_ID/index.json"`,
replacing `RUN_ID` with the run printed by normalization.
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

Inject the named credentials through your secret manager, then preview and run the pipeline:

```sh
rio plan --target release-registry --json
rio --target release-registry --json
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
`rio delivery inspect` and `rio record inspect` remain offline. Server tag immutability and retention policy
matter: generated tags avoid human release aliases but are not an atomic protection against racing
external writers. See [OCI configuration, recovery, demos and tested registry scope](tools/README.md#native-oci-delivery).

## One evidence record

Each invocation automatically produces one compact receipt for the work it performed. With your
pipeline configured, choose a fresh public filename and inspect it offline:

```sh
rio --receipt record.json
rio record inspect --file record.json
```

The receipt records byte identities, meaningful metadata changes, checks and delivery observations;
it does not embed indexes, journals or SBOM inventories. Inspection works after the source workspace
is gone. Separate `rio normalize`, `rio deliver` and reconciliation invocations have their own
receipts; retries and reconciliation link to prior attempts rather than copying their history.

Inspection checks internal consistency, without authenticating producers, fetching external SBOM
bytes, or proving ingestion. See the [receipt field guide and recovery instructions](docs/output.md)
and [installed-binary demo](tools/README.md#consolidated-record-demo).

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

You get `app.cdx.json`, `index.json` and `record.json` in the printed run directory. Explicit artifact paths are relative to `rio.yaml`, and
each must resolve to exactly one SBOM. `--gate fail` returns exit **1** for failed requirements,
with results still available for inspection. Missing inputs or invalid configuration return exit
**2**; ordinary failures still retain a failed receipt. See [exit codes](docs/cli.md#exit-codes) and [what the gate checks](docs/manifest.md#output-version-and-gate).

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
run → inspect. Each invocation gets a fresh run directory; `index.json` defines that run's outputs.

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

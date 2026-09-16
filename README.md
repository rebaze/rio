# rio

[![CI](https://github.com/rebaze/rio/actions/workflows/ci.yaml/badge.svg)](https://github.com/rebaze/rio/actions/workflows/ci.yaml)
[![Release](https://github.com/rebaze/rio/actions/workflows/release.yaml/badge.svg)](https://github.com/rebaze/rio/actions/workflows/release.yaml)
[![GitHub Release](https://img.shields.io/github/v/release/rebaze/rio)](https://github.com/rebaze/rio/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/github/go-mod/go-version/rebaze/rio)](go.mod)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/rebaze/rio/badge)](https://scorecard.dev/viewer/?uri=github.com/rebaze/rio)

rio is an open-source evidence compiler for software delivery. It turns supported engineering
inputs into structured, customer-owned records with explicit checks, sources and gaps.

The goal is to make check results useful for release decisions: which exact artifact was checked,
which requirements the results cover, and what remains missing or needs an authorized exception.
rio compiles the supported evidence; the surrounding release process enforces the release rules.

Today, rio compiles **SBOM normalization records**: it reads local CycloneDX SBOMs, applies
manifest-defined transformations, checks declared requirements, and writes normalized documents
plus an `index.json`. A pipeline or engineer can inspect what changed, identify gaps, and hand the
SBOMs to a downstream tool such as DependencyTrack.

## Why it exists

Coding agents increase the volume of changes, while teams still need to decide what can ship.
A green pipeline can leave important questions unanswered: did every required check run, do its
results belong to the artifact being released, and is an earlier exception still applicable?

For example, tests may pass for artifact A and a later rebuild produce artifact B from the same
source revision. The result for A does not establish that B was tested. A useful release record
must preserve that distinction and expose the missing evidence. This is a target workflow, not a
capability of today's SBOM normalization command.

rio starts by making evidence preparation repeatable. A manifest committed next to the code
declares the inputs and requirements. Explicit rules transform supported evidence into inspectable
records that remain usable after the pipeline run ends. Humans can follow the sources; agents and
downstream tools can consume the same structured facts. Missing information stays visible.

The starting point is practical: SBOMs arrive at different spec versions, describe build modules
instead of intended subjects, or carry package identities downstream tools cannot resolve. rio
normalizes those documents and records its changes and unresolved mappings. It runs in
customer-controlled infrastructure as a single static binary with no network calls.

### The case it was built for

In an Eclipse RCP workflow, p2 package identities prevented DependencyTrack from matching
components to vulnerability findings. Normalizing those identities to Maven coordinates made
findings visible in the downstream system.

For example, rio can rewrite `pkg:p2/com.google.gson@2.8.9.v20220111-1409` to
`pkg:maven/com.google.code.gson/gson@2.8.9` using its mapping rules. The original identity and
rewrite remain recorded in the output. This makes the SBOM more useful for downstream matching;
it does not independently prove that the component is equivalent to the Maven artifact. The
absence of scanner findings does not establish that a component is safe.

## What works today

`rio normalize`:

- **Levels the spec version.** Documents below the configured floor are uplifted to it. Documents
  at or above the floor keep their spec version; other configured processing still applies.
- **Repairs package identities.** Supported p2 and synthetic Maven purls are rewritten using
  supplied coordinates or an embedded, extendable mapping table. Applicable Eclipse version
  qualifiers are preserved as properties when removed from purl versions.
- **Enriches subject and SBOM metadata.** Shared manifest defaults and artifact-specific values
  describe the product, manufacturer, supplier, SBOM producer, contacts and SBOM data license.
  Differing existing values require explicit field replacement; every change records its source.
- **Checks declared SBOM requirements.** The gate checks subject name and version, and the
  configured component fields: name, version and parseable purl. Gate failures are recorded;
  `--gate` controls whether they also cause a nonzero exit.
- **Records the run.** Normalized SBOMs carry repairs and unresolved mappings. `index.json`
  records input and output digests, tool version, manifest reference, transform counts, schema
  validation status and findings. `--attest` also emits an unsigned statement per normalized SBOM.

`rio plan` describes the inputs, outputs and resolved transform configuration without normalizing
anything. Both commands run offline. The command and format documentation below describes current
behavior; [issue #4](https://github.com/rebaze/rio/issues/4) is the historical v1 implementation spec.

### What a record establishes

A consumer can check an output file against its recorded digest, inspect the reported gate result,
and see repairs and gaps. A structurally valid record can report failed checks. The gate covers
SBOM fields, not software acceptance, vulnerability absence or compliance. rio does not add missing
components or scan for vulnerabilities; a passing gate does not establish SBOM completeness.

Unmapped components and dangling dependency references can coexist with `gate: "ok"`. A schema
version beyond the embedded schemas produces `schemaValidated: false`, even if the gate passes.
Missing or invalid inputs stop compilation with exit 2 and produce no new record.

The attestation subject is the normalized SBOM, not a built binary or deployment. Source assertions
and mapping entries are inputs to normalization, not independently verified facts. Retain the
original SBOM, manifest and any external mapping table alongside the outputs if later inspection
or reproduction is required; rio does not package those inputs automatically. The index references
the manifest by digest but does not embed its requirements or identify the external table by digest.

## Direction

The next target is a release workflow that can explain which required checks belong to the exact
candidate and refuse release when the required evidence is missing. The first product and release
path must be validated through a [concrete consumer workflow](https://github.com/rebaze/rio/issues/47)
before expanding the compiler's supported inputs.

The SBOM foundation remains a [verifiable handoff](https://github.com/rebaze/rio/issues/43),
[repair provenance](https://github.com/rebaze/rio/issues/44),
[inspectable requirements](https://github.com/rebaze/rio/issues/45) and
[portable retention](https://github.com/rebaze/rio/issues/46).

The proposed extension connects [an artifact to its SBOM evidence](https://github.com/rebaze/rio/issues/52),
imports [artifact-level check results](https://github.com/rebaze/rio/issues/53), and
[evaluates declared release requirements](https://github.com/rebaze/rio/issues/54).
[Scoped, authorized exceptions](https://github.com/rebaze/rio/issues/55) follow once required-check
evaluation works. A [repeatable release-gate example](https://github.com/rebaze/rio/issues/56) will
exercise the complete path, including refusal of results for a different artifact. Independently,
Rio's own pipeline [verifies staged assets before publication](https://github.com/rebaze/rio/issues/51);
see the [release guard and offline demo](tools/README.md#verify-release-assets-before-publication).

The compiler extensions above are planned improvements, not capabilities of the current release.
rio does not yet compile
build provenance, external test results, release evaluations, exceptions or deployment records.
Engineering history remains useful beyond release decisions, but a build or release record alone
does not establish what is currently running; deployment systems remain the source for that state.

## rio and rebaze

[rebaze](https://www.rebaze.de/) implements
[release controls](https://www.rebaze.de/release-controls/): the required checks, artifact
associations and release rules for one product and one release path in a customer's existing
toolchain. The implementation and operating instructions stay with the team, which can repeat the
workflow at the next release. Business owners define requirements and authority to approve
exceptions; those rules are enforced in the release process.

rio provides a reusable open-source evidence compiler for the inputs it supports within that
workflow. A check result records what was assessed; whether the check adequately addresses a
business risk still depends on its scope and the surrounding controls.

You can use rio independently of rebaze services, without a hosted account. Working with rebaze
does not require rio. Records belong to the customer; humans, agents and downstream systems use
them to inspect claims and make decisions.

## Install

Single command, for pipelines:

```sh
curl -sSL https://raw.githubusercontent.com/rebaze/rio/main/install.sh | sh
```

The script detects the platform, downloads the matching release binary and installs it. Set
`RIO_VERSION` to pin a release instead of taking the latest, and `RIO_INSTALL_DIR` to choose the
install directory, which otherwise is `/usr/local/bin` when that is writable and `$HOME/.local/bin`
when it is not.

The assignments go after the pipe, on `sh`. In front of `curl` they would be set for `curl`, which
does not read them, and the installer would run with neither.

```sh
curl -sSL https://raw.githubusercontent.com/rebaze/rio/main/install.sh \
  | RIO_VERSION=v0.1.0 RIO_INSTALL_DIR=/usr/local/bin sh
```

Homebrew:

```sh
brew install rebaze/tap/rio
```

From source, if you already have a Go toolchain:

```sh
go install github.com/rebaze/rio/cmd/rio@latest
```

## Usage

Run from the repository root, after the build has produced SBOMs.

```
rio normalize [flags]

  --manifest string   path to manifest (default "rio.yaml")
  --out string        output directory (default "target/rio")
  --gate string       "warn" or "fail" (default "warn")
  --attest            write an unsigned in-toto statement per artifact
  --quiet             suppress per artifact progress on stdout

rio plan [flags]

  --manifest string   path to manifest (default "rio.yaml")
  --out string        output directory (default "target/rio")
  --json              print the plan as JSON
  --quiet             suppress per artifact progress on stdout

rio version
```

The three-command pipeline:

```sh
mvn -B verify
rio normalize --gate fail
DTRACK_URL=https://dtrack.example.com DTRACK_API_KEY=... \
  ./tools/rio-dtrack-upload.sh target/rio/index.json
```

That third step is not rio. rio does not upload anywhere; `tools/rio-dtrack-upload.sh` ships as an
example of what to do with `index.json` afterwards. Its environment variables, the DependencyTrack
permissions it needs, and how to nest artifacts under a parent project are documented in
[tools/README.md](tools/README.md).

One line per artifact on stdout, then a summary. Machine detail belongs in `index.json`, not here.
Errors and warnings go to stderr. A run over the committed fixtures `testdata/tycho-rcp.cdx.json`
and `testdata/gate-missing-version.cdx.json` prints:

```
rcp-client  12 components   repaired 8    unmapped 1    gate ok
server-war   2 components   repaired 0    unmapped 0    gate FAIL (1 component missing version)
2 artifacts, 1 gate failure
```

### Normalization attestations

`rio normalize --attest` writes one unsigned, pretty-printed JSON statement named
`<artifact-id>.intoto.json` beside each normalized SBOM. It records the normalized file's digest
and the evidence for that normalization. The format is
[in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md), with
this contract for each `index.artifacts[i]`:

| field | value |
|---|---|
| `_type` | `"https://in-toto.io/Statement/v1"` |
| `subject` | One-element array: `[{"name": artifact.output.path, "digest": {"sha256": artifact.output.sha256}}]` |
| `predicateType` | `"https://rebaze.com/attestation/sbom-normalization/v1"` |
| `predicate.tool` | The complete `index.tool` object: `name` and `version` |
| `predicate.manifest` | The complete `index.manifest` object: `path` and `sha256` |
| `predicate.artifact` | The complete `index.artifacts[i]` object |

The references in the table mean the actual JSON values from the same run's `index.json`.
`predicate.artifact` preserves every field: `id`, `input`, `output`, `specVersion`,
`schemaValidated`, `components`, `transforms`, `gate`, `gateFindings`, `integrityFindings`, and
`enrichment` when present. Arrays retain the index's order and empty-array representation; absent optional
fields stay absent. There is no additional `schemaVersion` field in the statement or predicate;
the two type URIs identify their versions.

The subject is the normalized SBOM, identified by the lowercase SHA-256 digest of its bytes on
disk. `subject[0].name` and `predicate.artifact.output.path` are relative to the statement's
directory. Input paths are relative to the manifest's directory, as in the index. These paths
are local file references, not download URIs; independently checking an input digest requires
the original input file.

Statements are deterministic for the same input SBOMs, manifest, mapping tables and rio version.
rio writes all SBOMs and statements before writing `index.json` last. `--attest` leaves the SBOM and index bytes
unchanged and does not change the gate: a gate failure still writes every statement, with exit 0
under `--gate warn` and exit 1 under `--gate fail`. Usage or input errors (exit 2) write nothing.
Without the flag, rio writes no statements and preserves its existing output bytes.

rio does not sign statements or make network calls. An unsigned statement records a claim; it
is not cryptographic proof of who made it. Signing and verification belong to the surrounding
pipeline. A signature can authenticate a statement without proving its assertions true; see
[the planned signing tools](tools/README.md#signing-and-verifying-normalization-attestations).

### `rio plan`

`plan` prints what a `normalize` run would read, write and repair, and does none of it. It writes no
files and, like everything else here, makes no network calls.

```
$ rio plan
manifest  rio.yaml (sha256 a1b2c3d4e5f6...)

rcp-client
  read   target/bom.json
  write  target/rio/rcp-client.cdx.json
  repair-purl  ecosystem p2  table p2-maven.json

gate  require name, version, purl
```

Only the options a manifest actually set are shown; `--json` carries every one of them, resolved.
Exit 2 for the same manifest and glob problems `normalize` refuses, exit 0 otherwise. There is no
exit 1, because no gate runs.

A table that does not exist yet is reported on the line that names it, rather than being an error.
That is the point of the command: the table is built *from* the plan, so the first run in a
repository necessarily names one that is not there.

#### The plan JSON

`rio plan --json` is a machine contract. It is what `tools/build-p2-table.py` reads to learn which
SBOMs to harvest, which table to write and under which scope filter, so that none of it has to be
restated on a command line where it could disagree with the manifest.

```json
{
  "planVersion": 1,
  "tool": { "name": "rio", "version": "0.4.2" },
  "manifest": { "path": "rio.yaml", "dir": "/abs/repo", "sha256": "a1b2c3..." },
  "out": "target/rio",
  "builtinTable": { "org.objectweb.asm": { "groupId": "org.ow2.asm", "artifactId": "asm" } },
  "artifacts": [
    {
      "id": "rcp-client",
      "input":  { "path": "target/bom.json" },
      "output": { "path": "rcp-client.cdx.json" },
      "transforms": [
        { "name": "repair-purl", "ecosystem": "p2", "table": "p2-maven.json",
          "groupPrefix": "p2.", "classifier": "osgi.bundle",
          "syntheticNamespace": "p2.eclipse.plugin" }
      ]
    }
  ],
  "gate": { "require": ["name", "version", "purl"] }
}
```

- `planVersion` is the compatibility lever, the role `version` plays in the manifest. A consumer
  checks it before anything else and refuses a number it does not know.
- Paths follow `index.json`'s convention: `input.path` is relative to the manifest's directory,
  `output.path` to `out`, and `table` is exactly as the manifest wrote it, since that is how rio
  resolves it.
- Every transform option is reported **resolved**, defaults filled in, so a consumer never carries
  its own copy of `p2.` or `osgi.bundle`.
- `builtinTable` is the mapping table compiled into this binary. An override always wins over it, so
  a generated table that repeats an entry verbatim would silently shadow any later fix rio makes to
  it; publishing the asset is what lets a generator stay a delta over it.
- `manifest.dir` is the one absolute path rio ever writes, and the one deliberate break from
  `index.json`'s rules. The index refuses absolute paths because it is a committed artifact whose
  digests are a contract; a plan is transient stdout that exists to be joined against, and making
  the consumer guess the base directory is worse.

When enrichment is configured, each artifact also has an optional `enrichment` object with its own
`version: 1` and resolved `fields`. Each field reports `field`, `value`, `source` (a manifest selector
such as `enrichment.producer.name` or `artifacts[0].enrichment.subject.name`) and `replace` (boolean).
Fields are sorted by name. Planning resolves declarations without reading SBOM content: it can
show replacement intent but cannot establish whether an existing value conflicts.

This is not `index.json` with fewer fields. The index describes a run that happened, and a run needs
the mapping table that the plan is read to produce, so the index can never describe the first run
in a repository.

### Repaired, unmapped, skipped

A transform reports changes, unresolved mappings and exclusions. `index.json` counts these outcomes:

```json
{ "id": "repair-purl/p2", "applied": 8, "unmapped": 1, "skipped": 4 }
```

- **repaired**, `applied` in the index: rio rewrote the purl.
- **unmapped**: the component was in scope and rio found no Maven coordinates for it. Its purl is
  not converted to Maven coordinates; version-qualifier processing may still apply, as described below.
- **skipped**: the component was out of scope for the transform, so rio never looked for
  coordinates. Out of scope is a different outcome from a miss.

The p2 transform is in scope for three shapes, because Tycho emits more than one:

| shape | example |
|---|---|
| a p2 purl for an OSGi bundle | `pkg:p2/com.google.gson@2.8.9.v20220111-1409?classifier=osgi.bundle` |
| a Maven-shaped purl under a synthetic namespace | `pkg:maven/p2.eclipse.plugin/com.google.gson@2.8.9?type=eclipse-plugin` |
| no purl at all, but a bundle symbolic name | `group: p2.eclipse.plugin`, `name: com.google.gson` |

The second is the common one on a real product: `p2.eclipse.plugin` is not a groupId, it is a
placeholder Tycho invents for a bundle it has no Maven coordinate for, so the purl cannot resolve
anywhere and repairing it destroys nothing. The namespace it looks for is `syntheticNamespace` in
the manifest, defaulting to `p2.eclipse.plugin`.

Everything else is skipped, and the list is a whitelist rather than a judgement about which
coordinates look real:

- Any Maven namespace other than `syntheticNamespace`, including the other placeholders
  `p2.eclipse.feature` and `p2.p2.installable.unit`. Those are features and installable units, not
  Maven artifacts, so a table hit against one would be a confident false positive.
- A synthetic purl carrying a `classifier`. That is an artefact shipped *inside* a bundle, and it
  repeats the bundle's own name and version. `org.eclipse.jdt.debug` appears both as the plugin
  and as `classifier=jdimodel.jar`. Resolving by name alone would assert that the jar is the plugin
  and put the same purl on two components.
- A `pkg:p2` purl whose group falls outside the `p2.` prefix, which is how a first-party reactor
  module is recognised.

That last guard only works on the p2 shape. Under `syntheticNamespace` every component has the same
group, so there is no field left to tell a first-party bundle from a third-party one, and
first-party bundles are reported as unmapped rather than skipped. On the estate rio was built for
that is 227 of 594 unmapped components, 111 of them `.source` bundles. Expect the honest table
backlog to be smaller than the unmapped count.

The coordinate always comes from the purl's own `maven-groupId` qualifier, the component's
properties, or the mapping table, in that order. rio never splits a symbolic name to guess one:
`org.apache.commons.commons-io` becomes `org.apache.commons:commons-io` only because a curated
entry says so.

The three do not partition the components. `skipped` never appears on stdout, and the two halves of
the p2 transform are independent: dropping the Eclipse version qualifier can succeed while the
coordinate lookup finds nothing, so one component can be counted in both `applied` and `unmapped`.

The fixture line above is exactly that. Of its 12 components, 4 are out of scope: the two
first-party `tycho-demo` modules, an Eclipse feature, and an installable unit already carrying a
`pkg:maven` purl. The other 8 all had their purl rewritten, and one of them,
`org.eclipse.equinox.launcher.gtk.linux.x86_64`, is also the unmapped one: its version qualifier was
dropped, but the table has no entry for it, so it stays `pkg:p2/...`.

### Exit codes

- **0** All artifacts processed. No gate failure, or `--gate warn`.
- **1** At least one artifact failed the gate, under `--gate fail`.
- **2** Usage or configuration error: missing manifest, invalid manifest, glob matched zero or
  several files, glob matched one file over a tree rio could not fully search, unreadable or
  schema-invalid SBOM.
- **3** Internal error.

Exit code 1 still writes every output file and the index: a human has to be able to see why the gate
failed. Exit code 2 writes nothing.

## The manifest

`rio.yaml`, committed at the repository root. It is the declared intent for the repository and is
reviewed like code. Its sha256 is recorded in every output.

```yaml
version: 1                        # must be 1; anything else is exit 2

artifacts:
  - id: rcp-client                # ^[a-z0-9][a-z0-9._-]*$, unique; used as the output
                                  # filename and as the DependencyTrack project name
    sbom: "com.example.product.client/target/**/bom.json"
                                  # glob relative to this file's directory;
                                  # must match exactly one file, or exit 2
    transforms:                   # ordered; each entry is one transform name plus its config
      - repair-purl:
          ecosystem: p2
          # table: mappings/p2-maven.json   # merged over the built-in mapping table

  - id: server-war
    sbom: "com.example.server.web/target/bom.json"
    # subject:                    # override metadata.component when the generator describes
    #   name: example-server         # the building module rather than the shipped artifact
    #   version: 3.2.0

output:
  specVersionFloor: "1.6"         # 1.5 or 1.6; defaults to 1.6

gate:
  require: [name, version, purl]  # subset of these three; defaults to all three
```

The "exactly one file" rule is deliberate. Merging multiple matches is unsupported. An empty match
is the most dangerous silent failure in this tool, because a run that processed nothing looks
identical to a clean run.

The rule is only worth as much as the search behind it, so rio will not assert it over a tree it
could not fully read. A directory under the glob that rio cannot open may hold a second SBOM, and
proceeding on the one file it could see would make the same repository answer differently depending
on nothing but a permission bit. The wrong answer would look clean because the
gate passes and the index records a valid digest. When that happens the run stops with exit 2 and
names the directory that blocked it.

### Manifest enrichment

Use top-level `enrichment` for shared defaults and `artifacts[].enrichment` for each artifact's
values. Enrichment applies to the SBOM subject (`metadata.component`) and document metadata;
it does not apply your product identity or organization to third-party dependency components.

```yaml
version: 1
enrichment:
  subject:
    group: com.example
    version: "1.0.0"
    type: application
    manufacturer:
      name: Example Products
      url: [https://products.example.com]
      contact:
        - name: Product Security
          email: security@example.com
    supplier:
      name: Example Distribution
    securityContact: mailto:security@example.com
    website: https://products.example.com
    documentation: https://products.example.com/docs
    support: https://products.example.com/support
  producer:
    name: Example Build Services
  dataLicense: CC0-1.0
artifacts:
  - id: console
    sbom: inputs/console.cdx.json
    enrichment:
      subject:
        name: console
        purl: pkg:maven/com.example/console@1.0.0
        documentation: https://products.example.com/console/docs
output:
  specVersionFloor: "1.6"
```

The artifact's leaves override the corresponding shared leaves; omitted leaves inherit. Organization
`name`, `url` and `contact` are separate leaves, while each `url` or `contact` list is one value
and is replaced as a whole, not merged by position. An organization accepts a name, a list of
HTTP(S) URLs and a list of contacts with `name`, `email` and/or `phone`. Blank strings and null
values cannot remove defaults. Website, documentation and support must be absolute HTTP(S) URLs;
security contact also accepts a `mailto:` address.

| Manifest field | CycloneDX target | Meaning |
|---|---|---|
| `subject.name`, `.group`, `.version`, `.type`, `.purl` | Corresponding fields under `metadata.component` | The described product's identity and component type |
| `subject.manufacturer` | `metadata.component.manufacturer` | Organization that made the product; requires 1.6 |
| `subject.supplier` | `metadata.component.supplier` | Organization supplying the product |
| `subject.securityContact`, `.website`, `.documentation`, `.support` | Typed entries in `metadata.component.externalReferences` | Product contact and information URLs |
| `producer` | `metadata.manufacturer` | Organization that created the SBOM; requires 1.6 |
| `dataLicense` | `metadata.licenses` | One SPDX license ID for the SBOM data, such as `CC0-1.0`; does not change component licenses |

CycloneDX 1.5 supports the other modeled fields. A 1.5 output with `producer` or
`subject.manufacturer` is refused: rio does not substitute a different organization role. The
configured spec floor applies first, so the default floor of 1.6 permits these fields on older
inputs after uplift. Unknown fields, malformed values and unsupported output targets fail with
exit 2 before writing outputs.

#### Existing values and explicit replacement

An absent SBOM value is filled. An identical value is left alone. A different existing value
causes exit 2 with the artifact, field and source identified, and no new output files are written.
Artifact precedence changes which manifest value wins; it does not authorize overwriting SBOM
values. To intentionally change an existing value, list each field under `replace`:

```yaml
    enrichment:
      replace: [subject.name, subject.version, subject.purl]
      subject:
        name: console
        version: "1.0.0"
        purl: pkg:maven/com.example/console@1.0.0
```

`replace` accepts only modeled leaf names with an effective enrichment value. For example,
`subject.supplier.name` replaces that name without replacing its URLs or contacts;
`subject.supplier.contact` replaces its contact list. There is no wildcard or blanket override.
An artifact's `replace` list replaces the shared list; omitting it inherits the list, and an
explicit `replace: []` clears inherited replacement permission.

When name, group, version or purl is supplied, the resulting subject name, group and version must
agree with its purl. Updating only a name while retaining an incompatible purl is refused. The subject's
`bom-ref` remains unchanged, including when its text contains the old purl: it is a local graph
identifier, and dependency references must keep resolving to it.

The original artifact-level `subject: {name, version}` option retains its existing behavior and
runs before enrichment. If both are configured, enrichment sees the legacy override result and
applies its own conflict and identity checks. Use `enrichment.subject` for the conflict-aware
fields and provenance described here.
The [runnable enrichment demo](tools/README.md#manifest-enrichment-demo) provides synthetic inputs
and examples for an installed release binary.

#### Enrichment provenance and compatibility

Every actual enrichment change records `field`, `target`, `before`, `after`, a `source` object
with `kind: "manifest"`, manifest `path`, `sha256` and field `selector`, and
`assertion: "producer"`. Missing prior values are represented as `null`. These records appear in
the artifact's optional `index.json` extension, `enrichment: {version: 1, changes: [...]}`;
the same change fields, with an additional `version: 1`, appear as JSON values in
`rebaze:normalize:enrichment` SBOM metadata properties. Unchanged values do not create change records. With `--attest`, the same artifact
extension is included in the unsigned normalization statement.

Existing subject organization assertions at `metadata.supplier` or the legacy
`metadata.manufacture` are also checked. An explicit replacement updates that existing leaf as
well as the subject location, preserving unrelated fields and recording both changes.

These are manifest-author assertions, not independently verified facts. They identify who the
manifest says made the product and SBOM; they do not authenticate that organization or replace
original build evidence. The input timestamp, existing generator tools, component membership and
dependency graph are preserved. rio adds its own tool entry and records alongside existing data.

The optional enrichment extensions are versioned separately. `planVersion`, index `schemaVersion`
and the normalization predicate remain v1, with their existing meanings. Manifests that omit
`enrichment` retain their previous behavior and output shape. This feature does not collect source
or CI/build facts, hash the built artifact, generate evidence references or normalize dependency
licenses.

## Out of scope

rio keeps compilation local. Collection from remote systems, storage, signing, querying and
presentation belong around the compiler. It does not replace scanners, test runners or
observability systems, and it is not a governance suite or an automatic compliance certification
system.

The current implementation also excludes:

- merging multiple SBOMs into one closure
- scope filtering or shipped-set reduction
- reading assembled artifacts (zip, war, product directories)
- drift comparison against previous runs
- SPDX support, or conversion between SBOM formats
- license normalization, scoring, grading
- vulnerability lookup or enrichment
- uploading anywhere from inside rio
- any network access at all

The broader direction does not relax these boundaries. Changes require an explicit scope decision
grounded in a concrete workflow and compatibility with existing users.

## What rio writes into the output SBOM

**Component membership never changes.** v1 adds no component and removes none. Configured repairs
can rewrite dependency identities; enrichment updates subject and SBOM metadata. The dependency
component array in equals the component array out, member for member.

An input-versus-output diff still shows more than the repaired purls. rio appends itself to
`metadata.tools`, in whichever shape the document already uses: an entry in the flat array, or a
component under `tools.components`. It adds the repair and run records described below to
`metadata.properties`, and the identity evidence and dropped Eclipse qualifier to the components
they belong to. What it never changes is the set of components. A change there is a bug.

### Reading the repair records

The output document records the rule and before-and-after values for each repair. It does not yet
record which coordinate source won or preserve the mapping table's evidence metadata.
`metadata.properties` carries one property per repaired component:

```json
{ "name": "rebaze:normalize:repair",
  "value": "rule=repair-purl/p2 | from=pkg:p2/com.google.gson@2.8.9.v20220111-1409?classifier=osgi.bundle | to=pkg:maven/com.google.code.gson/gson@2.8.9" }
```

The value is three pipe-separated fields:

- `rule=` the transform that made the change, as `<transform>/<ecosystem>`. It names who is
  answerable for the rewrite.
- `from=` the purl exactly as it was found in the input, qualifiers included.
- `to=` the purl rio wrote in its place.

Misses are recorded the same way, so they are as visible as hits:

```json
{ "name": "rebaze:normalize:unmapped",
  "value": "rule=repair-purl/p2 | purl=pkg:p2/com.example.internal@1.0.0.v20240101 | reason=no mapping entry" }
```

Here `purl=` is the purl as it was found in the input and `reason=` says why no coordinate was
written. An unmapped component can still pass the gate because both shapes are valid package URLs.
Unmapped is a count, not a failure. rio never guesses a groupId from a symbolic name, because a
wrong coordinate is worse than a missing one.

What happens to the version on a miss differs by shape, and deliberately. An unmapped `pkg:p2` purl
keeps its p2 type rather than asserting a Maven mapping. The Eclipse qualifier is stripped and
preserved as a property; the two halves of the transform are independent. An unmapped synthetic
purl is left byte-identical, because stripping the qualifier off
`pkg:maven/p2.eclipse.plugin/com.google.guava@30.1.0.v1` would make it indistinguishable from a
well-formed Maven coordinate, and a lenient consumer would act on a groupId that does not exist.

The same repair is also recorded on the component itself, as an `evidence.identity` entry:

```json
"evidence": {
  "identity": [
    { "field": "purl",
      "confidence": 0.9,
      "methods": [
        { "technique": "other", "confidence": 0.9,
          "value": "rio repair-purl/p2: pkg:p2/com.google.gson@2.8.9.v20220111-1409" }
      ] }
  ]
}
```

The `value` names the rule and the original purl, so a consumer holding only the normalized document
can still see what the identity used to be. If a component already carries `evidence.identity`, rio
appends to it and never overwrites an existing entry. The current implementation assigns `0.9`
to every repair; this is a fixed value, not a measured probability or independent verification.

Where an Eclipse build qualifier was dropped from a version, the component carries it as a
`rebaze:normalize:p2-qualifier` property, for example `v20230708-0916`. This preserves the version
detail from the input; it does not independently identify or verify the corresponding build bytes.

Alongside the per-component records, `metadata.properties` carries the run itself.
`rebaze:normalize:tool`, `rebaze:normalize:artifact-id`, `rebaze:normalize:manifest-sha256` and
`rebaze:normalize:input-sha256` are written on every run. `rebaze:normalize:spec-uplift` appears
only when the document was below the floor and was raised to it, and
`rebaze:normalize:subject-override` only when the manifest supplied a `subject` for the artifact,
carrying the `metadata.component` name and version it replaced.

## No network calls

rio makes no network calls. Not to resolve coordinates, not to check for updates, not to look
anything up.

That includes schema validation: the CycloneDX schemas are embedded in the binary with `go:embed`,
and their `$ref`s resolve against each other locally. The p2 mapping table is embedded the same way.
The binary is static, `CGO_ENABLED=0`, and runs the same on a build agent with no egress as on a
laptop.

That is exactly why building the mapping table is a separate job, done ahead of time on a
workstation by `tools/build-p2-table.py`, and why uploading is a separate script. Both are
documented in [tools/README.md](tools/README.md); neither is part of the binary.

## Build from source

```sh
make build     # builds ./rio with version ldflags
make test      # go test ./...
make vet       # go vet ./...
```

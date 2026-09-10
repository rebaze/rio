# rio

[![CI](https://github.com/rebaze/rio/actions/workflows/ci.yaml/badge.svg)](https://github.com/rebaze/rio/actions/workflows/ci.yaml)
[![Release](https://github.com/rebaze/rio/actions/workflows/release.yaml/badge.svg)](https://github.com/rebaze/rio/actions/workflows/release.yaml)
[![GitHub Release](https://img.shields.io/github/v/release/rebaze/rio)](https://github.com/rebaze/rio/releases/latest)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/github/go-mod/go-version/rebaze/rio)](go.mod)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/rebaze/rio/badge)](https://scorecard.dev/viewer/?uri=github.com/rebaze/rio)

rio is an open-source evidence compiler. It turns engineering evidence into structured,
customer-owned records against an explicit output contract.

Today, rio compiles **SBOM normalization records**: it reads local CycloneDX SBOMs, applies
manifest-defined transformations, checks declared requirements, and writes normalized documents
plus an `index.json`. A pipeline or engineer can inspect what changed, identify gaps, and hand the
SBOMs to a downstream tool such as DependencyTrack.

## Why it exists

Software changes faster than teams can manually reconstruct and verify what happened. Evidence
assembled by hand for each release depends on someone remembering where the inputs came from,
which checks ran, and what their results meant. Work produced by AI agents increases the volume
of changes, but the problem also applies to work done by humans and conventional automation.

rio makes evidence production a repeatable part of engineering. A manifest committed next to the
code declares the inputs and requirements. Explicit rules transform supported evidence into
inspectable records that remain usable after the pipeline run ends. The people using those records
may develop software themselves or integrate and consume upstream software.

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
SBOM fields, not software acceptance, vulnerability absence or compliance.

Unmapped components and dangling dependency references can coexist with `gate: "ok"`. A schema
version beyond the embedded schemas produces `schemaValidated: false`, even if the gate passes.
Missing or invalid inputs stop compilation with exit 2 and produce no new record.

The attestation subject is the normalized SBOM, not a built binary or deployment. Source assertions
and mapping entries are inputs to normalization, not independently verified facts. Retain the
original SBOM, manifest and any external mapping table alongside the outputs if later inspection
or reproduction is required; rio does not package those inputs automatically. The index references
the manifest by digest but does not embed its requirements or identify the external table by digest.

## Direction

Planned work starts with a [verifiable SBOM handoff](https://github.com/rebaze/rio/issues/43),
followed by [repair provenance](https://github.com/rebaze/rio/issues/44),
[inspectable requirements](https://github.com/rebaze/rio/issues/45) and
[portable retention](https://github.com/rebaze/rio/issues/46). These are planned improvements,
not capabilities claimed by the current release.

The longer-term direction is engineering history that stays useful after the pipeline has ended
and the original participants have moved on. Additional evidence types and record boundaries will
be chosen through [concrete consumer workflows](https://github.com/rebaze/rio/issues/47).
rio does not yet compile build
provenance, test results, acceptance events or deployment records. A build record alone would not
establish what is currently running.

## rio and rebaze

[rebaze](https://rebaze.com) delivers scoped technical work that improves a customer's evidence
path and leaves repeatable machinery behind: configurations, adapters, identity rules, contract
profiles and pipeline integrations. rio provides the reusable open-source compiler at the center
of that work.

You can use rio independently of rebaze services, without a hosted account. Records belong to the
customer; humans and downstream systems use them to verify claims and make decisions.

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
`schemaValidated`, `components`, `transforms`, `gate`, `gateFindings`, and `integrityFindings`
when present. Arrays retain the index's order and empty-array representation; absent optional
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

**Component membership never changes.** v1 adds no component and removes none. Only identity fields
are rewritten. The component array in equals the component array out, member for member.

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

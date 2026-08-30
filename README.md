# rio

A Go CLI that reads a manifest, finds each declared artifact's SBOM, levels the CycloneDX spec
version, repairs p2 coordinates to Maven coordinates, checks minimum quality, and writes the results
plus an index.

## Why it exists

An Eclipse RCP product's SBOM uploads to DependencyTrack today with almost no findings, because
nothing in the vulnerability world understands p2 coordinates. A component identified as
`pkg:p2/com.google.gson@2.8.9.v20220111-1409` matches nothing in any advisory database, so the
project comes back clean and the clean result is meaningless.

After normalization the same component reads `pkg:maven/com.google.code.gson/gson@2.8.9`, and the
CVEs that were there the whole time appear. That before-and-after difference is the acceptance
criterion for this tool.

## What `rio normalize` does

- **Levels the spec version.** Documents below the configured floor are uplifted to it; documents at
  or above it pass through unchanged.
- **Repairs identity.** p2 purls are rewritten to Maven purls via an embedded, extendable mapping
  table, and Eclipse version qualifiers are stripped from the purl version.
- **Checks quality.** A gate asserts the document's subject and the required fields on every
  component, and either warns or fails the build.
- **Records what it did.** Every repair, every miss and every run parameter is written into the
  output document itself and into `index.json`.

The full specification lives in issue #4.

## Install

Single command, for pipelines:

```sh
curl -sSL https://raw.githubusercontent.com/rebaze/rio/main/install.sh | sh
```

The script detects the platform, downloads the matching release binary and installs it. Set
`RIO_VERSION` to pin a release instead of taking the latest, and `RIO_INSTALL_DIR` to choose the
install directory.

```sh
RIO_VERSION=v0.1.0 RIO_INSTALL_DIR=/usr/local/bin \
  curl -sSL https://raw.githubusercontent.com/rebaze/rio/main/install.sh | sh
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
  --quiet             suppress per artifact progress on stdout

rio version
```

The three-command pipeline:

```sh
mvn -B verify
rio normalize --gate fail
./rio-dtrack-upload.sh target/rio/index.json
```

`rio-dtrack-upload.sh` ships in this repository as an example. It is not part of rio, because rio
does not upload anywhere.

One line per artifact on stdout, then a summary. Machine detail belongs in `index.json`, not here.
Errors and warnings go to stderr.

```
rcp-client   1284 components   repaired 947   unmapped 12   gate ok
server-war    412 components   repaired 0     unmapped 0    gate FAIL (3 components missing version)
2 artifacts, 1 gate failure
```

### Exit codes

- **0** All artifacts processed. No gate failure, or `--gate warn`.
- **1** At least one artifact failed the gate, under `--gate fail`.
- **2** Usage or configuration error: missing manifest, invalid manifest, glob matched zero or
  several files, unreadable or schema-invalid SBOM.
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
    sbom: "com.tkse.product.client/target/**/bom.json"
                                  # glob relative to this file's directory;
                                  # must match exactly one file, or exit 2
    transforms:                   # ordered; each entry is one transform name plus its config
      - repair-purl:
          ecosystem: p2
          # table: mappings/p2-maven.json   # merged over the built-in mapping table

  - id: server-war
    sbom: "com.tkse.server.web/target/bom.json"
    # subject:                    # override metadata.component when the generator describes
    #   name: tkse-server         # the building module rather than the shipped artifact
    #   version: 3.2.0

output:
  specVersionFloor: "1.6"         # 1.5 or 1.6; defaults to 1.6

gate:
  require: [name, version, purl]  # subset of these three; defaults to all three
```

The "exactly one file" rule is deliberate. A glob resolving to several files is the merge case, and
merge is not v1. An empty match is the most dangerous silent failure in this tool, because a run that
processed nothing looks identical to a clean run.

## Out of scope

These are deliberate refusals, not gaps. Do not implement, and do not leave hooks that invite
implementation:

- merging multiple SBOMs into one closure
- scope filtering or shipped-set reduction
- reading assembled artifacts (zip, war, product directories)
- drift comparison against previous runs
- SPDX support, or conversion between SBOM formats
- license normalization, scoring, grading
- vulnerability lookup or enrichment
- uploading anywhere from inside rio
- any network access at all

A pull request adding one of these is rejected regardless of quality. Naming what the tool refuses to
do is what keeps it small.

## What rio writes into the output SBOM

**Component membership never changes.** v1 adds no component and removes none. Only identity fields
are rewritten. The component array in equals the component array out, member for member. If you are
diffing an input against an output, any change in the set of components is a bug.

### Reading the repair records

Every repair is traceable from the output document alone, without the index and without the input.
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

Here `purl=` is the purl that was left untouched and `reason=` says why no coordinate was written.
An unmapped component keeps its p2 purl and still passes the gate: `pkg:p2/...` is a valid package
URL. Unmapped is a count, not a failure. rio never guesses a groupId from a symbolic name, because a
wrong coordinate is worse than a missing one.

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
appends to it and never overwrites an existing entry.

Alongside the per-component records, `metadata.properties` carries the run itself:
`rebaze:normalize:tool`, `rebaze:normalize:spec-uplift`, `rebaze:normalize:manifest-sha256`,
`rebaze:normalize:input-sha256` and `rebaze:normalize:artifact-id`.

## No network calls

rio makes no network calls. Not to resolve coordinates, not to check for updates, not to look
anything up.

That includes schema validation: the CycloneDX schemas are embedded in the binary with `go:embed`,
`$ref`s resolve locally, and so does the p2 mapping table. The binary is static, `CGO_ENABLED=0`, and
runs the same on a build agent with no egress as on a laptop.

## Build from source

```sh
make build     # builds ./rio with version ldflags
make test      # go test ./...
make vet       # go vet ./...
```

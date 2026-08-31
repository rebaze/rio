# rio

The open supply chain governance CLI: it collects the evidence your build already produces,
normalizes it into a shape the rest of the world can actually resolve, and holds it to a standard
you declared before it leaves the pipeline.

## Why it exists

Every build emits supply chain evidence, and everything downstream — advisory databases, policy
engines, dashboards, auditors — expects that evidence in a shape nobody produced. SBOMs land in a
dozen target directories, at different spec versions, describing the module that built the artifact
rather than the artifact, carrying identities that resolve nowhere. Between "the build wrote
something" and "a downstream tool can answer a question with it" sits a step nobody owns, and it is
usually a pile of pipeline glue nobody wants to maintain.

rio is the missing piece there. One manifest, committed next to the code and reviewed like code,
declares which artifacts a repository ships and what their evidence has to look like. One run
collects each artifact's SBOM, levels the spec version, repairs identity, checks the result against
the quality you asked for, and writes the normalized documents plus an `index.json` that says what
happened. It is a single static binary that makes no network calls, so it behaves the same on an
air-gapped build agent as on a laptop.

Nothing is guessed and nothing is silent. Every change rio makes is recorded in the document that
carries it, so a normalized SBOM can be read on its own and still say what was rewritten, by which
rule, and what it used to be. Every miss is recorded the same way, because a gap you can see is
worth more than a coordinate that might be wrong.

### The case it was built for

An Eclipse RCP product's SBOM uploads to DependencyTrack today with almost no findings, because
nothing in the vulnerability world understands p2 coordinates. A component identified as
`pkg:p2/com.google.gson@2.8.9.v20220111-1409` matches nothing in any advisory database, so the
project comes back clean and the clean result is meaningless.

After normalization the same component reads `pkg:maven/com.google.code.gson/gson@2.8.9`, and the
CVEs that were there the whole time appear. That before-and-after difference is the acceptance
criterion for this tool. p2 is the first ecosystem rio repairs, not the reason it exists: the seam
it plugs into is a transform seam, and the next broken identity scheme lands next to it.

## What `rio normalize` does

- **Levels the spec version.** Documents below the configured floor are uplifted to it; documents at
  or above it pass through unchanged.
- **Repairs identity.** p2 purls are rewritten to Maven purls via an embedded, extendable mapping
  table, and Eclipse version qualifiers are stripped from the purl version.
- **Checks quality.** A gate asserts the document's subject and the required fields on every
  component, and either warns or fails the build.
- **Records what it did.** Every repair and every miss is written into the output document itself.
  `index.json` carries the counts, the out-of-scope ones included, and the run parameters.

The full specification lives in issue #4.

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

### Repaired, unmapped, skipped

A transform leaves each component in one of three states, and `index.json` counts all three:

```json
{ "id": "repair-purl/p2", "applied": 8, "unmapped": 1, "skipped": 4 }
```

- **repaired**, `applied` in the index: rio rewrote the purl.
- **unmapped**: the component was in scope and rio found no Maven coordinates for it. Its purl is
  left exactly as the generator wrote it.
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

- Any Maven namespace other than `syntheticNamespace` — including the other placeholders
  `p2.eclipse.feature` and `p2.p2.installable.unit`. Those are features and installable units, not
  Maven artifacts, so a table hit against one would be a confident false positive.
- A synthetic purl carrying a `classifier`. That is an artefact shipped *inside* a bundle, and it
  repeats the bundle's own name and version — `org.eclipse.jdt.debug` appears both as the plugin
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

The "exactly one file" rule is deliberate. A glob resolving to several files is the merge case, and
merge is v2. An empty match is the most dangerous silent failure in this tool, because a run that
processed nothing looks identical to a clean run.

## Out of scope

rio owns the evidence layer — collect, normalize, gate, index. Analysis, enrichment and storage
belong to the tools it feeds, and the following are deliberate refusals rather than gaps. Do not
implement them, and do not leave hooks that invite implementation:

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
are rewritten. The component array in equals the component array out, member for member.

An input-versus-output diff still shows more than the repaired purls. rio appends itself to
`metadata.tools`, in whichever shape the document already uses: an entry in the flat array, or a
component under `tools.components`. It adds the repair and run records described below to
`metadata.properties`, and the identity evidence and dropped Eclipse qualifier to the components
they belong to. What it never changes is the set of components. A change there is a bug.

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

Here `purl=` is the purl as it was found in the input and `reason=` says why no coordinate was
written. An unmapped component still passes the gate — both shapes are valid package URLs — so
unmapped is a count, not a failure. rio never guesses a groupId from a symbolic name, because a
wrong coordinate is worse than a missing one.

What happens to the version on a miss differs by shape, and deliberately. An unmapped `pkg:p2` purl
keeps its type, which announces that it resolves nowhere, so the Eclipse qualifier is stripped and
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
appends to it and never overwrites an existing entry.

Where an Eclipse build qualifier was dropped from a version, the component carries it as a
`rebaze:normalize:p2-qualifier` property, for example `v20230708-0916`. It is the only link back to
the exact Eclipse build, so it is recorded rather than discarded.

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

# tools

Things that support rio without being part of it. Nothing here ships in the binary, nothing here is
covered by rio's compatibility promises, and rio never calls any of it.

Supporting network-facing helpers live here. **Normalization and planning stay offline**;
root pipeline execution and explicit native delivery/reconciliation may use network clients. Rio stays static,
`CGO_ENABLED=0`. Offline demos also live here: they exercise the binary with inspectable example
inputs and remain separate from its runtime.

| tool | what it does | when you run it |
|---|---|---|
| [Test binary workflow](#temporary-linux-test-binaries) | builds a selected revision as a temporary Linux download | when reproducing a problem or testing a fix |
| [`build-p2-table.py`](#build-p2-tablepy) | builds the bundle-symbolic-name → Maven coordinate table rio repairs purls with | occasionally, on a workstation |
| [`demo-delivery/`](demo-delivery/) | demonstrates native Dependency-Track delivery and batch evidence | with Rio 0.7.0+ and Python 3.9+ |
| [`demo-dtrack-tls/`](demo-dtrack-tls/) | demonstrates verified TLS and explicit certificate bypass with recorded policy | with Rio 0.7.0+ and Python 3.9+ |
| [`demo-oci/`](demo-oci/) | demonstrates native standalone and attached OCI delivery | with Rio 0.7.0+ and Python 3.9+ |
| [`demo-enrichment/run.sh`](#manifest-enrichment-demo) | demonstrates shared defaults, conflict refusal and explicit field replacement | with Rio 0.7.0+ and Python 3.9+ |
| [`demo-context/run.sh`](#ci-build-context-demo) | demonstrates two selected CI context entries, refusals and owned-claim replacement | with Rio 0.7.0+ and Python 3.9+ |
| [`demo-artifact-sets/`](#artifact-sets-demo) | discovers module SBOMs, refuses missing/overlapping inputs and retains offline scope/check evidence | with Rio 0.7.0+ and Python 3.9+ |
| [`demo-batch-evidence/`](demo-batch-evidence/) | demonstrates partial delivery, compact scope, explicit retry and offline crash recovery | with Rio 0.7.0+ and Python 3.9+ |
| [`demo-record/`](#consolidated-record-demo) | inspects independent pipeline, retry and reconciliation receipts | when retaining normalization and selected delivery facts |
| [`demo-normalization-evidence/`](demo-normalization-evidence/) | explains repair sources, exact changes and offline retention | with an installed release containing normalization evidence |
| [`demo-repair/`](#first-repair-sample) | shows optional p2 repair with an unchanged input and an audit record | when evaluating Eclipse/OSGi coordinate repair |
| [`demo-agent-integration/`](#agent-integration-examples) | tests project onboarding configurations and a one-command CI receipt step | with Rio 0.7.0+ and Python 3.9+ |
| [`rio-context.py`](#rio-contextpy) | emits one explicit build-context entry bound to original SBOM bytes | in a producing CI job |
| [`feature-video/`](#feature-video) | records, narrates and encodes the context feature walkthrough | when the feature or its demo changes |

---

## Temporary Linux test binaries

Use [Actions → Test binary](https://github.com/rebaze/rio/actions/workflows/test-binary.yaml)
to share a diagnostic build without publishing a GitHub Release or updating Homebrew.
Repository write access is required to start a run.

1. Click **Run workflow**, keeping **Use workflow from: main**.
2. Set **Source branch, tag or commit to build** to your fix branch or exact commit
   (default `main`). Choose Linux `amd64` or `arm64` (default `amd64`).
3. Open the completed run and follow **Download artifact** in its summary, or select the
   `rio-test-linux-…` artifact at the bottom of the run page.

The source must be in this repository and support the current `cmd/rio` build layout and repair
example. The workflow resolves the chosen revision once and records its full commit SHA.
Each architecture builds and runs its smoke test on a native Linux runner. It performs a static
build, checks the reported version/commit, and runs the synthetic normalization/repair example.
This fast workflow does not wait for the full CI suite or perform the official release checks.

The same flow with the GitHub CLI:

```sh
gh workflow run test-binary.yaml --repo rebaze/rio --ref main \
  -f ref=YOUR_FIX_BRANCH_OR_COMMIT -f architecture=amd64
gh run list --repo rebaze/rio --workflow test-binary.yaml --limit 5
gh run watch RUN_ID --repo rebaze/rio --exit-status
gh run download RUN_ID --repo rebaze/rio --name ARTIFACT_NAME --dir rio-test
```

Replace `YOUR_FIX_BRANCH_OR_COMMIT` and `RUN_ID` with the desired source and the run ID shown
by `gh run list`, and `ARTIFACT_NAME` with the artifact name shown on that run. The run summary
provides the complete download and verification commands with these values filled in. Specifying
`--name` extracts directly into `rio-test`, rather than an artifact-name subdirectory.
Share the run URL with the tester. GitHub requires sign-in and repository read
access to download artifacts, including those from public repositories. Downloads expire after
14 days; a new run produces a new artifact and build identity.

After downloading (and unzipping the artifact if using the browser), run on the matching Linux
architecture:

```sh
cd rio-test
sha256sum -c SHA256SUMS
tar -xzf rio-test-linux-amd64.tar.gz  # use arm64 for that architecture
./rio --version
sh example/run.sh "$PWD/rio"
```

The archive preserves executable permissions and contains `rio`, `version.txt`, `build-info.json`
and `example/` with synthetic fixtures. The example runs offline, needs no Go toolchain, preserves
its input, and prints the temporary directory containing its output and repair evidence.

`rio --version` reports `test-<short-commit>.<run-id>.<attempt>`, the full source commit and build
time. `build-info.json` also records the requested source, workflow commit, architecture, Go
version, run URL, binary SHA-256 and validation scope. An outer copy is available without
extracting the archive. `SHA256SUMS` covers both the archive and that metadata file.

These are unsigned, smoke-tested diagnostic builds. Checksums detect changed download bytes;
they do not provide the signature and attestation guarantees of official releases. No tag or
release is created. In particular, do not push a `v…-rc` tag for this purpose: the existing release
workflow runs on every `v*` tag. Use the regular release process after the fix passes full CI.

## build-p2-table.py

Produces the mapping table rio consumes. It reads the SBOMs you already have, takes the bundle
symbolic names rio could not map, and resolves them against Eclipse's and Maven Central's published
metadata. Python 3.9+, standard library only.

Run it from your repository root. It needs no arguments:

```sh
cd my-product
python3 tools/build-p2-table.py
```

```
rio.yaml (sha256 a1b2c3d4e5f6...), rio 0.4.2
  sample.product  com.example.sample.withrules.product/target/bom.json   412 in-scope bundles
  sample.server   com.example.sample.standort.server/target/bom.json      38 in-scope bundles
...
wrote p2-maven.json: 431 entries: 12 new, 400 re-derived unchanged, 19 carried over, 3 changed, 7 pinned
```

### It reads rio.yaml, through rio

`rio.yaml` already says which SBOMs to read, which table to write and under which scope filter:

```yaml
version: 1
artifacts:
  - id: sample.product
    sbom: "com.example.sample.withrules.product/target/bom.json"
    transforms:
      - repair-purl:
          ecosystem: p2
          table: p2-maven.json
```

So this tool asks for none of it. It execs `rio plan --json`, which describes what a `rio normalize`
run would read and repair, and works its way back from that. Nothing here can disagree with rio
about which files were read or which table was meant, because there is only one statement of it.

That matters most for the scope filter. `repair-purl` takes `groupPrefix`, `classifier` and
`syntheticNamespace`, and a manifest that overrides one of them used to leave this tool building a
table under a *different* filter than rio would read it back with — silently, and with no way to
notice. Now those values arrive in the plan, resolved, and this tool holds no copy of them.

| flag | replaced by |
|---|---|
| the `sbom...` positionals | `artifacts[].sbom` |
| `--out` | `transforms[].repair-purl.table` |
| `--existing` | the same file as `table`, read and rewritten in place |
| `--synthetic-namespace`, `--group-prefix`, `--classifier` | the same keys on `repair-purl` |

`--manifest` points at a manifest other than `rio.yaml`. `--rio` points at the binary when it is not
on `PATH`. `--plan FILE` (or `-`) takes a plan you already have and skips the exec, which is how the
tests run with no rio binary in sight:

```sh
rio plan --json > plan.json
python3 tools/build-p2-table.py --plan plan.json
```

Artifacts are bucketed by the table their `repair-purl` names: two artifacts pointing at one table
are one pass over both their SBOMs. An artifact with no `repair-purl`/`ecosystem: p2` is skipped
with a line saying so. Two artifacts sharing a table but disagreeing on a scope key is an error, not
a first-wins.

**Someone with a loose SBOM and no manifest now needs a four-line `rio.yaml`.** That is a real
cost of this design and it is deliberate: nothing here should be sayable in two places.

### Why it exists

A bundle symbolic name is not reliably `groupId.artifactId`, and the cases where it differs are
exactly the ones that matter:

| symbolic name | actual coordinate | what splitting the name would give |
|---|---|---|
| `com.google.inject` | `com.google.inject:guice` | `com.google:inject` |
| `com.ibm.icu` | `com.ibm.icu:icu4j` | `com.ibm:icu` |
| `com.sun.jna.platform` | `net.java.dev.jna:jna-platform` | nothing resembling it |
| `org.apache.commons.cli` | `commons-cli:commons-cli` | `org.apache.commons:cli` |
| `org.apache.httpcomponents.httpclient` | `...:httpclient-osgi` | `...:httpclient` |
| `org.objectweb.asm` | `org.ow2.asm:asm` | `org.objectweb:asm` |

So the name is never split first, and a split is never trusted on its own. rio's rule is that a
wrong coordinate is worse than a missing one — it produces confident lookups against the wrong
package — and this tool inherits it.

### How it resolves

Hardest evidence first. Each stage only sees what the ones before it could not settle.

1. **Eclipse's own p2 metadata.** SimRel and Orbit publish a `content.xml` in which installable
   units carry `maven-groupId` and `maven-artifactId` properties. That is Eclipse stating the
   coordinate. Point `--p2-repo` at the release your product is built against; it defaults to
   SimRel 2021-06 plus three Orbit aggregations, and later repositories win.

   The claim is still confirmed against Central, version included. Existence alone is too weak:
   `org.eclipse.core.contenttype` is published both by a maintained `org.eclipse.platform` and by
   an `org.eclipse.core` last touched in 2010, and only one of them ships the build you have.

2. **The same claim, with the groupId looked up again.** A p2 repository records the coordinate a
   bundle was *built* under, which for Eclipse's own projects is an unpublished Tycho reactor
   groupId — `org.eclipse.core.databinding` claims `eclipse.platform.ui`, which is a git repository
   name, not a groupId. The artifactId survives that; only the groupId has to be found again.

   This is the stage that resolves most of an RCP product, and no name-splitting could reach it:
   `org.eclipse.platform` appears nowhere in the symbolic name.

3. **Maven Central, proven against the jar.** A coordinate is guessed by splitting the symbolic
   name, then the jar is fetched and its `Bundle-SymbolicName` header read back. A mismatch rejects
   the guess and the next candidate is tried. Only the first 32 KB of each jar is fetched, since the
   manifest is a jar's first entry.

   The longest groupId is tried first, and the longest of all is the whole symbolic name with the
   artifactId repeating its last label — `com.thoughtworks.xstream:xstream`,
   `com.google.guava:guava`. That shape is not a split at all, and it is one of the commonest
   conventions in Java.

   The version is evidence rather than output — the table records no version — so it only has to be
   good enough to fetch the right jar. An OSGi version has nowhere to put a Maven qualifier, so
   guava's `30.1-jre` and `30.1-android` are both the bundle's `30.1.0`, and both are searched. A
   further numeric segment is not a qualifier: `30.1.1` is a different release from `30.1`, while
   `4.1.65.Final` is `4.1.65`. Which variant a bundle came from is still a guess, so a qualified
   version may only ever reach `manifest-proven` — never `inferred`, which would be two guesses
   stacked.

4. **Maven Central by exact SHA-1.** Exact when it hits, where the SBOM's hashes are usable at all.
   It asks only about what the stages above could not settle and skips any hash shared by more than
   one component, so it is normally a handful of requests. `--no-hash` turns it off.

`--search` is separate and off by default. It lets stages 2 and 3 ask `search.maven.org` which
groupIds publish a given artifactId. On the estate this was built for it found nothing the other
stages had not already found, and it is slow, because every answer it offers still costs a jar to
verify. It is also the only rate-limited dependency here.

### What it refuses to answer

Two outcomes are reported rather than guessed at, both in `<table>.review.md`:

- **Ambiguity.** When several groupIds publish a jar declaring the same symbolic name, one of them
  is a re-publisher and the manifest cannot say which. `org.junit` is claimed by both `junit` and
  `org.mod4j.org`; a re-publisher's jar honestly carries the same header, so proof does not
  discriminate. No entry is written.
- **Absence.** No stage produced a candidate.

### Reading the output

Every entry records how it was arrived at. rio ignores the extra keys; a reviewer should not.

```json
"org.apache.commons.lang3": {
  "groupId": "org.apache.commons", "artifactId": "commons-lang3",
  "confidence": "manifest-proven", "evidence": "org.apache.commons:commons-lang3:3.12.0"
}
```

| confidence | meaning |
|---|---|
| `eclipse-asserted` | Eclipse's own metadata says so, and Central publishes it at this version |
| `manifest-proven` | the published jar's own `Bundle-SymbolicName` matches |
| `hash-exact` | a SHA-1 in the SBOM matches exactly one artifact on Central |
| `inferred` | **not proof** — see below |
| *(absent)* | a human wrote this entry; the tool will not touch it |

`inferred` means the coordinate resolves to a real artifact at the right version, but that artifact
predates OSGi and carries no `Bundle-SymbolicName`, so nothing corroborates it — `commons-logging`,
`wsdl4j` and the Oracle JDBC bundles land here. They are emitted because a reviewable guess beats a
silent gap, and marked because a wrong coordinate is worse than a missing one. Read them before you
ship them.

### One table, kept across runs

The `table:` your manifest names is read and rewritten in place. There is no second file.

> **To pin an entry, delete its `confidence` key.**
>
> That is the whole rule. An entry carrying a `confidence` key is derived and this run owns it. An
> entry without one was written by a human and is never touched — not corrected, not re-evidenced,
> not even looked up, so a decided name costs no network. Editing a derived entry *in place* and
> leaving its `confidence` key behind does not pin it; the next run will move it back, and say so
> under "Changed since last run".

Four more rules follow from the same principle, each because its absence has a failure mode:

- **Never delete.** A derived entry this run produced no answer for — an `--offline` run against a
  thin cache, Central having a bad day, a `--no-hash` pass — is carried over unchanged. Otherwise a
  flaky network quietly shrinks the table and rio starts emitting unrepaired purls, which is the
  failure this tool exists to prevent. `--prune` opts into the deliberate rebuild that drops what no
  longer resolves.
- **Never downgrade.** `inferred` is not proof and never overwrites an entry something actually
  corroborated. The three proven tiers are not ranked against each other: they are different *kinds*
  of evidence, not different strengths, and ranking them would invent a hierarchy nothing supports.
- **Changes are taken, and shown.** A run that derives different coordinates than the table records
  replaces them and lists them under **Changed since last run** in the review file. A coordinate
  flipping is the single thing a reviewer most needs to see.
- **Stay a delta over the built-in table.** rio ships a small table of its own, and an override
  always wins over it — so an entry that redundantly repeats a built-in one silently shadows every
  later fix rio makes to it. A derived entry identical to a built-in one is left out, and an
  existing redundant entry is dropped on the next run. One that *contradicts* the built-in is kept,
  because that is a deliberate local override, and flagged in the review file.

A table rio would refuse to load is refused here too, and refused *before* any of it is rewritten —
a wrong `schemaVersion`, an entry that is not a coordinate pair, an empty `groupId`. The alternative
is spending a whole run producing a file rio still will not load, having destroyed what was there in
the process.

`--overwrite` lifts the pin rule and the no-downgrade rule together. Both exist for a reason; this
is the escape hatch, not the normal path.

The run summary says what happened rather than giving one total:

```
wrote p2-maven.json: 431 entries: 12 new, 400 re-derived unchanged, 19 carried over, 3 changed, 7 pinned
```

`<table>.review.md` is written beside the table (`--review` names it instead, and is an error when
the manifest builds more than one table). It opens with what it was built from — the rio version,
the manifest path and sha256, and every SBOM read — because it is the artifact a human is asked to
trust.

### First-party bundles

They are never mapped. Under `syntheticNamespace` nothing on a component distinguishes a
first-party bundle from a third-party one, so the prefix is inferred from `metadata.component`'s own
group: a product under `com.example.acme.product` excludes everything under `com.example`. Override
with `--first-party-prefix`, and check the count the run reports.

### Cost

The cache under `--cache` is keyed by URL and never expires, because released artifacts do not
change; delete the directory to force a refresh. A first run pulls roughly 40 MB of Eclipse
metadata. Later runs fetch almost nothing but still take a few minutes, because the cached SimRel
and Orbit `content.xml` documents are re-parsed each time.

`--offline` uses only what is cached. A cache miss offline is reported as unknown rather than as a
negative answer, so an incomplete cache can never quietly cost the table an entry.

### Tests

`build-p2-table_test.py` covers the tool offline — no network, and no rio binary, because every test
drives it through `--plan`:

```sh
python3 tools/build-p2-table_test.py
```

CI runs it on Python 3.9, the version the tool advertises, whenever a `.py` file changes.

---

<a id="rio-dtrack-uploadsh"></a>

## Migrating to native Dependency-Track delivery

The retired `rio-dtrack-upload.sh` is replaced by configured native delivery. Add a Dependency-Track target to `rio.yaml`, name the API-key environment variable, then run `rio` once. [Complete native configuration](../docs/delivery.md) and [quick start](../docs/quick-start.md).

The old prefix-plus-artifact-ID project convention is not inferred: configure explicit project names/versions or UUIDs when needed. Project creation requires `autoCreate: true`. Parent-project hierarchy remains a receiver administration concern. Explicit `--allow-failed-gate` belongs to standalone delivery; root uses its effective gate policy.

Uploads return acceptance/unknown/rejection facts. Optional native reconciliation uses `/api/v1/event/token`; no processing observed does not prove ingestion. Reuse of an existing standalone journal is refused, and possible duplicates require explicit retry authorization. See the [installed-binary fault matrix](demo-delivery/README.md), [TLS policy demo](demo-dtrack-tls/README.md), and [owned real-server harness](demo-delivery/integration/README.md).

## Signing and verifying normalization attestations

`rio normalize --attest` writes unsigned `<artifact-id>.intoto.json` statements beside the
normalized SBOMs. The [statement contract](../docs/output.md#normalization-attestations) describes
their subjects, digests and normalization evidence. rio produces these files locally; signing
and verification belong to the surrounding pipeline.

Signing and verification tooling is planned in [issue #14](https://github.com/rebaze/rio/issues/14).
No signing or verification script ships here yet. An unsigned statement is a claim, not
cryptographic proof of its origin. Its paths are local references, not download URIs, and
independently verifying the recorded input digests requires retaining the original files.


## Testing dependency auto-merge

`dependabot-auto-merge_test.py` executes the merge workflow's actual shell policy against
local GitHub API fixtures. It checks eligible patch/minor security groups and rejects routine
or major updates, upstream maintainer changes, missing metadata, edited commits, stale heads,
retargeted PRs, body edits before/during the run, and incomplete or failed required checks. The test replaces `gh` and polling sleeps locally: it makes no
network calls and cannot merge a real PR. Requires Python 3.9+, bash, and jq.

```sh
python3 tools/dependabot-auto-merge_test.py
```

CI runs it when Python tools or the merge workflow change. The live update and alert-closure
policy is documented in [SECURITY.md](../SECURITY.md#dependency-updates-and-alert-closure).


## Pinned Go vulnerability scanner

`tools/security/go.mod` and `go.sum` pin govulncheck and its dependencies separately from
rio's runtime module. Dependabot maintains both module directories. CI runs the scanner
against the rio module while continuing to fetch current Go vulnerability advisories:

```sh
go -C tools/security tool govulncheck -C ../.. -format text ./...
```

To intentionally change the scanner version, run `go -C tools/security get -tool
golang.org/x/vuln/cmd/govulncheck@<version>` and `go -C tools/security mod tidy`, then review
the module changes through a PR. Scanner code does not change merely because a new version
is published.

`python3 tools/ci-changes_test.py` checks that edits to every workflow and either module
trigger the Go checks. It also verifies the narrower triggers for the other CI checks.
Like the merge-policy tests, it runs offline and is included in CI's Python tests.

## Verify release assets before publication

`release-publish.py` is the publication guard used by Rio's own release workflow
([issue #51](https://github.com/rebaze/rio/issues/51)). It requires Python 3.9+, `gh` and
`cosign`; the workflow supplies GitHub credentials and pins its signing tools.

The workflow builds with GoReleaser's `--skip=publish,announce,homebrew`. It then stages
archives, their checksums and signature, the source CycloneDX SBOM, and the changelog.
The staging command writes a SHA-256 inventory last and refuses existing output paths,
so an interrupted run cannot silently reuse an earlier inventory.

```sh
python3 tools/release-publish.py stage \
  --dist dist --stage release-assets --inventory release-inventory.json \
  --tag "$TAG" --repo "$GITHUB_REPOSITORY"
```

The GitHub attestation actions consume these staged files. The workflow combines their
bundles into `release-attestations.jsonl`, outside the frozen asset directory, then runs:

```sh
python3 tools/release-publish.py publish \
  --stage release-assets --inventory release-inventory.json \
  --bundle release-attestations.jsonl --tag "$TAG" --repo "$GITHUB_REPOSITORY"
```

Before creating a draft, the guard checks the asset inventory, archive checksums, both
provenance and CycloneDX attestations for each archive, provenance for the checksum file,
and the checksum signature. It constrains the signer to this repository's release workflow
at the requested tag. The verified CycloneDX predicate must match the staged source SBOM.
The source SBOM describes the repository; attaching it to an archive does not establish a
complete inventory of that archive's assembled binary.

Verification and upload use the same private copy of the staged bytes. The guard downloads
the draft's assets and compares their names and SHA-256 digests before publishing the
identified draft. Homebrew runs only after successful publication and receives the staged
checksums. Prereleases keep their prerelease designation and do not update the tap.

An existing release **or draft** for the tag blocks creation. Lookup and verification errors
also block it. Failure after draft creation leaves the draft unpublished; the tool never
deletes tags, replaces assets, or recreates a release. Inspect the failure and use a new patch
tag for a corrected release. Do not rerun this tool to overwrite an existing tag's release.
The workflow serializes runs per tag. Its credentials, staging directory, inventory and
other release writers remain a trust boundary: this is not protection against an administrator
or another authorized process deliberately changing a draft during the final API calls.

### Run the offline terminal demo

```sh
python3 tools/demo-release-gate.py --out /tmp/rio-release-demo
python3 tools/release-publish_test.py
```

Use a new output directory for each run. The demo executes the production guard with synthetic
files and explicit offline substitutes for GitHub and signature verification. It performs real
hashing, inventory checks, byte comparisons and publication decisions, but does not authenticate
signatures or create a GitHub release. Four cases show an unchanged candidate proceeding and
replaced bytes, missing attestations and rejected verification stopping publication.

The output directory retains each scenario's files, inventories, service-call log, exact shell
commands, raw output, `results.json`, and a structured JSON/text transcript. The guided recording
inspects real demo archives, records fingerprints, and confirms publication side effects. The `remote/` directory and `published`
marker are the offline publisher's observable output. The fixtures live under
`tools/testdata/release/`; they must never be used as production verification tools.

To render that actual transcript as a short captioned MP4, install Pillow in a Python environment
and make `ffmpeg` available, then run:

```sh
python3 tools/render-release-demo.py \
  /tmp/rio-release-demo/transcript.json /tmp/rio-release-demo.mp4
```

The renderer uses Menlo on macOS or DejaVu Sans Mono on Linux; `--font /path/to/font.ttf`
selects another monospace font. On macOS, add `--voice Samantha` for spoken explanations.
Each case has a setup card, animated typing of the full commands, captured output, an explanation
and a distinct end card. MP4 chapters allow navigation between cases. The renderer writes scene
PNGs and a timeline alongside the video for visual inspection.
Only the optional renderer needs Pillow and ffmpeg; the demo and guard tests use the standard
Python library (the demo also uses bash, tar and shasum). The video preserves command output
and slows playback for reading; it clearly labels the offline service substitutes. Commands remain
on screen above their output. Version 2 transcripts require a fresh run of the demo capture command.

## Manifest enrichment demo

The [standalone enrichment demo](demo-enrichment/README.md) includes synthetic CycloneDX 1.6
SBOMs, three manifests and a shell runner. It uses a real installed rio release containing #61;
Python 3.9+ reads structured results; no Go toolchain, source build, jq or network access is needed. Copy `demo-enrichment/`
with its inputs from the matching tagged source archive, or use it from a checkout:

```sh
./tools/demo-enrichment/run.sh
# Or select an installed binary:
RIO_BIN=/absolute/path/to/rio ./tools/demo-enrichment/run.sh
```

Two products inherit organization and product defaults while supplying their own identities and
documentation URLs. A separate case refuses a conflicting existing subject with exit 2 and no new
output files; an explicit `replace` list then permits just the named fields to change. The runner
shows plans and subject before/after values and retains the complete inputs, plans, conflict log,
SBOMs, indexes and unsigned statements in a fresh temporary directory printed at exit. See the
[demo README](demo-enrichment/README.md) for expected values, inspection paths and limits.

## CI build context demo

The [standalone context demo](demo-context/README.md) contains two synthetic CycloneDX SBOMs
from different repositories, a shared context JSON file, three refusal cases, a prior-claim
replacement case and a POSIX shell runner. Use an installed Rio release containing #62 and the
matching tagged source archive; Python 3.9+ reads structured results; no Go toolchain, source build, jq or network is needed:

```sh
./tools/demo-context/run.sh
RIO_BIN=/absolute/path/to/rio ./tools/demo-context/run.sh
```

The runner first plans while the context file is absent, then normalizes both artifacts, reruns
to compare output bytes, checks stale-digest/missing-required-field/prior-revision refusals, and
applies explicit replacement for revision plus omitted workspace and build ID. It retains every
input, plan, output and diagnostic in a unique temporary directory printed at exit.

## rio-context.py

`rio-context.py` is an optional Python 3.9+ standard-library helper for a CI producer. It hashes
the **original local SBOM bytes** and prints one complete `contextVersion: 1` document containing
one artifact entry. The caller supplies every asserted value explicitly as flags. There is no
Git, CI-provider or environment discovery, clock default, network call, JSON merge, or call to
Rio. Redirect stdout to a temporary file and move it into place after the command succeeds:

```sh
set -eu
if python3 tools/rio-context.py \
  --artifact-id console --sbom target/console.cdx.json \
  --source-repository "$CI_SOURCE_URL" --source-revision "$CI_REVISION" \
  --source-workspace "$CI_WORKSPACE" --build-url "$CI_RUN_URL" \
  --build-id "$CI_RUN_ID" --generator-name 'CycloneDX Gradle Plugin' \
  > build-context.tmp.json; then
  mv build-context.tmp.json build-context.json
else
  rm -f build-context.tmp.json
  exit 1
fi
rio normalize --manifest rio.yaml
```

Pass only variables your CI job has actually established; the helper never reads these names
itself. For multiple artifacts, call it per artifact and have a producer assemble the one strict
JSON file required by Rio, or author that file directly with a JSON encoder. The helper does not
merge entries. Available flags cover all v1 leaves: `--source-repository`,
`--source-revision`, `--source-subdirectory`, `--source-ref`, `--source-workspace`,
`--build-url`, `--build-id`, `--build-timestamp`, `--build-system-name`,
`--build-system-version`, `--generator-name`, `--generator-version`, and `--lifecycle`.
`--artifact-id` and `--sbom` are mandatory. The helper checks obvious format errors before
writing any JSON; Rio remains the final validator of the context and manifest binding. See
the [native context contract](../docs/context.md) for field meaning and
authority limits.

## feature-video

The [feature-video tooling](feature-video/README.md) builds the narrated walkthrough of the
CI context feature: it runs the demo's commands for real, synthesizes the narration, draws a
split-screen terminal replay and checks the encoded result. Five steps, kept apart because
they fail for unrelated reasons and only one of them costs money:

```sh
python3 tools/feature-video/capture.py     # run the commands, record what they printed
python3 tools/feature-video/narrate.py     # synthesize the narration (about $0.16 a pass)
python3 tools/feature-video/render.py      # draw the frames and encode
python3 tools/feature-video/verify.py      # check the result is worth publishing
python3 tools/feature-video/bundle.py      # assemble the portable viewing folder
```

Outputs land in `target/feature-video/`, which is not tracked: the video is tens of megabytes
and regenerable, so what is committed is the thing that regenerates it.

Authoring needs Pillow, ffmpeg, a Go toolchain for the capture, and — for narration only —
the 1Password CLI and a paid Google Gemini key. None of them is a rio runtime dependency, and
none is needed to watch the video or to run the
[demo it walks through](demo-context/README.md).

The narration voice is a recorded decision: Google Gemini `gemini-3.1-flash-tts-preview`,
voice `Charon`, under fixed director instructions. The tool refuses to substitute another
model rather than quietly producing a video in the wrong voice. Clips are cached by a digest
of provider, model, voice, direction and the line itself, so editing one sentence re-buys one
sentence. `python3 tools/feature-video/narrate.py --dry-run` prints the estimate before
anything is spent.

`python3 tools/feature-video/feature_video_test.py` covers the pacing rules, the cache, the
audio decoding and the failure paths. It runs in CI, makes no network calls and reads no
credentials — the synthesizer is stubbed, so a test run never spends anything.

## Artifact sets demo

[`demo-artifact-sets/`](demo-artifact-sets/) supplies synthetic marker files, SBOMs, manifests and a
POSIX-shell runner. Use an installed Rio release containing #71, a shell and standard utilities;
Python 3.9+ is required; no Go toolchain, Maven, jq or network is needed:

```sh
./tools/demo-artifact-sets/run.sh
# Or choose the installed binary explicitly:
./tools/demo-artifact-sets/run.sh /path/to/rio
```

The runner copies fixtures into a temporary directory and retains the inputs, logs and outputs
for inspection. Every normalize run uses a fresh output directory. It checks explicit-only,
sets-only and mixed manifests; excludes a client through the marker selector; adds a server
without changing `rio.yaml`; removes only that server's SBOM to demonstrate exit 2 in both plan
and normalize; removes the marker to demonstrate absence from the new index; applies an explicit
marker exclusion; and refuses overlapping sets before output.

The copied reporting SBOM deliberately keeps its original subject: directory names define Rio
output IDs, not software identity. Markers are selected by filename; their XML is never parsed.
See [manifest semantics and limitations](../docs/manifest.md#discovering-module-artifacts), including
context/transform path rules and stale-file behavior. The current `index.json`, rather than every
file in a reused directory, defines membership.

## Agent integration examples

The [integration guide](../docs/agent-integration.md) and [examples](demo-agent-integration/) cover explicit inputs, discovered modules, mixed configuration, missing producers and ambiguous membership. Synthetic producers copy fixture SBOMs; they do not generate a real project's inventory.

Run with an installed Rio 0.7.0+, Python 3.9+, POSIX shell and standard utilities:

```sh
./tools/demo-agent-integration/run.sh /path/to/rio
RIO_BIN=/path/to/rio python3 tools/demo-agent-integration/test.py
```

No Go/Maven toolchain or network is required for these offline fixtures. Each execution uses its returned `runDirectory` and automatic receipt. Tests retain exact membership, deterministic SBOM/index, configured metadata and failed-run output checks.

### Copyable CI step

Copy [ci.sh](demo-agent-integration/ci.sh) into an existing producer pipeline and pass its actual build command:

```sh
sh ci/rio.sh /path/to/rio sh ci/build-and-sbom.sh
```

It stops on producer failure, previews the configuration, then runs the configured root pipeline once. Connect the printed automatic receipt path to the existing CI artifact collector. No client bundle is assembled, and failed runs are not presented as completed work. Configured targets may use the network. Producer freshness remains the build's responsibility.

### Automated checks

The onboarding checks cover literal path handling, ordered membership, existing settings, inclusion/exclusion, producer/gate failures and independent run/receipt isolation. The [evaluation procedure](demo-agent-integration/EVALUATION.md) separately evaluates an agent's configuration decisions; it is not a claim about a live agent run.

## First repair sample

[demo-repair/](demo-repair/) is a specialist offline example: one synthetic CycloneDX SBOM with a Gson P2 URL, a manifest selecting repair, and before/after evidence. It requires Rio 0.7.0+, Python 3.9+, POSIX shell and ordinary utilities, without Go, Maven, jq or a mapping-table download.

```sh
./tools/demo-repair/run.sh /path/to/rio
```

The example verifies unchanged input bytes, the repaired Maven URL, counts, schema and gate. It finds SBOM/index/receipt through the structured run result and leaves its temporary output available for inspection. [Repair semantics](../docs/p2-repair.md).

## Native verified delivery

The product's [delivery reference](../docs/delivery.md) explains Dependency-Track configuration, scoped credentials, projects, TLS/HTTP policy, native journals, explicit retries and observations. Normal root use is one `rio` invocation; deliberate stage commands each produce an honestly scoped receipt.

Synthetic installed-binary demonstrations require Python 3.9+:

```sh
python3 tools/demo-delivery/run.py /path/to/rio
python3 tools/demo-dtrack-tls/run.py /path/to/rio
```

The first exercises one root pipeline, exact bytes, indexed membership, fan-out/exclusions, preflight refusal, partial delivery, lost responses, explicit retry, gate override and unsupported-schema reporting. The TLS demo checks verified custom CA, explicit bypass, policy drift refusal and source-free receipt rendering. Runtime secret canaries must not appear in retained output.

These local receiver simulations are not real-server compatibility claims. The existing [Dependency-Track integration harness](demo-delivery/integration/README.md) provisions pinned disposable services with scoped synthetic credentials and verifies uploaded bytes/projects/tokens. Existing CI runs this separately from synthetic demos. Do not treat a skipped integration as a pass.

## Consolidated record demo

The directory name is historical; the current [receipt demo](demo-record/README.md) demonstrates separate compact receipts rather than an assembled history bundle:

```sh
python3 tools/demo-record/run.py /path/to/rio
```

It exercises one root pipeline, a lost-response attempt, explicit retry and three independent reconciliation invocations. Earlier public receipts remain byte-identical. After receiver shutdown and source removal, it inspects/renders each receipt and refuses dangling references and contradictory acknowledgment claims. Requires Rio 0.7.0+ and Python 3.9+; no Go or external receiver is needed.

## Native OCI delivery

The [OCI product reference](../docs/delivery.md#oci-registries) covers repository configuration, authentication, attachment and response meanings. The [installed-binary demonstration](demo-oci/README.md) is runnable with Python 3.9+:

```sh
python3 tools/demo-oci/run.py /path/to/rio
```

It preserves standalone/attached graph checks, exact submitted representations, mixed DTrack/OCI routing, credential/policy boundaries, already-present read-back, failed gate/tampered bytes, unusable receipts, lost responses, content mismatch and an actual killed delivery process. Automatic receipts stay separate by invocation and remain inspectable after the receiver and source workspace are gone.

The [real-registry harness](demo-oci/integration/README.md) uses the existing disposable Distribution/Zot/Nexus paths. Historical committed observation JSON is labeled as historical adapter evidence, not verification of a new candidate. Final integration must identify the exact tested candidate and actual native/archive execution scope.

## Client evidence demos

**Start here:** [actual generated JSON](demo-client-record/example/record.json), [offline HTML](demo-client-record/example/report.html), and [complete runnable ZIP](demo-client-record/example/example.zip). The standard receipt is 5,729 readable UTF-8 bytes, including full digests, URLs, timestamps and tokens. Its SBOMs, receiver and tokens are explicitly synthetic.

```sh
python3 tools/demo-client-record/run.py /path/to/rio
python3 tools/demo-batch-evidence/run.py /path/to/rio
python3 tools/demo-normalization-evidence/run.py /path/to/rio
```

All require an installed Rio 0.7.0+ and Python 3.9+; none requires a Go toolchain. The client example makes one root invocation per case, verifies exact context fields and multipart bytes/projects, then removes source state and stops the receiver before receipt-only inspection/rendering. The batch demo covers partial/unattempted/excluded pairs, explicit retry and actual process interruption with offline recovery **without lock breaking or upload replay**. The normalization demo keeps repair provenance and uplift in a specialist setting, with compact counts in the receipt and detailed local normalized outputs.

Each normal execution automatically publishes one `rio-run-receipt`, schema version 1. No `--evidence`, collection step, embedded source archive or legacy format reader remains. A retry/reconciliation has its own receipt with prior references, not a merged account of work from different invocations. See the [field guide, bounds and recovery semantics](../docs/output.md).

## Authored release notes

`release-notes.py` selects `docs/releases/<tag>.md` before `release-publish.py stage` freezes the
release inventory. The first line must identify the exact tag (`# Rio v0.6.0`, optionally followed
by a title), and the body must be nonempty. Exact bytes are copied into `dist/CHANGELOG.md`, which
remains inside the existing verification/publication boundary.

Tags v0.6.0 and newer, including prereleases, refuse missing, empty or mismatched authored notes.
For tags below v0.6.0, a missing authored file explicitly permits the nonempty generated GoReleaser
changelog; an authored file that exists still must validate. Existing tags/releases remain immutable.

## Published-release verification

`verify-release.py` downloads the complete stable OS/architecture asset set into a fresh directory,
checks archive checksums, the Sigstore checksum bundle, and GitHub build/SBOM attestations against
the exact repository, release workflow/tag and source commit. The downloaded source SBOM must match
the signed predicate, and the public non-draft release body must match the supplied authored notes.
Only after those checks does it extract and execute the native binary, assert version/commit, and
run the complete client-record demo. It does not install or replace a user's Rio binary.

```sh
python3 tools/verify-release.py --tag v0.7.0 --commit FULL_VERIFIED_COMMIT \
  --notes docs/releases/v0.7.0.md --output /absolute/new/private/verification
```

Requires Python 3.9+, `gh` and `cosign`. The manual `Verify published release` workflow runs the same
checks with native Linux/macOS/Windows binaries and installs the Homebrew cask only on a disposable
macOS runner. Its input commit is the exact verified integrated commit. Architecture execution is
reported explicitly; verifying an archive is not a claim that its binary ran natively.
`--legacy-smoke` permits version-only execution for older releases before v0.6.0, which lack this
client demo. It is refused for v0.6.0 and newer, so it cannot waive this release's client gate.

# tools

Things that support rio without being part of it. Nothing here ships in the binary, nothing here is
covered by rio's compatibility promises, and rio never calls any of it.

These tools handle network services and external signing dependencies around rio. Keeping them
out of the binary lets rio stay static, `CGO_ENABLED=0`, and run identically on a build agent
with no egress. The table builder and uploader make network calls; the signing tool uses local
keys and explicitly disables public transparency-log upload.

| tool | what it does | when you run it |
|---|---|---|
| [`build-p2-table.py`](#build-p2-tablepy) | builds the bundle-symbolic-name → Maven coordinate table rio repairs purls with | occasionally, on a workstation |
| [`rio-dtrack-upload.sh`](#rio-dtrack-uploadsh) | uploads normalized SBOMs to DependencyTrack | after every `rio normalize`, in a pipeline |
| [`rio-attest-sign.sh`](#signing-and-verifying-normalization-attestations) | signs and verifies normalization statements with a local key | after `rio normalize --attest` |

---

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

## rio-dtrack-upload.sh

Uploads the SBOMs from a `rio normalize` run to DependencyTrack, reading `index.json` to find them.

```sh
mvn -B verify
rio normalize --gate fail
DTRACK_URL=https://dtrack.example.com DTRACK_API_KEY=... \
  ./tools/rio-dtrack-upload.sh target/rio/index.json
```

It ships as an example, and it is deliberately not part of rio: rio does not upload anywhere. It
needs `DTRACK_URL` and `DTRACK_API_KEY` and stops immediately without either. The API key needs the
`BOM_UPLOAD`, `PROJECT_CREATION_UPLOAD` and `VIEW_PORTFOLIO` permissions. The comment block at the
top of the script lists every variable it reads.

### Nesting artifacts under one project

So that a product and its parts hang together in the portfolio, name the parent:

```sh
DTRACK_URL=https://dtrack.example.com DTRACK_API_KEY=... \
DTRACK_PARENT_NAME="RCP Product" DTRACK_PARENT_VERSION=2026.1 \
  ./tools/rio-dtrack-upload.sh target/rio/index.json
```

`DTRACK_PARENT_UUID` addresses the parent directly and is unambiguous. Set one or the other, not
both, since DependencyTrack ignores the name when a uuid is present.

Two things about parents are DependencyTrack's behaviour rather than the script's, and the script
reports both rather than letting them pass as silence:

- **The parent must already exist.** DependencyTrack looks it up and answers 404 rather than
  creating it.
- **The parent is applied only when the child is created.** Re-uploading a project that already
  exists leaves its place in the hierarchy alone, whatever the parent settings say. The script
  checks first and warns when that is about to happen.

### Tests

`rio-dtrack-upload_test.sh` covers the script offline — no DependencyTrack instance, no network:

```sh
./tools/rio-dtrack-upload_test.sh
```

CI runs it, along with `shellcheck`, whenever a `.sh` file changes.

---

## Signing and verifying normalization attestations

`rio normalize --attest` writes unsigned `<artifact-id>.intoto.json` statements beside the
normalized SBOMs. The [statement contract](../README.md#normalization-attestations) describes
their subjects, digests and normalization evidence. The rio binary remains self-contained and
makes no network calls. The optional `rio-attest-sign.sh` tool signs these existing statements
and verifies each bundle before publishing it beside its SBOM.

### Requirements and identity

The signing tool needs Bash 3.2+, jq, **cosign v3.0.6** (the same version as `release.yaml`), and
`sha256sum` or `shasum`. It rejects other cosign versions so a dependency upgrade cannot silently
change the signing defaults. Install cosign from its
[v3.0.6 release](https://github.com/sigstore/cosign/releases/tag/v3.0.6).

Supply a local private key and the corresponding PEM public key explicitly. The tool checks that
they match and unlocks the private key before signing anything. It does not generate keys or
fall back to OIDC or an interactive browser. The same interface works on a workstation and in CI;
no `id-token: write` permission is needed.

If you need a new key pair, generate it once in a secure directory:

```sh
cosign generate-key-pair --output-key-prefix signer
```

Keep `signer.key` private and distribute `signer.pub` through a trusted channel. Supply its password
as `COSIGN_PASSWORD`, using your CI secret store or a prompt on a workstation:

```sh
# Bash: read the password without echoing it or putting it in shell history.
read -r -s -p 'Signing key password: ' COSIGN_PASSWORD; printf '\n'
export COSIGN_PASSWORD

rio normalize --attest --out target/rio
./tools/rio-attest-sign.sh \
  --key /secure/signer.key --public-key /trusted/signer.pub target/rio
unset COSIGN_PASSWORD
```

`COSIGN_PASSWORD` must be set; explicitly empty is allowed for a key with an empty password.
The script never prints it and never prompts for it. Key files, passwords and customer outputs
should not be committed to this repository.

### Privacy and output

This tool uses **key-based signing with public transparency-log upload disabled**. It passes
`--tlog-upload=false --use-signing-config=false` explicitly to the pinned cosign version. There
is no public-log opt-in or keyless mode in this version. Private Rekor and keyless signing with a
trusted timestamp authority require separate service and trust configuration and are not supported.
In cosign v3.0.6 the log flag still works but is deprecated; revisit these flags when changing the pin.

For every artifact in `index.json`, the tool checks that the statement's type, subject and complete
predicate match that run, and hashes the actual SBOM. Missing or stale extra statements, malformed
JSON, mismatched digests, symlinks and existing destination bundles are refused before signing.
The accepted layout is rio's flat `<artifact-id>.cdx.json` / `<artifact-id>.intoto.json` layout.
A statement recording a failed quality gate can still be signed: the signature records that result,
and does not imply the gate passed.

Each `<artifact-id>.sigstore.json` contains the original statement in a signed DSSE envelope and
its verification material. Statements, SBOMs and `index.json` are unchanged; `index.json` is not
signed. Bundles have owner-only permissions. The tool stages copies in the output directory,
verifies each bundle, and publishes it without replacing an existing file. Allow disk space for
copies of the input files and do not run normalization concurrently with signing.

Exit codes are 0 when every bundle verifies, 2 for usage or preflight errors, and 1 for signing,
verification or publication errors. Signals also fail the run and remove staging files. If a later
artifact fails, earlier verified bundles remain and the command reports failure. To retry, use a
fresh normalization output directory; existing evidence is never overwritten.

### Recipient verification

A recipient needs cosign v3.0.6, the normalized SBOM, its bundle, and an independently trusted
public key. No rio installation, checkout, unsigned statement or `index.json` is needed:

```sh
cosign verify-blob-attestation \
  --key signer.pub \
  --bundle rcp-client.sigstore.json \
  --type https://rebaze.com/attestation/sbom-normalization/v1 \
  --insecure-ignore-tlog \
  rcp-client.cdx.json
```

This is the same verification the signing tool performs. The command checks the signature,
predicate type and SBOM digest. `--insecure-ignore-tlog` deliberately skips transparency-log
verification for this private mode; cosign prints a warning. It does **not** skip signature or
subject-digest verification. A key supplied only alongside an untrusted bundle is not an
independent trust anchor: authenticate the public key through your established distribution process.

A valid signature proves that the corresponding private key signed the statement. Without a
transparency log or trusted timestamp it does not establish a trusted signing time. It also does
not independently prove the recorded normalization was performed correctly. The statement's paths
are local references, not download URIs; checking the recorded input and manifest digests requires
retaining those original files.

### Tests

The shell suite replaces cosign with a PATH shim and exercises the real argument, JSON, digest,
file and failure handling without contacting Fulcio or Rekor:

```sh
./tools/rio-attest-sign_test.sh
```

CI runs it with the other offline shell tests and checks both scripts with ShellCheck. Real-cosign
verification should also be exercised with disposable keys and synthetic SBOMs when changing the
pinned version or signing commands.

# tools

Things that support rio without being part of it. Nothing here ships in the binary, nothing here is
covered by rio's compatibility promises, and rio never calls any of it.

They live together because they share one property: **rio makes no network calls**, and both of
these do. Keeping them out of the binary is what lets it stay static, `CGO_ENABLED=0`, and run
identically on a build agent with no egress. The work that needs a network happens here instead,
ahead of time or afterwards, where a human can look at the result.

| tool | what it does | when you run it |
|---|---|---|
| [`build-p2-table.py`](#build-p2-tablepy) | builds the bundle-symbolic-name → Maven coordinate table rio repairs purls with | occasionally, on a workstation |
| [`rio-dtrack-upload.sh`](#rio-dtrack-uploadsh) | uploads normalized SBOMs to DependencyTrack | after every `rio normalize`, in a pipeline |

---

## build-p2-table.py

Produces the mapping table rio consumes. It reads the SBOMs you already have, takes the bundle
symbolic names rio could not map, and resolves them against Eclipse's and Maven Central's published
metadata. Python 3.9+, standard library only.

```sh
python3 tools/build-p2-table.py path/to/bom.cdx.json \
    --out   mappings/p2-maven.json \
    --cache .p2cache
```

Point your manifest's `table:` at the result and rio picks it up:

```yaml
transforms:
  - repair-purl:
      ecosystem: p2
      table: mappings/p2-maven.json
```

### Why it exists

A bundle symbolic name is not reliably `groupId.artifactId`, and the cases where it differs are
exactly the ones that matter:

| symbolic name | actual coordinate | what splitting the name would give |
|---|---|---|
| `com.google.inject` | `com.google.inject:guice` | `com.google:inject` |
| `com.ibm.icu` | `com.ibm.icu:icu4j` | `com.ibm:icu` |
| `com.sun.jna.platform` | `net.java.dev.jna:jna-platform` | nothing resembling it |
| `org.apache.commons.cli` | `commons-cli:commons-cli` | `org.apache.commons:cli` |
| `org.apache.httpcomponents.httpclient` | `…:httpclient-osgi` | `…:httpclient` |
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

4. **Maven Central by exact SHA-1.** Exact when it hits, where the SBOM's hashes are usable at all.
   It asks only about what the stages above could not settle and skips any hash shared by more than
   one component, so it is normally a handful of requests. `--no-hash` turns it off.

`--search` is separate and off by default. It lets stages 2 and 3 ask `search.maven.org` which
groupIds publish a given artifactId. On the estate this was built for it found nothing the other
stages had not already found, and it is slow, because every answer it offers still costs a jar to
verify. It is also the only rate-limited dependency here.

### What it refuses to answer

Two outcomes are reported rather than guessed at, both in `<out>.review.md`:

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

### Curated entries and reruns

`--existing` entries are **never** overwritten, on the principle that a coordinate a human decided
outranks anything derived. That makes the intended layout two files rather than one:

```sh
python3 tools/build-p2-table.py bom.cdx.json \
    --existing curated.json \
    --out      p2-maven.json \
    --cache    .p2cache
```

`curated.json` holds only what you settled by hand; the rest is regenerated on every run and your
entries always win. Pointing `--existing` at the *generated* file instead is a silent no-op — every
entry in it is preserved, so nothing ever updates. `--overwrite` lifts the rule entirely.

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

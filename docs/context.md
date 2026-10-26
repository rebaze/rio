# Build and source context

[Manifest](manifest.md) · [Output records](output.md) · [Runnable demo](../tools/README.md#ci-build-context-demo)

This feature was added after v0.3.0. See [feature availability](manifest.md).

Bind an optional producer-supplied JSON document to each artifact. There are no root context
defaults. The file path resolves from the manifest directory; Rio selects an entry by exact
artifact ID and checks its `sbom.sha256` against the **original input SBOM bytes**:

```yaml
version: 1
artifacts:
  - id: console
    sbom: target/console.cdx.json
    context:
      file: build-context.json
      require: [source.repository, source.revision, build.url]
      replace: [source.repository]
```

`file` is required. `require` and `replace` default to empty arrays. `require` demands an explicitly
supplied leaf in the selected entry; an inferred or defaulted value does not count. `replace`
permits that exact leaf to change an existing subject reference or prior Rio-owned context claim.
It can name an omitted leaf to permit removal of an old owned assertion. Replacement is never a
wildcard. The allowed leaves are `source.repository`, `source.revision`,
`source.subdirectory`, `source.ref`, `source.workspace`, `build.url`, `build.id`,
`build.timestamp`, `build.system.name`, `build.system.version`, `generator.name`,
`generator.version`, `lifecycle` and `level`. `lifecycle` and `level` may be required but cannot be replaced.
IDs and digests cannot be replaced, so `distributions` can be named in neither list.
Duplicate/unknown selectors and wrong YAML types fail.

The file is one strict `contextVersion: 1` JSON document. A single file can serve multiple
artifacts; all entries must be structurally valid, but unselected entries are not matched by
filename or digest. Here is a complete two-entry example (use each real input SBOM's lowercase
64-character SHA-256 digest in place of the illustrative repeated digits):

```json
{
  "contextVersion": 1,
  "artifacts": [
    {
      "id": "console",
      "sbom": {"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
      "source": {
        "repository": "https://code.example.org/widgets/console",
        "revision": "1111111111111111111111111111111111111111",
        "subdirectory": "apps/console",
        "ref": "refs/heads/main",
        "workspace": "clean"
      },
      "build": {
        "url": "https://ci.example.org/runs/42",
        "id": "42",
        "timestamp": "2026-01-01T12:00:00Z",
        "system": {"name": "Gradle", "version": "8.14"}
      },
      "generator": {"name": "CycloneDX Gradle Plugin", "version": "3.0.0"},
      "lifecycle": "build",
      "distributions": [
        {
          "name": "console-1.0.0-linux-amd64.tar.gz",
          "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
          "url": "https://downloads.example.org/console/1.0.0/console-1.0.0-linux-amd64.tar.gz"
        },
        {
          "name": "console-1.0.0-windows-amd64.zip",
          "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
        }
      ]
    },
    {
      "id": "agent",
      "sbom": {"sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},
      "source": {"repository": "https://code.example.org/agents/agent"},
      "build": {"url": "https://ci.example.org/runs/7"}
    }
  ]
}
```

Only `id` and `sbom.sha256` are mandatory in each entry unless the binding requires more.
Digests must be lowercase SHA-256 hex. Revisions must be full 40- or 64-character lowercase hex;
abbreviated or uppercase revisions are refused. Repository and build URLs must be absolute
HTTP(S) URLs with a hostname and no credentials, query or fragment. `subdirectory` is a canonical
relative POSIX directory; omit it for repository root. Supplied strings must be nonblank and have
no surrounding whitespace or controls. `source.workspace` is `clean`, `dirty` or `unknown`.
When a source object exists but omits workspace, Rio records effective `unknown` and lists
`source.workspace` under `defaulted`; this does **not** satisfy `require` for that leaf. Build
timestamps must be RFC3339. A supplied build system or generator must have a name; version is
optional. Lifecycle phases are `design`, `pre-build`, `build`, `post-build`, `operations`,
`discovery`, `decommission`. `level` is `logical`, `identified` or `assembled` (see
[TR file components](#tr-file-components)). A supplied `distributions` array is nonempty and holds at most
1000 objects with `name`, `sha256` and an optional `url`, and optionally `sha512`, `executable`,
`archive` and `structured`, which come together or not at all. Each `name` follows the
supplied-string rule, contains neither `/` nor `\`, is not `.` or `..` and is unique within the
entry; `sha256` is lowercase 64-character hex; `sha512` is lowercase 128-character hex; `executable`,
`archive` and `structured` are booleans; `url` follows the repository URL rule and is
unique within the entry. Unknown JSON keys, duplicate keys at any depth, null/wrong types,
trailing documents, empty artifact lists and duplicate IDs fail before outputs are written.

`source.repository` maps to the subject's `vcs` external reference and `build.url` to its
`build-system` external reference. Matching rich references and unrelated references remain;
different existing values require the corresponding `replace` selector. These claims apply only
to `metadata.component`, never to dependency components. Other effective values remain in a
structured context record in `index.json`, the optional normalization statement and one active
`rebaze:normalize:context` SBOM metadata property. The property value is JSON with `version: 1`,
the context file's relative path and raw-byte digest, `/artifacts/N` selector, effective values,
defaulted fields, `assertion: "producer"`, and changes. Each change names a field, target,
before/after values, source selector and whether replacement was explicitly authorized. A
`context:/...` target denotes a logical context claim; `/metadata/...` denotes an SBOM mutation.
An omitted prior field is an auditable removal with `after: null`; absent revision, workspace or
build ID values are never silently inherited from a prior snapshot. The index artifact and
statement artifact carry identical context records.

The record's `ownedReferences` array lists `source.repository` and/or `build.url` only when
Rio added the corresponding bare native reference, and `distribution:<name>` for each
distribution reference Rio added (see [shipped files](#shipped-files-distributions)). Ownership
survives unchanged snapshots. An authorized omission of `source.repository` or `build.url`
removes that exact reference and records the native before/after arrays as well as the logical
removal. Pre-existing references, unrelated references and
references subsequently augmented with comments or hashes remain. Earlier v1 context records
without `ownedReferences` are accepted: Rio derives ownership only from an explicit native
addition in their change audit; otherwise it preserves the reference because ownership is
unknown. This extends the context record; context input files remain unchanged.

The generator claim describes the producer's reported generator. Rio preserves original
`metadata.tools` and separately records itself as the normalizer; it never re-labels the
generator as a tool that edited the original SBOM. A supplied lifecycle fills an empty native
`metadata.lifecycles` array. If native known phases exist, the supplied phase must match one of
them; the full native array stays. A custom-only array also stays, with the supplied phase held
as a separate context assertion. No phase is inferred from timestamps, and a prior owned
lifecycle assertion cannot be changed or removed.

## Shipped files (`distributions`)

`distributions` lists the files the producer ships for the artifact and the SHA-256 of each.
Checksum files such as `sha256sum` output or a GoReleaser `checksums.txt` already hold these
values; [`rio-context.py --checksums`](../tools/README.md#rio-contextpy) turns one into entries.
Rio adds one `distribution` external reference per entry to `metadata.component`, in context
order, after any existing references. `url` is the entry's `url`, or its `name` percent-encoded as one relative path segment
(`app#debug.zip` becomes `app%23debug.zip`) when no URL is given. For the example above the console subject gains:

```json
[
  {
    "type": "distribution",
    "url": "https://downloads.example.org/console/1.0.0/console-1.0.0-linux-amd64.tar.gz",
    "hashes": [{"alg": "SHA-256", "content": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}]
  },
  {
    "type": "distribution",
    "url": "console-1.0.0-windows-amd64.zip",
    "hashes": [{"alg": "SHA-256", "content": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}]
  }
]
```

An existing `distribution` reference with the same URL and the same SHA-256 (compared without
regard to case) is kept as it is, not duplicated and not owned. The same URL with a different or
missing SHA-256 hash fails the run. Distribution references with other URLs stay untouched.
`ownedReferences` records `distribution:<name>` for each reference Rio added. The context record's
`effective` value carries the list, and the audit holds at most two changes, both with field
`distributions` and selector `/artifacts/N/distributions`: target `context:/distributions` with
`before: null` and the full list as `after`, and target `/metadata/component/externalReferences`
with the full before and after arrays when references were added.

Distributions are digests, so they cannot be replaced or removed. When an SBOM already carries a
Rio context record with distributions, the new entry must declare the same set (keyed by name,
with equal digests and URLs). A changed, added or removed file fails, as does omitting
`distributions`, and `replace` cannot authorize it. A prior record without distributions may
gain them.

The [run receipt](output.md) lists each declared file under the artifact's `distributions`
with its `name`, `sha256` and `assertion: "producer"`; the field is omitted when the entry
declares none. Distribution references the SBOM generator wrote are not copied into the
receipt. `gate.subject.require: [digest]` passes when the subject has a `distribution`
reference with a SHA-256 hash, whoever supplied it ([gate](manifest.md#output-version-and-gate)).
An OCI target that attaches the SBOM to a `subject` descriptor stops the planner with
`subject_digest_mismatch` naming the artifact, before any request, unless the descriptor digest
is one of the declared digests; nothing in that plan is delivered
([OCI delivery](delivery.md#oci-registries)).

Rio does not hash the shipped files and never opens them. A distribution digest is what the
producer says it shipped; nothing proves those files were built from the components the SBOM
describes. The [context demo](../tools/README.md#ci-build-context-demo) declares two synthetic
files and shows the references and the receipt list.

### TR file components

[BSI TR-03183-2](manifest.md#requirement-profiles) wants, for each shipped file, a SHA-512 hash,
the file name and three file properties. A `distributions` entry can assert them:

```json
{"name": "cart-api-1.4.0-linux-amd64.tar.gz",
 "sha256": "58a2b94946578e74c783026a5ca8813d57be893e3ce5d48977ce7945147846de",
 "sha512": "f4c3007ddcdee256119b1db68eafbab212b4f395e28f5dadd95568ca69df7da6ff1e8f01c713a8dc8ff5cced4481a6ea8885f383d31e35f18781348b25d882f2",
 "executable": false, "archive": true, "structured": true,
 "url": "https://downloads.example.org/cart-api/1.4.0/cart-api-1.4.0-linux-amd64.tar.gz"}
```

An entry carries `sha512`, `executable`, `archive` and `structured` all together or none; a partial
entry is refused when the context file is read, because half an assertion would only produce a gate
finding later, far from its cause. [`rio-context.py`](../tools/README.md#rio-contextpy) emits them
from SHA-512 checksum files. Rio still never hashes or opens a file: these are the producer's
assertions, recorded with `assertion: "producer"`.

For each entry that carries the four fields, rio adds one component under the subject, in
`metadata.component.components`. They are not in the top-level `components` array, so the
dependency component array in equals the one out ([output](output.md#what-rio-writes-into-the-output-sbom)),
and tools that read only the top-level array, such as Dependency-Track, do not list the shipped files.
The profile gate does check them. For the entry above, with the subject at version 1.4.0 and a
manufacturer and a concluded licence (this output comes from a real run on synthetic data):

```json
{
  "type": "file",
  "bom-ref": "rio:distribution:cart-api-1.4.0-linux-amd64.tar.gz",
  "name": "cart-api-1.4.0-linux-amd64.tar.gz",
  "version": "1.4.0",
  "manufacturer": {"name": "Example GmbH", "url": ["https://example.org"]},
  "licenses": [{"acknowledgement": "concluded", "expression": "Apache-2.0"}],
  "properties": [
    {"name": "bsi:component:filename", "value": "cart-api-1.4.0-linux-amd64.tar.gz"},
    {"name": "bsi:component:executable", "value": "non-executable"},
    {"name": "bsi:component:archive", "value": "archive"},
    {"name": "bsi:component:structured", "value": "structured"}
  ],
  "externalReferences": [{
    "type": "distribution",
    "url": "https://downloads.example.org/cart-api/1.4.0/cart-api-1.4.0-linux-amd64.tar.gz",
    "hashes": [
      {"alg": "SHA-256", "content": "58a2b94946578e74c783026a5ca8813d57be893e3ce5d48977ce7945147846de"},
      {"alg": "SHA-512", "content": "f4c3007ddcdee256119b1db68eafbab212b4f395e28f5dadd95568ca69df7da6ff1e8f01c713a8dc8ff5cced4481a6ea8885f383d31e35f18781348b25d882f2"}
    ]
  }]
}
```

(Rio writes keys in sorted order; they are reordered here for reading.) `version`, `manufacturer`
and `licenses` are copied from the subject, and only when the subject has them when the context is
applied. Enrichment runs first, so an `enrichment.subject.manufacturer` counts. A subject without
them leaves the file components without them, and the profile reports both. `executable`, `archive`
and `structured` map to `executable`/`non-executable`, `archive`/`no archive` and
`structured`/`unstructured`.

Rio also gives each file component its own empty `dependencies` entry, adds the file refs to the
subject's `dependsOn` (when the subject has a `bom-ref`; rio never invents one), and adds one
`compositions` entry with `aggregate: complete` over the file refs, because the producer listed
every file it ships. The `distribution` references on the subject itself are written as before,
with SHA-256 only, so `gate.subject.require: [digest]` works unchanged. Entries without the four
fields behave exactly as before: a reference on the subject and nothing else.

**`level`.** With its files listed as components, the subject is what the TR calls a logical
component (3.2.2). Generators do not say so, and rio never infers it. The entry's optional
`"level": "logical"` (also `identified` or `assembled`) is written to the subject as the property
`rio:tr-03183-2:level`, as a producer assertion. `level` can be named in `context.require` and
never in `replace`; a different value already on the SBOM fails the run.

**Audit and ownership.** Each addition is an audit change with `field: "distributions"` and
`selector: /artifacts/N/distributions` for these targets: `/metadata/component/components`,
`/dependencies` and `/compositions` (only the entries rio added or changed, not the whole array),
alongside the existing `context:/distributions` and `/metadata/component/externalReferences`
changes. The level property is a change with `field: "level"` on
`/metadata/component/properties`. `ownedReferences` lists `distribution-component:<name>` for
each file component rio added and `level` for the property.

**No replacement.** Distributions cannot be replaced, and that includes these components. A
component that has the same `bom-ref` and the same content is kept, not duplicated; any other
content, or another component with that `bom-ref`, fails the run with `distributions cannot be
replaced: <name>`.

The trap: the file components copy the subject's `version`, `manufacturer` and `licenses` at the
time the context is applied. If you change the subject's version, manufacturer or licences later
and normalize rio's own output again with the same `distributions`, the freshly built components
no longer match the ones already in the SBOM and the run is refused:

```text
rio: rio.yaml: artifact "cart-api": context /artifacts/0: context distribution "cart-api-1.4.0-linux-amd64.tar.gz" conflicts with an existing component with bom-ref rio:distribution:cart-api-1.4.0-linux-amd64.tar.gz; distributions cannot be replaced: cart-api-1.4.0-linux-amd64.tar.gz
```

Make those changes in the SBOM before the first context run, or build the SBOM again from its
source rather than editing the normalized output. A subject version bump is a new release with
new files and a new context file.

## Authority and contracts

This is a **producer assertion**, not authentication of the source, build or generated artifact
bytes. The context digest binds the local context file and the entry binds original SBOM bytes;
neither binds a compiled artifact, and declared distribution digests are not checked against
any file. Keep the original SBOM, raw context JSON, manifest and outputs for audit and
reproduction. Rio does not package them. Context support adds optional v1 records under the
existing plan/index/predicate v1 contracts, and distributions add an optional artifact field to
the `schemaVersion: 1` receipt; manifests without `context` retain their previous output shape. The
[offline context demo](../tools/README.md#ci-build-context-demo) and
[explicit producer helper](../tools/README.md#rio-contextpy) are documented with the other tools.

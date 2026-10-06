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
`generator.version`, and `lifecycle`. `lifecycle` may be required but cannot be replaced.
IDs and digests cannot be replaced. Duplicate/unknown selectors and wrong YAML types fail.

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
      "lifecycle": "build"
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
`discovery`, `decommission`. Unknown JSON keys, duplicate keys at any depth, null/wrong types,
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
Rio added the corresponding bare native reference. Ownership survives unchanged snapshots.
An authorized omission removes that exact reference and records the native before/after
arrays as well as the logical removal. Pre-existing references, unrelated references and
references subsequently augmented with comments or hashes remain. Earlier v1 context records
without `ownedReferences` are accepted: Rio derives ownership only from an explicit native
addition in their change audit; otherwise it preserves the reference because ownership is
unknown. This extends the unreleased context record; context input files remain unchanged.

The generator claim describes the producer's reported generator. Rio preserves original
`metadata.tools` and separately records itself as the normalizer; it never re-labels the
generator as a tool that edited the original SBOM. A supplied lifecycle fills an empty native
`metadata.lifecycles` array. If native known phases exist, the supplied phase must match one of
them; the full native array stays. A custom-only array also stays, with the supplied phase held
as a separate context assertion. No phase is inferred from timestamps, and a prior owned
lifecycle assertion cannot be changed or removed.

This is a **producer assertion**, not authentication of the source, build or generated artifact
bytes. The context digest binds the local context file and the entry binds original SBOM bytes;
neither binds a compiled artifact. Keep the original SBOM, raw context JSON, manifest and outputs
for audit and reproduction. Rio does not package them. Context support adds optional v1 records
under the existing plan/index/predicate v1 contracts; manifests without `context` retain their
previous output shape. The [offline context demo](../tools/README.md#ci-build-context-demo) and
[explicit producer helper](../tools/README.md#rio-contextpy) are documented with the other tools.

## Walkthrough recording

A narrated walkthrough of everything above — the manifest bindings, both products, the three
refusals and the audited replacement — is recorded from real command output and paced for
reading. **Public hosting is pending; this repository does not yet provide a viewing link.**
The MP4, captions, transcript and portable browser viewer are delivered separately. A fresh
checkout contains the [authoring sources](../tools/feature-video/README.md), not the rendered
video. The offline example itself needs only rio and a POSIX shell; the recorded authoring
and inspection commands also use Go, Python and jq.

# Manifest enrichment

[Manifest](manifest.md) · [Output records](output.md) · [Runnable demo](../tools/README.md#manifest-enrichment-demo)

This feature was added after v0.3.0. See [feature availability](manifest.md).

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
    issueTracker: https://products.example.com/issues
    releaseNotes: https://products.example.com/releases
    advisories: https://products.example.com/security/advisories
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
        links:
          - label: Fact sheet
            url: https://ea.example.com/factsheet/Application/console
output:
  specVersionFloor: "1.6"
```

The artifact's leaves override the corresponding shared leaves; omitted leaves inherit. Organization
`name`, `url` and `contact` are separate leaves, while each `url` or `contact` list is one value
and is replaced as a whole, not merged by position. An organization accepts a name, a list of
HTTP(S) URLs and a list of contacts with `name`, `email` and/or `phone`. Blank strings and null
values cannot remove defaults. Website, documentation, support, issue tracker, release notes and
advisories must be absolute HTTP(S) URLs without credentials; security contact also accepts a
`mailto:` address. [Links](#links) merge per label.

| Manifest field | CycloneDX target | Meaning |
|---|---|---|
| `subject.name`, `.group`, `.version`, `.type`, `.purl` | Corresponding fields under `metadata.component` | The described product's identity and component type |
| `subject.manufacturer` | `metadata.component.manufacturer` | Organization that made the product; requires 1.6 |
| `subject.supplier` | `metadata.component.supplier` | Organization supplying the product |
| `subject.securityContact`, `.website`, `.documentation`, `.support`, `.issueTracker`, `.releaseNotes`, `.advisories` | One typed entry each in `metadata.component.externalReferences`: `security-contact`, `website`, `documentation`, `support`, `issue-tracker`, `release-notes`, `advisories` | Product contact and information URLs |
| `subject.links` | Labelled entries in `metadata.component.externalReferences`; the label is the reference's `comment` | The organization's own links, such as a fact sheet. See [Links](#links) |
| `producer` | `metadata.manufacturer` | Organization that created the SBOM; requires 1.6 |
| `dataLicense` | `metadata.licenses` | One SPDX licence identifier for the SBOM data, such as `CC0-1.0`; an exception identifier such as `LLVM-exception` is refused at manifest load. Does not change component licenses |

CycloneDX 1.5 supports the other modeled fields. A 1.5 output with `producer` or
`subject.manufacturer` is refused: rio does not substitute a different organization role. The
configured spec floor applies first, so the default floor of 1.6 permits these fields on older
inputs after uplift. Unknown fields, malformed values and unsupported output targets fail with
exit 2 before writing outputs.

## Links

`subject.links` adds labelled links to the subject, for any ecosystem. The main use is a link to
the application's fact sheet in an enterprise-architecture tool such as LeanIX, which names its
owner:

```yaml
enrichment:
  subject:
    links:
      - label: Fact sheet
        url: https://<tenant>.leanix.net/<workspace>/factsheet/Application/<id>
```

The SBOM then carries this reference on `metadata.component`:

```json
{"type": "other", "url": "https://<tenant>.leanix.net/<workspace>/factsheet/Application/<id>", "comment": "Fact sheet"}
```

Each entry has `label`, `url` and an optional `type`:

- `label` is required and nonblank, must not contain `]`, and is unique within the effective list.
  It becomes the reference's `comment`.
- `url` is an absolute HTTP(S) URL without credentials. rio never fetches it.
- `type` defaults to `other`. It may be any CycloneDX 1.6 external reference type that no
  dedicated field already models; `website`, `documentation`, `support`, `security-contact`,
  `issue-tracker`, `release-notes` and `advisories` are refused, so use their fields. A type that
  only CycloneDX 1.6 defines (`source-distribution`, `electronic-signature`,
  `digital-signature`, `rfc-9116`) is refused at a 1.5 output with the hint to set
  `output.specVersionFloor: 1.6`.
- Two labels with the same type and URL are refused: the subject carries the reference once.

Each label is its own leaf, `subject.links[<label>]`. Shared and artifact lists merge by label,
and the artifact's entry wins for its label. `replace: ["subject.links[Fact sheet]"]` replaces
that one label; it is the selector in change records and in `rio plan --json` too. A shared link
cannot be removed for one artifact; leave it out of the shared list instead.

| The SBOM subject already has | Result |
|---|---|
| A reference with the same type and URL, and none with the label pointing elsewhere | Left alone, no change record. Its existing `comment`, if any, stays, so the label is not shown for it |
| No reference with this type and label | Added |
| A reference with the same type and label (`comment`) but another URL | Conflict, exit 2, unless the label is listed under `replace`. Replacement retires that reference, even when another one already has the requested URL |

References of other types or labels, including those the generator wrote, are never touched.
Repeat application adds nothing.

Dependency-Track copies `metadata.component.externalReferences` to the project on every upload
and replaces what was there, so the SBOM is the lasting place for these links. A link set in
Dependency-Track's UI or API disappears with the next upload to that version.

### Ownership, reporting and routing

CycloneDX has no field for an internal owner. `authors` is whoever made the product, and
`securityContact` is the public channel for reporting vulnerabilities; neither should carry the
internal owner. Keep the three apart:

| Question | Where | Why |
|---|---|---|
| Who is responsible for the product? | A `Fact sheet` link to the enterprise-architecture tool | The tool stays the source of truth. When the owner changes, published SBOMs still lead to the current name, and none needs rebuilding. SBOMs that leave the organization, to customers or authorities, carry no personal names |
| Where are vulnerabilities reported? | `subject.securityContact` | The public reporting channel, which recipients and the CRA expect |
| Who is notified of findings? | A Dependency-Track project tag such as `owner:<team>` | A link cannot route anything; a notification rule matches a tag, which lives on the project, not in the SBOM |

## Existing values and explicit replacement

An absent SBOM value is filled. An identical value is left alone. A different existing value
causes exit 2 with the artifact, field and source identified, and no generated SBOM/index is published; a failed execution receipt may still be written.
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

`replace` accepts only modeled leaf names with an effective enrichment value, including
`subject.links[<label>]` for one link. For example,
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
The [runnable enrichment demo](../tools/README.md#manifest-enrichment-demo) provides synthetic inputs
and examples for an installed release binary.

## Enrichment provenance and compatibility

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

Normalization indexes also retain enrichment's before/after changes in the independently versioned
[normalization ledger](output.md#normalization-change-evidence), alongside repair, uplift and
context changes. Existing enrichment producer assertions and their selectors remain available;
the ledger does not turn them into independently verified facts.

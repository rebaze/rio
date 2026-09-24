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

## Existing values and explicit replacement

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

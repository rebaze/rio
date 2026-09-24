# Repairing Eclipse p2 package URLs

[Manifest](manifest.md) · [Output records](output.md#reading-the-repair-records)

Use `repair-purl` when an Eclipse/Tycho SBOM contains p2 or synthetic Maven identities that
need Maven coordinates for downstream tools. Ordinary Maven package URLs do not need this transform.

```yaml
transforms:
  - repair-purl:
      ecosystem: p2
      # table: mappings/p2-maven.json
```

The optional table supplements the built-in mappings. Its path is relative to the manifest.
[`rio plan --json`](cli.md#the-plan-json) reports resolved transform options without opening the
table. The [mapping-table tool](../tools/README.md#build-p2-tablepy) prepares external tables;
Rio itself makes no network calls.

## Repaired, unmapped, skipped

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
first-party bundles are reported as unmapped rather than skipped. The unmapped count can therefore include first-party bundles that do not need a published
Maven coordinate.

The coordinate always comes from the purl's own `maven-groupId` qualifier, the component's
properties, or the mapping table, in that order. rio never splits a symbolic name to guess one:
`org.apache.commons.commons-io` becomes `org.apache.commons:commons-io` only because a curated
entry says so.

The three do not partition the components. `skipped` never appears on stdout, and the two halves of
the p2 transform are independent: dropping the Eclipse version qualifier can succeed while the
coordinate lookup finds nothing, so one component can be counted in both `applied` and `unmapped`.

The [command-output example](cli.md#usage) shows this behavior. Of its 12 components, 4 are out of scope: the two
first-party `tycho-demo` modules, an Eclipse feature, and an installable unit already carrying a
`pkg:maven` purl. The other 8 all had their purl rewritten, and one of them,
`org.eclipse.equinox.launcher.gtk.linux.x86_64`, is also the unmapped one: its version qualifier was
dropped, but the table has no entry for it, so it stays `pkg:p2/...`.

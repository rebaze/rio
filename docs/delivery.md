# Native delivery

[One-command workflow](quick-start.md) · [CLI and exit codes](cli.md) · [Receipt meanings](output.md)

Put intake and delivery in one `rio.yaml`, inject credentials through the environment, then run `rio`. All selected inputs are resolved, processed and checked before dependent uploads begin. The receipt records the destination URL, resolved project/repository, byte identities, transport policy and observed responses.

## Dependency-Track

```yaml
version: 1
artifacts:
  - id: app
    sbom: target/bom.json
delivery:
  targets:
    security:
      type: dependency-track
      url: https://dtrack.example.org
      apiKeyEnv: DTRACK_API_KEY
      autoCreate: true
```

Use the server base URL, before `/api/v1`. The default project selector is the normalized SBOM subject's name/version. An explicit selector can be `project: {name: app, version: '1.0.0'}` or `project: {uuid: '00000000-0000-4000-8000-000000000001'}`. UUID selection cannot use `autoCreate`. Project creation is false unless explicitly enabled. Target `overrides` can set project selection/creation per artifact; `exclude: [test-fixtures]` excludes artifact IDs.

The adapter sends a multipart SBOM and records a validated event token from HTTP 200. Known rejection statuses remain rejected; unexpected statuses, malformed token responses and lost responses remain unknown. Arbitrary HTTP bodies and credential values are not retained. `delivery reconcile` can query the event token: no processing currently observed is not proof that analysis or ingestion completed.

Credentials must allow the requested BOM upload and, if enabled, project creation. Provision a scoped receiver account appropriate for the projects. Rio does not create the account or manage its access policy.

### Tags, parent and latest version

Dependency-Track reads a project's tags, parent and "latest version" flag only from the upload request, never from the SBOM. Set them on the target, and override them per artifact like `project`:

```yaml
delivery:
  targets:
    security:
      type: dependency-track
      url: https://dtrack.example.org
      autoCreate: true
      tags: [owner:payments, team:checkout]
      parent: {name: Payments, version: all}
      isLatest: true
      overrides:
        agent:
          tags: [owner:platform]
          parent: {uuid: 6b49ae15-eded-4780-a7c0-2bc1b9001cd5}
```

- `tags` is the project's **complete tag set**: the server replaces all tags with it. An omitted `tags` sends nothing and leaves the tags alone. An upload cannot clear tags, so `tags: []` is refused. Tags are literal, lowercase strings without commas or edge whitespace, at most 255 characters each, and unique; Dependency-Track lowercases tag names and splits the request on commas.
- `parent` is exactly one of `{uuid}` or `{name, version}` of an existing project.
- `isLatest: true` marks this version as the project's latest; the previous latest version loses the flag.
- `parent` and `isLatest` need a name/version or default subject project with `autoCreate: true`. With `project: {uuid}` or without `autoCreate` they could never apply, so they are refused before any request (`rio plan` refuses them too). `tags` work with every selector.

The adapter sends `projectTags`, `parentUUID` or `parentName`/`parentVersion`, and `isLatest` only when configured. A target without them sends exactly what it sent before.

What Dependency-Track 5.2.1 does with them, per case (verified against a real 5.2.1 server, see the [integration evidence](../tools/demo-delivery/integration/README.md#project-tags-parent-and-latest-version-on-521)):

| Upload | Tags | Parent and isLatest |
|---|---|---|
| Creates the project: a new name/version with `autoCreate: true` and a key with `PROJECT_CREATION_UPLOAD`, `PORTFOLIO_MANAGEMENT_CREATE` or `PORTFOLIO_MANAGEMENT` | Set | Set |
| Existing project, key with `PORTFOLIO_MANAGEMENT` or `PORTFOLIO_MANAGEMENT_UPDATE` | Replaced by the request's set | Ignored, 200 |
| Existing project, key without either, for example `BOM_UPLOAD` only | **Unchanged**; the server logs a warning and still answers 200 | Ignored, 200 |
| `parent` names a project that does not exist | Upload fails with 404 | |

Each version is its own Dependency-Track project. With a typical CI key (`BOM_UPLOAD` and `PROJECT_CREATION_UPLOAD`), tags, parent and latest therefore land on the **first upload of each new version**. Changing tags on an existing version needs `PORTFOLIO_MANAGEMENT_UPDATE`; parent and latest cannot be changed by an upload at all. A missing parent is its own non-retryable failure, `parent_not_found`, naming the parent selector; create the parent first.

Because a 200 does not say whether the fields were applied, Rio reads the project back after an accepted upload, and again on `delivery reconcile`. The receipt's `projectFields` lists each requested value and its state:

| State | Meaning |
|---|---|
| `observed` | The read-back shows the requested value |
| `different` | The read-back shows another value, recorded as `observed`, for example tags a key without `PORTFOLIO_MANAGEMENT_UPDATE` could not change |
| `unknown` | The project was not read. `readBack` says why: `not-attempted` (no accepted upload), `forbidden` (the key lacks `VIEW_PORTFOLIO`), `not-found`, `transient`, `unavailable` or `invalid-response` |

A requested value is never recorded as applied without being seen. The read-back needs `VIEW_PORTFOLIO`; without it every value stays `unknown`. Only the compared fields are kept, never the response body. `rio plan` and `rio delivery plan` show the effective tags, parent and `isLatest` per artifact offline, all `unknown`. A retry or reconciliation refuses with `destination_drift` if they changed since the recorded attempt.

Tags route findings: a notification rule's filter such as `"owner:payments" in subject.project.tags` sends them to the owning team. Keep the three apart per application: a `Fact sheet` link in the SBOM for who is responsible ([enrichment](enrichment.md#ownership-reporting-and-routing)), an `owner:` tag for who is notified, and `securityContact` for the public reporting channel. Rio does not set project properties, team access or collection logic; these need separate API calls.

## TLS and HTTP

HTTPS performs certificate and hostname verification by default. `caFile: certs/receiver-ca.pem` adds a public CA certificate using a manifest-relative path. Read-only plan describes the file without opening it; only requested native network work resolves transport files and credentials.

DTrack supports explicit `insecureSkipVerify: true` for HTTPS when certificate/hostname verification must be bypassed. It cannot be combined with `caFile`. Receipts report verification as `disabled`, independently from whether TLS was observed. Bypass does not assert the certificate was invalid. No automatic fallback exists.

Plain HTTP requires explicit `allowHTTP: true` and appears as HTTP with certificate verification `not-applicable`. Missing TLS observations remain unknown/not recorded, rather than being interpreted as false. [Synthetic TLS policy demo](../tools/demo-dtrack-tls/README.md).

## OCI registries

```yaml
version: 1
artifacts:
  - id: app
    sbom: target/bom.json
delivery:
  targets:
    registry:
      type: oci
      registry: registry.example.org
      repository: team/app
      auth:
        usernameEnv: REGISTRY_USER
        passwordEnv: REGISTRY_PASSWORD
```

A registry is an authority, without a scheme or repository path. The repository is a separate value. Authentication can instead use `auth: {anonymous: true}` or a supported bearer-token environment reference. CA files and explicit local-test HTTP are supported. OCI does not offer certificate-verification bypass.

Rio packages the exact verified SBOM bytes as an OCI blob and creates a deterministic manifest and generated tag. Optional `subject` uses a descriptor with `digest`, `mediaType` and `size`; attachment needs supported Referrers behavior. When the artifact's [build context](context.md#shipped-files-distributions) declares `distributions`, the `subject` digest must equal one of their SHA-256 values. Otherwise the planner (`rio delivery plan`, `rio deliver` and the root pipeline) stops with `subject_digest_mismatch` naming the artifact, before any request, and nothing in that plan is delivered. Without declared distributions the subject digest is not compared. No fallback tag scheme is silently substituted. [Detailed adapter examples and tested registry scope](../tools/demo-oci/README.md).

Receipts retain applicable immutable references, not a DTrack-shaped token. Intended config, SBOM and manifest representations have distinct digests, sizes and media types. `submitted` includes only bodies whose complete write was observed. Already-present content can be accepted after exact read-back without another upload, so acceptance need not imply a new submitted body. A complete body write does not prove what the server retained.

Explicit OCI reconciliation verifies supported manifest/config/SBOM content and attachment discovery. Content verification is separate from the earlier acknowledgment; a lost upload response may remain unknown even if later read-back verifies content.

## Scope and repeat execution

All targets apply to indexed artifacts unless excluded or filtered. Colliding destinations, invalid selected credentials, altered output digests and occupied journals refuse before uploads. Root execution uses a fresh run directory on every explicit invocation. Standalone delivery of the same index retains its stable journal slots, so an unchanged invocation cannot silently duplicate an earlier upload.

Retries require `--retry-of` and a fresh explicit journal for one pair, with matching source, target and policy. Credential references may be rotated where policy permits; changing TLS policy or project identity does not silently authorize retry/reconciliation. Each retry or reconciliation has a new public receipt; prior receipts are immutable.

[Installed-binary synthetic demonstrations](../tools/README.md#native-verified-delivery) are distinct from [real Dependency-Track](../tools/demo-delivery/integration/README.md) and [real OCI](../tools/demo-oci/integration/README.md) integration evidence.

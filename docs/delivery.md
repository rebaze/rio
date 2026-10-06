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

Rio packages the exact verified SBOM bytes as an OCI blob and creates a deterministic manifest and generated tag. Optional `subject` uses a descriptor with `digest`, `mediaType` and `size`; attachment needs supported Referrers behavior. No fallback tag scheme is silently substituted. [Detailed adapter examples and tested registry scope](../tools/demo-oci/README.md).

Receipts retain applicable immutable references, not a DTrack-shaped token. Intended config, SBOM and manifest representations have distinct digests, sizes and media types. `submitted` includes only bodies whose complete write was observed. Already-present content can be accepted after exact read-back without another upload, so acceptance need not imply a new submitted body. A complete body write does not prove what the server retained.

Explicit OCI reconciliation verifies supported manifest/config/SBOM content and attachment discovery. Content verification is separate from the earlier acknowledgment; a lost upload response may remain unknown even if later read-back verifies content.

## Scope and repeat execution

All targets apply to indexed artifacts unless excluded or filtered. Colliding destinations, invalid selected credentials, altered output digests and occupied journals refuse before uploads. Root execution uses a fresh run directory on every explicit invocation. Standalone delivery of the same index retains its stable journal slots, so an unchanged invocation cannot silently duplicate an earlier upload.

Retries require `--retry-of` and a fresh explicit journal for one pair, with matching source, target and policy. Credential references may be rotated where policy permits; changing TLS policy or project identity does not silently authorize retry/reconciliation. Each retry or reconciliation has a new public receipt; prior receipts are immutable.

[Installed-binary synthetic demonstrations](../tools/README.md#native-verified-delivery) are distinct from [real Dependency-Track](../tools/demo-delivery/integration/README.md) and [real OCI](../tools/demo-oci/integration/README.md) integration evidence.

# Disposable real-registry integration

`TestIntegrationOCI` is opt-in and uploads only synthetic data. Use a dedicated disposable hosted/local
repository. Do not point it at production content. Rio itself needs no Docker/ORAS/Go runtime tools;
this development harness needs Go and separately provisioned registries.

Required environment for Basic/PAT credentials:

- `RIO_OCI_INTEGRATION=1`
- `RIO_OCI_TEST_REGISTRY`: host/port authority
- `RIO_OCI_TEST_REPOSITORY`: dedicated repository path, including a path-routing product key
- `RIO_OCI_TEST_USERNAME`, `RIO_OCI_TEST_PASSWORD`
- `RIO_OCI_TEST_DENIED_USERNAME`, `RIO_OCI_TEST_DENIED_PASSWORD`: a separately supplied denied set
- `RIO_OCI_TEST_ALLOW_HTTP=1` only for an explicitly approved local HTTP registry; otherwise HTTPS
- `RIO_OCI_TEST_CA_FILE` for a custom CA, when needed
- `RIO_OCI_TEST_PRODUCT`, `RIO_OCI_TEST_VERSION`, `RIO_OCI_TEST_IMAGE_DIGEST` for setup metadata
- `RIO_OCI_TEST_EVIDENCE`: new path for sanitized observed evidence
- `RIO_OCI_TEST_REFERRERS=required` (default) or explicit `unsupported` for a known negative profile
- `RIO_OCI_TEST_DENIED_CAN_READ=1` when the separately supplied account must prove read success and write denial

Anonymous development runs require the explicit alternate auth mode `RIO_OCI_TEST_AUTH=anonymous`.
Missing Basic credentials never silently select anonymity. A registry with enforced tag immutability
may set `RIO_OCI_TEST_IMMUTABLE=1`; mutable registry behavior is recorded separately. Credential
values go through private environment/files, never command arguments or committed configuration.
Do not enable shell tracing or print/source the private file into logs.

```sh
# Variables are injected by a secret manager or a private environment file.
go test ./internal/delivery/oci -run '^TestIntegrationOCI$' -count=1 -v
```

The harness creates four small synthetic indexed SBOMs so conflict, denial and crash attempts have
fresh immutable identities in the same dedicated repository. It seeds a tiny OCI image and image index,
obtains and hashes their real descriptors,
and exercises standalone and attached delivery, exact raw-byte read-back, Referrers discovery,
already-present handling, conflicts, denied credentials and actual child-process termination behind a controlled response-dropping proxy.
It verifies portable evidence using recorded source bytes. Every run uses fresh synthetic input
identities. The child is killed only after the proxy observes the real registry’s HTTP 201, before the response
reaches Rio. The journal remains intent-only; the known-exited child’s lock is explicitly removed,
the original index/selected SBOM are deleted, and reconciliation verifies content while acknowledgment
remains unknown. Proxy-observed HTTP status is a separate field from Rio’s acknowledgment.
Partial remote content is retained for inspection; cleanup removes only the owned
container/data volumes, not individual shared registry blobs.

## Pinned Distribution with TLS and Basic authentication

`compose.yaml` pins the actual Distribution publisher image and multi-platform digest. The unavailable
illustrative `registry:3.1.2` reference is not used. Distribution 3.1.2 has no Referrers API route: its real profile verifies standalone storage/read-back,
and asserts that both attachment forms refuse before mutation. This was observed at runtime and
confirmed in [its versioned routes](https://github.com/distribution/distribution/blob/v3.1.2/registry/api/v2/routes.go).
The `unsupported` expectation is explicit; the harness does not turn an unexpected 404 into a pass.
CI also starts pinned zot for positive Referrers coverage, independently of the synthetic demo.

```sh
python3 tools/demo-oci/integration/setup.py /absolute/new/private/fixture-root --port 15000
export RIO_OCI_FIXTURE_ROOT=/absolute/new/private/fixture-root
export RIO_OCI_BIND_PORT=15000
docker compose -p rio-oci-test -f tools/demo-oci/integration/compose.yaml up -d
# Inject the generated private test.env without tracing or displaying its values.
set -a
. "$RIO_OCI_FIXTURE_ROOT/test.env"
set +a
go test ./internal/delivery/oci -run '^TestIntegrationOCI$' -count=1 -v
docker compose -p rio-oci-test -f tools/demo-oci/integration/compose.yaml down -v
```

Setup requires OpenSSL and bcrypt-capable Unix `crypt` (CI's Python 3.9 on Linux) or `htpasswd`.
The generated password is supplied through stdin to the fallback tool; only a fixed public synthetic
username is an argument. Private values are never displayed. A preexisting fixture root refuses.
The htpasswd file is created before startup so Distribution cannot print an automatically generated
password. The container is bound to loopback and the Compose project owns its own labeled volume.

Distribution's Basic-auth configuration has no repository ACL layer. Its separately supplied denied
set is deliberately unregistered and exercises authentication refusal (401), not a claim of a valid
read-only user's 403. Nexus's scoped read-only account supplies distinct permission coverage.

## Evidence and support scope

The tested matrix is populated only after actual runs. Setup-reported product/version/image metadata
must be checked against the running container and retained alongside the observations. Evidence
contains synthetic descriptors, locally computed hashes, safe statuses and Rio interpretations;
it excludes passwords, tokens, auth/session query strings and raw error bodies.

Planned targets are Distribution 3.1.2, zot 2.1.21, Nexus Community native OCI 3.94.0+, and a separately
provided Artifactory OCI local repository with Referrers 7.90.1+. Other versions, remote/proxy/virtual
routing, read offloading, fallback referrer tags, Xray/Lifecycle ingestion and retention guarantees
are not implied. An unavailable vendor instance remains an explicit open acceptance item; a skipped
opt-in test is not compatibility evidence. No Artifactory instance or license acceptance is created
by this harness.


## Observed configurations

| Registry | Observed transport/auth | Storage/read-back | Attachment / Referrers | Additional observed policy |
|---|---|---|---|---|
| Distribution 3.1.2, pinned multiarch image | Loopback TLS, custom CA, bcrypt Basic | Passed | API absent; both forms correctly refused without writes | Mutable synthetic tags; denied authentication; real intent-only crash recovery |
| zot 2.1.21, pinned arm64 image | Loopback TLS, custom CA, bcrypt Basic | Passed | Image and index subjects passed | Mutable synthetic tags; denied authentication; attached crash recovery |
| Nexus 3.94.0-12 Community, pinned image | Explicit loopback HTTP, Basic-to-Bearer negotiation, native OCI hosted path routing | Passed | Image and index subjects passed | ALLOW_ONCE tag rejection; valid read-only account can read and cannot write; attached crash recovery |
| Artifactory | No disposable endpoint/version/scoped credentials supplied | Not run | Not run | Required acceptance remains open |

Version-specific evidence from actual race-enabled runs on source commit `c84de29`:

- [Distribution 3.1.2](distribution-3.1.2.json): 10 scenarios, 79 sanitized request observations;
  standalone storage plus explicit no-write attachment refusal and actual standalone crash recovery.
- [zot 2.1.21 arm64](zot-2.1.21-arm64.json): 12 scenarios, 115 observations; positive image/index
  Referrers and attached crash recovery over TLS/Basic.
- [Nexus 3.94.0-12 Community](nexus-community-3.94.0-12.json): 12 scenarios, 138 observations;
  Basic and Bearer modes observed, native mounted path routing, ALLOW_ONCE, authenticated read
  success/write denial, and attached crash recovery.

The image/edition/routing settings are deliberately narrow. The evidence’s
`complete` flag means the declared profile passed, not that all registry features or other vendors
were verified. Setup-reported version/image metadata was checked against the running containers;
server response bodies, credentials and token/upload-session URLs are not retained. Read-back hashes
were recomputed over fetched bytes. The Nexus check covers this native OCI hosted recipe, not older
Docker repositories, TLS-fronted Nexus deployments or Xray/Lifecycle analysis.

The Compose `zot` profile adds the pinned amd64 image for CI. An arm64 local run can explicitly set
`RIO_OCI_ZOT_ARCH=arm64` and its documented platform digest. Both services share only this disposable
fixture's auth/CA files and use separate labeled volumes. `zot.json` disables garbage collection;
no extension, scanning or retention behavior is claimed. Native CI must actually execute its selected
platform; cross-building does not establish interoperability.

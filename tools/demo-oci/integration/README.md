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

Anonymous development runs require the explicit alternate auth mode `RIO_OCI_TEST_AUTH=anonymous`.
Missing Basic credentials never silently select anonymity. A registry with enforced tag immutability
may set `RIO_OCI_TEST_IMMUTABLE=1`; mutable registry behavior is recorded separately. Credential
values go through private environment/files, never command arguments or committed configuration.
Do not enable shell tracing or print/source the private file into logs.

```sh
# Variables are injected by a secret manager or a private environment file.
go test ./internal/delivery/oci -run '^TestIntegrationOCI$' -count=1 -v
```

The harness seeds a tiny synthetic OCI image and image index, obtains and hashes their real descriptors,
and exercises standalone and attached delivery, exact raw-byte read-back, Referrers discovery,
already-present handling, conflicts, denied credentials and controlled dropped-response recovery.
It verifies portable evidence using recorded source bytes. Every run uses fresh synthetic input
identities. Partial remote content is retained for inspection; cleanup removes only the owned
container/data volumes, not individual shared registry blobs.

## Pinned Distribution with TLS and Basic authentication

`compose.yaml` pins the actual Distribution publisher image and multi-platform digest. The unavailable
illustrative `registry:3.1.2` reference is not used. Referrers support is verified by the harness, not
inferred from image availability. CI uses this real container independently of the synthetic demo.

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

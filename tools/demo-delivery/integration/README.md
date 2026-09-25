# Real-server integration evidence

`dependency-track-5.1.1.json` was recorded by `TestIntegrationDependencyTrack` against a
new, disposable Docker API server `dependencytrack/apiserver:5.1.1` and PostgreSQL 18,
with a dedicated test project/team and a separate team lacking upload permission. The user
requested 5.1 instead of the original issue's 4.14.0 target. **5.1.1 is the tested adapter
contract; no claim is made for untested 4.x or other 5.x versions.**

Evidence includes actual server version, scenario, sanitized request method/path/form,
verified payload digest, HTTP status, allowlisted response fields, Rio interpretation, and
whether a separate harness read verified the expected synthetic project inventory. Project
and token identifiers are replaced with descriptive placeholders. API keys, session tokens,
passwords and raw response/error bodies are never retained. These examples are real server
observations, distinct from the synthetic loopback demo and unit-test fixtures.

The harness verifies both direct name/version and UUID uploads, replacement of the dedicated
project's inventory, absent project creation off/on, denied permissions, invalid credentials,
actual token activity transitions and an unknown token. `processing:false` stays
`not-observed`, even if the server also returns additional status fields. The adapter does not
use those fields to claim successful ingestion. Separate harness inventory reads do not prove
byte-for-byte retention. Missing/malformed status and ambiguous responses remain stub tests.

To run against **disposable infrastructure only**, explicitly inject these environment variables:

- `RIO_DTRACK_INTEGRATION=1`
- `RIO_DTRACK_TEST_URL` (API server base before `/api/v1`)
- `RIO_DTRACK_TEST_API_KEY` (dedicated test key)
- `RIO_DTRACK_TEST_PROJECT_UUID` (dedicated existing project with nonempty name/version)
- `RIO_DTRACK_TEST_DENIED_KEY` (valid key without upload permission)
- `RIO_DTRACK_TEST_ALLOW_HTTP=1` only for explicitly approved local HTTP
- Optional `RIO_DTRACK_TEST_CA_FILE` and `RIO_DTRACK_EVIDENCE` (sanitized evidence output path)

```sh
go test ./internal/delivery/dtrack -run '^TestIntegrationDependencyTrack$' -count=1 -v
```

The opt-in test **replaces the project's inventory and creates a uniquely named project**.
Never use a production project. The harness key needs upload, creation and portfolio-read
permissions for verification; setup may need project/access management. These are test-harness
permissions, not normal direct name/version upload prerequisites. Normal Rio upload does not
look up projects. Tear down the dedicated Docker project/database to clean up; Rio has no
project-deletion behavior. With opt-in unset the test reports a skip, not real-server coverage.

## HTTPS and explicit certificate-verification policy

The native TLS addition was also exercised against a new disposable Dependency-Track **5.1.1**
receiver, with a local HTTPS gateway presenting an untrusted test certificate. The API behind that
gateway used loopback HTTP. This establishes the client-to-gateway TLS behavior with a real
Dependency-Track receiver; it does not claim coverage of a particular production ingress or
Dependency-Track's own TLS termination.

- [HTTPS integration](dependency-track-5.1.1-https.json) is a fresh race-enabled run of the existing
  full integration harness, using the gateway and a supplied CA certificate. Upload, project,
  permission and activity checks passed.
- [TLS policy evidence](dependency-track-5.1.1-tls-policy.json) was recorded by an installed-binary
  check of source `89d577cbe129328fd921cbbce0bf69ede5579079`. Default trust refused before any
  application upload. A supplied CA succeeded with verification enforced. Explicit
  `insecureSkipVerify: true` succeeded with verification disabled and a successful TLS handshake
  recorded. Reconciliation preserved that mode; changing it refused before another upload.
  A portable record retained the facts and remained inspectable after its workspace was removed.

The TLS facts distinguish configured verification from an observed handshake. Disabled verification
does not assert that the certificate was invalid; an accepted upload still does not prove ingestion.
Neither file includes API keys, private certificate material, raw authentication responses, or
production identifiers. The endpoint, database, teams and projects were dedicated synthetic test
infrastructure. The [installed-binary HTTPS demo](../../demo-dtrack-tls/README.md) reproduces the
verification-policy and portable-record behavior with a clearly labeled local synthetic receiver.

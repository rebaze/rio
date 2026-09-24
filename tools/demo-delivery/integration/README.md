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

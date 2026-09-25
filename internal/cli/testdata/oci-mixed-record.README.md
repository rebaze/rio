# Mixed OCI/Dependency-Track record fixture

`oci-mixed-record.json` contains two selected histories from the installed-binary synthetic OCI
walkthrough: an accepted Dependency-Track attempt with activity, and an OCI attempt with only intent
and later verified content. Its OCI acknowledgment remains unknown. Original event/index bytes are
retained verbatim in the base64 sources; filtering preserves their hashes and rebuilds explicit
coverage. The original loopback receiver and workspace no longer exist.

This is a synthetic consistency fixture, not vendor, ingestion, identity or signing evidence.
`TestOCIMixedPortableRecordFixture` inspects it with client construction/environment resolution
forbidden, then proves that editing a readable acknowledgment without changing source bytes refuses.

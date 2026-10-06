# Service experiments (synthetic)

This checkout contains `services/api-server` and `services/preview-server`.
Both have marker files and SBOM output from `sh build.sh`. Release ownership and
which services ship together are not documented. The presence of an SBOM does not
settle that decision; preview may be a released product or a development experiment.

The build command copies synthetic fixture data. Do not install Maven tooling for
this exercise. Ask the release owner about intended bundle membership before
committing a selection policy.

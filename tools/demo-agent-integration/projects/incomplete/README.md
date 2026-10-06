# Billing and reporting release (synthetic)

Both `services/billing-server` and `services/reporting-server` are required release
deliverables. Future marked `services/*server` modules at that same directory depth must also be included.
Each should produce `target/bom.json` beneath its module directory.

The current `sh build.sh` produces billing's SBOM only. Reporting's SBOM producer
has not been implemented; its generator and build command are not specified yet.
Do not exclude reporting to make checks pass or copy billing's SBOM as its output.
Configuration can be prepared, but successful normalization must remain pending
until the reporting build produces its actual SBOM.

This is a synthetic project. The available producer copies fixture data; it does
not demonstrate how to generate a real project's SBOM.

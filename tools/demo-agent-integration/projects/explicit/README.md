# Desktop project (synthetic)

The only shipped deliverable is `desktop`. Its build produces
`desktop/target/bom.json`. Release automation invokes `sh build.sh` from the project
root. Integrate this existing SBOM with Rio; keep its software identity unchanged.

This fixture's build script copies synthetic data, not an actual compiled build.
Use the same script to exercise this example; do not install a Maven plugin.

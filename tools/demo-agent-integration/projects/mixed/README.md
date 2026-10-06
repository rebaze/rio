# Desktop and server release (synthetic)

Extend the existing `rio.yaml` to include every marked `services/*server` module,
including future modules. Preserve the desktop configuration, its explicit subject
override, mapping table path, output floor and gate requirements. Those are existing
release decisions. `clients/web-client` is a development aid, outside the release.

The uppercase `services/Legacy-server` directory is an existing path we cannot
rename. Use `legacy-server` as its Rio output ID. Preserve the SBOM's software
identity. The existing `config/p2-maven.json` is a synthetic empty override table.

The release command is `sh build.sh`, run from this directory. It writes
`desktop/target/bom.json` and `target/bom.json` under each module. The producer copies
synthetic fixture data; no actual Maven build or plugin installation is needed.

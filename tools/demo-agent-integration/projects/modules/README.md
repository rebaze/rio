# Server project (synthetic)

Every immediate child directory of `services/` whose name ends in `server` and contains a
`pom.xml` marker is a release deliverable. Include future matching modules too.
`clients/web-client` is a development aid and is not part of this release bundle.

Release automation invokes `sh build.sh` from this directory. It produces each
module's SBOM at `target/bom.json` beneath the module directory. Rio output should
use the module directory names; the SBOM's own software identity must stay intact.

The marker files demonstrate a filesystem convention; their XML is never parsed
by the synthetic producer or Rio. This build copies fixture data, so no Maven
installation or generator configuration is needed for the exercise.

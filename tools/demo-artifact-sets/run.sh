#!/bin/sh
# Synthetic example. Requires only an installed Rio containing #71 and standard utilities.
set -eu
if [ "$#" -gt 1 ]; then
  printf 'Usage: %s [rio-command-or-path]\n' "$0" >&2
  exit 2
fi
rio_command=${1:-${RIO_BIN:-rio}}
if ! rio_bin=$(command -v "$rio_command"); then
  printf 'Cannot find rio: %s. Install a release containing #71 or set RIO_BIN.\n' "$rio_command" >&2
  exit 2
fi
case "$rio_bin" in
  /*) ;;
  *) rio_bin=$(pwd)/$rio_bin ;;
esac
demo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/rio-artifact-sets.XXXXXXXX")
trap 'printf "\nDemo inputs and results retained in: %s\n" "$run_dir"' 0
cp -R "$demo_dir/services" "$demo_dir/desktop" "$run_dir/"
cp "$demo_dir/"*.yaml "$run_dir/"
cd "$run_dir"
cp rio.yaml original-manifest.yaml

# The index is authoritative; do not collect every file from a reused directory.
# Match the index's top-level artifact IDs, not context or transform IDs.
check_members() {
  sed -n 's/^      "id": "\([^"]*\)",$/\1/p' "$1/index.json" > actual-members
  printf '%s\n' "$2" > expected-members
  if ! cmp -s expected-members actual-members; then
    printf 'FAIL: unexpected membership in %s/index.json\n' "$1" >&2
    cat actual-members >&2
    exit 1
  fi
}
refuse() {
  status=0
  "$rio_bin" "$1" --manifest "$2" --out "$3" > "$3.log" 2>&1 || status=$?
  cat "$3.log"
  if [ "$status" -ne 2 ] || [ -e "$3" ]; then
    printf 'FAIL: expected exit 2 and no output at %s (exit %s)\n' "$3" "$status" >&2
    exit 1
  fi
}

printf 'Artifact sets demo (synthetic data; no network)\n'
"$rio_bin" version
printf '\n1. Explicit-only, sets-only and mixed declarations\n'
"$rio_bin" normalize --manifest explicit-only.yaml --out explicit --gate fail
check_members explicit desktop
"$rio_bin" normalize --manifest sets-only.yaml --out sets --gate fail
check_members sets 'billing-server
orders-server'
"$rio_bin" plan --json > plan.json
"$rio_bin" normalize --out mixed --gate fail --attest
check_members mixed 'desktop
billing-server
orders-server'
printf 'PASS: web-client is outside the marker selector. Each server has a separate SBOM.\n'

printf '\n2. Add a matching module without editing rio.yaml\n'
mkdir -p services/reporting-server/target
cp services/billing-server/pom.xml services/reporting-server/pom.xml
# Keep the copied subject unchanged: the directory sets only Rio output identity.
cp services/billing-server/target/bom.json services/reporting-server/target/bom.json
"$rio_bin" plan
"$rio_bin" normalize --out added --gate fail
check_members added 'desktop
billing-server
orders-server
reporting-server'
[ -f added/reporting-server.cdx.json ]
cmp -s rio.yaml original-manifest.yaml
printf 'PASS: reporting-server appeared automatically; rio.yaml is unchanged.\n'

printf '\n3. Remove only its SBOM: plan and normalize must refuse\n'
rm services/reporting-server/target/bom.json
refuse plan rio.yaml missing-plan
refuse normalize rio.yaml missing-normalize
printf 'PASS: selected module with no SBOM is an explicit failure.\n'

printf '\n4. Remove its marker: the new index omits the module\n'
rm services/reporting-server/pom.xml
"$rio_bin" normalize --out removed --gate fail
check_members removed 'desktop
billing-server
orders-server'
printf 'PASS: reporting-server is absent from removed/index.json.\n'

printf '\n5. Exclude a selected marker before requiring its SBOM\n'
mkdir -p services/experimental-server
cp services/billing-server/pom.xml services/experimental-server/pom.xml
"$rio_bin" normalize --manifest excluded.yaml --out excluded --gate fail
check_members excluded 'billing-server
orders-server'
rm services/experimental-server/pom.xml

printf '\n6. Refuse overlapping sets\n'
refuse plan overlap.yaml overlap-plan
refuse normalize overlap.yaml overlap-normalize
cmp -s rio.yaml original-manifest.yaml
printf '\nPASS: discovery, automatic inclusion, missing-SBOM refusal, removal, exclusion and overlap refusal.\n'
printf 'All runs used fresh output directories. Reused directories can retain old files; index.json defines current membership.\n'

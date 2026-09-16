#!/bin/sh
# Run against an installed release binary; keep every input and result for inspection.
set -eu

if [ "$#" -gt 1 ]; then
  printf 'Usage: %s [rio-command-or-path]\n' "$0" >&2
  exit 2
fi
rio_command=${1:-${RIO_BIN:-rio}}
if ! rio_bin=$(command -v "$rio_command"); then
  printf 'Cannot find rio: %s. Install a release containing #61 or set RIO_BIN.\n' "$rio_command" >&2
  exit 2
fi
case "$rio_bin" in
  /*) ;;
  *) rio_bin=$(pwd)/$rio_bin ;;
esac
demo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/rio-enrichment.XXXXXXXX")
trap 'printf "\nDemo inputs and results retained in: %s\n" "$run_dir"' 0
cp -R "$demo_dir/inputs" "$run_dir/inputs"
cp "$demo_dir/rio.yaml" "$demo_dir/conflict.yaml" "$demo_dir/replace.yaml" "$run_dir/"
cd "$run_dir"

# Display only: the complete JSON documents remain available in the output directory.
show_subject() {
  printf '\n%s\n' "$1"
  sed -n '/^    "component": {/,/^    }/p' "$1"
}

printf 'Manifest enrichment demo (synthetic data; no network)\n'
"$rio_bin" version
printf '\n1. Shared defaults and artifact-specific product values\n'
printf '$ rio plan --manifest rio.yaml --out enriched\n'
"$rio_bin" plan --manifest rio.yaml --out enriched
"$rio_bin" plan --manifest rio.yaml --out enriched --json > plan.json
printf '\nFull resolved field values and manifest selectors: plan.json\n'
show_subject inputs/console.cdx.json
printf '\n$ rio normalize --manifest rio.yaml --out enriched --gate fail --attest\n'
"$rio_bin" normalize --manifest rio.yaml --out enriched --gate fail --attest
show_subject enriched/console.cdx.json
show_subject enriched/agent.cdx.json
printf '\nBoth products inherit the organizations, group and version. Their names, purls\nand documentation URLs come from their artifact entries.\n'
printf 'Inspect enriched/index.json and *.intoto.json for enrichment sources and changes.\n'

printf '\n2. Refuse conflicting existing product identity\n'
show_subject inputs/legacy-console.cdx.json
printf '\n$ rio normalize --manifest conflict.yaml --out refused --gate fail\n'
status=0
"$rio_bin" normalize --manifest conflict.yaml --out refused --gate fail > conflict.log 2>&1 || status=$?
cat conflict.log
if [ "$status" -ne 2 ]; then
  printf 'FAIL: expected conflict exit 2, got %s\n' "$status" >&2
  exit 1
fi
if [ -d refused ] && [ -n "$(find refused -type f -print)" ]; then
  printf 'FAIL: conflict wrote output files\n' >&2
  exit 1
fi
printf 'PASS: exit 2; no newly written output files.\n'

printf '\n3. Explicitly replace only the conflicting fields\n'
printf 'replace: [subject.name, subject.version, subject.purl]\n'
printf '$ rio normalize --manifest replace.yaml --out replaced --gate fail --attest\n'
"$rio_bin" normalize --manifest replace.yaml --out replaced --gate fail --attest
show_subject replaced/console.cdx.json
printf '\nThe subject bom-ref remains the original local identifier, even though it\ncontains the old purl. The dependency graph still points at that identifier.\n'
printf '\nCompare inputs/ with enriched/ and replaced/: the third-party tiny-json\ncomponent, its MIT license, original generator and timestamp remain unchanged.\n'
printf 'New dataLicense describes the SBOM data; it does not relicense tiny-json.\n'
printf '\nPASS: defaults, conflict refusal and explicit replacement completed.\n'

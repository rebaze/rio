#!/bin/sh
# Offline showcase using only an installed Rio binary and committed synthetic data.
set -eu

if [ "$#" -gt 1 ]; then
  printf 'Usage: %s [rio-command-or-path]\n' "$0" >&2
  exit 2
fi
rio_command=${1:-${RIO_BIN:-rio}}
if ! rio_bin=$(command -v "$rio_command"); then
  printf 'Cannot find rio: %s\n' "$rio_command" >&2
  exit 2
fi
case "$rio_bin" in
  /*) ;;
  *) rio_bin=$(pwd)/$rio_bin ;;
esac
demo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/rio-context.XXXXXXXX")
trap 'printf "\nDemo inputs and results retained in: %s\n" "$run_dir"' 0
cp -R "$demo_dir/inputs" "$run_dir/inputs"
cp "$demo_dir"/*.yaml "$demo_dir"/*.json "$run_dir/"
cd "$run_dir"

printf 'CI build context demo (synthetic inputs; no network)\n'
"$rio_bin" version

printf '\n1. Plan before the declared context file exists\n'
mv context.json context-saved.json
"$rio_bin" plan --manifest rio.yaml --out normalized --json > plan-before-context.json
if ! grep -F '"file": "context.json"' plan-before-context.json >/dev/null; then
  printf 'FAIL: plan did not report the context binding\n' >&2
  exit 1
fi
mv context-saved.json context.json

printf '\n2. Normalize both products from one selected context file\n'
"$rio_bin" normalize --manifest rio.yaml --out normalized --gate fail --attest > normalize.log
cp normalized/index.json first-index.json
cp normalized/console.cdx.json first-console.cdx.json
cp normalized/agent.cdx.json first-agent.cdx.json
"$rio_bin" normalize --manifest rio.yaml --out normalized --gate fail --attest > rerun.log
cmp first-index.json normalized/index.json
cmp first-console.cdx.json normalized/console.cdx.json
cmp first-agent.cdx.json normalized/agent.cdx.json
printf 'PASS: two products normalized; same inputs produced identical index and SBOM bytes.\n'

refuse() {
  manifest=$1
  diagnostic=$2
  output=$3
  status=0
  "$rio_bin" normalize --manifest "$manifest" --out "$output" > "$output.log" 2>&1 || status=$?
  if [ "$status" -ne 2 ] || ! grep -F "$diagnostic" "$output.log" >/dev/null; then
    printf 'FAIL: %s expected exit 2 with %s (got %s)\n' "$manifest" "$diagnostic" "$status" >&2
    cat "$output.log" >&2
    exit 1
  fi
  if [ -d "$output" ] && [ -n "$(find "$output" -type f -print)" ]; then
    printf 'FAIL: %s wrote output files\n' "$manifest" >&2
    exit 1
  fi
  printf 'PASS: %s refused with %s; no outputs written.\n' "$manifest" "$diagnostic"
}

printf '\n3. Refuse stale digest, missing required field, and prior revision conflict\n'
refuse stale.yaml sha256 stale-refused
refuse missing.yaml build.url missing-refused
refuse conflict.yaml source.revision conflict-refused

printf '\n4. Explicit replacement of revision and removal of old owned claims\n'
"$rio_bin" normalize --manifest replace.yaml --out replaced > replacement.log
if ! grep -F '"workspace": "unknown"' replaced/index.json >/dev/null; then
  printf 'FAIL: omitted workspace did not become explicit unknown\n' >&2
  exit 1
fi
if grep -F '"old-run"' replaced/index.json >/dev/null && ! grep -F '"after": null' replaced/index.json >/dev/null; then
  printf 'FAIL: prior build ID has no removal audit\n' >&2
  exit 1
fi
printf 'PASS: authorized replacement; inspect replaced/index.json for before/after and null removal.\n'
printf '\nInspect plan-before-context.json, normalized/, replaced/, and refusal logs in the retained directory.\n'

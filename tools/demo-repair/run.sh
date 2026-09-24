#!/bin/sh
# A first real repair using synthetic input and an installed Rio (v0.3.0 works).
set -eu
if [ "$#" -gt 1 ]; then
  printf 'Usage: %s [rio-command-or-path]\n' "$0" >&2
  exit 2
fi
rio_command=${1:-${RIO_BIN:-rio}}
if ! rio_bin=$(command -v "$rio_command"); then
  printf 'Cannot find Rio: %s. Install a release or set RIO_BIN.\n' "$rio_command" >&2
  exit 2
fi
case "$rio_bin" in
  /*) ;;
  *) rio_bin=$(pwd)/$rio_bin ;;
esac
demo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/rio-repair.XXXXXXXX")
cp "$demo_dir/bom.json" "$demo_dir/rio.yaml" "$run_dir/"
printf 'Synthetic sample: one Eclipse p2 dependency, using the built-in mapping.\n'
printf '\nBefore:\n'
sed -n '/"purl":/p' "$run_dir/bom.json"
"$rio_bin" normalize --manifest "$run_dir/rio.yaml" --out "$run_dir/out" --gate fail
printf '\nAfter:\n'
sed -n '/"purl":/p' "$run_dir/out/sample.cdx.json"
grep -Fq '"purl": "pkg:maven/com.google.code.gson/gson@2.8.9"' "$run_dir/out/sample.cdx.json"
cmp -s "$demo_dir/bom.json" "$run_dir/bom.json"
printf '\nInput unchanged. Repair record and index retained in: %s\n' "$run_dir"

#!/bin/sh
# A first real repair using synthetic input and an installed Rio (v0.7.0+; Python 3.9+ required).
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

# Python 3.9+ reads the structured execution result; paths may contain spaces.
result_dir() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["runDirectory"])' "$1"
}
inspect_result() {
  receipt=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["receipt"]["path"])' "$1")
  "$rio_bin" record inspect --file "$receipt" --json > "$1.inspection.json"
  python3 - "$1" "${2:-success}" <<'PY_CHECK'
import json, sys
result = json.load(open(sys.argv[1]))
record = json.load(open(sys.argv[1] + ".inspection.json"))["record"]
assert record["kind"] == "rio-run-receipt" and record["schemaVersion"] == 1
assert record["run"]["id"] == result["runId"]
assert record["run"]["operation"] == "normalize"
assert record["run"]["outcome"] == result["outcome"] == sys.argv[2]
PY_CHECK
}

demo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/rio-repair.XXXXXXXX")
cp "$demo_dir/bom.json" "$demo_dir/rio.yaml" "$run_dir/"
printf 'Synthetic sample: one Eclipse p2 dependency, using the built-in mapping.\n'
printf '\nBefore:\n'
sed -n '/"purl":/p' "$run_dir/bom.json"
"$rio_bin" normalize --manifest "$run_dir/rio.yaml" --out "$run_dir/out" --gate fail --json > "$run_dir/result.json"
output_dir=$(result_dir "$run_dir/result.json")
inspect_result "$run_dir/result.json"
printf '\nAfter:\n'
sed -n '/"purl":/p' "$output_dir/sample.cdx.json"
grep -Fq '"purl": "pkg:maven/com.google.code.gson/gson@2.8.9"' "$output_dir/sample.cdx.json"
cmp -s "$demo_dir/bom.json" "$run_dir/bom.json"
printf '\nInput unchanged. Repair record and index retained in: %s\n' "$run_dir"

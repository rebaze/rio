#!/bin/sh
# Copyable CI step. Run from your project root, with Rio installed and rio.yaml present.
# Usage: sh ci/rio.sh /path/to/rio sh ci/build-and-sbom.sh [build arguments...]
# Requires Python 3.9+. Configured delivery targets run in the root pipeline.
set -eu
if [ "$#" -lt 2 ]; then
  printf 'Usage: %s rio-command-or-path build-command [arguments...]\n' "$0" >&2
  exit 2
fi
rio_command=$1
shift
if ! rio_bin=$(command -v "$rio_command"); then
  printf 'Cannot find Rio: %s\n' "$rio_command" >&2
  exit 2
fi
# Resolve before running a build; relative binary paths remain unambiguous.
case "$rio_bin" in
  /*) ;;
  *) rio_bin=$(pwd)/$rio_bin ;;
esac

# Use the project's actual producer. Its success is not proof of freshness:
# that command must ensure the selected SBOMs belong to this build.
"$@"
run_dir=$(mktemp -d "./rio-run.XXXXXXXX")
run_dir=$(CDPATH='' cd "$run_dir" && pwd)
printf 'Rio run directory: %s\n' "$run_dir"
"$rio_bin" version
"$rio_bin" plan --manifest rio.yaml --out "$run_dir/output" --json > "$run_dir/plan.json"
# Root execution applies the manifest's local processing and configured delivery.
# On failure its automatic receipt remains available, but no success is announced.
"$rio_bin" --manifest rio.yaml --out "$run_dir/output" --gate fail --json > "$run_dir/result.json"
receipt=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["receipt"]["path"])' "$run_dir/result.json")
"$rio_bin" record inspect --file "$receipt" --json > "$run_dir/inspection.json"
printf 'Receipt ready for the CI artifact collector: %s\n' "$receipt"

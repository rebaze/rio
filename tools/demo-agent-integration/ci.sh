#!/bin/sh
# Copyable CI step. Run from your project root, with Rio installed and rio.yaml present.
# Usage: sh ci/rio.sh /path/to/rio sh ci/build-and-sbom.sh [build arguments...]
# This does not install Rio, choose a generator, upload files, or delete old outputs.
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
"$rio_bin" plan --manifest rio.yaml --out "$run_dir/normalized" --json > "$run_dir/plan.json"
"$rio_bin" normalize --manifest rio.yaml --out "$run_dir/normalized" --gate fail --attest
# This directory was created for this invocation. It cannot include an older run.
# With set -e, neither a plan refusal nor a gate failure reaches collection.
# Suppress macOS AppleDouble metadata entries; ignored by other tar implementations.
COPYFILE_DISABLE=1 tar -czf "$run_dir/bundle.tgz.partial" -C "$run_dir" plan.json normalized
# Only expose the completed bundle name once archiving succeeds.
mv "$run_dir/bundle.tgz.partial" "$run_dir/bundle.tgz"
printf 'Bundle ready for the CI artifact collector: %s/bundle.tgz\n' "$run_dir"

#!/bin/sh
# Check the controlled, pretty-printed one-artifact index from replace.yaml.
set -eu

if [ "$#" -ne 1 ]; then
  printf 'Usage: %s replaced/index.json\n' "$0" >&2
  exit 2
fi
index=$1
effective=$(sed -n '/^        "effective": {/,/^        "defaulted": \[/p' "$index")
build=$(printf '%s\n' "$effective" | sed -n '/^          "build": {/,/^          }/p')
removal=$(sed -n '/^            "field": "build.id",/,/^          }/p' "$index")

if [ -z "$effective" ] || [ -z "$build" ] || [ -z "$removal" ]; then
  printf 'FAIL: replacement index lacks effective snapshot, build, or build.id change\n' >&2
  exit 1
fi
if ! printf '%s\n' "$effective" | grep -F '"id": "console"' >/dev/null; then
  printf 'FAIL: replacement selected a different effective artifact ID\n' >&2
  exit 1
fi
if ! printf '%s\n' "$effective" | grep -F '"revision": "1111111111111111111111111111111111111111"' >/dev/null; then
  printf 'FAIL: replacement did not set the new revision\n' >&2
  exit 1
fi
if ! printf '%s\n' "$effective" | grep -F '"workspace": "unknown"' >/dev/null; then
  printf 'FAIL: omitted workspace did not become unknown\n' >&2
  exit 1
fi
if printf '%s\n' "$build" | grep -F '"id":' >/dev/null; then
  printf 'FAIL: replacement inherited a build ID\n' >&2
  exit 1
fi
if ! printf '%s\n' "$removal" | grep -F '"before": "old-run"' >/dev/null ||
   ! printf '%s\n' "$removal" | grep -F '"after": null' >/dev/null ||
   ! printf '%s\n' "$removal" | grep -F '"override": true' >/dev/null; then
  printf 'FAIL: build.id removal lacks its exact authorized before/after audit\n' >&2
  exit 1
fi

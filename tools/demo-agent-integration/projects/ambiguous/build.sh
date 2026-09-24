#!/bin/sh
# Synthetic producer; run from this project directory. Not a real build recipe.
set -eu
for marker in services/*server/pom.xml; do
  [ -f "$marker" ] || continue
  module=$(dirname "$marker")
  mkdir -p "$module/target"
  cp seed.cdx.json "$module/target/bom.json"
done

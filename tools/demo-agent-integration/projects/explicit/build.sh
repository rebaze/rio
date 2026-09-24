#!/bin/sh
# Synthetic producer; run from this project directory. Not a real build recipe.
set -eu
mkdir -p desktop/target
cp seed.cdx.json desktop/target/bom.json

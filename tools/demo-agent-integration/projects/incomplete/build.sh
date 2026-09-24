#!/bin/sh
# Synthetic producer; run from this project directory. Not a real build recipe.
set -eu
mkdir -p services/billing-server/target
cp seed.cdx.json services/billing-server/target/bom.json
printf "Reporting SBOM producer is not configured yet.\n"

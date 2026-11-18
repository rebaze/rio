#!/bin/sh
set -eu

# Resolve both inputs before entering the disposable example project.
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
binary=$(command -v "${RIO_BIN:-rio}") || { echo "Set RIO_BIN to an installed Rio binary." >&2; exit 1; }
case "$binary" in /*) ;; *) binary="$(pwd)/$binary" ;; esac

project=$(mktemp -d)
echo "Synthetic project and receipt: $project"
cd "$project"
mkdir target
cp "$here/../demo-use-case/inputs/bom.json" target/bom.json
"$binary" init
"$binary" init --write
"$binary" plan
"$binary" --skip-delivery

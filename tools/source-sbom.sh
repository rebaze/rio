#!/usr/bin/env sh
#
# source-sbom.sh - the CycloneDX SBOM of rio's own source, as a release ships it.
#
#   tools/source-sbom.sh VERSION OUT [RIO RECEIPT]
#
# VERSION is the release without its v (0.8.2). The SBOM's subject is rio at
# that version. Demo fixtures, test data and workflows are not part of rio,
# and syft's file entries name manifests, not dependencies, so all of them are
# left out: what remains is rio's Go modules, each with a version and a purl.
#
# Given a rio binary and a receipt path, rio's own strict gate then checks the
# SBOM and writes its run receipt there. A failing gate fails the script, and
# the receipt of the failure is still written.
#
# Release preflight, the release and CI all make the SBOM here, so what a
# release gate saw is what ships.

set -eu

usage() {
	echo "usage: $0 VERSION OUT [RIO RECEIPT]" >&2
	exit 2
}

[ $# -eq 2 ] || [ $# -eq 4 ] || usage
version=$1
out=$2
# grep reads lines, so a version must also be exactly one line.
if [ "$(printf '%s\n' "$version" | wc -l)" -ne 1 ] ||
	! printf '%s\n' "$version" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$'; then
	echo "source-sbom.sh: version must be X.Y.Z without a v, not \"$version\"" >&2
	exit 2
fi
absolute() {
	case $1 in
	/*) printf '%s\n' "$1" ;;
	*) printf '%s/%s\n' "$PWD" "$1" ;;
	esac
}
out=$(absolute "$out")

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
(
	cd "$root"
	SYFT_FILE_METADATA_SELECTION=none syft dir:. \
		--source-name rio --source-version "$version" \
		--exclude './dist/**' --exclude './tools/**' --exclude './testdata/**' --exclude './.github/**' \
		--output "cyclonedx-json@1.6=$out"
)

[ $# -eq 4 ] || exit 0
rio=$(absolute "$3")
receipt=$(absolute "$4")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cp "$out" "$work/rio-source.cdx.json"
cat >"$work/rio.yaml" <<'EOF'
version: 1
artifacts:
  - id: rio-source
    sbom: rio-source.cdx.json
gate:
  mode: fail
  require: [name, version, purl]
EOF
"$rio" normalize --manifest "$work/rio.yaml" --out "$work/out" --gate fail --receipt "$receipt" --quiet

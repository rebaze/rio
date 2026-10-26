#!/usr/bin/env sh
#
# source-sbom.sh - the CycloneDX SBOM of rio, as a release ships it.
#
#   tools/source-sbom.sh VERSION OUT RIO RECEIPT
#
# VERSION is the release without its v (0.9.0). The SBOM lists every Go module
# linked into any of the six release binaries, the standard library included,
# with its dependency graph, and declares that inventory complete. The Go
# toolchain and the other files in the release archives are not part of it.
#
# cyclonedx-gomod, pinned in tools/security, reads the modules each target
# links. It runs in a throwaway clone of the committed tree, tagged vVERSION
# there so the subject's purl carries the release version; the caller's
# repository is never written. The six results are merged into one SBOM, and
# tools/source-sbom-modules.json supplies each module's creator and concluded
# licence: a module without a row there, or one whose detected licence the row
# neither concludes nor records, fails the script.
#
# rio then normalizes the SBOM, adds the creators of the SBOM and of rio, and
# checks it against BSI TR-03183-2 with its strict gate. OUT is rio's output,
# the SBOM a release attests, and RECEIPT rio's run receipt, written even when
# the gate fails; a failing gate fails the script.
#
# Release preflight, the release and CI all make the SBOM here, so what a
# release gate saw is what ships.

set -eu

usage() {
	echo "usage: $0 VERSION OUT RIO RECEIPT" >&2
	exit 2
}

[ $# -eq 4 ] || usage
version=$1
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
out=$(absolute "$2")
rio=$(absolute "$3")
receipt=$(absolute "$4")

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
# SOURCE_SBOM_MODULES points at another table; only the script's own checks use it.
modules=$(absolute "${SOURCE_SBOM_MODULES:-$root/tools/source-sbom-modules.json}")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# The generator is built for this machine before any GOOS is set.
go -C "$root/tools/security" build -o "$work/cyclonedx-gomod" github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod

git clone --quiet --no-local "$root" "$work/src"
git -C "$work/src" tag -f "v$version" HEAD >/dev/null

# linux/amd64 comes first: its subject is the one kept. The targets are
# .goreleaser.yaml's.
for target in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
	GOOS=${target%/*} GOARCH=${target#*/} CGO_ENABLED=0 "$work/cyclonedx-gomod" app \
		-json -std -licenses -short-purls -output-version 1.6 \
		-main cmd/rio -output "$work/$(echo "$target" | tr / -).cdx.json" "$work/src" 2>"$work/gomod.log" || {
		cat "$work/gomod.log" >&2
		exit 1
	}
done
set -- "$work"/linux-amd64.cdx.json "$work"/linux-arm64.cdx.json "$work"/darwin-amd64.cdx.json \
	"$work"/darwin-arm64.cdx.json "$work"/windows-amd64.cdx.json "$work"/windows-arm64.cdx.json

# One component per bom-ref, and for each ref the union of what it depends on
# on any target. cyclonedx-gomod makes the standard library a dependency of
# rio only, but every linked module imports it, so it becomes one of each.
jq -n '[inputs] as $docs | $docs[0]
	| .components = ([$docs[].components[]] | group_by(."bom-ref") | map(.[0]))
	| ([.components[] | select(.name == "std")."bom-ref"][0]
		// error("source-sbom.sh: cyclonedx-gomod listed no standard library")) as $std
	| .dependencies = ([$docs[].dependencies[]] | group_by(.ref)
		| map(.[0].ref as $ref | {ref: $ref, dependsOn: ([.[].dependsOn // [] | .[]]
			+ (if $ref == $std then [] else [$std] end) | unique)}))' "$@" >"$work/merged.cdx.json"

# The table's verdict: one line per module it cannot vouch for.
subject=$(jq -r '.metadata.component.name' "$work/merged.cdx.json")
jq -r --slurpfile table "$modules" --arg subject "$subject" '$table[0].modules as $rows
	| ([.components[]] + [.metadata.component])[]
	| .name as $name | $rows[$name] as $row
	| ([.evidence.licenses[]? | .license.id // .license.name // .expression // empty] | sort | join(" AND ")) as $detected
	| if $row == null then "no row for \($name)"
	  elif ($row.licence // "") == "" then "no licence for \($name)"
	  elif $name != $subject and ($row.creator // "") == "" then "no creator for \($name)"
	  elif $row.detected != null and ($row.note // "") == "" then "no note for \($name), whose detected licence differs"
	  elif $detected != "" and $row.detected != null and $detected != $row.detected then "\($name) is detected as \($detected), but the table records the detection \($row.detected)"
	  elif $detected != "" and $row.detected == null and $detected != $row.licence then "\($name) is detected as \($detected), but the table concludes \($row.licence)"
	  else empty end' "$work/merged.cdx.json" >"$work/problems"
if [ -s "$work/problems" ]; then
	echo "source-sbom.sh: $modules does not cover the linked modules:" >&2
	sed 's/^/  /' "$work/problems" >&2
	exit 1
fi

# Creators, concluded licences and levels from the table, and the claim: the
# subject's inventory and every listed component's dependencies are complete.
jq --slurpfile table "$modules" '$table[0].modules as $rows
	| def concluded($row): [{expression: $row.licence, acknowledgement: "concluded"}];
	  def level($l): (.properties // []) + [{name: "rio:tr-03183-2:level", value: $l}];
	.components |= map($rows[.name] as $row
		| .manufacturer = {url: [$row.creator]} | .licenses = concluded($row) | .properties = level("assembled"))
	| .metadata.component |= ($rows[.name] as $row
		| .properties = [.properties[]? | select(.name | startswith("cdx:gomod:build:env:") | not)]
		| .licenses = concluded($row) | .properties = level("logical"))
	| .metadata.component["bom-ref"] as $root
	| .compositions = [{aggregate: "complete", assemblies: [$root],
		dependencies: ([$root] + [.components[]."bom-ref"])}]' "$work/merged.cdx.json" >"$work/rio-source.cdx.json"

cat >"$work/rio.yaml" <<EOF
version: 1
artifacts:
  - id: rio-source
    sbom: rio-source.cdx.json
    subject:
      name: rio
      version: "$version"
enrichment:
  producer:
    name: rebaze GmbH
    url: [https://rebaze.de]
  subject:
    manufacturer:
      name: rebaze GmbH
      url: [https://rebaze.de]
gate:
  mode: fail
  profile: bsi-tr-03183-2@2.1.0
  require: [name, version, purl]
EOF
status=0
"$rio" normalize --manifest "$work/rio.yaml" --out "$work/out" --gate fail --receipt "$receipt" --quiet || status=$?
if [ -f "$receipt" ]; then
	normalized="$work/out/runs/$(jq -r '.run.id' "$receipt")/$(jq -r '.artifacts[0].output.path // empty' "$receipt")"
	[ ! -f "$normalized" ] || cp "$normalized" "$out"
fi
exit "$status"

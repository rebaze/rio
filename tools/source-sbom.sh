#!/usr/bin/env sh
#
# source-sbom.sh - the CycloneDX SBOM of rio, as a release ships it.
#
#   tools/source-sbom.sh VERSION OUT RIO RECEIPT [NORMALIZATION_OUTPUT_ROOT [CLAIMS_JSON]]
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
# NORMALIZATION_OUTPUT_ROOT optionally preserves rio's run directory, index
# and normalized SBOM for verified native delivery after this script exits.
# CLAIMS_JSON optionally supplies explicit source/build claims, bound to the raw
# producer SBOM by rio-context.py before the same native normalization pass.
#
# CI and the release both make the SBOM here, so the SBOM checked before the
# tag is made the same way as the one that ships.

set -eu

usage() {
	echo "usage: $0 VERSION OUT RIO RECEIPT [NORMALIZATION_OUTPUT_ROOT [CLAIMS_JSON]]" >&2
	exit 2
}

[ $# -eq 4 ] || [ $# -eq 5 ] || [ $# -eq 6 ] || usage
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
claims=
if [ $# -eq 6 ]; then
	claims=$(absolute "$6")
	# Share the orchestrator's strict nonsecret-claims validation, before Go or
	# the cross-platform generator can run. Importing it performs no work.
	python3 - "$root/tools/self-sbom.py" "$claims" <<'PY'
import importlib.util
import json
from pathlib import Path
import sys
spec = importlib.util.spec_from_file_location('self_sbom', sys.argv[1])
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)
try:
    tool.validate_build_claims(json.loads(Path(sys.argv[2]).read_text(encoding='utf-8')))
except (ValueError, OSError):
    sys.exit('source-sbom.sh: invalid build claims')
PY
fi
# SOURCE_SBOM_MODULES points at another table; only the script's own checks use it.
modules=$(absolute "${SOURCE_SBOM_MODULES:-$root/tools/source-sbom-modules.json}")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
normalization_out=$(absolute "${5:-$work/out}")

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
jq -n '
	# Validate every target before deduplication can hide a conflicting identity.
	# -short-purls emits exactly pkg:golang/std@goVERSION. A bom-ref is opaque;
	# keep it, even when the generator happens to use the old purl as its value.
	def standard_library:
		[.components[] | select(.name == "std" or .name == "stdlib"
			or (.purl // "" | strings | test("^pkg:golang/(std|stdlib)(@|$)")))]
		| if length != 1 then error("source-sbom.sh: expected exactly one standard library per target")
		  else .[0] end
		| if .name != "std" or .type != "library"
			or (.version | type) != "string" or (."bom-ref" | type) != "string"
			or ."bom-ref" == "" then error("source-sbom.sh: malformed generator standard library identity")
		  elif (.version | test("^go1\\.(0|[1-9][0-9]*)(\\.(0|[1-9][0-9]*)|(beta|rc)[1-9][0-9]*)$")) == false
			then error("source-sbom.sh: unsupported standard library Go version")
		  elif .purl != ("pkg:golang/std@" + .version)
			then error("source-sbom.sh: conflicting standard library name, version or purl")
		  else {name, version, purl, "bom-ref"} end;
	[inputs] as $docs
	| ([$docs[] | standard_library] | unique) as $stdlibs
	| if ($stdlibs | length) != 1 then error("source-sbom.sh: conflicting standard library identities across targets") else . end
	| $stdlibs[0]."bom-ref" as $std
	| $docs[0]
	| .components = ([$docs[].components[]] | group_by(."bom-ref") | map(.[0]))
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
		dependencies: ([$root] + [.components[]."bom-ref"])}]
	# Apply the reviewed std row first, then use the consumer/OSV identity.
	# Only identity fields change; graph and composition references stay intact.
	| .components |= map(if .name == "std" then
		.name = "stdlib" | .version |= ltrimstr("go") | .purl = ("pkg:golang/stdlib@" + .version)
		else . end)' "$work/merged.cdx.json" >"$work/rio-source.cdx.json"

context_yaml=
if [ -n "$claims" ]; then
	set -- python3 "$root/tools/rio-context.py" --artifact-id rio-source --sbom "$work/rio-source.cdx.json" \
		--source-repository https://github.com/rebaze/rio \
		--source-revision "$(jq -r '.sourceRevision' "$claims")" --build-url "$(jq -r '.buildURL' "$claims")"
	if jq -e 'has("buildID")' "$claims" >/dev/null; then
		set -- "$@" --build-id "$(jq -r '.buildID' "$claims")"
	fi
	"$@" >"$work/context.json"
	context_yaml='    context:
      file: context.json
      require: [source.repository, source.revision, build.url]
'
fi

cat >"$work/rio.yaml" <<EOF
version: 1
artifacts:
  - id: rio-source
    sbom: rio-source.cdx.json
    subject:
      name: rio
      version: "$version"
${context_yaml}enrichment:
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
"$rio" normalize --manifest "$work/rio.yaml" --out "$normalization_out" --gate fail --receipt "$receipt" --quiet || status=$?
if [ -f "$receipt" ]; then
	normalized="$normalization_out/runs/$(jq -r '.run.id' "$receipt")/$(jq -r '.artifacts[0].output.path // empty' "$receipt")"
	[ ! -f "$normalized" ] || cp "$normalized" "$out"
fi
exit "$status"

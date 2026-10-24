#!/bin/sh
# Offline showcase using only an installed Rio binary and committed synthetic data.
set -eu

if [ "$#" -gt 1 ]; then
  printf 'Usage: %s [rio-command-or-path]\n' "$0" >&2
  exit 2
fi
rio_command=${1:-${RIO_BIN:-rio}}
if ! rio_bin=$(command -v "$rio_command"); then
  printf 'Cannot find rio: %s\n' "$rio_command" >&2
  exit 2
fi
case "$rio_bin" in
  /*) ;;
  *) rio_bin=$(pwd)/$rio_bin ;;
esac

# Python 3.9+ reads the structured execution result; paths may contain spaces.
result_dir() {
  python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["runDirectory"])' "$1"
}
inspect_result() {
  receipt=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["receipt"]["path"])' "$1")
  "$rio_bin" record inspect --file "$receipt" --json > "$1.inspection.json"
  python3 - "$1" "${2:-success}" <<'PY_CHECK'
import json, sys
result = json.load(open(sys.argv[1]))
record = json.load(open(sys.argv[1] + ".inspection.json"))["record"]
assert record["kind"] == "rio-run-receipt" and record["schemaVersion"] == 1
assert record["run"]["id"] == result["runId"]
assert record["run"]["operation"] == "normalize"
assert record["run"]["outcome"] == result["outcome"] == sys.argv[2]
PY_CHECK
}

demo_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/rio-context.XXXXXXXX")
trap 'printf "\nDemo inputs and results retained in: %s\n" "$run_dir"' 0
cp -R "$demo_dir/inputs" "$run_dir/inputs"
cp "$demo_dir"/*.yaml "$demo_dir"/*.json "$run_dir/"
cp "$demo_dir/check-replacement.sh" "$run_dir/"
cd "$run_dir"

printf 'CI build context demo (synthetic inputs; no network)\n'
"$rio_bin" version

printf '\n1. Plan before the declared context file exists\n'
mv context.json context-saved.json
"$rio_bin" plan --manifest rio.yaml --out normalized --json > plan-before-context.json
if ! grep -F '"file": "context.json"' plan-before-context.json >/dev/null; then
  printf 'FAIL: plan did not report the context binding\n' >&2
  exit 1
fi
mv context-saved.json context.json

printf '\n2. Normalize both products from one selected context file\n'
"$rio_bin" normalize --manifest rio.yaml --out normalized --gate fail --attest --json > first-result.json
first_dir=$(result_dir first-result.json)
inspect_result first-result.json
"$rio_bin" normalize --manifest rio.yaml --out normalized --gate fail --attest --json > rerun-result.json
second_dir=$(result_dir rerun-result.json)
inspect_result rerun-result.json
[ "$first_dir" != "$second_dir" ]
for file in index.json console.cdx.json agent.cdx.json; do
  cmp "$first_dir/$file" "$second_dir/$file"
done
printf 'PASS: two products normalized; same inputs produced identical index and SBOM bytes.\n'

printf '\n3. Shipped-file digests declared for console (synthetic values, producer assertions)\n'
python3 - context.json "$first_dir" first-result.json.inspection.json <<'PY_DISTRIBUTIONS'
import json, os, sys
declared = {a["id"]: a.get("distributions", []) for a in json.load(open(sys.argv[1]))["artifacts"]}
receipt = {a["id"]: a for a in json.load(open(sys.argv[3]))["record"]["artifacts"]}
for artifact in ("console", "agent"):
    sbom = json.load(open(os.path.join(sys.argv[2], artifact + ".cdx.json")))
    refs = [r for r in sbom["metadata"]["component"].get("externalReferences", []) if r["type"] == "distribution"]
    expected = [{"type": "distribution", "url": d.get("url", d["name"]),
                 "hashes": [{"alg": "SHA-256", "content": d["sha256"]}]} for d in declared[artifact]]
    assert refs == expected, (artifact, refs)
    listed = receipt[artifact].get("distributions")
    if not declared[artifact]:
        assert listed is None, (artifact, listed)
        print("%s: no distributions declared; the SBOM gains none and the receipt omits the field" % artifact)
        continue
    assert listed == [{"name": d["name"], "sha256": d["sha256"], "assertion": "producer"} for d in declared[artifact]], listed
    print("%s SBOM metadata.component.externalReferences:" % artifact)
    for ref in refs:
        print("  distribution %s SHA-256 %s" % (ref["url"], ref["hashes"][0]["content"]))
    print("%s receipt distributions:" % artifact)
    for item in listed:
        print("  %s sha256=%s assertion=%s" % (item["name"], item["sha256"], item["assertion"]))
PY_DISTRIBUTIONS
printf 'PASS: each declared file became a distribution reference and a receipt entry; Rio did not hash any file.\n'

refuse() {
  manifest=$1
  diagnostic=$2
  output=$3
  status=0
  "$rio_bin" normalize --manifest "$manifest" --out "$output" --json > "$output-result.json" 2> "$output.log" || status=$?
  if [ "$status" -ne 2 ] || ! grep -F "$diagnostic" "$output.log" >/dev/null; then
    printf 'FAIL: %s expected exit 2 with %s (got %s)\n' "$manifest" "$diagnostic" "$status" >&2
    cat "$output.log" >&2
    exit 1
  fi
  inspect_result "$output-result.json" failed
  if [ -n "$(find "$output" -type f \( -name index.json -o -name '*.cdx.json' -o -name '*.intoto.json' \) -print)" ]; then
    printf 'FAIL: %s wrote normalized outputs\n' "$manifest" >&2
    exit 1
  fi
  printf 'PASS: %s refused with %s; failed receipt retained, no normalized outputs.\n' "$manifest" "$diagnostic"
}

printf '\n4. Refuse stale digest, missing required field, and prior revision conflict\n'
refuse stale.yaml sha256 stale-refused
refuse missing.yaml build.url missing-refused
refuse conflict.yaml source.revision conflict-refused

printf '\n5. Explicit replacement of revision and removal of old owned claims\n'
"$rio_bin" normalize --manifest replace.yaml --out replaced --json > replacement-result.json
replaced_dir=$(result_dir replacement-result.json)
inspect_result replacement-result.json
sh ./check-replacement.sh "$replaced_dir/index.json"
python3 - replacement-result.json.inspection.json <<'PY_CHECK'
import json, sys
changes = json.load(open(sys.argv[1]))["record"]["artifacts"][0]["changes"]["metadata"]
removal = next(c for c in changes if c["field"] == "build.id")
assert removal["before"] == "old-run" and removal["after"] is None
revision = next(c for c in changes if c["field"] == "source.revision")
assert revision["before"] != revision["after"]
assert revision["after"] == "1111111111111111111111111111111111111111"
PY_CHECK
printf 'PASS: authorized replacement; inspect the replacement runDirectory/index.json for before/after and null removal.\n'
printf '\nInspect plan-before-context.json, normalized/, replaced/, and refusal logs in the retained directory.\n'

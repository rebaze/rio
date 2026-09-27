#!/bin/sh
# Synthetic example. Requires only an installed Rio v0.7.0+ and standard utilities, and Python 3.9+.
set -eu
if [ "$#" -gt 1 ]; then
  printf 'Usage: %s [rio-command-or-path]\n' "$0" >&2
  exit 2
fi
rio_command=${1:-${RIO_BIN:-rio}}
if ! rio_bin=$(command -v "$rio_command"); then
  printf 'Cannot find rio: %s. Install a release v0.7.0 or newer or set RIO_BIN.\n' "$rio_command" >&2
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
run_dir=$(mktemp -d "${TMPDIR:-/tmp}/rio-artifact-sets.XXXXXXXX")
trap 'printf "\nDemo inputs and results retained in: %s\n" "$run_dir"' 0
cp -R "$demo_dir/services" "$demo_dir/desktop" "$run_dir/"
cp "$demo_dir/"*.yaml "$run_dir/"
cd "$run_dir"
cp rio.yaml original-manifest.yaml

# The index is authoritative; do not collect every file from a reused directory.
# Match the index's top-level artifact IDs, not context or transform IDs.
check_members() {
  directory=$(result_dir "$1-result.json")
  python3 -c 'import json,sys; print("\n".join(a["id"] for a in json.load(open(sys.argv[1]))["artifacts"]))' "$directory/index.json" > actual-members
  printf '%s\n' "$2" > expected-members
  if ! cmp -s expected-members actual-members; then
    printf 'FAIL: unexpected membership in %s/index.json\n' "$1" >&2
    cat actual-members >&2
    exit 1
  fi
}
refuse() {
  status=0
  "$rio_bin" "$1" --manifest "$2" --out "$3" --json > "$3-result.json" 2> "$3.log" || status=$?
  cat "$3.log"
  if [ "$status" -ne 2 ]; then
    printf 'FAIL: expected exit 2 without normalized output at %s (exit %s)\n' "$3" "$status" >&2
    exit 1
  fi
  if [ "$1" = normalize ]; then
    inspect_result "$3-result.json" failed
    python3 - "$3-result.json" <<'PY_CHECK'
import json, pathlib, sys
result = json.load(open(sys.argv[1]))
assert result["outcome"] == "failed"
run = pathlib.Path(result["runDirectory"])
assert not (run / "index.json").exists()
assert not list(run.glob("*.cdx.json")) and not list(run.glob("*.intoto.json"))
PY_CHECK
  else
    [ ! -e "$3" ]
  fi
}

printf 'Artifact sets demo (synthetic data; no network)\n'
"$rio_bin" version
printf '\n1. Explicit-only, sets-only and mixed declarations\n'
"$rio_bin" normalize --manifest explicit-only.yaml --out explicit --gate fail --json > explicit-result.json
inspect_result explicit-result.json
check_members explicit desktop
"$rio_bin" normalize --manifest sets-only.yaml --out sets --gate fail --json > sets-result.json
inspect_result sets-result.json
check_members sets 'billing-server
orders-server'
"$rio_bin" plan --json > plan.json
"$rio_bin" normalize --out mixed --gate fail --attest --json > mixed-result.json
inspect_result mixed-result.json
check_members mixed 'desktop
billing-server
orders-server'
printf 'PASS: web-client is outside the marker selector. Each server has a separate SBOM.\n'

printf '\n2. Add a matching module without editing rio.yaml\n'
mkdir -p services/reporting-server/target
cp services/billing-server/pom.xml services/reporting-server/pom.xml
# Keep the copied subject unchanged: the directory sets only Rio output identity.
cp services/billing-server/target/bom.json services/reporting-server/target/bom.json
"$rio_bin" plan
"$rio_bin" normalize --out added --gate fail --json > added-result.json
inspect_result added-result.json
check_members added 'desktop
billing-server
orders-server
reporting-server'
[ -f "$(result_dir added-result.json)/reporting-server.cdx.json" ]
cmp -s rio.yaml original-manifest.yaml
printf 'PASS: reporting-server appeared automatically; rio.yaml is unchanged.\n'

printf '\n3. Remove only its SBOM: plan and normalize must refuse\n'
rm services/reporting-server/target/bom.json
refuse plan rio.yaml missing-plan
refuse normalize rio.yaml missing-normalize
printf 'PASS: selected module with no SBOM is an explicit failure.\n'

printf '\n4. Remove its marker: the new index omits the module\n'
rm services/reporting-server/pom.xml
"$rio_bin" normalize --out removed --gate fail --json > removed-result.json
inspect_result removed-result.json
check_members removed 'desktop
billing-server
orders-server'
printf 'PASS: reporting-server is absent from the removal run index.\n'

printf '\n5. Exclude a selected marker before requiring its SBOM\n'
mkdir -p services/experimental-server
cp services/billing-server/pom.xml services/experimental-server/pom.xml
"$rio_bin" normalize --manifest excluded.yaml --out excluded --gate fail --json > excluded-result.json
inspect_result excluded-result.json
check_members excluded 'billing-server
orders-server'
rm services/experimental-server/pom.xml

printf '\n6. Refuse overlapping sets\n'
refuse plan overlap.yaml overlap-plan
refuse normalize overlap.yaml overlap-normalize
cmp -s rio.yaml original-manifest.yaml
printf '\nPASS: discovery, automatic inclusion, missing-SBOM refusal, removal, exclusion and overlap refusal.\n'
printf 'All invocations own separate run directories; index.json defines their membership.\n'

printf '\n7. Retain and inspect selection scope and requirements offline\n'
# Each execution owns its receipt; inspect the actual exclusion run only.
inspect_result excluded-result.json
python3 - excluded-result.json.inspection.json <<'PY_CHECK'
import json, sys
record = json.load(open(sys.argv[1]))["record"]
assert record["kind"] == "rio-run-receipt" and record["schemaVersion"] == 1
assert [a["id"] for a in record["artifacts"]] == ["billing-server", "orders-server"]
assert record["exclusions"] == [{"rule": "services/experimental-server/pom.xml",
                                  "scope": "artifactSets[0]: services/**/*server/pom.xml",
                                  "reason": "artifact-set-exclude"}]
assert all(a["checks"]["componentScope"] == "all components including nested" and
           a["checks"]["mode"] == "fail" for a in record["artifacts"])
PY_CHECK
printf 'PASS: automatic receipt retains configured exclusions, resolved membership and effective checks.\n'

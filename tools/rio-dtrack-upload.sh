#!/usr/bin/env bash
#
# Uploads the SBOMs listed in a rio normalize index.json to DependencyTrack.
#
# Usage:
#   DTRACK_URL=https://dtrack.example.com \
#   DTRACK_API_KEY=... \
#   ./tools/rio-dtrack-upload.sh [path/to/index.json]
#
# Optional:
#   DTRACK_PROJECT_PREFIX   prepended to the artifact id, e.g. "acme/"
#   DTRACK_PARENT_UUID      uuid of the project to nest each artifact under
#   DTRACK_PARENT_NAME      name of that project, as an alternative to the uuid
#   DTRACK_PARENT_VERSION   version of it; only read alongside DTRACK_PARENT_NAME
#   DTRACK_POLL             1 to wait for processing to finish (default 1)
#   DTRACK_POLL_TIMEOUT     seconds to wait per upload (default 120)
#   DTRACK_UPLOAD_FAILED    1 to upload artifacts that failed the rio gate
#
# The parent project must already exist: DependencyTrack looks it up and refuses
# the upload with 404 if it is missing, rather than creating it. It also applies
# the parent ONLY when it creates the child, so setting a parent for a project
# that already exists does nothing. This script says so instead of letting the
# run imply a hierarchy it did not build.
#
# API key needs: BOM_UPLOAD, PROJECT_CREATION_UPLOAD, VIEW_PORTFOLIO.

set -euo pipefail

: "${DTRACK_URL:?set DTRACK_URL}"
: "${DTRACK_API_KEY:?set DTRACK_API_KEY}"

INDEX="${1:-target/rio/index.json}"
PREFIX="${DTRACK_PROJECT_PREFIX:-}"
POLL="${DTRACK_POLL:-1}"
POLL_TIMEOUT="${DTRACK_POLL_TIMEOUT:-120}"
UPLOAD_FAILED="${DTRACK_UPLOAD_FAILED:-0}"
PARENT_UUID="${DTRACK_PARENT_UUID:-}"
PARENT_NAME="${DTRACK_PARENT_NAME:-}"
PARENT_VERSION="${DTRACK_PARENT_VERSION:-}"

# DependencyTrack reads parentUUID in preference to parentName and ignores the
# name entirely when both arrive. Refuse the ambiguity here rather than upload
# something that looks like it honoured a name it never read.
if [ -n "$PARENT_UUID" ] && [ -n "$PARENT_NAME" ]; then
  echo "set DTRACK_PARENT_UUID or DTRACK_PARENT_NAME, not both:" \
       "DependencyTrack ignores the name when a uuid is present" >&2
  exit 2
fi

# parentVersion is only read alongside parentName, so a version on its own is a
# setting that silently does nothing.
if [ -n "$PARENT_VERSION" ] && [ -z "$PARENT_NAME" ]; then
  echo "DTRACK_PARENT_VERSION needs DTRACK_PARENT_NAME:" \
       "DependencyTrack only reads the parent version when a parent name is given" >&2
  exit 2
fi

# Built once: the same parent applies to every artifact in the run.
parent_form=()
if [ -n "$PARENT_UUID" ]; then
  parent_form=(--form-string "parentUUID=${PARENT_UUID}")
elif [ -n "$PARENT_NAME" ]; then
  parent_form=(--form-string "parentName=${PARENT_NAME}")
  if [ -n "$PARENT_VERSION" ]; then
    parent_form+=(--form-string "parentVersion=${PARENT_VERSION}")
  fi
fi

DTRACK_URL="${DTRACK_URL%/}"

command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; exit 2; }
[ -f "$INDEX" ] || { echo "no index at $INDEX" >&2; exit 2; }

base_dir="$(cd "$(dirname "$INDEX")" && pwd)"
rc=0

# project_exists reports whether DependencyTrack already holds this project.
# 0 means it does, 1 means it does not, 2 means the question could not be
# answered — a warning check must never fail an upload that would have worked.
project_exists() {
  local code
  code="$(curl -sS -o /dev/null -w '%{http_code}' -G "${DTRACK_URL}/api/v1/project/lookup" \
    --data-urlencode "name=$1" \
    --data-urlencode "version=$2" \
    -H "X-Api-Key: ${DTRACK_API_KEY}" \
    -H "Accept: application/json")" || return 2

  case "$code" in
    200) return 0 ;;
    404) return 1 ;;
    *) return 2 ;;
  esac
}

upload() {
  local id="$1" sbom="$2" gate="$3"
  local name version token http body

  name="${PREFIX}${id}"

  # The project version is the release the SBOM describes, never the CI build
  # number: DependencyTrack holds releases, the records hold builds.
  version="$(jq -r '.metadata.component.version // empty' "$sbom")"
  if [ -z "$version" ]; then
    echo "SKIP  $id: no metadata.component.version in $sbom" >&2
    return 1
  fi

  # DependencyTrack applies the parent only when it CREATES the project: in
  # BomResource the parent lookup sits inside `if (project == null &&
  # autoCreate)`. Re-uploading a project that already exists ignores
  # parentUUID and parentName without saying so, and the run would look like it
  # built a hierarchy it did not touch. Ask first, and warn.
  if [ -n "${PARENT_UUID}${PARENT_NAME}" ] && project_exists "$name" "$version"; then
    echo "WARN  $id: ${name} ${version} already exists, so the parent is not applied:" \
         "DependencyTrack sets a parent only when it creates the project." \
         "Re-parent it in the UI or the API, or delete and re-upload." >&2
  fi

  # Multipart POST rather than the base64 PUT: no whole-file encoding in shell.
  # A transport failure is reported per artifact instead of aborting the run
  # under set -e, so one unreachable moment does not strand the rest.
  #
  # --form-string, not -F, for every field whose value is data: curl reads a
  # leading @ or < in an -F value as "send this local file". projectVersion
  # comes straight out of the SBOM, which is generator- and dependency-
  # influenced content, so a crafted metadata.component.version of
  # "@/home/runner/.netrc" would post the runner's credentials to DTRACK_URL.
  # Only bom= is a real file reference.
  body="$(curl -sS -X POST "${DTRACK_URL}/api/v1/bom" \
    -H "X-Api-Key: ${DTRACK_API_KEY}" \
    -H "Accept: application/json" \
    --form-string "projectName=${name}" \
    --form-string "projectVersion=${version}" \
    --form-string "autoCreate=true" \
    ${parent_form[@]+"${parent_form[@]}"} \
    -F "bom=@${sbom}" \
    -w '\n%{http_code}')" || {
    echo "FAIL  $id: upload request to ${DTRACK_URL} failed" >&2
    return 1
  }

  http="$(printf '%s' "$body" | tail -n1)"
  body="$(printf '%s' "$body" | sed '$d')"

  # DependencyTrack answers 200, but a proxy in front of it may rewrite the
  # accepted upload to 201, so treat both as success.
  case "$http" in
    200 | 201) ;;
    404)
      # 404 on an upload is the parent lookup, not a bad URL: DependencyTrack
      # refuses rather than creating a parent that does not exist.
      echo "FAIL  $id: HTTP 404 ${body}" >&2
      if [ -n "${PARENT_UUID}${PARENT_NAME}" ]; then
        echo "      the parent ${PARENT_UUID:-${PARENT_NAME}${PARENT_VERSION:+ $PARENT_VERSION}}" \
             "must exist before an artifact can be nested under it; create it first" >&2
      fi
      return 1
      ;;
    403)
      echo "FAIL  $id: HTTP 403 ${body}" >&2
      if [ -n "${PARENT_UUID}${PARENT_NAME}" ]; then
        echo "      the api key needs access to the parent project as well as permission to upload" >&2
      fi
      return 1
      ;;
    *)
      echo "FAIL  $id: HTTP $http ${body}" >&2
      return 1
      ;;
  esac

  token="$(printf '%s' "$body" | jq -r '.token // empty')"
  echo "OK    $id -> ${name} ${version} (gate=${gate}, token=${token:-none})"

  if [ "$POLL" != "1" ] || [ -z "$token" ]; then
    return 0
  fi

  # 4.x serves the upload token status at /api/v1/bom/token/{token}; newer
  # builds also expose /api/v1/event/token/{token}. Try the 4.x path and fall
  # back once, per artifact.
  #
  # Per artifact, not once per run: a 404 does not mean "this instance is a
  # newer build". An unknown or already consumed token 404s on a 4.x server
  # too, and latching on that would silently stop polling every later artifact
  # whose status was perfectly readable.
  local waited=0 resp code poll_path="/api/v1/bom/token" fell_back=0
  while [ "$waited" -lt "$POLL_TIMEOUT" ]; do
    resp="$(curl -sS "${DTRACK_URL}${poll_path}/${token}" \
      -H "X-Api-Key: ${DTRACK_API_KEY}" \
      -H "Accept: application/json" \
      -w '\n%{http_code}')" || resp=""
    code="$(printf '%s' "$resp" | tail -n1)"
    resp="$(printf '%s' "$resp" | sed '$d')"

    if [ "$code" = "404" ] && [ "$fell_back" = "0" ]; then
      poll_path="/api/v1/event/token"
      fell_back=1
      continue
    fi

    case "$code" in
      200 | 201) ;;
      *)
        # The upload itself was accepted; only the status query is unavailable.
        echo "WARN  $id: cannot read token status (HTTP ${code:-none})" >&2
        return 0
        ;;
    esac

    if [ "$(printf '%s' "$resp" | jq -r '.processing // empty')" != "true" ]; then
      echo "      $id processed"
      return 0
    fi
    sleep 3
    waited=$((waited + 3))
  done

  echo "WARN  $id: still processing after ${POLL_TIMEOUT}s" >&2
  return 0
}

# Read the index into a file first. Process substitution hides jq's exit
# status from set -e and from pipefail, so a malformed or shape-changed
# index.json made the script exit 0 having uploaded nothing: exactly the "a run
# that processed nothing looks identical to a clean run" failure rio is built
# to avoid.
rows="$(mktemp)"
trap 'rm -f "$rows"' EXIT

# Unit separator rather than tab: bash treats tab as IFS *whitespace*, so runs
# of tabs collapse and an empty output.path would shift the gate value into the
# path field, reporting a missing file named "ok".
if ! jq -r '.artifacts[]
      | [(.id // ""), (.output.path // ""), (.gate // "unknown")]
      | join("\u001f")' "$INDEX" > "$rows" 2>/dev/null; then
  echo "cannot read $INDEX: not a rio normalize index.json" >&2
  exit 2
fi

if [ ! -s "$rows" ]; then
  echo "no artifacts listed in $INDEX; nothing was uploaded" >&2
  exit 2
fi

while IFS=$'\x1f' read -r id out gate; do
  [ -n "$id" ] || continue

  if [ -z "$out" ]; then
    echo "FAIL  $id: index entry has no output.path" >&2
    rc=1
    continue
  fi

  case "$out" in
    /*) sbom="$out" ;;
    *) sbom="${base_dir}/${out}" ;;
  esac

  if [ ! -f "$sbom" ]; then
    echo "FAIL  $id: missing $sbom" >&2
    rc=1
    continue
  fi

  # A failed rio gate blocks the upload, otherwise the gate is decoration.
  if [ "$gate" = "fail" ] && [ "$UPLOAD_FAILED" != "1" ]; then
    echo "SKIP  $id: rio gate failed" >&2
    rc=1
    continue
  fi

  upload "$id" "$sbom" "$gate" || rc=1
done < "$rows"

exit "$rc"

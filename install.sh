#!/usr/bin/env sh
#
# install.sh - install the rio CLI with one command.
#
#   curl -sSL https://raw.githubusercontent.com/rebaze/rio/main/install.sh | sh
#
# POSIX sh only. This has to work on a bare CI runner under dash or busybox
# ash, so there are no bashisms, no `local`, and no `set -o pipefail` (which
# is not POSIX). The only things it needs on the box are curl or wget, tar,
# and one of sha256sum, shasum or openssl.
#
# It fetches nothing but public release assets and accepts no credential, so
# no token can end up in an argument list, in `ps` output, or in a CI log.
#
# Environment:
#   RIO_VERSION       version or tag to install, e.g. 0.1.0 or v0.1.0.
#                     Default: the latest published release.
#   RIO_INSTALL_DIR   directory to install into. Default: /usr/local/bin when
#                     it is writable, otherwise $HOME/.local/bin.
#
# Everything a human reads goes to stderr, so stdout stays clean for a caller
# that wants to capture it.

set -eu

# A set CDPATH makes `cd` print the directory it landed in, which would end up
# inside the command substitution that resolves the install directory below.
unset CDPATH

rio_repo="rebaze/rio"
rio_releases_url="https://github.com/${rio_repo}/releases"
rio_api_latest_url="https://api.github.com/repos/${rio_repo}/releases/latest"

# Testing seam: install_test.sh overrides this so the "is the system bin dir
# writable" probe is deterministic on any machine. Not a public knob.
rio_system_bin="${RIO_SYSTEM_BIN:-/usr/local/bin}"

# Set by pick_http_client, read by the http_* helpers. A plain global because
# POSIX sh has no `local` and command substitution cannot export upwards.
rio_http_client=""
rio_wget_flags=""

# Cleaned up by the EXIT trap installed in main.
rio_tmp=""
rio_staged=""

log() { printf '%s\n' "$*" >&2; }

die() { printf 'install.sh: %s\n' "$*" >&2; exit 1; }

have() { command -v "$1" >/dev/null 2>&1; }

usage() {
  # stderr, like every other message here, so that piping the script's stdout
  # somewhere never mixes prose into the pipe.
  cat >&2 <<EOF
install.sh - install the rio CLI.

Usage:
  curl -sSL https://raw.githubusercontent.com/${rio_repo}/main/install.sh | sh
  ./install.sh [--help]

Environment:
  RIO_VERSION       version or tag to install, e.g. 0.1.0 or v0.1.0.
                    Default: the latest release at
                    ${rio_releases_url}/latest
  RIO_INSTALL_DIR   directory to install rio into.
                    Default: /usr/local/bin when writable, else
                    \$HOME/.local/bin (created if missing).

Examples:
  RIO_VERSION=0.1.0 sh install.sh
  RIO_INSTALL_DIR=\$HOME/bin sh install.sh

The download is verified against the release's checksums.txt before anything
is installed. That is a transport-integrity check and nothing more: the
checksum file is served from the same release as the archive, so it says that
the bytes arrived intact, not where they came from.

For provenance, verify the keyless cosign signature the release publishes next
to it as checksums.txt.sigstore.json:

  cosign verify-blob --bundle checksums.txt.sigstore.json \\
    --certificate-identity-regexp '^https://github.com/${rio_repo}/' \\
    --certificate-oidc-issuer https://token.actions.githubusercontent.com \\
    checksums.txt

The installer never uses sudo; if the target directory is not writable it says
so and stops.

Supported: linux and darwin on amd64 and arm64. Windows builds are published
as rio_<version>_windows_<arch>.zip at ${rio_releases_url}
EOF
}

# --- platform ----------------------------------------------------------------

detect_os() { # uname -s output
  case "$1" in
    Linux) printf 'linux\n' ;;
    Darwin) printf 'darwin\n' ;;
    MINGW* | MSYS* | CYGWIN* | Windows*)
      die "unsupported operating system: $1. Windows builds are published as rio_<version>_windows_<arch>.zip, download one from ${rio_releases_url}"
      ;;
    *)
      die "unsupported operating system: $1. rio publishes linux and darwin builds at ${rio_releases_url}"
      ;;
  esac
}

detect_arch() { # uname -m output
  case "$1" in
    x86_64 | amd64) printf 'amd64\n' ;;
    aarch64 | arm64) printf 'arm64\n' ;;
    *)
      die "unsupported architecture: $1. rio publishes amd64 and arm64 builds at ${rio_releases_url}"
      ;;
  esac
}

# The release tag carries a leading v; the asset names carry the version
# without it (goreleaser's .Version strips it). Both directions are needed.
strip_v() { printf '%s\n' "${1#v}"; }
add_v() { printf 'v%s\n' "${1#v}"; }

# Must stay in step with the archives name_template in .goreleaser.yaml;
# install_test.sh pins the two against each other.
asset_name() { # version os arch
  printf 'rio_%s_%s_%s.tar.gz\n' "$1" "$2" "$3"
}

# The version is interpolated into the asset name, which becomes both a url and
# a path under the temp dir, so it is checked before it is used anywhere:
# RIO_VERSION=../../../../tmp/pwned would otherwise write outside the temp dir.
# Tags are alphanumerics plus . + - (semver's build and prerelease separators);
# anything else is a mistake or an attack, and either way is not installable.
valid_version() { # version
  case "$1" in
    '' | *[!0-9A-Za-z.+-]*) return 1 ;;
    *) return 0 ;;
  esac
}

# --- http --------------------------------------------------------------------

# Every hop is pinned to https. This script is meant to be run straight off the
# network, and -L follows redirects, so without --proto-redir a single 302 to
# http:// would hand the whole install to anyone on the wire.
#
# The timeouts are what keep this usable in a pipeline: with only --retry, a
# mirror that accepts the connection and then stalls blocks the job forever.
# --connect-timeout bounds the handshake, --max-time the whole transfer.
rio_curl_flags="-fsSL --proto =https --proto-redir =https --connect-timeout 10 --max-time 300 --retry 3 --retry-delay 1"

# wget builds differ too much to hardcode: busybox's understands neither
# --tries nor --https-only, and older GNU builds have no --https-only either.
# So ask this wget what it has and fall back to what both have, -T (in
# GNU that is the dns, connect and read timeout at once; in busybox the network
# timeout). Neither build has a total-time cap, so -T is the whole deadline
# story on the wget path.
wget_flags() {
  rio_help=$(wget --help 2>&1 || true)
  rio_flags="-T 30"
  case "$rio_help" in *--tries*) rio_flags="$rio_flags --tries=3 --waitretry=1" ;; esac
  case "$rio_help" in *--https-only*) rio_flags="$rio_flags --https-only" ;; esac
  printf '%s\n' "$rio_flags"
}

pick_http_client() {
  if have curl; then
    rio_http_client=curl
  elif have wget; then
    rio_http_client=wget
    rio_wget_flags=$(wget_flags)
  else
    die "neither curl nor wget was found. Install one of them and re-run."
  fi
}

# The flag variables are deliberately unquoted: POSIX sh has no arrays, so word
# splitting is how a flag list gets passed on. Both are built above, never from
# anything a caller supplies.
http_fetch() { # url -> body on stdout
  if [ "$rio_http_client" = curl ]; then
    # shellcheck disable=SC2086
    curl $rio_curl_flags "$1"
  else
    # shellcheck disable=SC2086
    wget $rio_wget_flags -q -O - "$1"
  fi
}

http_download() { # url dest
  if [ "$rio_http_client" = curl ]; then
    # shellcheck disable=SC2086
    curl $rio_curl_flags -o "$2" "$1"
  else
    # shellcheck disable=SC2086
    wget $rio_wget_flags -q -O "$2" "$1"
  fi
}

# --- version resolution ------------------------------------------------------

# github.com/<repo>/releases/latest redirects to .../releases/tag/<tag>, so the
# tag can be read off the final url with no jq and no API rate limit.
tag_from_url() { # url -> tag, empty when the url is not a tag url
  printf '%s\n' "$1" | sed -n 's#^.*/releases/tag/\([^/[:space:]][^/[:space:]]*\)$#\1#p'
}

# Fallback for when the redirect cannot be observed (some wget builds do not
# report the effective url). A bare runner has no jq, hence sed.
tag_from_api_json() { # json on stdin -> tag
  sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1
}

resolve_latest_tag() {
  rio_tag=""
  if [ "$rio_http_client" = curl ]; then
    # -I keeps it a HEAD request; -w prints where the redirects landed.
    # shellcheck disable=SC2086
    rio_effective=$(curl $rio_curl_flags -I -o /dev/null -w '%{url_effective}' "${rio_releases_url}/latest" 2>/dev/null || true)
    rio_tag=$(tag_from_url "$rio_effective")
  fi
  if [ -z "$rio_tag" ]; then
    rio_tag=$(http_fetch "$rio_api_latest_url" 2>/dev/null | tag_from_api_json || true)
  fi
  [ -n "$rio_tag" ] || die "could not determine the latest rio release. Set RIO_VERSION explicitly, e.g. RIO_VERSION=0.1.0, or check ${rio_releases_url}"
  printf '%s\n' "$rio_tag"
}

# --- checksums ---------------------------------------------------------------

sha256_tool() {
  if have sha256sum; then
    printf 'sha256sum\n'
  elif have shasum; then
    printf 'shasum\n'
  elif have openssl; then
    printf 'openssl\n'
  else
    return 1
  fi
}

sha256_file() { # file tool -> lowercase hex digest
  case "$2" in
    sha256sum) sha256sum "$1" | cut -d' ' -f1 ;;
    shasum) shasum -a 256 "$1" | cut -d' ' -f1 ;;
    openssl) openssl dgst -sha256 "$1" | sed 's/^.*[= ]//' ;;
    *) return 1 ;;
  esac
}

# awk rather than sed so the asset name is compared as a literal string: the
# name contains dots, which a regex would happily match against anything.
# goreleaser writes "<hash>  <name>"; the "*<name>" binary-mode form is
# accepted too because other tooling emits it.
expected_sha256() { # checksums-file asset-name
  awk -v want="$2" '$2 == want || $2 == "*" want { print $1; exit }' "$1"
}

# What this does and does not prove: checksums.txt is fetched from the same
# release as the archive over the same connection, so matching it catches a
# truncated or corrupted download and nothing more. It is not a provenance
# check - whoever could serve a bad archive could serve a matching checksum.
# .goreleaser.yaml signs checksums.txt with cosign and publishes the bundle as
# checksums.txt.sigstore.json; verifying that is the stronger check, and the
# --help text spells out the cosign verify-blob command for it. Deliberately
# not done here: it would make cosign a prerequisite of a one-line installer.
verify_checksum() { # archive checksums-file asset-name
  rio_tool=$(sha256_tool) || die "no sha256 tool found (looked for sha256sum, shasum and openssl). Refusing to install an unverified download."
  rio_want=$(expected_sha256 "$2" "$3")
  [ -n "$rio_want" ] || die "checksums.txt has no entry for $3. Refusing to install an unverified download."
  rio_got=$(sha256_file "$1" "$rio_tool")
  rio_want=$(printf '%s' "$rio_want" | tr 'ABCDEF' 'abcdef')
  rio_got=$(printf '%s' "$rio_got" | tr 'ABCDEF' 'abcdef')
  if [ "$rio_want" != "$rio_got" ]; then
    die "checksum mismatch for $3: expected $rio_want, got $rio_got. Refusing to install."
  fi
  log "checksum ok for $3 (verified with $rio_tool)"
}

# --- install location --------------------------------------------------------

# /opt/x/ and /opt/x are the same directory, so a trailing slash on either side
# must not decide the comparison - it only made the installer print a "add this
# to your PATH" hint for a directory that was already on PATH.
strip_trailing_slash() { # path
  rio_path="$1"
  while [ "$rio_path" != "/" ] && [ "${rio_path%/}" != "$rio_path" ]; do
    rio_path="${rio_path%/}"
  done
  printf '%s\n' "$rio_path"
}

path_has_dir() { # dir
  rio_want=$(strip_trailing_slash "$1")
  # A subshell keeps IFS and -f from leaking into the rest of the run:
  # splitting on : is the point here, and -f stops a PATH entry containing a *
  # from being expanded against the filesystem on the way through.
  (
    IFS=:
    set -f
    for rio_entry in ${PATH:-}; do
      if [ "$(strip_trailing_slash "$rio_entry")" = "$rio_want" ]; then
        exit 0
      fi
    done
    exit 1
  )
}

choose_install_dir() {
  if [ -n "${RIO_INSTALL_DIR:-}" ]; then
    printf '%s\n' "$RIO_INSTALL_DIR"
  elif [ -d "$rio_system_bin" ] && [ -w "$rio_system_bin" ]; then
    printf '%s\n' "$rio_system_bin"
  else
    # Without HOME the old fallback was "./.local/bin", which quietly installed
    # into whatever directory the caller happened to be standing in. Say what
    # is missing instead of guessing.
    [ -n "${HOME:-}" ] ||
      die "HOME is not set, so there is no \$HOME/.local/bin to fall back to. Set RIO_INSTALL_DIR to the directory rio should be installed into."
    printf '%s\n' "$HOME/.local/bin"
  fi
}

ensure_install_dir() { # dir
  if [ ! -d "$1" ]; then
    mkdir -p "$1" 2>/dev/null || die "cannot create $1. Set RIO_INSTALL_DIR to a directory you can write to. This installer will not use sudo on your behalf."
  fi
  [ -w "$1" ] || die "$1 is not writable. Set RIO_INSTALL_DIR to a directory you own, for example RIO_INSTALL_DIR=\$HOME/.local/bin. This installer will not use sudo on your behalf."
}

# --- main --------------------------------------------------------------------

cleanup() {
  if [ -n "$rio_tmp" ] && [ -d "$rio_tmp" ]; then
    rm -rf "$rio_tmp"
  fi
  # A failed rename would otherwise leave a stray dotfile in the user's bin
  # directory.
  if [ -n "$rio_staged" ] && [ -e "$rio_staged" ]; then
    rm -f "$rio_staged"
  fi
  return 0
}

main() {
  for rio_arg in "$@"; do
    case "$rio_arg" in
      -h | --help)
        usage
        exit 0
        ;;
      *)
        printf 'install.sh: unknown argument: %s\n\n' "$rio_arg" >&2
        usage
        exit 1
        ;;
    esac
  done

  pick_http_client
  have tar || die "tar was not found. Install it and re-run."

  rio_os=$(detect_os "$(uname -s)")
  rio_arch=$(detect_arch "$(uname -m)")

  if [ -n "${RIO_VERSION:-}" ]; then
    valid_version "$(strip_v "$RIO_VERSION")" ||
      die "RIO_VERSION is not a usable version: ${RIO_VERSION}. Expected something like RIO_VERSION=0.1.0 or RIO_VERSION=v0.1.0 (letters, digits, dot, plus and dash only)."
    rio_tag=$(add_v "$RIO_VERSION")
  else
    log "resolving the latest rio release"
    rio_tag=$(resolve_latest_tag)
  fi
  rio_version=$(strip_v "$rio_tag")
  # The resolved tag is parsed out of a redirect target or an API body, so it
  # gets the same check before it reaches a path.
  valid_version "$rio_version" ||
    die "refusing to build a download path from an unusable release tag: ${rio_tag}. Set RIO_VERSION explicitly, e.g. RIO_VERSION=0.1.0."

  rio_asset=$(asset_name "$rio_version" "$rio_os" "$rio_arch")
  rio_base="${rio_releases_url}/download/${rio_tag}"

  # The EXIT trap covers failure too, so a botched download leaves nothing
  # behind. The signals need handlers of their own: a bare `trap cleanup INT`
  # cleans up and then *resumes* the script, which would carry on downloading
  # into a temp dir that no longer exists. Exit with the conventional 128+signo
  # instead; that also re-runs cleanup through EXIT, which is harmless because
  # cleanup only removes what is still there.
  trap cleanup EXIT
  trap 'cleanup; exit 130' INT
  trap 'cleanup; exit 143' TERM
  trap 'cleanup; exit 129' HUP

  # The template is explicit because a bare `mktemp -d` ignores TMPDIR on macOS
  # (it always lands in /var/folders/...), which is both surprising for anyone
  # pointing TMPDIR at a big disk and invisible to a test that watches TMPDIR.
  rio_tmp=$(mktemp -d "${TMPDIR:-/tmp}/rio.XXXXXX" 2>/dev/null || mktemp -d 2>/dev/null) ||
    die "could not create a temporary directory"

  log "downloading ${rio_base}/${rio_asset}"
  http_download "${rio_base}/${rio_asset}" "$rio_tmp/$rio_asset" ||
    die "download failed: ${rio_base}/${rio_asset}. Check that ${rio_tag} exists for ${rio_os}/${rio_arch} at ${rio_releases_url}"

  http_download "${rio_base}/checksums.txt" "$rio_tmp/checksums.txt" ||
    die "could not download ${rio_base}/checksums.txt. Refusing to install an unverified download."

  verify_checksum "$rio_tmp/$rio_asset" "$rio_tmp/checksums.txt" "$rio_asset"

  tar -xzf "$rio_tmp/$rio_asset" -C "$rio_tmp" || die "could not unpack $rio_asset"
  [ -f "$rio_tmp/rio" ] || die "$rio_asset did not contain a rio binary"

  rio_dir=$(choose_install_dir)
  ensure_install_dir "$rio_dir"
  rio_dir=$(cd -- "$rio_dir" && pwd)

  # Copy then rename, so an interrupted install cannot leave a half-written
  # binary at the destination, and so replacing a running rio works.
  rio_staged="$rio_dir/.rio.install.$$"
  cp "$rio_tmp/rio" "$rio_staged" || die "could not write to $rio_dir"
  # chmod the copy, not the source: cp creates the destination under the
  # caller's umask, so setting the mode on the extracted file left a 0700
  # binary in a shared bin directory whenever the caller ran with umask 077.
  chmod 0755 "$rio_staged" || die "could not set the mode on the new rio in $rio_dir"
  mv -f "$rio_staged" "$rio_dir/rio" || die "could not install into $rio_dir"
  rio_staged=""

  log "installed rio ${rio_version} (${rio_os}/${rio_arch}) to ${rio_dir}/rio"

  if ! path_has_dir "$rio_dir"; then
    log ""
    log "${rio_dir} is not on your PATH. Add it with:"
    log "  export PATH=\"${rio_dir}:\$PATH\""
  fi
}

[ "${RIO_SOURCE_ONLY:-0}" = "1" ] || main "$@"

#!/usr/bin/env sh
#
# install_test.sh - offline tests for install.sh.
#
#   sh install_test.sh
#   dash install_test.sh
#
# Makes no network calls. install.sh is sourced with RIO_SOURCE_ONLY=1 so the
# pure helpers can be exercised directly, and the end to end runs get a PATH
# shim whose `curl` and `wget` serve fixture files from a temp directory and
# record every url they were asked for.

# SC1091/SC2154/SC2034: the helpers and constants under test come from sourcing
# install.sh, which shellcheck does not follow here.
# SC2030/SC2031: PATH is meant to be scoped to the subshells and `env` calls
# that run install.sh with a stubbed http client.
# shellcheck disable=SC1091,SC2034,SC2030,SC2031,SC2154

set -eu

unset CDPATH

here=$(cd -- "$(dirname -- "$0")" && pwd)
script="$here/install.sh"

# Absolute, because two cases below run install.sh with a PATH that has been
# stripped down to a shim directory.
sh_bin=$(command -v sh)

checks=0
failures=0

pass() { checks=$((checks + 1)); printf 'ok   %s\n' "$1"; }
flunk() { checks=$((checks + 1)); failures=$((failures + 1)); printf 'FAIL %s\n' "$1"; }

eq() { # want got label
  if [ "$1" = "$2" ]; then pass "$3"; else flunk "$3: want [$1], got [$2]"; fi
}

contains() { # haystack needle label
  case "$1" in
    *"$2"*) pass "$3" ;;
    *) flunk "$3: [$1] does not contain [$2]" ;;
  esac
}

t=$(mktemp -d 2>/dev/null || mktemp -d -t rio-install-test)
# Physical path: install.sh reports the install dir after cd, and on macOS
# /var is a symlink to /private/var. Compare like with like.
t=$(cd -- "$t" && pwd)
trap 'rm -rf "$t"' EXIT INT TERM HUP

[ -f "$script" ] || { printf 'FAIL install.sh not found at %s\n' "$script"; exit 1; }
[ -x "$script" ] || { printf 'FAIL install.sh is not executable\n'; exit 1; }

# Sourcing pulls in `set -eu`; the assertions below deliberately run commands
# that fail, so turn -e back off and check statuses by hand.
RIO_SOURCE_ONLY=1
# shellcheck source=install.sh
. "$script"
set +e

# --- os detection ------------------------------------------------------------

eq linux "$(detect_os Linux)" "detect_os Linux"
eq darwin "$(detect_os Darwin)" "detect_os Darwin"

out=$( (detect_os FreeBSD) 2>&1 )
eq 1 "$?" "detect_os FreeBSD exits non-zero"
contains "$out" FreeBSD "detect_os FreeBSD names what it saw"
contains "$out" "$rio_releases_url" "detect_os FreeBSD points at the releases page"

out=$( (detect_os MINGW64_NT-10.0-22621) 2>&1 )
eq 1 "$?" "detect_os MINGW exits non-zero"
contains "$out" windows "detect_os MINGW mentions the windows asset"

# --- arch detection ----------------------------------------------------------

eq amd64 "$(detect_arch x86_64)" "detect_arch x86_64"
eq amd64 "$(detect_arch amd64)" "detect_arch amd64"
eq arm64 "$(detect_arch aarch64)" "detect_arch aarch64"
eq arm64 "$(detect_arch arm64)" "detect_arch arm64"

out=$( (detect_arch armv7l) 2>&1 )
eq 1 "$?" "detect_arch armv7l exits non-zero"
contains "$out" armv7l "detect_arch armv7l names what it saw"

# --- version handling --------------------------------------------------------

eq 0.1.0 "$(strip_v v0.1.0)" "strip_v strips a leading v"
eq 0.1.0 "$(strip_v 0.1.0)" "strip_v leaves a bare version alone"
eq v0.1.0 "$(add_v 0.1.0)" "add_v adds a leading v"
eq v0.1.0 "$(add_v v0.1.0)" "add_v does not double the v"

eq v1.2.3 "$(tag_from_url https://github.com/rebaze/rio/releases/tag/v1.2.3)" \
  "tag_from_url reads the tag out of a redirect target"
eq "" "$(tag_from_url https://github.com/rebaze/rio/releases/latest)" \
  "tag_from_url yields nothing when the redirect was not followed"
eq "" "$(tag_from_url '')" "tag_from_url tolerates an empty url"

eq v2.0.1 "$(printf '{\n  "url": "x",\n  "tag_name": "v2.0.1",\n  "name": "v2.0.1"\n}\n' | tag_from_api_json)" \
  "tag_from_api_json parses tag_name without jq"
eq v2.0.1 "$(printf '{"tag_name":"v2.0.1","draft":false}\n' | tag_from_api_json)" \
  "tag_from_api_json parses minified json"
eq "" "$(printf '{"message":"Not Found"}\n' | tag_from_api_json)" \
  "tag_from_api_json yields nothing for an error body"

eq rio_0.1.0_linux_amd64.tar.gz "$(asset_name 0.1.0 linux amd64)" "asset_name linux/amd64"
eq rio_1.2.3_darwin_arm64.tar.gz "$(asset_name 1.2.3 darwin arm64)" "asset_name darwin/arm64"

# --- checksums ---------------------------------------------------------------

sums="$t/checksums.txt"
cat > "$sums" <<'SUMS'
1111111111111111111111111111111111111111111111111111111111111111  rio_0.1.0_linux_amd64.tar.gz
2222222222222222222222222222222222222222222222222222222222222222 *rio_0.1.0_darwin_arm64.tar.gz
3333333333333333333333333333333333333333333333333333333333333333  checksums-other.txt
SUMS

eq 1111111111111111111111111111111111111111111111111111111111111111 \
  "$(expected_sha256 "$sums" rio_0.1.0_linux_amd64.tar.gz)" "expected_sha256 exact match"
eq 2222222222222222222222222222222222222222222222222222222222222222 \
  "$(expected_sha256 "$sums" rio_0.1.0_darwin_arm64.tar.gz)" "expected_sha256 binary-mode (*name) match"
eq "" "$(expected_sha256 "$sums" rio_9.9.9_linux_arm64.tar.gz)" "expected_sha256 misses cleanly"

tool=$(sha256_tool) || tool=""
if [ -z "$tool" ]; then
  printf 'FAIL no sha256 tool on this machine, cannot run the rest\n'
  exit 1
fi
pass "sha256_tool found $tool"

printf 'abc' > "$t/abc"
eq ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad \
  "$(sha256_file "$t/abc" "$tool")" "sha256_file hashes the known vector for 'abc'"

good="$t/good.txt"
printf 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  abc\n' > "$good"
out=$( (verify_checksum "$t/abc" "$good" abc) 2>&1 )
eq 0 "$?" "verify_checksum accepts a matching digest"
contains "$out" "$tool" "verify_checksum names the tool that verified it"

bad="$t/bad.txt"
printf 'deadbeef8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  abc\n' > "$bad"
out=$( (verify_checksum "$t/abc" "$bad" abc) 2>&1 )
eq 1 "$?" "verify_checksum refuses a mismatching digest"
contains "$out" checksum "verify_checksum says what went wrong"

out=$( (verify_checksum "$t/abc" "$sums" abc) 2>&1 )
eq 1 "$?" "verify_checksum refuses when the asset has no checksum entry"

# --- install directory selection --------------------------------------------

eq 0 "$( PATH="/bin:/usr/bin"; path_has_dir /usr/bin; printf '%s' "$?" )" "path_has_dir finds a dir on PATH"
eq 1 "$( PATH="/bin:/usr/bin"; path_has_dir /opt/nope; printf '%s' "$?" )" "path_has_dir rejects a dir off PATH"

mkdir -p "$t/sysbin"
eq "$t/explicit" "$( RIO_INSTALL_DIR="$t/explicit"; choose_install_dir )" "RIO_INSTALL_DIR wins"
eq "$t/sysbin" "$( rio_system_bin="$t/sysbin"; choose_install_dir )" "a writable system bin dir comes next"
eq "$HOME/.local/bin" "$( rio_system_bin="$t/does-not-exist"; choose_install_dir )" "falls back to ~/.local/bin"

# --- end to end, with a stubbed http client ---------------------------------

os=$(detect_os "$(uname -s)")
arch=$(detect_arch "$(uname -m)")
version=9.9.9
asset=$(asset_name "$version" "$os" "$arch")

www="$t/www"
shim="$t/shim"
scratch="$t/scratch"
mkdir -p "$www" "$shim" "$scratch" "$t/build" "$t/home"

cat > "$t/build/rio" <<'FAKE'
#!/usr/bin/env sh
echo "rio version 9.9.9"
FAKE
chmod +x "$t/build/rio"
( cd "$t/build" && tar -czf "$www/$asset" rio )

sha=$(sha256_file "$www/$asset" "$tool")
printf '%s  %s\n' "$sha" "$asset" > "$www/checksums.txt"
printf 'https://github.com/rebaze/rio/releases/tag/v%s' "$version" > "$www/effective_url"

cat > "$shim/curl" <<'CURL'
#!/usr/bin/env sh
set -eu
url=""; out=""; head=0; writeout=0
while [ $# -gt 0 ]; do
  case "$1" in
    -o) out="$2"; shift 2 ;;
    -w) writeout=1; shift 2 ;;
    --retry|--retry-delay|--connect-timeout|-H) shift 2 ;;
    http://*|https://*) url="$1"; shift ;;
    -*I*) head=1; shift ;;
    *) shift ;;
  esac
done
printf '%s\n' "$url" >> "$RIO_TEST_LOG"
if [ "$head" = 1 ] && [ "$writeout" = 1 ]; then
  cat "$RIO_TEST_WWW/effective_url"
  exit 0
fi
name=${url##*/}
[ -f "$RIO_TEST_WWW/$name" ] || exit 22
if [ -n "$out" ]; then cp "$RIO_TEST_WWW/$name" "$out"; else cat "$RIO_TEST_WWW/$name"; fi
CURL

cat > "$shim/wget" <<'WGET'
#!/usr/bin/env sh
set -eu
url=""; out="-"
while [ $# -gt 0 ]; do
  case "$1" in
    -O) out="$2"; shift 2 ;;
    http://*|https://*) url="$1"; shift ;;
    *) shift ;;
  esac
done
printf '%s\n' "$url" >> "$RIO_TEST_LOG"
name=${url##*/}
[ -f "$RIO_TEST_WWW/$name" ] || exit 8
if [ "$out" = "-" ]; then cat "$RIO_TEST_WWW/$name"; else cp "$RIO_TEST_WWW/$name" "$out"; fi
WGET

chmod +x "$shim/curl" "$shim/wget"

run_install() { # NAME=value ... ; runs install.sh with the shims in front
  env PATH="$shim:$PATH" \
    RIO_TEST_WWW="$www" RIO_TEST_LOG="$t/requests.log" \
    TMPDIR="$scratch" HOME="$t/home" "$@" sh "$script"
}

scratch_is_empty() {
  [ -z "$(ls -A "$scratch" 2>/dev/null)" ]
}

: > "$t/requests.log"
out=$(run_install RIO_VERSION="$version" RIO_INSTALL_DIR="$t/bin1" 2>&1)
eq 0 "$?" "end to end install with an explicit RIO_VERSION succeeds"
if [ -x "$t/bin1/rio" ]; then pass "the binary landed and is executable"; else flunk "no executable at $t/bin1/rio"; fi
contains "$out" "$t/bin1/rio" "the run prints the final absolute path"
contains "$out" "$tool" "the run names the tool that verified the checksum"
if grep -q 'api.github.com' "$t/requests.log"; then flunk "an explicit version still hit the release API"; else pass "an explicit version needs no release lookup"; fi
if scratch_is_empty; then pass "no temp dir left behind after a successful run"; else flunk "temp dir survived: $(ls -A "$scratch")"; fi
if grep -q 'releases/download/v9.9.9/checksums.txt' "$t/requests.log"; then pass "checksums.txt is fetched from the same tag"; else flunk "checksums.txt was not fetched"; fi

: > "$t/requests.log"
out=$(run_install RIO_INSTALL_DIR="$t/bin2" 2>&1)
eq 0 "$?" "end to end install resolving the latest release succeeds"
if [ -x "$t/bin2/rio" ]; then pass "resolved-version install landed"; else flunk "no executable at $t/bin2/rio"; fi
contains "$out" 9.9.9 "the resolved version is reported"

# No releases published yet: the redirect does not land on a tag and the API
# has nothing either. The user must be told to set RIO_VERSION.
mv "$www/effective_url" "$www/effective_url.tag"
printf 'https://github.com/rebaze/rio/releases' > "$www/effective_url"
out=$(run_install RIO_INSTALL_DIR="$t/bin10" 2>&1)
eq 1 "$?" "an unresolvable latest release fails"
contains "$out" RIO_VERSION "the unresolvable-version message suggests RIO_VERSION"
mv "$www/effective_url.tag" "$www/effective_url"

# A tampered archive must never be installed.
cp "$www/$asset" "$t/pristine.tar.gz"
printf 'tampered' >> "$www/$asset"
out=$(run_install RIO_VERSION="$version" RIO_INSTALL_DIR="$t/bin3" 2>&1)
eq 1 "$?" "a checksum mismatch fails the install"
if [ -e "$t/bin3/rio" ]; then flunk "a tampered archive was installed anyway"; else pass "nothing was installed from a tampered archive"; fi
contains "$out" checksum "the mismatch is reported as a checksum failure"
if scratch_is_empty; then pass "no temp dir left behind after a failed run"; else flunk "temp dir survived a failure: $(ls -A "$scratch")"; fi
cp "$t/pristine.tar.gz" "$www/$asset"

# A missing checksums.txt must fail rather than install unverified.
mv "$www/checksums.txt" "$www/checksums.hidden"
out=$(run_install RIO_VERSION="$version" RIO_INSTALL_DIR="$t/bin4" 2>&1)
eq 1 "$?" "a missing checksums.txt fails the install"
if [ -e "$t/bin4/rio" ]; then flunk "installed without a checksum file"; else pass "nothing installed without checksums.txt"; fi
mv "$www/checksums.hidden" "$www/checksums.txt"

# A missing asset for this platform fails with a pointer at the releases page.
out=$(run_install RIO_VERSION=0.0.0 RIO_INSTALL_DIR="$t/bin6" 2>&1)
eq 1 "$?" "a version with no asset fails"
contains "$out" "$rio_releases_url" "the missing-asset message points at the releases page"

# An unwritable target is reported, never sudo'd around.
mkdir -p "$t/ro"
chmod 500 "$t/ro"
out=$(run_install RIO_VERSION="$version" RIO_INSTALL_DIR="$t/ro/bin" 2>&1)
rc=$?
chmod 700 "$t/ro"
eq 1 "$rc" "an unwritable install dir fails"
contains "$out" RIO_INSTALL_DIR "the unwritable-dir message suggests RIO_INSTALL_DIR"
contains "$out" "will not use sudo" "the failure says it will not sudo"

# The PATH hint fires only when the install dir is off PATH.
out=$(run_install RIO_VERSION="$version" RIO_INSTALL_DIR="$t/bin7" 2>&1)
contains "$out" "export PATH=\"$t/bin7:\$PATH\"" "an off-PATH install dir prints the exact export line"
out=$(env PATH="$t/bin8:$shim:$PATH" \
  RIO_TEST_WWW="$www" RIO_TEST_LOG="$t/requests.log" TMPDIR="$scratch" HOME="$t/home" \
  RIO_VERSION="$version" RIO_INSTALL_DIR="$t/bin8" sh "$script" 2>&1)
case "$out" in
  *"export PATH="*) flunk "PATH hint printed for a dir already on PATH" ;;
  *) pass "no PATH hint when the install dir is already on PATH" ;;
esac

# wget-only boxes work too: hide curl by pointing PATH at a shim dir with only wget.
mkdir -p "$t/wgetonly"
cp "$shim/wget" "$t/wgetonly/wget"
for b in sh tar uname sed awk cut tr mktemp rm cp mv mkdir chmod ls shasum sha256sum openssl; do
  p=$(command -v "$b" 2>/dev/null) && ln -sf "$p" "$t/wgetonly/$b"
done
out=$(env PATH="$t/wgetonly" RIO_TEST_WWW="$www" RIO_TEST_LOG="$t/requests.log" \
  TMPDIR="$scratch" HOME="$t/home" RIO_VERSION="$version" RIO_INSTALL_DIR="$t/bin9" "$sh_bin" "$script" 2>&1)
eq 0 "$?" "install works with wget and no curl"
if [ -x "$t/bin9/rio" ]; then pass "wget-only install landed"; else flunk "wget-only install produced nothing: $out"; fi

# --- flags -------------------------------------------------------------------

out=$(env PATH="$shim:$PATH" sh "$script" --help 2>&1)
eq 0 "$?" "--help exits 0"
contains "$out" RIO_VERSION "--help documents RIO_VERSION"
contains "$out" RIO_INSTALL_DIR "--help documents RIO_INSTALL_DIR"
eq "" "$(env PATH="$shim:$PATH" sh "$script" --help 2>/dev/null)" "--help writes nothing to stdout"

out=$(env PATH="$shim:$PATH" sh "$script" --nonsense 2>&1)
eq 1 "$?" "an unknown flag exits non-zero"
contains "$out" -- --nonsense "the unknown flag is named back"

# --- no http client ----------------------------------------------------------

mkdir -p "$t/empty"
out=$(env PATH="$t/empty" RIO_VERSION="$version" RIO_INSTALL_DIR="$t/bin5" "$sh_bin" "$script" 2>&1)
eq 1 "$?" "no curl and no wget fails"
contains "$out" curl "the message names curl"
contains "$out" wget "the message names wget"

printf '\n%s checks, %s failures\n' "$checks" "$failures"
[ "$failures" -eq 0 ]

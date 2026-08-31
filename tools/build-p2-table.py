#!/usr/bin/env python3
"""Build the p2 bundle-symbolic-name -> Maven coordinate table rio consumes.

rio itself never touches the network: it repairs p2 purls from a table that is
embedded in the binary or merged in from the manifest. This script is how that
table is produced. It runs occasionally, on a workstation, and its output is
reviewed and committed like any other asset.

The ordering of the resolution stages is the whole design. A bundle symbolic
name is NOT reliably groupId.artifactId -- com.google.inject is guice,
com.ibm.icu is icu4j, com.sun.jna.platform is net.java.dev.jna:jna-platform,
org.apache.commons.cli is commons-cli:commons-cli -- so splitting the name is
the last thing tried, never the first, and only when something else can
corroborate it.

  1. Eclipse's own p2 metadata. SimRel and Orbit publish content.xml documents
     in which installable units carry maven-groupId / maven-artifactId
     properties. That is Eclipse stating the coordinate. It is still checked
     against Maven Central before it is believed, because a p2 repository
     records the coordinate a bundle was BUILT under, and for Eclipse's own
     projects that is an unpublished Tycho reactor groupId.
  1b. The same claim, with the groupId looked up again. A rejected claim named
     the artifactId correctly; only its groupId was a build artifact. This is
     where the Eclipse Platform bundles come back, and no split of a symbolic
     name could reach them: org.eclipse.core.databinding is published under
     org.eclipse.platform, which appears nowhere in the name.
  2. Maven Central, proven against the jar. A coordinate is guessed by
     splitting the symbolic name, then the jar is fetched and its
     Bundle-SymbolicName header read back. A mismatch rejects the guess and the
     next candidate is tried. The guess is never trusted on its own.
  3. Maven Central by exact SHA-1, where the SBOM's hashes are usable at all;
     often they are not, see poisoned_hashes. Needs --search.

Anything that survives none of those is reported rather than guessed at. So is
anything genuinely ambiguous: when several groupIds publish a jar declaring the
same symbolic name, one of them is a re-publisher and the manifest cannot say
which, so nothing is emitted.

Requires Python 3.9+ and nothing else.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import io
import json
import lzma
import os
import re
import struct
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
import zlib
from collections import Counter
from typing import Iterable, Iterator, NamedTuple, Optional

SCHEMA_VERSION = 1
USER_AGENT = "rio-build-p2-table/1 (+https://github.com/rebaze/rio)"

REPO1 = "https://repo1.maven.org/maven2"
CENTRAL_SEARCH = "https://search.maven.org/solrsearch/select"

# The p2 repositories harvested when --p2-repo is not given. Ordered from
# lowest to highest precedence, so a later repository's answer wins.
#
# The Orbit aggregation repositories are last on purpose. Around 2022 Orbit
# switched from republishing third-party jars under its own groupId to
# recording the upstream coordinate, so where an old SimRel says
# org.eclipse.orbit.bundles:com.google.gson a recent Orbit says
# com.google.code.gson:gson. The upstream coordinate is the one vulnerability
# databases carry findings for, which is the entire reason rio repairs these
# purls, so the recent answer must be able to override the old one.
DEFAULT_P2_REPOS = (
    "https://download.eclipse.org/releases/2021-06/",
    "https://download.eclipse.org/tools/orbit/simrel/orbit-aggregation/release/4.29.0/",
    "https://download.eclipse.org/tools/orbit/simrel/orbit-aggregation/release/4.33.0/",
    "https://download.eclipse.org/tools/orbit/simrel/orbit-aggregation/release/4.39.0/",
)

# The groupIds the Eclipse Foundation publishes its own bundles under, where
# the artifactId is the bundle symbolic name verbatim. Tried directly against
# repo1 before any search, because this is both the largest slice of a typical
# RCP product and the one a search cannot reach: no split of
# org.eclipse.core.databinding ever proposes org.eclipse.platform.
ECLIPSE_GROUPS = (
    "org.eclipse.platform",
    "org.eclipse.jdt",
    "org.eclipse.pde",
    "org.eclipse.emf",
    "org.eclipse.xtext",
    "org.eclipse.xtend",
    "org.eclipse.ecf",
    "org.eclipse.persistence",
    "org.eclipse.birt",
    "org.eclipse.orbit.bundles",
    "org.eclipse.jetty",
    "org.eclipse.equinox",
    "org.eclipse.core",
    "org.eclipse.ant",
    "org.eclipse.microprofile.config",
    "org.eclipse.microprofile.health",
)

# Set by --synthetic-namespace; matches rio's DefaultSyntheticNamespace.
DEFAULT_SYNTHETIC_NAMESPACE = "p2.eclipse.plugin"
DEFAULT_GROUP_PREFIX = "p2."
DEFAULT_CLASSIFIER = "osgi.bundle"

# Confidence tiers, strongest first. The value lands in the emitted entry so a
# reviewer can see how each coordinate was arrived at without rerunning this.
ECLIPSE_ASSERTED = "eclipse-asserted"
MANIFEST_PROVEN = "manifest-proven"
HASH_EXACT = "hash-exact"
INFERRED = "inferred"

# Not a confidence tier but an outcome: several groupIds publish a jar
# declaring this symbolic name, so the manifest cannot pick one. Never emitted.
AMBIGUOUS = "ambiguous"

CONFIDENCE_RANK = {
    ECLIPSE_ASSERTED: 0,
    MANIFEST_PROVEN: 1,
    HASH_EXACT: 2,
    INFERRED: 3,
}


class Transient(Exception):
    """The network could not answer, which is not the same as a negative answer.

    Keeping these apart is a correctness requirement, not a nicety. A timed-out
    maven-metadata.xml read as "Central does not publish this" would silently
    reject a coordinate that is perfectly good, and the resulting table would be
    quietly worse on a bad network day than on a good one. Every caller that
    turns an absence into a decision has to see this instead.
    """


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------
# Fetching
# --------------------------------------------------------------------------


class Fetcher:
    """HTTP GET with an on-disk cache, so a rerun costs nothing.

    The cache is keyed by URL and never expires. These are immutable release
    artifacts -- a published p2 repository and a released Maven jar do not
    change -- so re-fetching them would only burn Eclipse's and Sonatype's
    bandwidth. Delete the directory to force a refresh.
    """

    def __init__(self, cache_dir: str, offline: bool = False, retries: int = 3,
                 backoff: float = 2.0):
        self.cache_dir = cache_dir
        self.offline = offline
        self.retries = retries
        self.backoff = backoff
        self.hits = 0
        self.misses = 0
        os.makedirs(cache_dir, exist_ok=True)

    def _path(self, url: str) -> str:
        digest = hashlib.sha256(url.encode()).hexdigest()[:32]
        return os.path.join(self.cache_dir, digest)

    def _cached(self, path: str, marker: str):
        if os.path.exists(path):
            self.hits += 1
            with open(path, "rb") as fh:
                return True, fh.read()
        if os.path.exists(marker):
            self.hits += 1
            return True, None
        return False, None

    def _store(self, path: str, data: bytes) -> None:
        tmp = path + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(data)
        os.replace(tmp, path)

    def _fetch(self, req, path: str, marker: str, timeout: int) -> Optional[bytes]:
        """Fetch with bounded retries, raising Transient when it never answered.

        A 404 is cached: the artifact genuinely is not there and asking again
        tomorrow will not change that. A timeout is never cached, because doing
        so would freeze a network hiccup into a permanent wrong answer.
        """
        last = None
        for attempt in range(self.retries):
            if attempt:
                time.sleep(self.backoff * (2 ** (attempt - 1)))
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    data = resp.read()
                self._store(path, data)
                return data
            except urllib.error.HTTPError as exc:
                if exc.code in (404, 403, 410):
                    open(marker, "wb").close()
                    return None
                last = exc
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last = exc
        raise Transient(f"{req.full_url}: {last}")

    def get(self, url: str, timeout: int = 30) -> Optional[bytes]:
        """Return the body, or None when the server said it is not there.

        Raises Transient when the server said nothing at all.
        """
        path = self._path(url)
        marker = path + ".404"
        cached, data = self._cached(path, marker)
        if cached:
            return data
        if self.offline:
            # A cache miss offline means nobody was asked, which is not the
            # same as being told no. Returning None here would let --offline
            # quietly demote good coordinates on a half-warm cache.
            raise Transient(f"{url}: not cached and running offline")
        self.misses += 1
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        return self._fetch(req, path, marker, timeout)

    def get_range(self, url: str, nbytes: int, timeout: int = 30) -> Optional[bytes]:
        """Fetch the first nbytes of url, cached under its own key.

        A server that ignores Range answers 200 with the whole body, which is
        still correct, only not the saving that was hoped for.
        """
        key = f"{url}#range0-{nbytes}"
        path = self._path(key)
        marker = path + ".404"
        cached, data = self._cached(path, marker)
        if cached:
            return data
        if self.offline:
            raise Transient(f"{url}: not cached and running offline")
        self.misses += 1
        req = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT, "Range": f"bytes=0-{nbytes - 1}"},
        )
        return self._fetch(req, path, marker, timeout)


# --------------------------------------------------------------------------
# Reading the SBOM
# --------------------------------------------------------------------------


class Bundle(NamedTuple):
    bsn: str
    version: str
    sha1: Optional[str]


def parse_purl(purl: str) -> Optional[dict]:
    """Enough of a purl parser for the three shapes rio puts in scope."""
    if not purl.startswith("pkg:"):
        return None
    body = purl[4:]
    qualifiers: dict[str, str] = {}
    if "#" in body:
        body = body.split("#", 1)[0]
    if "?" in body:
        body, query = body.split("?", 1)
        for pair in query.split("&"):
            if "=" in pair:
                k, v = pair.split("=", 1)
                qualifiers[k.lower()] = urllib.parse.unquote(v)
    version = ""
    if "@" in body:
        body, version = body.rsplit("@", 1)
        version = urllib.parse.unquote(version)
    parts = [urllib.parse.unquote(p) for p in body.split("/") if p]
    if len(parts) < 2:
        return None
    return {
        "type": parts[0],
        "namespace": "/".join(parts[1:-1]),
        "name": parts[-1],
        "version": version,
        "qualifiers": qualifiers,
    }


def sha1_of(component: dict) -> Optional[str]:
    for h in component.get("hashes") or []:
        if h.get("alg") == "SHA-1":
            return (h.get("content") or "").lower() or None
    return None


def in_scope(component: dict, synthetic_ns: str, group_prefix: str, classifier: str):
    """Mirror rio's scope filter, so this script and rio agree on the work-list.

    Diverging here would be worse than useless: the script would curate entries
    for components rio never looks up, and leave the ones it does unmapped.
    """
    purl = component.get("purl") or ""
    group = component.get("group") or ""
    name = component.get("name") or ""
    version = component.get("version") or ""

    if not purl:
        # A component with no purl beside an OSGi symbolic name.
        if group.startswith(group_prefix) and name:
            return Bundle(name, version, sha1_of(component))
        return None

    parsed = parse_purl(purl)
    if not parsed:
        return None

    if parsed["type"] == "maven" and parsed["namespace"] == synthetic_ns:
        # A nested artefact repeats its bundle's name and version; resolving it
        # by name would put the bundle's coordinate on a jar shipped inside it.
        if parsed["qualifiers"].get("classifier"):
            return None
        return Bundle(parsed["name"], parsed["version"] or version, sha1_of(component))

    if parsed["type"] == "p2":
        if parsed["qualifiers"].get("classifier") != classifier:
            return None
        if not group.startswith(group_prefix):
            return None
        return Bundle(parsed["name"], parsed["version"] or version, sha1_of(component))

    return None


def infer_first_party_prefix(doc: dict) -> Optional[str]:
    """Guess the first-party prefix from the document's own subject.

    Tycho flattens every bundle under the same synthetic group, so nothing in a
    component distinguishes a first-party bundle from a third-party one. The
    subject is the one place the product's own coordinate survives: a
    metadata.component group of com.example.acme.product yields com.example,
    which excludes the reactor's own bundles from the work-list.

    Two labels is the useful depth. One would exclude every com.* bundle in the
    build; three would miss sibling reactors under the same organisation.
    """
    group = ((doc.get("metadata") or {}).get("component") or {}).get("group") or ""
    labels = [p for p in group.split(".") if p]
    if len(labels) >= 2:
        return ".".join(labels[:2])
    return None


def read_sbom(path: str, args) -> tuple[list[Bundle], Optional[str]]:
    with open(path, "rb") as fh:
        doc = json.load(fh)
    bundles = []
    for component in doc.get("components") or []:
        b = in_scope(
            component, args.synthetic_namespace, args.group_prefix, args.classifier
        )
        if b:
            bundles.append(b)
    return bundles, infer_first_party_prefix(doc)


def poisoned_hashes(bundles: Iterable[Bundle], threshold: int = 2) -> set[str]:
    """SHA-1 values that appear on more than one component, and so identify none.

    Not a hypothetical. The document this was written against carries one
    identical SHA-1 on 504 of its 603 bundles: the generator emitted a
    placeholder rather than hashing each artifact. Feeding those to Central
    would be harmless but pointless, and trusting a collision would be worse,
    so any repeated value is dropped before the hash stage runs.
    """
    counts = Counter(b.sha1 for b in bundles if b.sha1)
    return {h for h, n in counts.items() if n >= threshold}


# --------------------------------------------------------------------------
# Stage 1: Eclipse p2 metadata
# --------------------------------------------------------------------------


def try_get(fetcher: Fetcher, url: str, timeout: int = 30) -> Optional[bytes]:
    """get() for speculative URLs, where a failure to answer is just a miss."""
    try:
        return fetcher.get(url, timeout=timeout)
    except Transient:
        return None


def read_p2_document(fetcher: Fetcher, base: str, stem: str) -> Optional[bytes]:
    """Fetch one p2 metadata document, trying the encodings p2 publishes.

    A repository serves exactly one of these three and 404s the others, so all
    three are tried rather than guessed at from the URL.
    """
    base = base if base.endswith("/") else base + "/"

    data = try_get(fetcher, base + stem + ".xml.xz", timeout=120)
    if data:
        try:
            return lzma.decompress(data)
        except lzma.LZMAError:
            pass

    data = try_get(fetcher, base + stem + ".jar", timeout=120)
    if data:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                return zf.read(stem + ".xml")
        except (zipfile.BadZipFile, KeyError):
            pass

    return try_get(fetcher, base + stem + ".xml", timeout=120)


def walk_p2_repo(
    fetcher: Fetcher, url: str, depth: int = 0, seen: Optional[set] = None
) -> Iterator[bytes]:
    """Yield every content.xml reachable from url, following composites.

    Eclipse publishes releases as a composite pointing at timestamped children
    (/releases/2021-06/ -> /releases/2021-06/202106161001/), so the URL a human
    would quote is never the one holding the units. Recursing means the caller
    passes the memorable URL and this finds the real ones.
    """
    if seen is None:
        seen = set()
    url = url if url.endswith("/") else url + "/"
    if url in seen or depth > 4:
        return
    seen.add(url)

    content = read_p2_document(fetcher, url, "content")
    if content:
        yield content
        return

    composite = read_p2_document(fetcher, url, "compositeContent")
    if not composite:
        log(f"  ! no p2 metadata at {url}")
        return
    try:
        root = ET.fromstring(composite)
    except ET.ParseError:
        return
    for child in root.iterfind(".//child"):
        location = child.get("location")
        if location:
            yield from walk_p2_repo(
                fetcher, urllib.parse.urljoin(url, location), depth + 1, seen
            )


def harvest_p2(content: bytes) -> Iterator[tuple[str, str, str]]:
    """Yield (bsn, groupId, artifactId) for every unit that carries coordinates."""
    for _, unit in ET.iterparse(io.BytesIO(content), events=("end",)):
        if unit.tag != "unit":
            continue
        bsn = unit.get("id") or ""
        props = {
            p.get("name"): p.get("value") for p in unit.findall("./properties/property")
        }
        group = props.get("maven-groupId")
        artifact = props.get("maven-artifactId")
        if bsn and group and artifact:
            yield bsn, group, artifact
        unit.clear()


def stage_p2_metadata(fetcher: Fetcher, repos: Iterable[str]) -> dict[str, tuple]:
    """Build bsn -> (groupId, artifactId, evidence) from Eclipse's own metadata.

    Later repositories override earlier ones, and an upstream coordinate always
    beats an Orbit republication regardless of order: org.eclipse.orbit.bundles
    is a real place to download the bundle from, but almost no vulnerability
    database carries findings under it, so preferring it would repair the purl
    and still report nothing.
    """
    table: dict[str, tuple] = {}
    for repo in repos:
        log(f"  fetching {repo}")
        found = 0
        for content in walk_p2_repo(fetcher, repo):
            for bsn, group, artifact in harvest_p2(content):
                found += 1
                previous = table.get(bsn)
                if previous and is_orbit(group) and not is_orbit(previous[0]):
                    continue
                table[bsn] = (group, artifact, repo)
        log(f"    {found} units with Maven coordinates")
    return table


def bundle_version(work: dict, bsn: str) -> str:
    b = work.get(bsn)
    return b.version if b else ""


def is_orbit(group_id: str) -> bool:
    return group_id.startswith("org.eclipse.orbit")


# --------------------------------------------------------------------------
# Stage 2: Maven Central, proven against the jar manifest
# --------------------------------------------------------------------------


ECLIPSE_QUALIFIER = re.compile(r"\.(v\d{8}[-\d]*|[A-Za-z][\w-]*)$")
EMBEDDED_VERSION = re.compile(r"_\d+(\.\d+)*$")
BSN_HEADER = re.compile(r"^Bundle-SymbolicName:\s*([^;\s]+)", re.MULTILINE)


def strip_embedded_version(bsn: str) -> str:
    """com.fasterxml.jackson.core.jackson-annotations_2.10.2 -> ...jackson-annotations."""
    return EMBEDDED_VERSION.sub("", bsn)


def version_candidates(version: str) -> list[str]:
    """Maven versions an OSGi version could have come from.

    OSGi pads to three segments and Maven does not, so the bundle's 1.4.0 is
    Maven's 1.4 and 30.1.0 is 30.1. Both forms are tried, longest first.
    """
    version = ECLIPSE_QUALIFIER.sub("", version.strip())
    if not version:
        return []
    out = [version]
    parts = version.split(".")
    while len(parts) > 1 and parts[-1] == "0":
        parts = parts[:-1]
        out.append(".".join(parts))
    return out


def coordinate_candidates(bsn: str, limit: int = 12) -> list[tuple[str, str]]:
    """Every (groupId, artifactId) the symbolic name could decompose into.

    Longest groupId first, because org.glassfish.jersey.core:jersey-client is
    far more likely than org.glassfish:jersey.core.jersey-client. Both the
    dotted and the dashed artifactId are offered, since Eclipse writes
    org.apache.commons.lang3 for what Maven calls commons-lang3.

    Nothing here is trusted. These are hypotheses for the manifest check.
    """
    stem = strip_embedded_version(bsn)
    parts = stem.split(".")
    out: list[tuple[str, str]] = []
    if len(parts) == 1:
        out.append((stem, stem))
    for i in range(len(parts) - 1, 0, -1):
        group = ".".join(parts[:i])
        out.append((group, ".".join(parts[i:])))
        dashed = "-".join(parts[i:])
        if dashed != ".".join(parts[i:]):
            out.append((group, dashed))
    seen = set()
    unique = []
    for candidate in out:
        if candidate not in seen:
            seen.add(candidate)
            unique.append(candidate)
    return unique[:limit]


JAR_HEAD_BYTES = 32768


def manifest_from_jar_head(data: bytes) -> Optional[bytes]:
    """Pull META-INF/MANIFEST.MF out of the first bytes of a jar, if it is there.

    A jar is a zip, and the jar tool writes the manifest first, so the whole
    entry almost always sits within the first few kilobytes. Reading it from
    there turns a multi-megabyte download into a 32 KB range request, which for
    several hundred candidate coordinates is the difference between minutes and
    an hour. Returns None when the manifest is not in the fetched prefix, and
    the caller falls back to the whole file.
    """
    offset = 0
    while offset + 30 <= len(data) and data[offset : offset + 4] == b"PK\x03\x04":
        flags, method = struct.unpack_from("<HH", data, offset + 6)
        csize, = struct.unpack_from("<I", data, offset + 18)
        namelen, extralen = struct.unpack_from("<HH", data, offset + 26)
        name = data[offset + 30 : offset + 30 + namelen]
        body = offset + 30 + namelen + extralen
        if name.upper() == b"META-INF/MANIFEST.MF":
            if method == 8:
                # Bit 3 puts the sizes in a trailing descriptor, leaving csize
                # zero here -- which is how the jar tool writes a streamed jar,
                # so it is the common case rather than the exotic one. The
                # deflate stream is self-terminating, so it is decompressed
                # incrementally and eof tells us whether the whole entry was
                # inside the fetched prefix.
                decompressor = zlib.decompressobj(-15)
                try:
                    out = decompressor.decompress(data[body:])
                except zlib.error:
                    return None
                return out if decompressor.eof else None
            if method == 0 and not flags & 0x08:
                blob = data[body : body + csize]
                return blob if len(blob) == csize else None
            return None
        if flags & 0x08:
            return None
        offset = body + csize
    return None


def read_bsn(manifest: bytes) -> str:
    # MANIFEST.MF wraps at 72 columns and continues with a leading space.
    text = manifest.decode("utf-8", "replace").replace("\r\n", "\n").replace("\n ", "")
    match = BSN_HEADER.search(text)
    return match.group(1).strip() if match else ""


def jar_symbolic_name(fetcher: Fetcher, group: str, artifact: str, version: str):
    """Read Bundle-SymbolicName out of the published jar.

    Returns the header value, "" when the jar carries no such header, or None
    when there is no jar to read. The empty string is a distinct and important
    answer: it means the artifact exists but predates OSGi, so this coordinate
    can never be proven this way and must not be reported as if it had been.
    """
    url = f"{REPO1}/{group.replace('.', '/')}/{artifact}/{version}/{artifact}-{version}.jar"

    try:
        head = fetcher.get_range(url, JAR_HEAD_BYTES)
        if head:
            manifest = manifest_from_jar_head(head)
            if manifest is not None:
                return read_bsn(manifest)
        data = fetcher.get(url, timeout=90)
    except Transient:
        # Unknown, not "no such header" -- returning "" would let an unproven
        # coordinate through as merely-inferred.
        return None
    if not data:
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            return read_bsn(zf.read("META-INF/MANIFEST.MF"))
    except (zipfile.BadZipFile, KeyError):
        return ""


METADATA_VERSION = re.compile(r"<version>([^<]+)</version>")


def published_versions(fetcher: Fetcher, group: str, artifact: str) -> Optional[list[str]]:
    """Versions Maven Central publishes for a groupId:artifactId, or None if absent.

    One request per coordinate answers both "does this exist" and "which
    versions", which is cheaper and far more reliable than probing a guessed
    version and reading 404 as "wrong coordinate" when it only meant "wrong
    version".
    """
    url = f"{REPO1}/{group.replace('.', '/')}/{artifact}/maven-metadata.xml"
    data = fetcher.get(url, timeout=45)
    if not data:
        return None
    return METADATA_VERSION.findall(data.decode("utf-8", "replace"))


# How well a claimed coordinate stood up to Central.
CONFIRMED = "confirmed"        # exists, and publishes this bundle's version
WRONG_VERSION = "wrong-version"  # exists, but not at this version
ABSENT = "absent"              # Central publishes no such coordinate
UNKNOWN = "unknown"            # Central did not answer


def confirm_on_central(fetcher: Fetcher, group: str, artifact: str, bundle: Bundle) -> str:
    """Check a claimed coordinate against Central, version included.

    Existence alone is too weak a test. org.eclipse.core.contenttype is claimed
    by two real coordinates: org.eclipse.core, last published in 2010 at
    3.4.100, and org.eclipse.platform, still maintained at 3.9.x. The bundle
    here is 3.8.100, so an existence check would happily pick the stale one and
    pin a decade-old artifact's identity onto a current bundle. Requiring the
    version narrows it to the coordinate that actually ships this build.
    """
    try:
        published = published_versions(fetcher, group, artifact)
    except Transient:
        return UNKNOWN
    if published is None:
        return ABSENT
    wanted = version_candidates(bundle.version)
    return CONFIRMED if any(v in published for v in wanted) else WRONG_VERSION


def resolve_by_name(fetcher: Fetcher, bundle: Bundle) -> Optional[tuple]:
    """Try each candidate coordinate until one is proven or plausibly exists.

    A candidate whose jar declares a DIFFERENT symbolic name is rejected
    outright and the search continues. That rejection is what separates this
    from guessing: the artifact that exists at a plausible coordinate is not
    necessarily the artifact the bundle was built from.
    """
    stem = strip_embedded_version(bundle.bsn)
    wanted = version_candidates(bundle.version)

    fallback = None
    for group, artifact in coordinate_candidates(bundle.bsn):
        try:
            published = published_versions(fetcher, group, artifact)
        except Transient:
            continue
        if published is None:
            continue
        # The table records only groupId and artifactId, so the version is
        # evidence rather than output: it is what lets the jar be fetched and
        # the symbolic name read back.
        matching = [v for v in wanted if v in published]
        if not matching:
            continue
        version = matching[0]
        declared = jar_symbolic_name(fetcher, group, artifact, version)
        if declared in (bundle.bsn, stem):
            return group, artifact, MANIFEST_PROVEN, f"{group}:{artifact}:{version}"
        if declared:
            # The jar names a different bundle. Wrong artifact, keep going.
            continue
        # Exists at the right version, but the jar predates OSGi and carries no
        # symbolic name, so nothing can prove it. Hold it in case nothing
        # better turns up.
        if fallback is None:
            fallback = (
                group,
                artifact,
                INFERRED,
                f"{group}:{artifact}:{version} (jar has no Bundle-SymbolicName)",
            )
    return fallback


# --------------------------------------------------------------------------
# Stage 3: Maven Central by exact SHA-1
# --------------------------------------------------------------------------


MAX_PROOF_DOWNLOADS = 6


def shared_labels(group: str, bsn: str) -> int:
    """How many leading dot-labels a groupId shares with a symbolic name."""
    a, b = group.split("."), bsn.split(".")
    n = 0
    for x, y in zip(a, b):
        if x != y:
            break
        n += 1
    return n


def resolve_in_known_groups(
    fetcher: Fetcher, groups: Iterable[str], artifact: str, bundle: Bundle
) -> Optional[tuple]:
    """Look for artifactId under a fixed set of groupIds, using repo1 alone.

    No search API and no throttle, so this is both fast and immune to the
    search endpoint being slow, rate-limited or down.
    """
    stem = strip_embedded_version(bundle.bsn)
    wanted = version_candidates(bundle.version)
    for group in groups:
        try:
            published = published_versions(fetcher, group, artifact)
        except Transient:
            continue
        if not published:
            continue
        matching = [v for v in wanted if v in published]
        if not matching:
            continue
        version = matching[0]
        if jar_symbolic_name(fetcher, group, artifact, version) in (bundle.bsn, stem):
            return group, artifact, MANIFEST_PROVEN, f"{group}:{artifact}:{version}"
    return None


def groups_publishing(fetcher: Fetcher, throttle: "Throttle", artifact: str) -> list[str]:
    """Ask Central which groupIds publish this artifactId.

    This inverts the search. Splitting a symbolic name guesses the groupId and
    can only ever propose one that is a literal prefix of the name, which is
    hopeless for the Eclipse Platform: org.eclipse.core.databinding is
    published as org.eclipse.platform:org.eclipse.core.databinding, and no
    split of the name yields "org.eclipse.platform". Letting Central enumerate
    the real groupIds for a known artifactId reaches coordinates no amount of
    string surgery would.
    """
    query = urllib.parse.urlencode(
        {"q": f'a:"{artifact}"', "rows": "20", "wt": "json"}
    )
    url = f"{CENTRAL_SEARCH}?{query}"
    if not os.path.exists(fetcher._path(url)):
        throttle.wait()
    data = try_get(fetcher, url)
    if not data:
        return []
    try:
        docs = json.loads(data)["response"]["docs"]
    except (ValueError, KeyError):
        return []
    out = []
    for doc in docs:
        group = doc.get("g")
        if group and group not in out:
            out.append(group)
    return out


def resolve_by_artifact_id(
    fetcher: Fetcher, throttle: "Throttle", artifact: str, bundle: Bundle
) -> Optional[tuple]:
    """Find the groupId that publishes a known artifactId, and prove it.

    Used with an artifactId that came from Eclipse's own metadata, whose
    groupId turned out to be an unpublished reactor coordinate. The artifactId
    survives that rejection intact; only the groupId has to be found again.
    """
    stem = strip_embedded_version(bundle.bsn)
    wanted = version_candidates(bundle.version)
    proven: list[tuple[str, str]] = []
    fallback = None
    groups = groups_publishing(fetcher, throttle, artifact)
    # Central returns up to 20 groupIds and each proof costs a jar download, so
    # the ones sharing leading labels with the symbolic name go first and the
    # tail is cut. A re-publisher rarely shares a prefix with what it repackages.
    groups.sort(key=lambda g: -shared_labels(g, stem))
    for group in groups[:MAX_PROOF_DOWNLOADS]:
        try:
            published = published_versions(fetcher, group, artifact)
        except Transient:
            continue
        if not published:
            continue
        matching = [v for v in wanted if v in published]
        if not matching:
            continue
        version = matching[0]
        declared = jar_symbolic_name(fetcher, group, artifact, version)
        if declared in (bundle.bsn, stem):
            proven.append((group, version))
        elif not declared and fallback is None:
            fallback = (
                group,
                artifact,
                INFERRED,
                f"{group}:{artifact}:{version} (jar has no Bundle-SymbolicName)",
            )

    # More than one groupId publishing a jar that declares this symbolic name
    # means a re-publisher is in the set, and the manifest cannot say which of
    # them the bundle came from -- both jars honestly carry the same header.
    # Re-publisher coordinates are the cardinal false positive here: they look
    # entirely plausible and carry no vulnerability data, so an ambiguous
    # answer is reported rather than guessed at.
    if len(proven) > 1:
        candidates = ", ".join(f"{g}:{artifact}" for g, _ in proven)
        return None, artifact, AMBIGUOUS, candidates
    if proven:
        group, version = proven[0]
        return group, artifact, MANIFEST_PROVEN, f"{group}:{artifact}:{version}"
    return fallback


class Throttle:
    """Central's search API throttles; repo1 does not. Only the former uses this."""

    def __init__(self, min_interval: float = 1.0):
        self.min_interval = min_interval
        self.last = 0.0

    def wait(self) -> None:
        delta = time.monotonic() - self.last
        if delta < self.min_interval:
            time.sleep(self.min_interval - delta)
        self.last = time.monotonic()


def resolve_by_sha1(fetcher: Fetcher, throttle: "Throttle", sha1: str) -> Optional[tuple]:
    query = urllib.parse.urlencode({"q": f'1:"{sha1}"', "rows": "5", "wt": "json"})
    url = f"{CENTRAL_SEARCH}?{query}"
    if not os.path.exists(fetcher._path(url)):
        throttle.wait()
    data = try_get(fetcher, url)
    if not data:
        return None
    try:
        docs = json.loads(data)["response"]["docs"]
    except (ValueError, KeyError):
        return None
    if len(docs) != 1:
        # Zero is a miss. More than one means the same bytes are published under
        # several coordinates and the hash does not pick one, so it proves nothing.
        return None
    doc = docs[0]
    return doc["g"], doc["a"], HASH_EXACT, f"sha1:{sha1}"


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------


def load_existing(path: Optional[str]) -> dict:
    if not path or not os.path.exists(path):
        return {}
    with open(path, "rb") as fh:
        doc = json.load(fh)
    if doc.get("schemaVersion") != SCHEMA_VERSION:
        raise SystemExit(
            f"{path}: schemaVersion is {doc.get('schemaVersion')}, want {SCHEMA_VERSION}"
        )
    return doc.get("entries") or {}


def write_table(path: str, entries: dict) -> None:
    """Emit the table sorted, so a rerun that changes nothing produces no diff."""
    doc = {
        "schemaVersion": SCHEMA_VERSION,
        "entries": {k: entries[k] for k in sorted(entries)},
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False)
        fh.write("\n")


def write_review(path: str, unresolved: list, inferred: list, ambiguous: dict, skipped: dict) -> None:
    lines = [
        "# p2 table build report",
        "",
        f"unresolved: {len(unresolved)}   inferred (unproven): {len(inferred)}"
        f"   ambiguous: {len(ambiguous)}",
        "",
    ]
    if inferred:
        lines += [
            "## Emitted but only inferred",
            "",
            "The coordinate resolves to a real artifact on Maven Central, but that",
            "artifact predates OSGi and carries no Bundle-SymbolicName, so nothing",
            "could prove the bundle was built from it. Confirm each before relying on it.",
            "",
        ]
        for bsn, group, artifact, evidence in sorted(inferred):
            lines.append(f"- `{bsn}` -> `{group}:{artifact}`  ({evidence})")
        lines.append("")
    if ambiguous:
        lines += [
            "## Ambiguous",
            "",
            "Several groupIds publish a jar declaring this symbolic name, so the",
            "manifest cannot say which one the bundle came from. Usually one is the",
            "canonical project and the rest are re-publishers. Pick by hand.",
            "",
        ]
        for bsn in sorted(ambiguous):
            lines.append(f"- `{bsn}` -> {ambiguous[bsn]}")
        lines.append("")
    if unresolved:
        lines += ["## Unresolved", "", "No channel produced a candidate.", ""]
        for bsn, version in sorted(unresolved):
            lines.append(f"- `{bsn}` @ `{version}`")
        lines.append("")
    if skipped:
        lines += ["## Excluded from the work-list", ""]
        for reason, names in sorted(skipped.items()):
            lines.append(f"- {reason}: {len(names)}")
        lines.append("")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))


# --------------------------------------------------------------------------


def main() -> int:
    p = argparse.ArgumentParser(
        description="Build the p2 bundle-symbolic-name to Maven coordinate table.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("sbom", nargs="+", help="CycloneDX JSON documents to take names from")
    p.add_argument("-o", "--out", default="p2-maven.json", help="table to write")
    p.add_argument(
        "--existing",
        help="table to merge onto; its entries are never overwritten unless --overwrite",
    )
    p.add_argument("--overwrite", action="store_true", help="let this run replace existing entries")
    p.add_argument("--review", default=None, help="write a review report here (default: <out>.review.md)")
    p.add_argument("--cache", default=".p2cache", help="HTTP cache directory")
    p.add_argument("--offline", action="store_true", help="use only what is already cached")
    p.add_argument("--p2-repo", action="append", dest="p2_repos", metavar="URL",
                   help="p2 repository to harvest; repeatable, later wins. Defaults to SimRel + Orbit")
    p.add_argument("--no-p2", action="store_true", help="skip the Eclipse metadata stage")
    p.add_argument("--no-name-split", action="store_true", help="skip the name-split stage")
    p.add_argument("--no-hash", action="store_true", help="skip the SHA-1 stage")
    p.add_argument(
        "--search",
        action="store_true",
        help="also ask search.maven.org which groupIds publish an artifactId. Off by "
        "default: on the estate this was built for it added nothing the repo1 stages "
        "had not already found, while being the only rate-limited dependency here",
    )
    p.add_argument("--first-party-prefix", action="append", dest="first_party", default=[],
                   metavar="PREFIX", help="never map bundles under this prefix; repeatable")
    p.add_argument("--no-infer-first-party", action="store_true",
                   help="do not guess the first-party prefix from metadata.component")
    p.add_argument("--include-source-bundles", action="store_true",
                   help="also try to map .source bundles")
    p.add_argument("--synthetic-namespace", default=DEFAULT_SYNTHETIC_NAMESPACE)
    p.add_argument("--group-prefix", default=DEFAULT_GROUP_PREFIX)
    p.add_argument("--classifier", default=DEFAULT_CLASSIFIER)
    p.add_argument("-j", "--jobs", type=int, default=6, help="concurrent Maven Central requests")
    args = p.parse_args()

    fetcher = Fetcher(args.cache, offline=args.offline)

    # ---- work-list -------------------------------------------------------
    bundles: dict[str, Bundle] = {}
    inferred_prefixes: list[str] = []
    for path in args.sbom:
        found, prefix = read_sbom(path, args)
        log(f"{path}: {len(found)} in-scope bundles")
        if prefix and not args.no_infer_first_party:
            inferred_prefixes.append(prefix)
        for b in found:
            bundles.setdefault(b.bsn, b)

    first_party = list(args.first_party)
    for prefix in inferred_prefixes:
        if prefix not in first_party:
            log(f"inferred first-party prefix from metadata.component: {prefix}")
            first_party.append(prefix)

    skipped: dict[str, list] = {}
    work: dict[str, Bundle] = {}
    for bsn, bundle in bundles.items():
        if any(bsn == fp or bsn.startswith(fp + ".") for fp in first_party):
            skipped.setdefault("first-party", []).append(bsn)
        elif bsn.endswith(".source") and not args.include_source_bundles:
            skipped.setdefault("source bundle", []).append(bsn)
        else:
            work[bsn] = bundle

    log(f"{len(bundles)} distinct bundles, {len(work)} to resolve")
    for reason, names in sorted(skipped.items()):
        log(f"  excluded {len(names)} ({reason})")

    existing = load_existing(args.existing)
    if existing:
        log(f"{len(existing)} entries in {args.existing}")

    resolved: dict[str, tuple] = {}

    # Coordinates Eclipse asserts but Maven Central does not publish. Kept only
    # as a last resort, after the stages that can do better have had their turn.
    deferred: dict[str, tuple] = {}
    # BSNs several groupIds could plausibly claim. Reported, never emitted.
    ambiguous: dict[str, str] = {}

    def accept(bsn: str, hit) -> None:
        """Route a resolver result: ambiguity is a report, not an answer."""
        if not hit:
            return
        if hit[2] == AMBIGUOUS:
            ambiguous[bsn] = hit[3]
            return
        resolved[bsn] = hit

    # ---- stage 1 ---------------------------------------------------------
    if not args.no_p2:
        repos = args.p2_repos or list(DEFAULT_P2_REPOS)
        log(f"stage 1: Eclipse p2 metadata ({len(repos)} repositories)")
        p2_table = stage_p2_metadata(fetcher, repos)
        log(f"  {len(p2_table)} coordinates known to Eclipse")

        claimed = {}
        for bsn in work:
            hit = p2_table.get(bsn) or p2_table.get(strip_embedded_version(bsn))
            if hit:
                claimed[bsn] = hit

        # Eclipse asserting a coordinate is not the same as that coordinate
        # existing. A SimRel content.xml records the coordinate the bundle was
        # BUILT under, which for Eclipse's own reactor projects is an internal
        # groupId that was never published: org.eclipse.e4.ui.css.swt claims
        # eclipse.platform.ui, a git repository name, and the artifact actually
        # lives under org.eclipse.platform. Emitting the claim unchecked would
        # be exactly the confident-but-wrong coordinate this table must not
        # contain, so every one is confirmed against Central before it is
        # accepted, and the rest fall through to the stages below.
        log(f"  {len(claimed)} claimed; confirming each is published on Central")
        with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
            published = list(
                pool.map(
                    lambda item: confirm_on_central(
                        fetcher, item[1][0], item[1][1], work[item[0]]
                    ),
                    claimed.items(),
                )
            )
        unpublished: list[tuple[str, str]] = []
        unknown = 0
        stale = 0
        absent = 0
        for (bsn, hit), verdict in zip(claimed.items(), published):
            entry = (hit[0], hit[1], ECLIPSE_ASSERTED, hit[2])
            if verdict == UNKNOWN:
                # Central never answered. Rejecting on that would let a flaky
                # network quietly shrink the table, so the claim is kept and
                # the count is reported for a rerun to settle.
                unknown += 1
                resolved[bsn] = entry
            elif verdict == ABSENT:
                absent += 1
                unpublished.append((bsn, hit[1]))
            elif verdict == WRONG_VERSION:
                # A real coordinate, but not one that ships this build. The
                # later stages get first refusal; this is only the fallback.
                stale += 1
                unpublished.append((bsn, hit[1]))
                deferred.setdefault(
                    bsn,
                    (hit[0], hit[1], INFERRED,
                     f"{hit[0]}:{hit[1]} (Eclipse metadata; version {bundle_version(work, bsn)} not on Central)"),
                )
            elif is_orbit(hit[0]):
                # Real, but a republication almost no vulnerability database
                # carries findings under. Let stage 2 look for the upstream
                # coordinate first and fall back to this only if it finds none.
                deferred[bsn] = entry
            else:
                resolved[bsn] = entry
        if absent:
            log(f"  {absent} name a coordinate Central does not publish at all")
        if stale:
            log(f"  {stale} exist on Central but not at this bundle's version")
        if unknown:
            log(f"  {unknown} could not be confirmed (network); kept, rerun to settle")
        if deferred:
            log(f"  deferred {len(deferred)} Orbit republications pending an upstream match")
        log(f"  resolved {len(resolved)}/{len(work)}")

        # Stage 1b. A rejected claim is not a dead end: Eclipse named the
        # artifactId correctly and only the groupId was a reactor coordinate,
        # so the artifactId is carried forward and the real groupId is looked
        # up. This is where the Eclipse Platform bundles come back, since no
        # split of org.eclipse.core.databinding ever proposes the
        # org.eclipse.platform that actually publishes it.
        if unpublished:
            log(f"stage 1b: re-finding the groupId for {len(unpublished)} Eclipse artifactIds")
            with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
                fast = list(
                    pool.map(
                        lambda item: resolve_in_known_groups(
                            fetcher, ECLIPSE_GROUPS, item[1], work[item[0]]
                        ),
                        unpublished,
                    )
                )
            still_unpublished = []
            for (bsn, artifact), hit in zip(unpublished, fast):
                if hit:
                    resolved[bsn] = hit
                else:
                    still_unpublished.append((bsn, artifact))
            log(f"  {len(unpublished) - len(still_unpublished)} found in the known Eclipse groupIds")
            if still_unpublished and args.search:
                throttle = Throttle()
                for bsn, artifact in still_unpublished:
                    accept(bsn, resolve_by_artifact_id(fetcher, throttle, artifact, work[bsn]))
            log(f"  resolved {len(resolved)}/{len(work)}")

    # ---- stage 2 ---------------------------------------------------------
    if not args.no_name_split:
        pending = [b for bsn, b in work.items() if bsn not in resolved]
        log(f"stage 2: Maven Central, proven by jar manifest ({len(pending)} names)")
        with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
            for bundle, hit in zip(
                pending, pool.map(lambda b: resolve_by_name(fetcher, b), pending)
            ):
                if hit:
                    resolved[bundle.bsn] = hit
        log(f"  resolved {len(resolved)}/{len(work)}")

        # Eclipse publishes its own bundles with the artifactId equal to the
        # symbolic name, so for anything still missing the name is worth trying
        # as an artifactId in its own right before giving up.
        still = [b for bsn, b in work.items() if bsn not in resolved]
        if still:
            log(f"stage 2b: trying the symbolic name as an artifactId ({len(still)} names)")
            with concurrent.futures.ThreadPoolExecutor(args.jobs) as pool:
                fast = list(
                    pool.map(
                        lambda b: resolve_in_known_groups(
                            fetcher, ECLIPSE_GROUPS, strip_embedded_version(b.bsn), b
                        ),
                        still,
                    )
                )
            remaining = []
            for bundle, hit in zip(still, fast):
                if hit:
                    resolved[bundle.bsn] = hit
                else:
                    remaining.append(bundle)
            log(f"  {len(still) - len(remaining)} found in the known Eclipse groupIds")
            if args.search:
                throttle = Throttle()
                for bundle in remaining:
                    accept(
                        bundle.bsn,
                        resolve_by_artifact_id(
                            fetcher, throttle, strip_embedded_version(bundle.bsn), bundle
                        ),
                    )
            log(f"  resolved {len(resolved)}/{len(work)}")
            if ambiguous:
                log(f"  {len(ambiguous)} left ambiguous between several groupIds")

    # ---- stage 3 ---------------------------------------------------------
    if not args.no_hash and args.search:
        poisoned = poisoned_hashes(list(work.values()))
        if poisoned:
            log(f"stage 3: ignoring {len(poisoned)} SHA-1 values shared by several components")
        pending = [
            b for bsn, b in work.items()
            if bsn not in resolved and b.sha1 and b.sha1 not in poisoned
        ]
        log(f"stage 3: Maven Central by exact SHA-1 ({len(pending)} usable hashes)")
        throttle = Throttle()
        for bundle in pending:
            hit = resolve_by_sha1(fetcher, throttle, bundle.sha1)
            if hit:
                resolved[bundle.bsn] = hit
        log(f"  resolved {len(resolved)}/{len(work)}")

    # Nothing better was found for these, so Eclipse's republication stands.
    for bsn, entry in deferred.items():
        resolved.setdefault(bsn, entry)

    # ---- merge and emit --------------------------------------------------
    entries = dict(existing)
    kept = 0
    for bsn, (group, artifact, confidence, evidence) in sorted(resolved.items()):
        if bsn in existing and not args.overwrite:
            kept += 1
            continue
        entries[bsn] = {
            "groupId": group,
            "artifactId": artifact,
            "confidence": confidence,
            "evidence": evidence,
        }
    if kept:
        log(f"kept {kept} existing entries (use --overwrite to replace)")

    write_table(args.out, entries)

    review_path = args.review or args.out + ".review.md"
    write_review(
        review_path,
        [(bsn, b.version) for bsn, b in sorted(work.items()) if bsn not in resolved and bsn not in existing and bsn not in ambiguous],
        [(bsn, v[0], v[1], v[3]) for bsn, v in resolved.items() if v[2] == INFERRED],
        ambiguous,
        skipped,
    )

    by_confidence = Counter(v[2] for v in resolved.values())
    log("")
    log(f"wrote {args.out}: {len(entries)} entries")
    for tier in sorted(by_confidence, key=lambda t: CONFIDENCE_RANK.get(t, 9)):
        log(f"  {tier:18s} {by_confidence[tier]}")
    log(f"unresolved: {len(work) - len(resolved)}")
    log(f"review report: {review_path}")
    log(f"cache: {fetcher.hits} hits, {fetcher.misses} fetches in {args.cache}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

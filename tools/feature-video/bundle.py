#!/usr/bin/env python3
"""Assemble the portable viewing bundle: one folder that plays anywhere.

The bundle is deliberately boring — an HTML page, an MP4, a caption file, a poster and
the text of everything said and run. It has no build step, no framework and no external
request, so it can be opened from disk, served by any static host, or dropped onto
rebaze.io later without being rebuilt.

Python 3.9+, standard library only.

    python3 tools/feature-video/bundle.py
"""
import argparse
import hashlib
import html
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import storyboard  # noqa: E402
import timeline as tl  # noqa: E402
import verify  # noqa: E402

TEMPLATE = HERE / "viewer" / "index.html"
MARKER = ".rio-feature-video-bundle"

DESCRIPTION = (
    "Attaching explicitly supplied source and build context to normalized SBOMs, "
    "shown end to end with real commands."
)

# Copied into the bundle. Everything here is small; the MP4 is the only large file.
# SHA256SUMS is not among them: the bundle gets its own, covering exactly the files it
# contains, so `shasum -a 256 -c SHA256SUMS` works inside the folder someone was handed.
ASSETS = [
    "{base}.mp4", "{base}.srt", "{base}.vtt", "poster.png", "commands.sh",
    "command-output.txt", "narration.txt", "chapters.txt", "transcript.json",
    "timeline.json", "usage.json", "chapters.json", "narration.json",
]


def checksums(paths):
    """`shasum -a 256 -c` format, over the files as shipped."""
    lines = []
    for path in sorted(paths, key=lambda p: p.name):
        lines.append("%s  %s" % (hashlib.sha256(path.read_bytes()).hexdigest(), path.name))
    return "\n".join(lines) + "\n"


def chapter_markup(marks):
    items = []
    for mark in marks:
        items.append(
            '<li><button type="button" data-start="%.3f">'
            "<time>%s</time><span>%s</span></button></li>"
            % (mark["start"], tl.timestamp(mark["start"]), html.escape(mark["title"]))
        )
    return "\n        ".join(items)


def render_page(template, marks, meta):
    values = {
        "TITLE": storyboard.TITLE,
        "DESCRIPTION": DESCRIPTION,
        "FEATURE": storyboard.FEATURE,
        "BASE": storyboard.VIDEO_ID,
        "CHAPTERS": chapter_markup(marks),
        "TRANSCRIPT": html.escape(meta["transcript"]),
        "VOICE": html.escape("%s %s, voice %s" % (
            storyboard.VOICE_PROVIDER.title(), storyboard.VOICE_MODEL, storyboard.VOICE_NAME)),
        "META": html.escape(meta["footer"]),
    }
    page = template
    for key, value in values.items():
        page = page.replace("{{%s}}" % key, value)
    left = [token for token in ("{{", "}}") if token in page]
    if left:
        raise SystemExit("the viewer template still has unfilled placeholders")
    return page


def publish_bundle(work, out, page):
    """Replace an owned bundle with a complete, freshly assembled directory."""
    if out == work or out in work.parents:
        raise SystemExit("bundle output must not contain the rendered source directory")
    if out.exists() and any(out.iterdir()):
        legacy_bundle = ((out / "SHA256SUMS").is_file() and (out / "index.html").is_file()
                         and storyboard.TITLE in (out / "index.html").read_text())
        if not (out / MARKER).is_file() and not legacy_bundle:
            raise SystemExit("bundle output must be empty or an existing feature-video bundle")
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".rio-bundle-", dir=out.parent) as scratch:
        stage = Path(scratch) / "next"
        stage.mkdir()
        for name in ASSETS:
            name = name.format(base=storyboard.VIDEO_ID)
            shutil.copy2(work / name, stage / name)
        # Older recordings hold voice settings in the authoring cache. Consolidate
        # that validated metadata without changing the recording or source manifest.
        clips = json.loads((work / "narration.json").read_text())
        problems = verify.check_narration(clips, work)
        if problems:
            raise SystemExit("invalid narration metadata: " + "; ".join(problems))
        for clip in clips:
            missing = [key for key in ("provider", "model", "voice") if key not in clip]
            if missing:
                sidecar = Path(clip["path"]).with_suffix(".json")
                if not sidecar.is_absolute():
                    sidecar = work / sidecar
                metadata = json.loads(sidecar.read_text())
                clip.update({key: metadata[key] for key in missing})
            clip.pop("path", None)  # Individual authoring WAVs are not playback assets.
        (stage / "narration.json").write_text(json.dumps(clips, indent=2) + "\n")
        (stage / "index.html").write_text(page)
        (stage / MARKER).write_text("1\n")
        (stage / "SHA256SUMS").write_text(checksums(stage.iterdir()))
        previous = Path(scratch) / "previous"
        if out.exists():
            out.rename(previous)
        try:
            stage.rename(out)
        except OSError:
            if previous.exists():
                previous.rename(out)
            raise


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dir", type=Path, default=None, help="rendered output directory")
    parser.add_argument("--out", type=Path, default=None, help="bundle directory to write")
    args = parser.parse_args(argv)

    root = Path(os.environ.get("RIO_VIDEO_ROOT", HERE.parents[1]))
    work = (args.dir or root / "target" / "feature-video").resolve()
    out = (args.out or work / "bundle").resolve()

    base = storyboard.VIDEO_ID
    transcript = json.loads((work / "transcript.json").read_text())
    marks = json.loads((work / "chapters.json").read_text())
    total = marks[-1]["end"]

    missing = [name.format(base=base) for name in ASSETS
               if not (work / name.format(base=base)).exists()]
    if missing:
        raise SystemExit("run render.py and verify.py first; missing: " + ", ".join(missing))

    footer = (
        "%s · %s · captured from %s at commit %s · %d commands · narration synthesized with "
        "%s %s (voice %s)."
        % (storyboard.TITLE, tl.timestamp(total), storyboard.FEATURE, transcript["commit"][:12],
           len(transcript["steps"]), storyboard.VOICE_PROVIDER, storyboard.VOICE_MODEL,
           storyboard.VOICE_NAME)
    )
    page = render_page(
        TEMPLATE.read_text(), marks,
        {"transcript": (work / "narration.txt").read_text().strip(), "footer": footer},
    )
    publish_bundle(work, out, page)

    size = sum(p.stat().st_size for p in out.iterdir())
    print("bundle written to %s (%d files, %.1f MB)"
          % (out, len(list(out.iterdir())), size / 1e6))
    print("preview it with:  python3 -m http.server --directory %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

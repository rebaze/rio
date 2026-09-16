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
import html
import json
import os
import shutil
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import storyboard  # noqa: E402
import timeline as tl  # noqa: E402

TEMPLATE = HERE / "viewer" / "index.html"

DESCRIPTION = (
    "Attaching explicitly supplied source and build context to normalized SBOMs, "
    "shown end to end with real commands."
)

# Copied into the bundle. Everything here is small; the MP4 is the only large file.
ASSETS = [
    "{base}.mp4", "{base}.srt", "{base}.vtt", "poster.png", "commands.sh",
    "command-output.txt", "narration.txt", "chapters.txt", "transcript.json",
    "timeline.json", "usage.json", "SHA256SUMS",
]


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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dir", type=Path, default=None, help="rendered output directory")
    parser.add_argument("--out", type=Path, default=None, help="bundle directory to write")
    args = parser.parse_args(argv)

    root = Path(os.environ.get("RIO_VIDEO_ROOT", HERE.parents[1]))
    work = (args.dir or root / "target" / "feature-video").resolve()
    out = (args.out or work / "bundle").resolve()
    out.mkdir(parents=True, exist_ok=True)

    base = storyboard.VIDEO_ID
    transcript = json.loads((work / "transcript.json").read_text())
    marks = json.loads((work / "chapters.json").read_text())
    total = marks[-1]["end"]

    missing = [name.format(base=base) for name in ASSETS
               if not (work / name.format(base=base)).exists()]
    if missing:
        raise SystemExit("run render.py and verify.py first; missing: " + ", ".join(missing))

    for name in ASSETS:
        name = name.format(base=base)
        shutil.copy2(work / name, out / name)

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
    (out / "index.html").write_text(page)

    size = sum(p.stat().st_size for p in out.iterdir())
    print("bundle written to %s (%d files, %.1f MB)"
          % (out, len(list(out.iterdir())), size / 1e6))
    print("preview it with:  python3 -m http.server --directory %s" % out)
    return 0


if __name__ == "__main__":
    sys.exit(main())

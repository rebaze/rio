#!/usr/bin/env python3
"""Render the end screen shown over the last seconds of the walkthrough on YouTube.

This is the one asset in here that is not in the video's own palette. The video is rio's
terminal styling; an end card is rebaze speaking, so it uses the brand's colours, mark and
typography as they are on rebaze.de: near-black green, warm cream, sage, and a medium-weight
grotesque with tight negative tracking.

The right-hand third is deliberately empty. YouTube draws its end-screen elements — a video
thumbnail, a subscribe badge — on top of the frame, and anything put there would be covered.
The message stays left of them.

Needs Pillow and rsvg-convert (librsvg). The brand SVGs are vendored in brand/.

    python3 tools/feature-video/endscreen.py
    python3 tools/feature-video/endscreen.py --headline "Find out more" --url rebaze.de
"""
import argparse
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BRAND = HERE / "brand"

W, H = 1920, 1080

# Read off rebaze.de: body rgb(32,37,31), text rgb(244,241,232), CTA rgb(183,204,170).
BG = "#20251f"
CREAM = "#f4f1e8"
SAGE = "#b7ccaa"
MUTED = "#96a290"
INK = "#20251f"

# The site sets Inter 500 with -3% tracking and falls back to -apple-system. Inter is not a
# system font; SF Pro is that fallback, and its Medium instance is the same weight.
FONT_FILE = os.environ.get("REBAZE_FONT", "/System/Library/Fonts/SFNS.ttf")
TRACKING = -0.03

MARGIN = 132

DEFAULT_HEADLINE = "Find out more here"
DEFAULT_URL = "rebaze.de"
DEFAULT_EYEBROW_LEAD = "Release controls"
DEFAULT_EYEBROW_REST = "  for the agentic era."
DEFAULT_SUBLINE = "Source and build context is one piece of the release path."


def font(size, weight="Regular"):
    from PIL import ImageFont

    if not Path(FONT_FILE).exists():
        raise SystemExit("font not found: %s\nSet REBAZE_FONT to a variable or static "
                         "grotesque on this machine." % FONT_FILE)
    face = ImageFont.truetype(FONT_FILE, size)
    try:
        face.set_variation_by_name(weight)
    except Exception:
        # A static font has no axes; the caller gets the single weight it ships.
        pass
    return face


def tracked_width(draw, text, face, tracking=0.0):
    extra = tracking * face.size
    return sum(draw.textlength(ch, font=face) + extra for ch in text) - (extra if text else 0)


def draw_tracked(draw, xy, text, face, fill, tracking=0.0):
    """Pillow has no letter-spacing, and the brand's headline tracking is part of its look."""
    x, y = xy
    extra = tracking * face.size
    for ch in text:
        draw.text((x, y), ch, font=face, fill=fill)
        x += draw.textlength(ch, font=face) + extra
    return x


def svg(name, height):
    from PIL import Image
    import io

    source = BRAND / name
    if not source.exists():
        raise SystemExit("missing brand asset: %s" % source)
    try:
        png = subprocess.run(["rsvg-convert", "-h", str(height), str(source)],
                             capture_output=True, check=True).stdout
    except FileNotFoundError:
        raise SystemExit("rsvg-convert not found; install librsvg") from None
    return Image.open(io.BytesIO(png)).convert("RGBA")


def build(headline, url, eyebrow_lead, eyebrow_rest, subline, watermark=True):
    from PIL import Image, ImageDraw

    image = Image.new("RGB", (W, H), BG)
    draw = ImageDraw.Draw(image)

    if watermark:
        # The mark, very faint, bleeding off the right edge so it reads as a deliberate
        # crop rather than a clipped logo. YouTube's own elements land on top of it.
        mark = svg("rebaze-symbol.svg", 920)
        faded = mark.copy()
        faded.putalpha(mark.getchannel("A").point(lambda a: int(a * 0.08)))
        image.paste(faded, (W - 590, (H - faded.height) // 2), faded)

    logo = svg("rebaze-horizontal.svg", 66)
    image.paste(logo, (MARGIN, 118), logo)

    y = 372
    lead = font(29, "Medium")
    x = draw_tracked(draw, (MARGIN, y), eyebrow_lead, lead, SAGE)
    draw.text((x, y), eyebrow_rest, font=font(29, "Regular"), fill=MUTED)

    y = 436
    head = font(112, "Medium")
    draw_tracked(draw, (MARGIN, y), headline, head, CREAM, TRACKING)

    y = 606
    draw.text((MARGIN, y), subline, font=font(34, "Regular"), fill=MUTED)

    # The CTA, as the site draws it: sage fill, near-black green text, 10px radius scaled up.
    y = 714
    pill = font(42, "Medium")
    text_width = tracked_width(draw, url, pill)
    pad_x, pad_y = 46, 27
    box = (MARGIN, y, MARGIN + text_width + pad_x * 2, y + pill.size + pad_y * 2)
    draw.rounded_rectangle(box, radius=16, fill=SAGE)
    draw_tracked(draw, (MARGIN + pad_x, y + pad_y - 4), url, pill, INK)

    draw.text((MARGIN, 946), "rebaze GmbH · Hannover · release controls in your existing toolchain",
              font=font(24, "Regular"), fill="#6f7a6b")
    return image


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--headline", default=DEFAULT_HEADLINE)
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--eyebrow-lead", default=DEFAULT_EYEBROW_LEAD)
    parser.add_argument("--eyebrow-rest", default=DEFAULT_EYEBROW_REST)
    parser.add_argument("--subline", default=DEFAULT_SUBLINE)
    parser.add_argument("--no-watermark", action="store_true")
    parser.add_argument("--out", type=Path, default=None)
    args = parser.parse_args(argv)

    root = Path(os.environ.get("RIO_VIDEO_ROOT", HERE.parents[1]))
    out = args.out or root / "target" / "feature-video" / "endscreen.png"
    out.parent.mkdir(parents=True, exist_ok=True)
    image = build(args.headline, args.url, args.eyebrow_lead, args.eyebrow_rest,
                  args.subline, watermark=not args.no_watermark)
    image.save(out)
    print("wrote %s (%dx%d)" % (out, image.width, image.height))
    return 0


if __name__ == "__main__":
    sys.exit(main())

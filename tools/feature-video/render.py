#!/usr/bin/env python3
"""Draw the captured walkthrough and encode it with the generated narration.

Left: the terminal, typed and revealed at reading speed. Right: a panel that stays put,
so a viewer always knows which chapter they are in, what to look for and why it matters.
Nothing on screen is invented here — every character in the terminal comes from
`transcript.json`, and every pause comes from `timeline.py`.

Needs Pillow and ffmpeg. Neither is a Rio runtime dependency; see tools/README.md.

    python3 tools/feature-video/render.py --preview-only   # frames and timing, no encode
    python3 tools/feature-video/render.py
"""
import argparse
import json
import math
import os
import subprocess
import sys
import wave
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import storyboard  # noqa: E402
import timeline as tl  # noqa: E402

W, H = 1920, 1080
FPS = tl.FPS
RATE = tl.RATE

C = {
    "bg": "#080e18", "terminal": "#0c1421", "panel": "#121e2e", "border": "#26384e",
    "ink": "#e9eff8", "muted": "#91a4bc", "mint": "#73e1bb", "blue": "#a8ceff",
    "red": "#ff9fa4", "amber": "#f1ce8b",
}

# Overridable because they are the one part of this that is not portable.
FONT_MONO = os.environ.get("RIO_VIDEO_FONT_MONO", "/System/Library/Fonts/Menlo.ttc")
FONT_SANS = os.environ.get("RIO_VIDEO_FONT_SANS", "/System/Library/Fonts/Supplemental/Arial.ttf")
FONT_BOLD = os.environ.get("RIO_VIDEO_FONT_BOLD", "/System/Library/Fonts/Supplemental/Arial Bold.ttf")

LINE = 29   # terminal line height, in pixels
_fonts = {}


def font(size, kind="sans"):
    from PIL import ImageFont

    key = (size, kind)
    if key not in _fonts:
        path = {"sans": FONT_SANS, "bold": FONT_BOLD, "mono": FONT_MONO}[kind]
        if not Path(path).exists():
            raise SystemExit(
                "font not found: %s\nSet RIO_VIDEO_FONT_MONO / _SANS / _BOLD to fonts "
                "on this machine." % path
            )
        _fonts[key] = ImageFont.truetype(path, size)
    return _fonts[key]


def wrap(draw, text, max_width, size, kind="sans"):
    lines = []
    for paragraph in text.split("\n"):
        if not paragraph:
            lines.append("")
            continue
        line = ""
        for word in paragraph.split():
            trial = (line + " " + word).strip()
            if draw.textlength(trial, font=font(size, kind)) <= max_width:
                line = trial
            else:
                if line:
                    lines.append(line)
                line = word
        if line:
            lines.append(line)
    return lines


def block(draw, text, x, y, width, size=26, color=None, kind="sans", leading=None):
    for line in wrap(draw, text, width, size, kind):
        draw.text((x, y), line, font=font(size, kind), fill=color or C["ink"])
        y += leading or round(size * 1.35)
    return y


def draw_card(draw, shot, meta):
    if shot["kind"] == "intro":
        draw.text((76, 201), "THE PIPELINE HANDOFF", font=font(20, "bold"), fill=C["muted"])
        block(draw, "The build is done.\nWhat does this SBOM belong to?", 76, 258, 1050, 47,
              kind="bold", leading=60)
        cards = [
            ("1", "Ecosystem build", "Existing SBOM inventory"),
            ("2", "Explicit local inputs", "rio.yaml + producer context"),
            ("3", "Rio normalization", "SBOM + index + unsigned statement"),
        ]
        for index, (number, title, detail) in enumerate(cards):
            y = 445 + index * 129
            draw.rounded_rectangle((77, y, 1178, y + 105), radius=12, fill="#152235",
                                   outline=C["border"])
            draw.text((102, y + 25), number, font=font(37, "bold"), fill=C["mint"])
            draw.text((171, y + 20), title, font=font(28, "bold"), fill=C["ink"])
            draw.text((171, y + 61), detail, font=font(23), fill=C["muted"])
        draw.text((1274, 200), "WHAT YOU WILL SEE", font=font(19, "bold"), fill=C["mint"])
        y = block(draw, "A developer's walkthrough", 1274, 246, 564, 35, kind="bold")
        y = block(draw, "Two products.\nSource and build claims.\nClear refusals.\n"
                        "An inspectable change record.", 1274, y + 23, 555, 27, leading=41)
        draw.line((1274, y + 25, 1845, y + 25), fill=C["border"])
        y = block(draw, "For this recording", 1274, y + 51, 552, 23, kind="bold")
        y = block(draw, "PR checkout + Go for the local build.\nBash, Git, standard tools and jq.\n"
                        "Python only for the optional helper.", 1274, y + 18, 550, 24, leading=34)
        block(draw, "The shipped fixture demo needs only Rio, a POSIX shell and standard tools.",
              1274, y + 32, 550, 23, C["mint"], leading=32)
    else:
        draw.text((76, 201), "AN INSPECTABLE HANDOFF", font=font(20, "bold"), fill=C["mint"])
        y = block(draw, "What we established", 76, 261, 1020, 45, kind="bold")
        for title, detail in [
            ("Correct input binding", "Artifact ID + original SBOM digest"),
            ("Explicit source and build claims", "With missing workspace state kept unknown"),
            ("Controlled changes", "Conflicts refused; authorized replacements audited"),
            ("Consistent records", "SBOM property, index and unsigned statement"),
        ]:
            y += 33
            draw.text((82, y), title, font=font(28, "bold"), fill=C["ink"])
            y += 42
            draw.text((82, y), detail, font=font(24), fill=C["muted"])
            y += 28
        draw.text((1274, 200), "TRY THE SAME EXAMPLES", font=font(19, "bold"), fill=C["mint"])
        y = block(draw, "Run the shipped demo", 1274, 245, 553, 35, kind="bold")
        y = block(draw, "Use a Rio release containing this feature and the matching example "
                        "directory.", 1274, y + 23, 552, 26, leading=36)
        y += 32
        draw.rounded_rectangle((1272, y, 1847, y + 103), radius=10, fill=C["terminal"])
        draw.text((1290, y + 18), "RIO_BIN=/path/to/rio " + chr(92), font=font(22, "mono"),
                  fill=C["mint"])
        draw.text((1290, y + 58), "  ./tools/demo-context/run.sh", font=font(22, "mono"),
                  fill=C["ink"])
        y += 138
        draw.text((1274, y), "THE BOUNDARY", font=font(18, "bold"), fill=C["muted"])
        y += 35
        y = block(draw, "Producer assertions are not authenticated build provenance or proof "
                        "about compiled artifact bytes.", 1274, y, 552, 27, leading=39)
        block(draw, storyboard.FEATURE + "  ·  github.com/rebaze/rio", 1274, y + 37, 551, 23,
              C["mint"])


def render(shot, local, total, meta):
    from PIL import Image, ImageDraw

    image = Image.new("RGB", (W, H), C["bg"])
    draw = ImageDraw.Draw(image)
    draw.text((42, 27), "RIO  /  " + storyboard.FEATURE, font=font(21, "bold"), fill=C["mint"])
    draw.text((42, 67), storyboard.SUBTITLE, font=font(39, "bold"), fill=C["ink"])
    draw.text((1500, 37), meta["label"], font=font(16), fill=C["muted"])
    draw.line((42, 133, 1878, 133), fill=C["border"], width=1)
    draw.rounded_rectangle((40, 163, 1214, 943), radius=16, fill=C["terminal"],
                           outline=C["border"], width=2)
    draw.rounded_rectangle((1240, 163, 1880, 943), radius=16, fill=C["panel"],
                           outline=C["border"], width=2)

    if shot["kind"] != "step":
        draw_card(draw, shot, meta)
    else:
        step = shot["step"]
        out = shot["out"]
        if local < shot["typing_end"]:
            count = max(0, min(len(step["command"]),
                               int((local - tl.TYPING_LEAD) / shot["typing"] * len(step["command"]))))
            current = tl.command_rows(step["command"][:count], shot["where"])
            if int(local * 2) % 2 == 0:
                row, color, prefix = current[-1]
                current[-1] = (row + "▌", color, prefix)
            rows = shot["history"] + current
            phase, phasecolor, status = "TYPING", C["blue"], ""
        elif local < shot["output_start"]:
            rows = shot["history"] + tl.command_rows(step["command"], shot["where"])
            phase, phasecolor, status = "RUNNING", C["amber"], ""
        else:
            fraction = min(1, (local - shot["output_start"]) / shot["reveal"]) if shot["reveal"] else 1
            shown = min(len(out), math.ceil(fraction * len(out)))
            rows = shot["history"] + tl.command_rows(step["command"], shot["where"]) + out[:shown]
            ready = local >= shot["output_end"]
            if ready:
                rows = rows + [("", "ink", 0)] + tl.command_rows("", shot["next_where"])
                if int(local * 2) % 2 == 0:
                    row, color, prefix = rows[-1]
                    rows[-1] = (row + "▌", color, prefix)
            phase = "READ THE RESULT" if ready else "OUTPUT"
            phasecolor = (C["mint"] if step["exitCode"] == 0
                          else C["red"] if step["exitCode"] == 2 else C["amber"])
            status = ""
            if ready:
                status = ("EXIT 0" if step["exitCode"] == 0
                          else "EXPECTED REFUSAL  ·  EXIT 2" if step["exitCode"] == 2
                          else "DIFF FOUND  ·  EXIT 1")
                if step["command"] == "echo $?":
                    status = "PREVIOUS EXIT  ·  " + step["output"].strip()
                    phasecolor = C["red"] if step["output"].strip() != "0" else C["mint"]

        for number, color in enumerate(("#fc6b6b", "#edc05b", "#6fc88b")):
            draw.ellipse((64 + number * 23, 182, 76 + number * 23, 194), fill=color)
        title = ("bash  ·  Rio PR checkout" if shot["where"] == "repo"
                 else "bash  ·  " + step["cwd"].replace("/private/tmp/", "/tmp/"))
        draw.text((160, 179), title, font=font(17, "mono"), fill=C["muted"])
        draw.line((42, 212, 1212, 212), fill=C["border"])
        for index, (line, color, prefix) in enumerate(rows[-tl.ROWS:]):
            y = 229 + index * LINE
            if prefix:
                left = line[:prefix]
                draw.text((65, y), left, font=font(22, "mono"), fill=C["mint"])
                x = 65 + draw.textlength(left, font=font(22, "mono"))
                draw.text((x, y), line[prefix:], font=font(22, "mono"), fill=C[color])
            else:
                draw.text((65, y), line, font=font(22, "mono"), fill=C[color])

        draw.text((1272, 190), step["chapter"].upper(), font=font(18, "bold"), fill=C["mint"])
        y = block(draw, step["title"], 1272, 231, 572, 32, kind="bold", leading=39)
        draw.line((1272, y + 19, 1848, y + 19), fill=C["border"])
        y += 46
        draw.text((1272, y), "LOOK FOR", font=font(17, "bold"), fill=C["muted"])
        y += 33
        y = block(draw, step["meaning"], 1272, y, 567, 25, leading=35)
        y += 31
        draw.text((1272, y), "WHY IT MATTERS", font=font(17, "bold"), fill=C["muted"])
        y += 33
        y = block(draw, storyboard.WHY[step["chapter"][:2]], 1272, y, 567, 24, leading=34)
        if y > 816:
            raise SystemExit("right panel overflows on step %d (%d)" % (shot["index"], y))
        draw.rounded_rectangle((1272, 852, 1848, 907), radius=9, fill="#1c3045")
        draw.text((1290, 868), status or phase, font=font(19, "bold"), fill=phasecolor)
        draw.text((1080, 980), "%02d / %d" % (shot["index"], meta["steps"]),
                  font=font(18, "mono"), fill=C["muted"])

    elapsed = shot["start"] + local
    draw.text((42, 978), "ACTUAL COMMAND OUTPUT  ·  SYNTHETIC DATA  ·  PACED REPLAY",
              font=font(18), fill=C["muted"])
    draw.text((1690, 978), tl.timestamp(elapsed) + " / " + tl.timestamp(total),
              font=font(20, "mono"), fill=C["ink"])
    draw.line((42, 1038, 1878, 1038), fill=C["border"], width=5)
    draw.line((42, 1038, 42 + 1836 * min(1, elapsed / total), 1038), fill=C["mint"], width=5)
    return image


def frame_key(shot, local):
    """Frames that would be drawn identically are drawn once and written twice."""
    if shot["kind"] != "step":
        return (int(shot["start"] + local),)
    command = shot["step"]["command"]
    chars = min(len(command), max(0, int((local - tl.TYPING_LEAD) / shot["typing"] * len(command))))
    lines = (min(len(shot["out"]),
                 max(0, math.ceil((local - shot["output_start"]) / shot["reveal"] * len(shot["out"]))))
             if shot["reveal"] else 0)
    return (chars, lines, int(local * 2) % 2, int(shot["start"] + local),
            local >= shot["typing_end"], local >= shot["output_start"], local >= shot["output_end"])


def load_narration(path):
    """Measured clip durations and their audio, keyed by clip name."""
    clips = json.loads(Path(path).read_text())
    seconds = {}
    audio = {}
    for clip in clips:
        seconds[clip["clip"]] = clip["seconds"]
        with wave.open(clip["path"], "rb") as handle:
            if handle.getframerate() != RATE or handle.getnchannels() != 1:
                raise SystemExit("clip %s is not %d Hz mono" % (clip["clip"], RATE))
            audio[clip["clip"]] = handle.readframes(handle.getnframes())
    return seconds, audio


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dir", type=Path, default=None, help="working directory")
    parser.add_argument("--preview-only", action="store_true", help="frames and timing only")
    args = parser.parse_args(argv)

    root = Path(os.environ.get("RIO_VIDEO_ROOT", HERE.parents[1]))
    work = (args.dir or root / "target" / "feature-video").resolve()
    transcript = json.loads((work / "transcript.json").read_text())
    seconds, audio = load_narration(work / "narration.json")

    shots, total = tl.build(transcript, seconds, storyboard.INTRO_VOICE, storyboard.OUTRO_VOICE)
    problems = tl.check_ordering(shots, seconds)
    if problems:
        raise SystemExit("timeline is not playable:\n  " + "\n  ".join(problems))
    meta = {
        "label": transcript["commit"][:7] + "  ·  FEATURE WALKTHROUGH",
        "steps": len(transcript["steps"]),
    }
    print("DURATION %.1f s (%s), %d shots" % (total, tl.timestamp(total), len(shots)))

    # Text outputs first: they are what a reviewer reads, and they cost nothing to redo.
    cues = tl.captions(shots, seconds)
    marks = tl.chapters(shots, total)
    base = storyboard.VIDEO_ID
    (work / (base + ".srt")).write_text(tl.srt(cues))
    (work / (base + ".vtt")).write_text(tl.vtt(cues))
    (work / "chapters.ffmeta").write_text(tl.ffmetadata(
        marks, storyboard.TITLE,
        "Real captured commands and outputs, paced terminal replay. Synthetic fixture data "
        "and synthetic narration (%s %s, voice %s)."
        % (storyboard.VOICE_PROVIDER, storyboard.VOICE_MODEL, storyboard.VOICE_NAME)))
    (work / "chapters.txt").write_text(tl.chapter_list(marks))
    # Exact boundaries for verify.py; chapters.txt is rounded for humans to read.
    (work / "chapters.json").write_text(json.dumps(marks, indent=2) + "\n")
    (work / "narration.txt").write_text(
        "\n\n".join(shot["voice"] for shot in shots if shot.get("voice")) + "\n")
    (work / "timeline.json").write_text(json.dumps(
        [{k: v for k, v in shot.items() if k not in ("history", "out", "step")}
         for shot in shots], indent=2) + "\n")

    frames = work / "frames"
    frames.mkdir(exist_ok=True)
    for index, shot in enumerate(shots):
        render(shot, max(0, shot["duration"] - 0.5), total, meta).save(frames / ("%02d.png" % index))
    render(shots[0], tl.CARD_LEAD, total, meta).save(work / "poster.png")
    if args.preview_only:
        print("wrote %d preview frames to %s" % (len(shots), frames))
        return 0

    encoder = subprocess.Popen(
        ["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-f", "rawvideo",
         "-pixel_format", "rgb24", "-video_size", "%dx%d" % (W, H), "-framerate", str(FPS),
         "-i", "-", "-an", "-c:v", "libx264", "-preset", "slow", "-crf", "20",
         "-pix_fmt", "yuv420p", str(work / "silent.mp4")],
        stdin=subprocess.PIPE)
    with wave.open(str(work / "narration.wav"), "wb") as track:
        track.setnchannels(1)
        track.setsampwidth(2)
        track.setframerate(RATE)
        for index, shot in enumerate(shots):
            print("render %d/%d  %s" % (index + 1, len(shots), shot["title"]), flush=True)
            cache = {}
            for number in range(round(shot["duration"] * FPS)):
                local = number / FPS
                key = frame_key(shot, local)
                if key not in cache:
                    cache = {key: render(shot, local, total, meta).tobytes()}
                encoder.stdin.write(cache[key])
            samples = round(shot["duration"] * RATE) * 2
            lead = round(shot["audio_start"] * RATE) * 2
            clip = audio.get(shot.get("clip"), b"")
            placed = b"\0" * lead + clip
            if len(placed) > samples:
                raise SystemExit("narration for %s does not fit its shot" % shot["title"])
            track.writeframes(placed + b"\0" * (samples - len(placed)))
    encoder.stdin.close()
    if encoder.wait() != 0:
        raise SystemExit("video encoding failed")

    subprocess.run(
        ["ffmpeg", "-v", "error", "-y",
         "-i", str(work / "silent.mp4"), "-i", str(work / "narration.wav"),
         "-i", str(work / (base + ".srt")), "-i", str(work / "chapters.ffmeta"),
         "-map", "0:v:0", "-map", "1:a:0", "-map", "2:0",
         "-map_metadata", "3", "-map_chapters", "3",
         "-c:v", "copy", "-c:a", "aac", "-b:a", "128k",
         "-af", "loudnorm=I=-18:TP=-2:LRA=7", "-ar", "48000",
         "-c:s", "mov_text", "-disposition:s:0", "0",
         "-metadata:s:s:0", "title=English captions",
         "-metadata:s:s:0", "language=eng", "-metadata:s:a:0", "language=eng",
         # Without an explicit timescale ffmpeg picks one that rounds chapter
         # boundaries into each other and players show the wrong chapter.
         "-movie_timescale", "1000", "-movflags", "+faststart",
         str(work / (base + ".mp4"))],
        check=True)
    print("wrote", work / (base + ".mp4"))
    return 0


if __name__ == "__main__":
    sys.exit(main())

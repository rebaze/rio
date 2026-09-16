#!/usr/bin/env python3
"""Check the encoded video against what the timeline said it would be.

Rendering can succeed and still produce something not worth publishing: a stream that
will not decode, chapters rounded into each other, captions running past the end,
narration so quiet it is unusable or so loud it clips. Each check here failed at least
once in a draft, which is why it is a check and not a habit.

Needs ffmpeg and ffprobe.

    python3 tools/feature-video/verify.py
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import storyboard  # noqa: E402
import timeline as tl  # noqa: E402

# A synthesizer that ignores "read the transcript exactly" shows up as a clip that takes
# far longer or shorter to say than its word count allows — an added preamble, a dropped
# sentence. The direction asks for about 150 wpm; this band is wide enough that ordinary
# variation between lines passes and only a real discrepancy fails.
MIN_WPM = 90.0
MAX_WPM = 200.0

TARGET_LUFS = -18.0
LUFS_TOLERANCE = 1.5
MAX_TRUE_PEAK = -1.0


def parse_caption_time(text):
    match = re.match(r"(\d+):(\d\d):(\d\d)[.,](\d+)", text.strip())
    if not match:
        raise ValueError("not a caption timestamp: %r" % text)
    hours, minutes, seconds, fraction = match.groups()
    return (int(hours) * 3600 + int(minutes) * 60 + int(seconds)
            + int(fraction) / (10 ** len(fraction)))


def parse_cues(text):
    """Start and end of every cue in an SRT or WebVTT file."""
    cues = []
    for line in text.splitlines():
        if "-->" in line:
            start, _, end = line.partition("-->")
            cues.append((parse_caption_time(start), parse_caption_time(end)))
    return cues


def check_cues(cues, duration):
    """Cues must be ordered, non-empty, non-overlapping and inside the video."""
    problems = []
    if not cues:
        return ["no caption cues"]
    previous_end = 0.0
    for index, (start, end) in enumerate(cues, 1):
        if end <= start:
            problems.append("cue %d ends before it starts" % index)
        if start < previous_end - 0.001:
            problems.append("cue %d overlaps the one before it" % index)
        previous_end = end
    if cues[-1][1] > duration + 0.5:
        problems.append("the last cue ends %.2fs after the video does" % (cues[-1][1] - duration))
    return problems


def check_chapters(chapters, expected, duration):
    problems = []
    if len(chapters) != len(expected):
        problems.append("%d chapters in the file, %d in the timeline"
                        % (len(chapters), len(expected)))
        return problems
    for index, (found, want) in enumerate(zip(chapters, expected), 1):
        start = float(found["start_time"])
        if abs(start - want["start"]) > 0.5:
            problems.append("chapter %d starts at %.2fs, expected %.2fs"
                            % (index, start, want["start"]))
        if found.get("tags", {}).get("title") != want["title"]:
            problems.append("chapter %d is titled %r, expected %r"
                            % (index, found.get("tags", {}).get("title"), want["title"]))
    # A zero-length chapter is how the draft's broken timescale showed up.
    for index, found in enumerate(chapters, 1):
        if float(found["end_time"]) - float(found["start_time"]) <= 0:
            problems.append("chapter %d has no duration" % index)
    if chapters and abs(float(chapters[-1]["end_time"]) - duration) > 1.0:
        problems.append("the last chapter ends %.2fs from the end of the video"
                        % abs(float(chapters[-1]["end_time"]) - duration))
    return problems


def speaking_rates(clips):
    """Words per minute per clip, from the written line and its measured duration."""
    rates = {}
    for clip in clips:
        seconds = clip.get("seconds", 0.0)
        words = len(clip.get("text", "").split())
        if seconds > 0 and words:
            rates[clip["clip"]] = words / seconds * 60.0
    return rates


def check_speaking_rates(rates, low=MIN_WPM, high=MAX_WPM):
    """Flag any clip whose length does not match the words it was given."""
    problems = []
    for name in sorted(rates):
        rate = rates[name]
        if rate < low:
            problems.append("%s takes %.0f wpm; it may have gained words" % (name, rate))
        elif rate > high:
            problems.append("%s runs at %.0f wpm; it may have lost words" % (name, rate))
    return problems


def loudness(path):
    """Integrated loudness and true peak, measured over the whole track."""
    result = subprocess.run(
        ["ffmpeg", "-v", "info", "-i", str(path), "-af", "ebur128=peak=true", "-f", "null", "-"],
        capture_output=True, text=True)
    text = result.stderr
    summary = text.rsplit("Summary:", 1)[-1]
    values = {}
    for name, key in (("I:", "lufs"), ("Peak:", "peak"), ("LRA:", "lra")):
        match = re.search(re.escape(name) + r"\s*(-?\d+\.?\d*)", summary)
        if match:
            values[key] = float(match.group(1))
    return values


def probe(path):
    result = subprocess.run(
        ["ffprobe", "-v", "error", "-show_format", "-show_streams", "-show_chapters",
         "-of", "json", str(path)],
        capture_output=True, text=True, check=True)
    return json.loads(result.stdout)


def decodes(path):
    """Decode every frame and sample. Anything printed here is a real defect."""
    result = subprocess.run(
        ["ffmpeg", "-v", "error", "-xerror", "-i", str(path), "-f", "null", "-"],
        capture_output=True, text=True)
    return result.returncode == 0, result.stderr.strip()


def faststart(path):
    """`moov` before `mdat` is what lets playback begin before the file is downloaded."""
    with open(path, "rb") as handle:
        head = handle.read(4 * 1024 * 1024)
    moov, mdat = head.find(b"moov"), head.find(b"mdat")
    return moov != -1 and (mdat == -1 or moov < mdat)


def checksums(paths):
    lines = []
    for path in sorted(paths):
        digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
        lines.append("%s  %s" % (digest, Path(path).name))
    return "\n".join(lines) + "\n"


def verify(work, log=print):
    base = storyboard.VIDEO_ID
    video = work / (base + ".mp4")
    problems = []

    def check(name, ok, detail=""):
        log("%-46s %s%s" % (name, "ok" if ok else "FAIL", "  " + detail if detail else ""))
        if not ok:
            problems.append(name + (": " + detail if detail else ""))

    if not video.exists():
        raise SystemExit("no video at %s; run render.py first" % video)

    ok, detail = decodes(video)
    check("decodes without errors", ok, detail[:200])

    info = probe(video)
    streams = {s["codec_type"]: s for s in info["streams"]}
    duration = float(info["format"]["duration"])

    check("video is H.264", streams.get("video", {}).get("codec_name") == "h264")
    check("pixel format is yuv420p", streams.get("video", {}).get("pix_fmt") == "yuv420p")
    check("resolution is 1920x1080",
          (streams.get("video", {}).get("width"), streams.get("video", {}).get("height")) == (1920, 1080))
    check("audio is AAC", streams.get("audio", {}).get("codec_name") == "aac")
    check("a subtitle track is present", "subtitle" in streams)
    check("playback can start before download", faststart(video))
    # -movie_timescale sets the movie header, which ffprobe does not report directly.
    # What it is passed for is chapter boundaries that survive the round trip, and
    # check_chapters below is the test for that. Here, just confirm the frame rate.
    rate = streams.get("video", {}).get("avg_frame_rate", "0/1")
    numerator, _, denominator = rate.partition("/")
    measured = float(numerator) / float(denominator or 1)
    check("frame rate matches the timeline", abs(measured - tl.FPS) < 0.01, "%g fps" % measured)

    timeline_shots = json.loads((work / "timeline.json").read_text())
    expected_total = timeline_shots[-1]["start"] + timeline_shots[-1]["duration"]
    check("duration matches the timeline", abs(duration - expected_total) < 1.0,
          "%.2fs vs %.2fs" % (duration, expected_total))

    # The exact boundaries the muxer was given, not the rounded ones humans read.
    expected = json.loads((work / "chapters.json").read_text())
    chapter_problems = check_chapters(info.get("chapters", []), expected, duration)
    check("chapters match the timeline", not chapter_problems, "; ".join(chapter_problems[:3]))

    srt_cues = parse_cues((work / (base + ".srt")).read_text())
    vtt_cues = parse_cues((work / (base + ".vtt")).read_text())
    check("captions are well formed", not check_cues(srt_cues, duration),
          "; ".join(check_cues(srt_cues, duration)[:3]))
    check("SRT and WebVTT agree",
          len(srt_cues) == len(vtt_cues)
          and all(abs(a[0] - b[0]) < 0.01 for a, b in zip(srt_cues, vtt_cues)),
          "%d vs %d cues" % (len(srt_cues), len(vtt_cues)))

    levels = loudness(video)
    check("audio is audible", levels.get("lufs", 0.0) < -1 and levels.get("lufs", -99) > -40,
          "%.1f LUFS" % levels.get("lufs", float("nan")))
    check("loudness is on target",
          abs(levels.get("lufs", -99) - TARGET_LUFS) <= LUFS_TOLERANCE,
          "%.1f LUFS, target %.1f" % (levels.get("lufs", float("nan")), TARGET_LUFS))
    check("audio does not clip", levels.get("peak", 99) <= MAX_TRUE_PEAK,
          "%.1f dBTP" % levels.get("peak", float("nan")))

    clips = json.loads((work / "narration.json").read_text())
    rates = speaking_rates(clips)
    rate_problems = check_speaking_rates(rates)
    ordered = sorted(rates.values())
    check("every clip is paced like its script", not rate_problems,
          "%d-%d wpm, median %d" % (min(ordered), max(ordered), ordered[len(ordered) // 2])
          if ordered else "no clips")
    check("every clip uses the approved voice",
          all(c.get("clip") for c in clips) and len(clips) == len(storyboard.narration_clips()),
          "%d of %d clips" % (len(clips), len(storyboard.narration_clips())))

    narration = (work / "narration.txt").read_text()
    spoken = [text for _, text in storyboard.narration_clips()]
    check("every scripted line is in the narration",
          all(text in narration for text in spoken),
          "%d of %d" % (sum(1 for t in spoken if t in narration), len(spoken)))
    caption_text = " ".join(
        line for line in (work / (base + ".srt")).read_text().splitlines()
        if line and "-->" not in line and not line.isdigit())
    check("captions read as prose, not as the spoken form", "S B O M" not in caption_text)

    assets = [work / (base + ext) for ext in (".mp4", ".srt", ".vtt")]
    assets += [work / name for name in ("poster.png", "transcript.json", "commands.sh",
                                        "command-output.txt", "chapters.txt", "chapters.json",
                                        "narration.txt", "timeline.json", "usage.json",
                                        "narration.json")]
    present = [p for p in assets if p.exists()]
    check("every deliverable is present", len(present) == len(assets),
          ", ".join(p.name for p in assets if not p.exists()))
    (work / "SHA256SUMS").write_text(checksums(present))

    log("")
    log("%s  %s  %s  %.1f MB"
        % (video.name, tl.timestamp(duration), "%dx%d" % (streams["video"]["width"],
                                                          streams["video"]["height"]),
           video.stat().st_size / 1e6))
    return problems


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--dir", type=Path, default=None)
    args = parser.parse_args(argv)
    root = Path(os.environ.get("RIO_VIDEO_ROOT", HERE.parents[1]))
    work = (args.dir or root / "target" / "feature-video").resolve()
    problems = verify(work)
    if problems:
        print("\n%d check(s) failed" % len(problems), file=sys.stderr)
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())

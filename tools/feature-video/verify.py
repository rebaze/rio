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
import math
import os
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import narrate  # noqa: E402
import storyboard  # noqa: E402
import timeline as tl  # noqa: E402

# A broad duration plausibility guard around the direction's roughly 150 wpm.
# The recorded pass's observed 111.94–155.17 wpm range is not an acceptance band.
# Word count / duration cannot establish what was actually spoken: omitted words,
# additions or substitutions can still fall inside these limits. Listen to the audio.
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


def parse_cues(text, include_text=False):
    """Read cue boundaries, optionally including whitespace-normalized caption text."""
    cues = []
    for block in re.split(r"\n\s*\n", text.strip()):
        lines = block.splitlines()
        for index, line in enumerate(lines):
            if "-->" in line:
                start, _, end = line.partition("-->")
                cue = (parse_caption_time(start), parse_caption_time(end))
                if include_text:
                    cue += (" ".join(" ".join(lines[index + 1:]).split()),)
                cues.append(cue)
                break
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
        end = float(found["end_time"])
        if abs(end - want["end"]) > 0.5:
            problems.append("chapter %d ends at %.2fs, expected %.2fs"
                            % (index, end, want["end"]))
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



def check_narration(clips, work):
    """Validate recorded metadata, not the audible speaker or spoken words.

    Older manifests keep provider/model/voice in the WAV's cache sidecar. Require
    that sidecar to match the content key and text before trusting its voice fields.
    A run-wide usage summary cannot establish which voice produced each clip.
    """
    if not isinstance(clips, list):
        return ["narration must be a list of clips"]
    expected = dict(storyboard.narration_clips())
    approved = dict(provider=storyboard.VOICE_PROVIDER, model=storyboard.VOICE_MODEL,
                    voice=storyboard.VOICE_NAME)
    problems = []
    seen = set()
    for index, clip in enumerate(clips, 1):
        if not isinstance(clip, dict):
            problems.append("clip %d is not an object" % index)
            continue
        name = clip.get("clip")
        if not isinstance(name, str) or name not in expected:
            problems.append("clip %d has an unknown identity" % index)
            continue
        if name in seen:
            problems.append("duplicate clip %s" % name)
        seen.add(name)
        if clip.get("text") != expected[name]:
            problems.append("%s text does not match its scripted line" % name)
        seconds = clip.get("seconds")
        if (type(seconds) not in (int, float) or not math.isfinite(seconds) or seconds <= 0):
            problems.append("%s has no finite positive measured duration" % name)
        metadata = clip
        missing = [field for field in approved if field not in clip]
        if missing:
            # Never let a sidecar override a conflicting field in the manifest.
            for field in approved:
                if field in clip and clip[field] != approved[field]:
                    problems.append("%s %s is not the approved voice setting" % (name, field))
            path = clip.get("path")
            try:
                if not isinstance(path, str) or not path:
                    raise ValueError("no cache path")
                sidecar = Path(path).with_suffix(".json")
                if not sidecar.is_absolute():
                    sidecar = work / sidecar
                metadata = json.loads(sidecar.read_text())
                if not isinstance(metadata, dict):
                    raise ValueError("not an object")
            except (OSError, ValueError) as error:
                problems.append("%s is missing approved voice metadata: %s" % (name, error))
                continue
            spoken = narrate.spoken_form(expected[name])
            key = narrate.cache_key(spoken)
            if (clip.get("key") != key or sidecar.stem != key
                    or metadata.get("text") != expected[name] or metadata.get("spoken") != spoken):
                problems.append("%s cache metadata does not match its content key and script" % name)
        for field, value in approved.items():
            if metadata.get(field) != value:
                problems.append("%s %s is not the approved voice setting" % (name, field))
    missing = sorted(set(expected) - seen)
    if missing:
        problems.append("missing clips: %s" % ", ".join(missing))
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
    """Flag implausible durations; this does not verify the words in the audio."""
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

    srt_text = (work / (base + ".srt")).read_text()
    vtt_text = (work / (base + ".vtt")).read_text()
    srt_cues = parse_cues(srt_text)
    vtt_cues = parse_cues(vtt_text)
    caption_problems = (["SRT: " + p for p in check_cues(srt_cues, duration)]
                        + ["WebVTT: " + p for p in check_cues(vtt_cues, duration)])
    check("captions are well formed", not caption_problems,
          "; ".join(caption_problems[:3]))
    check("SRT and WebVTT agree",
          len(srt_cues) == len(vtt_cues)
          and all(abs(a[0] - b[0]) < 0.01 and abs(a[1] - b[1]) < 0.01 and a[2] == b[2]
                  for a, b in zip(parse_cues(srt_text, include_text=True),
                                  parse_cues(vtt_text, include_text=True))),
          "%d vs %d cues; comparing starts, ends and text" % (len(srt_cues), len(vtt_cues)))

    levels = loudness(video)
    check("audio is audible", levels.get("lufs", 0.0) < -1 and levels.get("lufs", -99) > -40,
          "%.1f LUFS" % levels.get("lufs", float("nan")))
    check("loudness is on target",
          abs(levels.get("lufs", -99) - TARGET_LUFS) <= LUFS_TOLERANCE,
          "%.1f LUFS, target %.1f" % (levels.get("lufs", float("nan")), TARGET_LUFS))
    check("audio does not clip", levels.get("peak", 99) <= MAX_TRUE_PEAK,
          "%.1f dBTP" % levels.get("peak", float("nan")))

    try:
        clips = json.loads((work / "narration.json").read_text())
        narration_problems = check_narration(clips, work)
    except (OSError, ValueError) as error:
        clips = []
        narration_problems = [str(error)]
    check("narration metadata uses approved voice and script", not narration_problems,
          "; ".join(narration_problems[:3]))
    # Malformed or incomplete metadata must not yield an empty, passing rate check.
    rates = speaking_rates(clips) if not narration_problems else {}
    rate_problems = check_speaking_rates(rates)
    ordered = sorted(rates.values())
    check("clip durations pass the pacing heuristic", bool(rates) and not rate_problems,
          ("%.1f-%.1f wpm, median %.1f; guard %.0f-%.0f" % (
              min(ordered), max(ordered), ordered[len(ordered) // 2], MIN_WPM, MAX_WPM)
           + ("; " + "; ".join(rate_problems[:3]) if rate_problems else ""))
          if ordered else "no valid complete narration metadata")

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
    if (work / ".rio-feature-video-bundle").exists():
        assets += [work / "index.html", work / ".rio-feature-video-bundle"]
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

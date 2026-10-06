#!/usr/bin/env python3
"""Render guided case recordings with typed commands, chapter cuts and optional speech."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import shutil
import subprocess
import textwrap
import wave

from PIL import Image, ImageDraw, ImageFont

WIDTH, HEIGHT, FPS = 1600, 1000, 12
BG, PANEL, INK = "#0b1321", "#111e30", "#e5edf8"
GREEN, RED, BLUE, MUTED = "#77e3b3", "#ff939d", "#91caff", "#9eafc7"
RATE = 24000


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("transcript", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--font", type=Path)
    parser.add_argument("--voice", help="optional macOS say voice, e.g. Samantha")
    args = parser.parse_args()
    if not shutil.which("ffmpeg") or (args.voice and not shutil.which("say")):
        parser.error("ffmpeg is required; --voice also requires macOS say")
    choices = [args.font, Path("/System/Library/Fonts/Menlo.ttc"),
               Path("/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf")]
    font_path = next((p for p in choices if p and p.exists()), None)
    if not font_path:
        parser.error("pass a monospace font using --font")
    fonts = {n: ImageFont.truetype(str(font_path), n) for n in (18, 20, 22, 26, 34, 48, 64)}
    doc = json.loads(args.transcript.read_text())
    if doc.get("version") != 2 or len(doc.get("cases", [])) != 4:
        parser.error("record a fresh version 2 transcript with demo-release-gate.py")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    assets = args.output.parent / (args.output.stem + "-render")
    assets.mkdir(exist_ok=True)
    timeline, chapters, elapsed = [], [dict(title="Introduction", start=0.0)], 0.0

    def speech(text):
        if not args.voice or not text:
            return b""
        key = hashlib.sha256((args.voice + text).encode()).hexdigest()[:16]
        aiff, wav = assets / (key + ".aiff"), assets / (key + ".wav")
        if not wav.exists():
            subprocess.run(["say", "-v", args.voice, "-r", "170", "-o", str(aiff), text], check=True)
            subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(aiff), "-ar", str(RATE),
                            "-ac", "1", "-c:a", "pcm_s16le", str(wav)], check=True)
        with wave.open(str(wav), "rb") as stream:
            return stream.readframes(stream.getnframes())

    def add(kind, title, lines=None, voice="", case=None, step=None, minimum=5):
        nonlocal elapsed
        audio = speech(voice)
        if step:
            typing = max(1.8, len(step["command"]) / 40)
            reveal = max(1.2, len(step["output"].splitlines()) * 0.45)
            audio_start = 0.6 + typing + 0.8 + reveal
            duration = audio_start + max(3.5, len(audio) / (RATE * 2) + 0.7)
        else:
            typing = reveal = audio_start = 0
            duration = max(minimum, len(audio) / (RATE * 2) + 1)
        duration = math.ceil(duration * FPS) / FPS
        timeline.append(dict(kind=kind, title=title, lines=lines, case=case, step=step,
                             duration=duration, start=elapsed, audio=audio,
                             typing=typing, reveal=reveal, audio_start=audio_start))
        elapsed += duration

    add("intro", "What is allowed to ship?", [
        "ONE RULE", "Publish only the candidate whose bytes and evidence pass the gate.", "",
        "HOW TO WATCH", "Each case: setup  >  command  >  output  >  meaning  >  end", "",
        "WHAT IS REAL", "Real archives, real shell commands and the production guard.", "",
        "WHAT IS SIMULATED", "GitHub and signature verification use explicit offline substitutes."
    ], "This demo shows a release publication guard. Each case starts in a fresh folder. We will inspect the inputs, type the real command, read the output, and explain the decision. The guard is real. GitHub and signature verification are offline substitutes.", minimum=12)
    for case in doc["cases"]:
        chapters.append(dict(title=f"Case {case['number']}: {case['title']}", start=elapsed))
        add("start", case["title"], ["AT HAND", case["setup"], "",
            "FRESH WORKSPACE", "dist/            candidate archive + supporting release files",
            "bundle.jsonl     synthetic attestation evidence",
            "release-publish.py   production publication guard", "",
            "stage/ and remote/ do not exist yet."], case["voice"], case=case, minimum=7)
        for step in case["steps"]:
            voice = step["voice"]
            if case["number"] > 1 and step["title"] in ("Freeze the candidate", "Confirm that nothing was uploaded"):
                voice = ""
            add("step", step["title"], voice=voice, case=case, step=step)
        add("end", "CASE COMPLETE", [case["verdict"], case["takeaway"], "",
            "Confirmed: " + ("uploaded archive matches the staged bytes." if case["verdict"] == "PUBLISH" else "no draft was created and no upload occurred."),
            "", "The next case starts with a fresh workspace." if case["number"] < 4 else "All four cases are complete."],
            "Case complete. " + case["takeaway"], case=case, minimum=6)
        add("cut", "", minimum=0.6)
    chapters.append(dict(title="Summary", start=elapsed))
    add("outro", "The same command. Four clear outcomes.", [
        "CASE 1    Unchanged archive + accepted evidence     PUBLISH",
        "CASE 2    Replaced archive                           BLOCK",
        "CASE 3    Missing attestation bundle                 BLOCK",
        "CASE 4    Rejected required verification             BLOCK", "",
        "The filenames and version labels alone are not enough.",
        "The guard checks the candidate bytes and the required evidence.", "",
        "Every displayed command was executed. Outputs are captured verbatim.",
        "No real GitHub release was published during this demo."
    ], "Only the unchanged candidate with accepted evidence reached publication. A replaced archive, missing evidence, or rejected check blocked it. The key is to verify the bytes and the required evidence before allowing the release.", minimum=10)

    def wrapped(draw, text, x, y, width, size=22, color=INK, spacing=31):
        lines = []
        for line in text.splitlines():
            lines.extend(textwrap.wrap(line, width, replace_whitespace=False, drop_whitespace=False) or [""])
        for line in lines:
            draw.text((x, y), line.rstrip(), font=fonts[size], fill=color)
            y += spacing
        return y

    def render(shot, local):
        im = Image.new("RGB", (WIDTH, HEIGHT), "#050a12" if shot["kind"] == "cut" else BG)
        d = ImageDraw.Draw(im)
        if shot["kind"] == "cut":
            return im
        case = shot["case"]
        tag = f"CASE {case['number']} / 4  ·  {case['title']}" if case else "RIO  /  RELEASE CONTROLS"
        d.text((46, 29), tag, font=fonts[26], fill=BLUE)
        d.text((46, 78), shot["title"], font=fonts[34], fill=INK)
        d.text((46, 957), "OFFLINE DEMO  |  Real guard and commands. Synthetic evidence and external services.", font=fonts[18], fill=MUTED)
        if shot["kind"] != "step":
            color = GREEN if case and case["verdict"] == "PUBLISH" else RED if shot["kind"] == "end" else BLUE
            if shot["kind"] in ("start", "end"):
                d.text((53, 172), "START OF CASE" if shot["kind"] == "start" else "END OF CASE", font=fonts[48], fill=color)
            y = 277 if case else 196
            for line in shot["lines"]:
                highlight = line in ("PUBLISH", "BLOCK", "AT HAND", "FRESH WORKSPACE", "ONE RULE", "HOW TO WATCH", "WHAT IS REAL", "WHAT IS SIMULATED")
                y = wrapped(d, line, 58, y, 90, 26 if highlight else 22,
                            color if highlight else INK, 39)
            return im
        step = shot["step"]
        typed_until = 0.6 + shot["typing"]
        output_start = typed_until + 0.8
        explain = local >= shot["audio_start"]
        state = "MEANING" if explain else "OUTPUT" if local >= output_start else "COMMAND"
        for i, phase in enumerate(("COMMAND", "OUTPUT", "MEANING")):
            d.rounded_rectangle((46 + i * 188, 140, 217 + i * 188, 181), radius=6,
                                fill="#214466" if phase == state else PANEL)
            d.text((62 + i * 188, 149), phase, font=fonts[18], fill=INK if phase == state else MUTED)
        d.rounded_rectangle((42, 210, 1121, 909), radius=14, fill=PANEL)
        d.text((66, 227), "bash  ·  fresh workspace: " + case["name"] + "/", font=fonts[18], fill=MUTED)
        d.line((43, 264, 1120, 264), fill="#29415e")
        d.text((66, 285), "COMMAND", font=fonts[18], fill=MUTED)
        command = step["command"]
        count = min(len(command), int(max(0, local - 0.6) / shot["typing"] * len(command)))
        displayed = "$ " + command[:count]
        if local < typed_until and int(local * 3) % 2 == 0:
            displayed += "▌"
        wrapped(d, displayed, 66, 323, 77, 22, BLUE, 29)
        # The full command always remains visible, separate from its output.
        d.line((64, 490, 1099, 490), fill="#29415e")
        d.text((66, 509), "OUTPUT", font=fonts[18], fill=MUTED)
        if local >= output_start:
            lines = step["output"].splitlines() or ["(no output)"]
            n = min(len(lines), 1 + int((local - output_start) / shot["reveal"] * len(lines)))
            y = 548
            for line in lines[:n]:
                color = RED if line.startswith(("BLOCKED:", "fixture service:", "ls:")) else GREEN if line.startswith(("STAGED:", "VERIFIED:", "PUBLISHED:")) else INK
                y = wrapped(d, line, 66, y, 77, 20, color, 27)
            if y > 840:
                raise ValueError("Output does not fit; split the recorded step: " + step["title"])
            if n == len(lines):
                d.text((66, max(y + 20, 820)), "exit code " + str(step["exitCode"]), font=fonts[20], fill=GREEN if step["exitCode"] == 0 else RED)
        d.rounded_rectangle((1147, 210, 1557, 909), radius=14, fill="#17273c")
        d.text((1172, 235), "WHAT IT MEANS", font=fonts[20], fill=GREEN if explain else MUTED)
        if explain:
            wrapped(d, step["explanation"], 1172, 292, 26, 22, INK, 33)
        else:
            wrapped(d, "Watch the command being typed." if state == "COMMAND" else "Read the output. The command remains above it.", 1172, 292, 26, 22, MUTED, 33)
        return im

    # Preflight final states before encoding, and retain every explanation frame.
    for index, shot in enumerate(timeline):
        render(shot, shot["duration"] - 1 / FPS).save(assets / f"{index:02d}-{shot['kind']}.png")
    silent = assets / "silent.mp4"
    encoder = subprocess.Popen(["ffmpeg", "-hide_banner", "-loglevel", "error", "-y", "-f", "rawvideo",
        "-pixel_format", "rgb24", "-video_size", f"{WIDTH}x{HEIGHT}", "-framerate", str(FPS), "-i", "-",
        "-an", "-c:v", "libx264", "-preset", "fast", "-crf", "22", "-pix_fmt", "yuv420p", str(silent)], stdin=subprocess.PIPE)
    audio_path = assets / "narration.wav"
    with wave.open(str(audio_path), "wb") as audio:
        audio.setnchannels(1)
        audio.setsampwidth(2)
        audio.setframerate(RATE)
        for index, shot in enumerate(timeline):
            print(f"Rendering {index + 1}/{len(timeline)}: {shot['title']}", flush=True)
            for f in range(round(shot["duration"] * FPS)):
                encoder.stdin.write(render(shot, f / FPS).tobytes())
            total = round(shot["duration"] * RATE) * 2
            lead = round(shot["audio_start"] * RATE) * 2
            samples = b"\0" * lead + shot["audio"]
            audio.writeframes(samples + b"\0" * max(0, total - len(samples)))
    encoder.stdin.close()
    if encoder.wait() != 0:
        raise RuntimeError("video encoder failed")
    metadata = [";FFMETADATA1"]
    for i, chapter in enumerate(chapters):
        end = chapters[i + 1]["start"] if i + 1 < len(chapters) else elapsed
        metadata.extend(["[CHAPTER]", "TIMEBASE=1/1000", "START=" + str(round(chapter["start"] * 1000)),
                         "END=" + str(round(end * 1000)), "title=" + chapter["title"]])
    chapter_file = assets / "chapters.ffmeta"
    chapter_file.write_text("\n".join(metadata) + "\n")
    subprocess.run(["ffmpeg", "-v", "error", "-y", "-i", str(silent), "-i", str(audio_path), "-i", str(chapter_file),
                    "-map", "0:v:0", "-map", "1:a:0", "-map_metadata", "2", "-map_chapters", "2", "-c:v", "copy",
                    "-c:a", "aac", "-b:a", "96k", "-movflags", "+faststart", str(args.output)], check=True)
    (assets / "timeline.json").write_text(json.dumps([{k: v for k, v in shot.items() if k != "audio"} for shot in timeline], indent=2) + "\n")
    print(f"{args.output} ({elapsed:.1f} seconds)")


if __name__ == "__main__":
    main()

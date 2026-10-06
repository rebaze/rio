#!/usr/bin/env python3
"""Generate the narration with the approved Google Gemini TTS voice.

The voice is a decision, not a detail: provider, model, voice name and the director
instructions are all fixed in `storyboard.py` and all four go into the cache key. A clip
is regenerated when its own text changes or when the direction changes, and not
otherwise, so a retake costs one clip rather than a whole pass.

The API key is read from 1Password at runtime, kept in memory, and passed as a header.
It is never an argument, never printed, and never written to the cache, the usage record
or an error message: HTTP failures are reported as status plus the API's own short error
code, with anything else discarded.

Python 3.9+, standard library only (ffmpeg is not required; PCM is wrapped as WAV here).

    python3 tools/feature-video/narrate.py --dry-run     # what would be generated
    python3 tools/feature-video/narrate.py               # generate missing clips
    python3 tools/feature-video/narrate.py --only step-07 --force
"""
import argparse
import base64
import hashlib
import io
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
import wave
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import storyboard  # noqa: E402

CREDENTIAL = "op://Employee/Gemini_TTS_gf/API_KEY"
ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/interactions"
MODELS_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models"
API_REVISION = "2026-05-20"

# Paid-tier rates read from PRICE_SOURCE on PRICE_CHECKED. Output dominates the bill by
# two orders of magnitude: the prompt is a few thousand characters, the speech is minutes.
# Audio is billed per token at a fixed 25 tokens per second, so measured clip duration is
# the cost, and a retake of one clip costs that clip's seconds.
PRICE_PER_MILLION_INPUT_TOKENS = 1.00
PRICE_PER_MILLION_AUDIO_TOKENS = 20.00
AUDIO_TOKENS_PER_SECOND = 25
PRICE_SOURCE = "https://ai.google.dev/gemini-api/docs/pricing"
PRICE_CHECKED = "2026-09-16"


def estimate_cost(input_tokens, audio_seconds):
    """Dollars, from the rates above. An estimate, never a billed amount."""
    audio_tokens = audio_seconds * AUDIO_TOKENS_PER_SECOND
    return (
        input_tokens / 1_000_000 * PRICE_PER_MILLION_INPUT_TOKENS
        + audio_tokens / 1_000_000 * PRICE_PER_MILLION_AUDIO_TOKENS
    )


def reported_tokens(payload):
    """Token counts the API reported, if it reported any. None means "it did not"."""
    if not isinstance(payload, dict):
        return None
    for field in ("usageMetadata", "usage_metadata", "usage"):
        usage = payload.get(field)
        if isinstance(usage, dict):
            for name in ("promptTokenCount", "prompt_tokens", "inputTokenCount", "input_tokens"):
                if isinstance(usage.get(name), int):
                    return usage[name]
    return None


class NarrationError(RuntimeError):
    """A failure safe to print: it never carries credential material."""


def spoken_form(text, rules=storyboard.PRONUNCIATION):
    """The bytes handed to the synthesizer. Subtitles keep the written prose."""
    for pattern, replacement in rules:
        text = re.sub(pattern, replacement, text)
    return text


def cache_key(text, provider=storyboard.VOICE_PROVIDER, model=storyboard.VOICE_MODEL,
              voice=storyboard.VOICE_NAME, direction=storyboard.VOICE_DIRECTION):
    """Identity of one clip. Every input that can change the audio is in here."""
    material = "\x00".join([provider, model, voice, direction, text])
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:20]


def parse_audio_mime(mime):
    """Read rate and channel count out of a MIME type, tolerantly.

    The tested response said `audio/l16; rate=24000; channels=1`, but the spelling of
    both the subtype and the parameters is not guaranteed, so nothing here is matched
    case-sensitively and every part has a documented default.
    """
    mime = (mime or "").strip().lower()
    rate = 24000
    channels = 1
    match = re.search(r"rate\s*=\s*(\d+)", mime)
    if match:
        rate = int(match.group(1))
    match = re.search(r"channels\s*=\s*(\d+)", mime)
    if match:
        channels = int(match.group(1))
    if rate <= 0 or channels <= 0:
        raise NarrationError("audio MIME reported a nonpositive rate or channel count")
    return rate, channels


def is_raw_pcm(mime):
    mime = (mime or "").strip().lower()
    return "l16" in mime or "pcm" in mime or "linear16" in mime


def wrap_pcm(data, rate=24000, channels=1):
    """Wrap raw signed 16-bit little-endian PCM as a WAV file."""
    if len(data) % (2 * channels):
        raise NarrationError("PCM payload is not a whole number of 16-bit frames")
    buffer = io.BytesIO()
    with wave.open(buffer, "wb") as out:
        out.setnchannels(channels)
        out.setsampwidth(2)
        out.setframerate(rate)
        out.writeframes(data)
    return buffer.getvalue()


def to_wav(data, mime):
    """Normalize whatever the API returned into WAV bytes."""
    if data[:4] == b"RIFF":
        return data
    if is_raw_pcm(mime):
        rate, channels = parse_audio_mime(mime)
        return wrap_pcm(data, rate, channels)
    raise NarrationError("unrecognized audio format %r" % (mime or "")[:60])


def audio_blocks(obj):
    """Yield (base64 data, mime) for every audio part in a response, at any depth."""
    if isinstance(obj, dict):
        if obj.get("type") == "audio" and isinstance(obj.get("data"), str):
            yield obj["data"], obj.get("mime_type") or obj.get("mimeType") or "audio/pcm"
        elif isinstance(obj.get("inlineData"), dict):
            inline = obj["inlineData"]
            if isinstance(inline.get("data"), str):
                yield inline["data"], inline.get("mimeType", "audio/pcm")
        elif isinstance(obj.get("inline_data"), dict):
            inline = obj["inline_data"]
            if isinstance(inline.get("data"), str):
                yield inline["data"], inline.get("mime_type", "audio/pcm")
        else:
            for value in obj.values():
                for found in audio_blocks(value):
                    yield found
    elif isinstance(obj, list):
        for value in obj:
            for found in audio_blocks(value):
                yield found


def decode_response(payload):
    """Turn a decoded JSON response into WAV bytes, or say why it could not."""
    found = list(audio_blocks(payload))
    if not found:
        raise NarrationError("response contained no audio block")
    mime = found[0][1]
    # Single-speaker, nonstreaming: normally one block, but concatenating is correct
    # for a split payload and identical for the usual one.
    data = b"".join(base64.b64decode(item[0]) for item in found)
    if not data:
        raise NarrationError("response audio block was empty")
    return to_wav(data, mime), mime


def wav_duration(data):
    with wave.open(io.BytesIO(data), "rb") as source:
        return source.getnframes() / float(source.getframerate())


def read_credential(reference=CREDENTIAL, timeout=60):
    """Read the API key from 1Password into memory. The value never leaves this process."""
    try:
        result = subprocess.run(
            ["op", "read", reference], capture_output=True, text=True, timeout=timeout
        )
    except FileNotFoundError:
        raise NarrationError("the 1Password CLI (op) is not installed") from None
    except subprocess.TimeoutExpired:
        raise NarrationError("reading the 1Password credential timed out") from None
    if result.returncode or not result.stdout.strip():
        hint = (result.stderr or "").strip().splitlines()
        detail = hint[-1] if hint else "no output"
        if "not signed in" in detail:
            detail = "account is not signed in; run `op signin` first"
        raise NarrationError("could not read %s: %s" % (reference, detail))
    return result.stdout.strip()


def _request(url, key, body=None, timeout=180):
    headers = {"Content-Type": "application/json", "x-goog-api-key": key}
    if "/interactions" in url:
        headers["Api-Revision"] = API_REVISION
    request = urllib.request.Request(
        url,
        data=None if body is None else json.dumps(body).encode(),
        headers=headers,
        method="GET" if body is None else "POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.read()
    except urllib.error.HTTPError as error:
        code = ""
        try:
            detail = json.loads(error.read()).get("error", {})
            code = str(detail.get("status") or detail.get("code") or "")
            if not re.fullmatch(r"[A-Za-z0-9_.-]{0,80}", code):
                code = ""
        except Exception:
            pass
        raise NarrationError(("HTTP %s %s" % (error.code, code)).strip()) from None
    except Exception as error:
        raise NarrationError("request failed: %s" % type(error).__name__) from None


def check_model(key, model=storyboard.VOICE_MODEL):
    """Refuse to silently fall back to a different voice or model."""
    payload = json.loads(_request(MODELS_ENDPOINT, key, timeout=60))
    names = [m.get("name", "").split("/")[-1] for m in payload.get("models", [])]
    if model not in names:
        available = ", ".join(n for n in names if "tts" in n) or "none"
        raise NarrationError(
            "the approved model %s is not available on this key "
            "(accessible TTS models: %s). The voice is a recorded decision; "
            "do not substitute another model." % (model, available)
        )


def synthesize(key, text, model=storyboard.VOICE_MODEL, voice=storyboard.VOICE_NAME,
               direction=storyboard.VOICE_DIRECTION, timeout=180):
    """One clip. Returns (wav bytes, mime, prompt characters, reported input tokens)."""
    prompt = (
        "Synthesize speech.\nDirector instructions: "
        + direction
        + "\n\nSpoken transcript begins:\n"
        + text
    )
    body = {
        "model": model,
        "input": prompt,
        "response_format": {"type": "audio"},
        "generation_config": {"speech_config": [{"voice": voice}]},
    }
    raw = _request(ENDPOINT, key, body, timeout=timeout)
    try:
        payload = json.loads(raw)
    except ValueError:
        raise NarrationError("response was not JSON") from None
    wav, mime = decode_response(payload)
    return wav, mime, len(prompt), reported_tokens(payload)


class Cache:
    """Clips on disk, addressed by everything that determines how they sound."""

    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def path(self, key):
        return self.directory / (key + ".wav")

    def meta_path(self, key):
        return self.directory / (key + ".json")

    def has(self, key):
        return self.path(key).exists() and self.meta_path(key).exists()

    def read(self, key):
        return self.path(key).read_bytes()

    def write(self, key, wav, meta):
        # The audio lands first: a clip is only claimed as cached once it is readable.
        self.path(key).write_bytes(wav)
        self.meta_path(key).write_text(json.dumps(meta, indent=2, sort_keys=True) + "\n")


def plan_clips(clips, cache, only=None, force=False):
    """Decide per clip whether it is reused or generated. No network, no credential."""
    planned = []
    for name, text in clips:
        spoken = spoken_form(text)
        key = cache_key(spoken)
        selected = only is None or name in only
        cached = cache.has(key)
        planned.append(
            dict(
                clip=name,
                key=key,
                text=text,
                spoken=spoken,
                characters=len(spoken),
                cached=cached,
                generate=selected and (force or not cached),
            )
        )
    return planned


def narrate(clips, cache, only=None, force=False, key_reader=read_credential, log=print):
    """Generate what is missing, reuse what is not, and report what it cost.

    Returns (clips, usage). `clips` is None when `--only` deliberately left part of the
    narration ungenerated: that is a partial pass, not a failure, and the caller declines
    to write a narration manifest that would claim to describe a complete soundtrack.
    """
    planned = plan_clips(clips, cache, only=only, force=force)
    todo = [item for item in planned if item["generate"]]
    requests = 0
    characters = 0
    reported = 0
    estimated_tokens = 0
    generated_seconds = 0.0
    if todo:
        api_key = key_reader()
        try:
            check_model(api_key)
            for item in todo:
                log("generating %s (%d characters)" % (item["clip"], item["characters"]))
                wav, mime, billed, tokens = synthesize(api_key, item["spoken"])
                requests += 1
                characters += billed
                generated_seconds += wav_duration(wav)
                if tokens is None:
                    # No usage reported: about four characters per token is the
                    # standard rule of thumb, and it is labelled as such below.
                    estimated_tokens += billed / 4.0
                else:
                    reported += tokens
                cache.write(
                    item["key"],
                    wav,
                    {
                        "clip": item["clip"],
                        "provider": storyboard.VOICE_PROVIDER,
                        "model": storyboard.VOICE_MODEL,
                        "voice": storyboard.VOICE_NAME,
                        "mime": mime,
                        "characters": billed,
                        "inputTokensReported": tokens,
                        "seconds": round(wav_duration(wav), 3),
                        "text": item["text"],
                        "spoken": item["spoken"],
                    },
                )
        finally:
            del api_key
    else:
        log("every clip was already cached; nothing was generated")
    missing = [i["clip"] for i in planned if not cache.has(i["key"])]
    result = []
    for item in planned:
        if not cache.has(item["key"]):
            continue
        wav = cache.read(item["key"])
        try:
            metadata = json.loads(cache.meta_path(item["key"]).read_text())
        except (OSError, ValueError) as error:
            raise NarrationError("%s cache metadata is unreadable: %s" % (item["clip"], error)) from error
        approved = dict(provider=storyboard.VOICE_PROVIDER, model=storyboard.VOICE_MODEL,
                        voice=storyboard.VOICE_NAME)
        # The cache is addressed by content and voice settings; its original
        # scene label may differ when a line is moved or reused.
        expected = dict(approved, text=item["text"], spoken=item["spoken"])
        if not isinstance(metadata, dict) or any(metadata.get(k) != v for k, v in expected.items()):
            raise NarrationError("%s cache metadata does not match the approved voice and script"
                             % item["clip"])
        result.append(dict(item, **approved, seconds=wav_duration(wav),
                           path=str(cache.path(item["key"]))))
    input_tokens = reported + estimated_tokens
    if missing:
        log("%d clip(s) still have no audio: %s" % (len(missing), ", ".join(missing)))
        result = None
    usage = {
        "provider": storyboard.VOICE_PROVIDER,
        "model": storyboard.VOICE_MODEL,
        "voice": storyboard.VOICE_NAME,
        "requestsThisRun": requests,
        "clipsTotal": len(planned),
        "clipsReused": len([i for i in planned if i["cached"] and not i["generate"]]),
        "inputCharactersThisRun": characters,
        "inputTokensReportedByApi": reported,
        "inputTokensEstimatedFromCharacters": round(estimated_tokens, 1),
        "audioSecondsGeneratedThisRun": round(generated_seconds, 2),
        "audioSecondsTotal": round(sum(item["seconds"] for item in result), 2) if result else None,
        "estimatedUsdThisRun": round(estimate_cost(input_tokens, generated_seconds), 4),
        "estimatedUsdFullPass": round(
            estimate_cost(
                sum(i["characters"] for i in planned) / 4.0,
                sum(item["seconds"] for item in result),
            ),
            4,
        ) if result else None,
        "rates": {
            "inputPerMillionTextTokens": PRICE_PER_MILLION_INPUT_TOKENS,
            "outputPerMillionAudioTokens": PRICE_PER_MILLION_AUDIO_TOKENS,
            "audioTokensPerSecond": AUDIO_TOKENS_PER_SECOND,
            "source": PRICE_SOURCE,
            "checked": PRICE_CHECKED,
        },
        "note": (
            "Estimated from the published paid-tier rates above and measured audio "
            "duration. Not a billed amount; confirm against the Google Cloud console."
        ),
    }
    return result, usage


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--out", type=Path, default=None, help="output directory")
    parser.add_argument("--cache", type=Path, default=None, help="clip cache directory")
    parser.add_argument("--only", action="append", default=None, help="clip name; repeatable")
    parser.add_argument("--force", action="store_true", help="regenerate even when cached")
    parser.add_argument("--dry-run", action="store_true", help="report the plan, call nothing")
    args = parser.parse_args(argv)

    root = Path(os.environ.get("RIO_VIDEO_ROOT", HERE.parents[1]))
    out = (args.out or root / "target" / "feature-video").resolve()
    cache = Cache(args.cache or out / "narration-cache")
    out.mkdir(parents=True, exist_ok=True)
    clips = storyboard.narration_clips()

    if args.dry_run:
        planned = plan_clips(clips, cache, only=args.only, force=args.force)
        fresh = [i for i in planned if i["generate"]]
        chars = sum(i["characters"] for i in fresh)
        for item in planned:
            print("%-10s %s %5d chars  %s" % (
                item["clip"], item["key"], item["characters"],
                "GENERATE" if item["generate"] else ("cached" if item["cached"] else "MISSING"),
            ))
        # Without the audio there is no measured duration, so the speaking rate the
        # direction asks for (about 150 words per minute) is what a forecast can use.
        words = sum(len(i["text"].split()) for i in fresh)
        seconds = words / 150.0 * 60.0
        print("\n%d of %d clips would be generated: %d characters, about %.0f s of speech "
              "at the directed 150 wpm, roughly $%.3f"
              % (len(fresh), len(planned), chars, seconds,
                 estimate_cost(chars / 4.0, seconds)))
        return 0

    result, usage = narrate(clips, cache, only=args.only, force=args.force)
    (out / "usage.json").write_text(json.dumps(usage, indent=2) + "\n")
    if result is None:
        print("partial pass: %d request(s), %d characters. narration.json was not written; "
              "run without --only to complete the narration."
              % (usage["requestsThisRun"], usage["inputCharactersThisRun"]))
        return 0
    (out / "narration.json").write_text(
        json.dumps(
            [{k: v for k, v in item.items() if k != "generate"} for item in result],
            indent=2,
        )
        + "\n"
    )
    total = sum(item["seconds"] for item in result)
    print("%d clips, %.1f s of speech, %d request(s) this run, %d characters, about $%.3f"
          % (len(result), total, usage["requestsThisRun"],
             usage["inputCharactersThisRun"], usage["estimatedUsdThisRun"]))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except NarrationError as error:
        print("narration failed: %s" % error, file=sys.stderr)
        sys.exit(1)

"""Render the launch-film voiceover with Gnani Timbre TTS (api.vachana.ai).

    set GNANI_API_KEY=...                 (or)   --key-file path/to/gnani.env
    python docs/demo/make_voiceover.py --out demo_media/voiceover

Writes one WAV per line plus `voiceover_full.wav`, with each clip placed at its storyboard timestamp
(docs/demo/voiceover_lines.json), and `timing.json`, which reports any line that runs into the next one.
The key is sent only as the X-API-Key-ID header; it is never printed or written to disk. demo_media/ is git-ignored.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import time
import wave
from pathlib import Path

import requests

TTS_URL = "https://api.vachana.ai/api/v1/tts/inference"
HERE = Path(__file__).resolve().parent


def load_key(key_file: str | None) -> str:
    key = os.environ.get("GNANI_API_KEY", "").strip()
    if not key and key_file:
        for line in Path(key_file).read_text(encoding="utf-8-sig").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, eq, value = line.partition("=")
            key = (value if eq and name.strip().removeprefix("export ").strip() == "GNANI_API_KEY"
                   else "" if eq else line).strip().strip("'\"")
            if key:
                break
    if not key:
        sys.exit("No Gnani key: set GNANI_API_KEY or pass --key-file")
    return key


def synth(session: requests.Session, key: str, text: str, cfg: dict) -> bytes:
    rate = cfg["sample_rate"]
    body = {"text": text, "voice": cfg["voice"], "model": cfg["model"], "language": cfg["language"],
            "speed": cfg.get("speed", 1.0),
            "audio_config": {"sample_rate": rate, "num_channels": 1, "sample_width": 2,
                             "encoding": "linear_pcm", "container": "wav"}}
    for attempt in range(5):
        r = session.post(TTS_URL, headers={"X-API-Key-ID": key, "Content-Type": "application/json"}, json=body, timeout=120)
        if r.status_code != 429:
            break
        time.sleep(min(int(r.headers.get("Retry-After") or 0) or 15 * (attempt + 1), 120))
    if r.status_code >= 400:
        sys.exit(f"Timbre error {r.status_code}: {r.text[:200]}")
    data = r.content
    pcm = data[data.find(b"data") + 8:]  # Timbre streams its WAV: header length fields are placeholders
    return pcm[: len(pcm) // 2 * 2]


def to_wav(pcm: bytes, rate: int) -> bytes:
    buf = io.BytesIO()
    with wave.open(buf, "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(pcm)
    return buf.getvalue()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lines", default=str(HERE / "voiceover_lines.json"))
    ap.add_argument("--out", default="demo_media/voiceover")
    ap.add_argument("--key-file", default=None)
    ap.add_argument("--voice", default=None, help="override the voice in the lines file")
    ap.add_argument("--only", nargs="*", default=None, help="render only these line ids")
    ap.add_argument("--total-seconds", type=float, default=117.0)
    ap.add_argument("--reuse", action="store_true", help="reuse clips already in --out (no new TTS requests)")
    a = ap.parse_args()
    cfg = json.loads(Path(a.lines).read_text(encoding="utf-8"))
    if a.voice:
        cfg["voice"] = a.voice
    key = None if a.reuse else load_key(a.key_file)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    rate = cfg["sample_rate"]
    s = requests.Session()
    lines = [l for l in cfg["lines"] if not a.only or l["id"] in a.only]
    clips, timing = {}, []
    for i, line in enumerate(lines):
        clip = out / f"{line['id']}.wav"
        if a.reuse:
            with wave.open(str(clip)) as w:
                pcm = w.readframes(w.getnframes())
        else:
            pcm = synth(s, key, line["text"], cfg)
            clip.write_bytes(to_wav(pcm, rate))
        clips[line["id"]] = pcm
        dur = len(pcm) / 2 / rate
        nxt = lines[i + 1]["start"] if i + 1 < len(lines) else a.total_seconds
        slack = round(nxt - line["start"] - dur, 2)
        timing.append({"id": line["id"], "start": line["start"], "seconds": round(dur, 2), "slack_to_next": slack})
        print(f"{line['id']:13s} {dur:5.2f}s  start {line['start']:6.2f}  slack {slack:+.2f}{'  <-- overlaps next' if slack < 0 else ''}")
    if not a.only:
        total = bytearray(int(a.total_seconds * rate) * 2)
        for line in lines:
            off = int(line["start"] * rate) * 2
            pcm = clips[line["id"]]
            total[off: off + len(pcm)] = pcm[: max(0, len(total) - off)]
        (out / "voiceover_full.wav").write_bytes(to_wav(bytes(total), rate))
    (out / "timing.json").write_text(json.dumps({"voice": cfg["voice"], "model": cfg["model"], "lines": timing}, indent=2),
                                     encoding="utf-8")
    print(f"wrote {len(lines)} clips -> {out}")


if __name__ == "__main__":
    main()

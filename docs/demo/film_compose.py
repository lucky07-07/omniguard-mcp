"""Compose the launch film from the captured shots, the Gnani voiceover and a synthesized sound bed.

    python docs/demo/film_compose.py [--film demo_media/film] [--vo demo_media/voiceover/voiceover_full.wav]
                                     [--out demo_media/omniguard_launch_film.mp4]

Timeline = docs/demo/LAUNCH_SCRIPT.md (1:57). Each beat is a real screenshot with an eased push-in between two
focus rectangles (taken from the live page's element positions), 0.35 s crossfades, and the storyboard's kinetic
captions. Audio = voiceover + ambient pulse (ducked under the voice) + key clicks, a verdict thunk and section
whooshes, mixed and loudness-normalised by ffmpeg. Needs ffmpeg on PATH, numpy and Pillow.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import wave
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont

FPS, OW, OH = 30, 1920, 1080
TOTAL = 117.0
XFADE = 0.35
SR = 48000

# (start, end, shot, from_focus, to_focus, caption) - focus = key in shots.json entry, or explicit [x0,y0,x1,y1]
BEATS = [
    (2.3, 3.0, "denied_b64", "focus", "focus", None),
    (3.0, 8.0, "denied_b64", "focus", "why", None),
    (8.0, 12.0, "card_diagram", [0.04, 0.04, 0.96, 0.96], [0.12, 0.2, 0.88, 0.8], None),
    (12.0, 19.0, "denied_b64", "steps", "card", None),
    (19.0, 21.0, "card_inspect", [0.0, 0.0, 1.0, 1.0], [0.06, 0.06, 0.94, 0.94], None),
    (21.0, 28.0, "card_decode", [0.02, 0.1, 0.98, 0.9], [0.48, 0.18, 0.98, 0.72], "decoded before it's read"),
    (28.0, 32.0, "exfil_toast", "focus", "toast", None),
    (32.0, 36.0, "redacted_raw", "focus", "focus", "masked, not hidden"),
    (36.0, 41.0, "exfil_denied", "focus", "why", None),
    (41.0, 43.0, "card_prove", [0.0, 0.0, 1.0, 1.0], [0.06, 0.06, 0.94, 0.94], None),
    (43.0, 48.0, "lab_explain", "focus", "focus", "R1 · R2 · R3"),
    (48.0, 55.0, "lab_clean", "focus", "focus", "one root, on-chain, every 4 records"),
    (55.0, 59.0, "lab_attack", "focus", "focus", "act as root"),
    (59.0, 61.0, "lab_sweeping", "focus", "focus", None),
    (61.0, 67.0, "lab_caught", "focus", "r3", "clean · clean · caught"),
    (67.0, 70.0, "lab_anchors", "focus", "focus", None),
    (70.0, 72.0, "card_measure", [0.0, 0.0, 1.0, 1.0], [0.06, 0.06, 0.94, 0.94], None),
    (72.0, 78.0, "bench_compare", "focus", "focus", "held-out data · thresholds frozen first"),
    (78.0, 86.0, "bench_compare", "focus", "row_pi", "F1  0.30  to  0.84"),
    (86.0, 91.0, "card_pinned", [0.02, 0.1, 0.98, 0.9], [0.05, 0.25, 0.85, 0.75], None),
    (91.0, 94.0, "bench_tamper", "focus", "focus", "40 / 40 tamper trials"),
    (94.0, 98.0, "bench_latency", "focus", "focus", "0.64 ms · no model on the fast path"),
    (98.0, 104.0, "card_misses", [0.0, 0.0, 1.0, 1.0], [0.04, 0.12, 0.84, 0.88], None),
    (104.0, 110.0, "hero", [0.0, 0.0, 1.0, 1.0], "focus", None),
    (110.0, TOTAL, "card_end", [0.03, 0.03, 0.97, 0.97], [0.08, 0.08, 0.92, 0.92], None),
]
TYPE_END = 2.3  # 0.0-2.3 s: the typing sequence (type_01..type_14)


def ease(t: float) -> float:
    return t * t * (3 - 2 * t)


def fit_169(r: list[float], min_w: float = 0.32) -> list[float]:
    """Expand a focus rect to 16:9 (on a 16:9 page), keep it inside the page."""
    x0, y0, x1, y1 = r
    cx, cy = (x0 + x1) / 2, (y0 + y1) / 2
    w = max(x1 - x0, (y1 - y0), min_w)  # page is 16:9, so equal normalised w/h keeps 16:9
    w = min(w, 1.0)
    h = w
    x0 = min(max(cx - w / 2, 0), 1 - w)
    y0 = min(max(cy - h / 2, 0), 1 - h)
    return [x0, y0, x0 + w, y0 + h]


class Shots:
    def __init__(self, film: Path):
        self.dir = film / "shots"
        self.meta = json.loads((film / "shots.json").read_text(encoding="utf-8"))
        self.cache: dict[str, Image.Image] = {}

    def img(self, name: str) -> Image.Image:
        if name not in self.cache:
            if len(self.cache) > 6:
                self.cache.pop(next(iter(self.cache)))
            self.cache[name] = Image.open(self.dir / f"{name}.png").convert("RGB")
        return self.cache[name]

    def rect(self, name: str, key) -> list[float]:
        return list(key) if isinstance(key, list) else self.meta[name][key]

    def frame(self, name: str, r: list[float]) -> Image.Image:
        im = self.img(name)
        W, H = im.size
        box = (r[0] * W, r[1] * H, r[2] * W, r[3] * H)
        return im.resize((OW, OH), Image.BILINEAR, box=box, reducing_gap=2.0)


def font(names: list[str], size: int):
    for n in names:
        for d in (Path("C:/Windows/Fonts"), Path("/usr/share/fonts/truetype/dejavu")):
            p = d / n
            if p.exists():
                return ImageFont.truetype(str(p), size)
    return ImageFont.load_default()


CAP_FONT = font(["georgia.ttf", "DejaVuSerif.ttf"], 46)


def caption(img: Image.Image, text: str, alpha: float) -> Image.Image:
    if alpha <= 0:
        return img
    layer = Image.new("RGBA", img.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(layer)
    tw = d.textlength(text, font=CAP_FONT)
    x, y = 96, OH - 150
    a = int(255 * alpha)
    d.rounded_rectangle((x - 28, y - 18, x + tw + 28, y + 64), radius=18, fill=(29, 27, 24, int(232 * alpha)))
    d.text((x, y), text, font=CAP_FONT, fill=(246, 241, 231, a))
    return Image.alpha_composite(img.convert("RGBA"), layer).convert("RGB")


def render_beat_frame(shots: Shots, beat, t: float) -> Image.Image:
    s, e, name, f0, f1, cap = beat
    p = ease(min(max((t - s) / (e - s), 0), 1))
    r0, r1 = fit_169(shots.rect(name, f0)), fit_169(shots.rect(name, f1))
    r = [a + (b - a) * p for a, b in zip(r0, r1)]
    img = shots.frame(name, r)
    if cap:
        fade = min(1.0, (t - s - 0.4) / 0.35, (e - t - 0.2) / 0.3)
        img = caption(img, cap, max(0.0, fade))
    return img


def frame_at(shots: Shots, t: float) -> Image.Image:
    if t < TYPE_END:
        i = min(14, 1 + int(t / TYPE_END * 14))
        name = f"type_{i:02d}"
        r = fit_169(shots.rect(name, "focus"), 0.5)
        return shots.frame(name, r)
    idx = next(i for i, b in enumerate(BEATS) if b[0] <= t < b[1] or i == len(BEATS) - 1)
    img = render_beat_frame(shots, BEATS[idx], t)
    if idx + 1 < len(BEATS) and t > BEATS[idx][1] - XFADE and BEATS[idx + 1][2] != BEATS[idx][2]:
        a = (t - (BEATS[idx][1] - XFADE)) / XFADE
        nxt = render_beat_frame(shots, BEATS[idx + 1], BEATS[idx + 1][0])
        img = Image.blend(img, nxt, ease(a))
    return img


# ---------------------------------------------------------------------------------------------- audio
def read_wav(path: Path) -> tuple[np.ndarray, int]:
    with wave.open(str(path)) as w:
        sr, n = w.getframerate(), w.getnframes()
        x = np.frombuffer(w.readframes(n), dtype=np.int16).astype(np.float32) / 32768
    return x, sr


def resample(x: np.ndarray, sr: int, to: int) -> np.ndarray:
    n = int(len(x) * to / sr)
    return np.interp(np.linspace(0, len(x) - 1, n), np.arange(len(x)), x).astype(np.float32)


def lowpass(x: np.ndarray, k: int) -> np.ndarray:
    return np.convolve(x, np.ones(k) / k, mode="same").astype(np.float32)


def build_audio(vo_path: Path, out: Path) -> None:
    rng = np.random.default_rng(7)
    n = int(TOTAL * SR)
    t = np.arange(n) / SR
    vo, sr = read_wav(vo_path)
    vo = resample(vo, sr, SR)[:n]
    vo = np.pad(vo, (0, n - len(vo)))
    # ambient pulse: soft A/E dyad, 72 BPM swell, slow fades; ducked under the voice
    beat = 60 / 72
    env = 0.55 + 0.45 * np.exp(-((t % beat) / 0.35))
    bed = (0.5 * np.sin(2 * np.pi * 110 * t) + 0.32 * np.sin(2 * np.pi * 164.8 * t) + 0.18 * np.sin(2 * np.pi * 220.4 * t)) * env
    bed *= np.clip(t / 3.0, 0, 1) * np.clip((TOTAL - t) / 5.0, 0, 1) * (t >= 3.0)
    voice_env = lowpass(np.abs(vo), 4800) * 6
    bed *= (0.10 - 0.06 * np.clip(voice_env, 0, 1))
    fx = np.zeros(n, dtype=np.float32)

    def place(sig: np.ndarray, at: float, gain: float) -> None:
        i = int(at * SR)
        j = min(n, i + len(sig))
        fx[i:j] += gain * sig[: j - i]

    def click() -> np.ndarray:
        k = int(0.018 * SR)
        s = rng.standard_normal(k).astype(np.float32) * np.exp(-np.arange(k) / (0.003 * SR))
        return s - lowpass(s, 8)

    def thunk() -> np.ndarray:
        k = int(0.45 * SR)
        tt = np.arange(k) / SR
        return (np.sin(2 * np.pi * (85 - 30 * tt) * tt) * np.exp(-tt / 0.12)).astype(np.float32)

    def whoosh(dur: float = 0.55) -> np.ndarray:
        k = int(dur * SR)
        s = rng.standard_normal(k).astype(np.float32)
        s = lowpass(s, 24) - lowpass(s, 240)
        w = np.sin(np.linspace(0, np.pi, k)) ** 2
        return s * w * 3

    for i in range(14):
        place(click(), 0.08 + i * (TYPE_END - 0.25) / 14, 0.55)
    place(thunk(), TYPE_END, 0.9)
    for at in (8.0, 19.0, 41.0, 70.0, 104.0):
        place(whoosh(), at - 0.25, 0.22)
    for at in (28.15, 55.6, 59.0):  # UI clicks: scenario, attack, sweep
        place(click(), at, 0.5)
    place(whoosh(0.8), 59.1, 0.18)
    for i in range(8):  # tamper heatmap rows
        place(click() * 0.6, 91.2 + i * 0.25, 0.35)
    mix = vo * 0.95 + bed + fx
    mix /= max(1.0, float(np.max(np.abs(mix))) / 0.95)
    with wave.open(str(out), "wb") as w:
        w.setnchannels(1)
        w.setsampwidth(2)
        w.setframerate(SR)
        w.writeframes((mix * 32767).astype(np.int16).tobytes())


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--film", default="demo_media/film")
    ap.add_argument("--vo", default="demo_media/voiceover/voiceover_full.wav")
    ap.add_argument("--out", default="demo_media/omniguard_launch_film.mp4")
    ap.add_argument("--preview", type=float, default=0, help="render only the first N seconds")
    a = ap.parse_args()
    ffmpeg = shutil.which("ffmpeg")
    if not ffmpeg:
        raise SystemExit("ffmpeg not found on PATH")
    film = Path(a.film)
    shots = Shots(film)
    audio = film / "mix.wav"
    build_audio(Path(a.vo), audio)
    dur = a.preview or TOTAL
    cmd = [ffmpeg, "-y", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{OW}x{OH}", "-r", str(FPS), "-i", "-",
           "-i", str(audio), "-map", "0:v", "-map", "1:a", "-c:v", "libx264", "-preset", "medium", "-crf", "18",
           "-pix_fmt", "yuv420p", "-af", "loudnorm=I=-16:TP=-1.5:LRA=11", "-c:a", "aac", "-b:a", "192k",
           "-t", f"{dur:.2f}", "-movflags", "+faststart", a.out]
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stderr=subprocess.DEVNULL)
    frames = int(dur * FPS)
    for k in range(frames):
        proc.stdin.write(frame_at(shots, k / FPS).tobytes())
        if k % 300 == 0:
            print(f"frame {k}/{frames}", flush=True)
    proc.stdin.close()
    proc.wait()
    print("wrote", a.out, "rc", proc.returncode)


if __name__ == "__main__":
    main()

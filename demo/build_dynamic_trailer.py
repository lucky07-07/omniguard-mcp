"""Build the OmniGuard-MCP dynamic trailer: 1920x1080, 60 fps, about 80 s, five acts, no static slides.

    python demo/build_dynamic_trailer.py --key-file ../Project/gnani.env
        [--site https://omniguard-mcp.vercel.app] [--api https://omniguard-mcp-api.onrender.com]
        [--work demo_media/trailer] [--skip-live] [--skip-tts]

Pipeline
  1. Narration: one Gnani Timbre clip per act (voice Avinash, en-IN); durations measured with ffprobe. Each act is
     stretched to fit its narration, so no line is ever cut.
  2. Motion cards: dark HTML/CSS/SVG pages driven only by CSS @keyframes. They are rendered frame by frame at 60 fps
     by pausing every animation (Web Animations API) at t = i/60 and screenshotting, so motion is exact, not sampled.
  3. Live recordings: Playwright records the deployed dashboard (Vercel UI + Render API) while a scripted cursor
     glides between targets (mouse.move steps=35) and types (keyboard.type delay=30 ms). Marks taken during the run
     cut the recording into shots; act 2 gets a slow zoompan push-in.
  4. Edit: every shot is conformed to 1920x1080@60, then chained with 0.4 s xfade transitions.
  5. Audio: narration + synthesized SFX (whooshes on transitions, low hits on blocks) + a synth pulse bed at -22 dB,
     mastered with two-pass loudnorm to -16 LUFS.
Outputs docs/OmniGuard-MCP_Trailer.mp4 and a copy at --copy-to.
The Gnani key is read from the env file and sent only in the X-API-Key-ID header; it is never printed or stored.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "docs" / "demo"))
FF = Path("C:/Users/anilk/AppData/Local/Microsoft/WinGet/Packages/Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe/ffmpeg-8.1.1-full_build/bin")
FFMPEG = str(FF / "ffmpeg.exe") if (FF / "ffmpeg.exe").exists() else "ffmpeg"
FFPROBE = str(FF / "ffprobe.exe") if (FF / "ffprobe.exe").exists() else "ffprobe"
W, H, FPS, XF = 1920, 1080, 60, 0.4
TARGET = [12.0, 18.0, 20.0, 15.0, 15.0]  # act lengths on the timeline (0-12, 12-30, 30-50, 50-65, 65-80)

NARRATION = [
    "AI agents now execute real tools. One poisoned schema, one leaked secret, or one silent database edit "
    "compromises the entire chain.",
    "OmniGuard sits between the agent and every tool. A SQL injection is stopped at ingress. And when a server "
    "swaps a tool's description mid-session, its SHA-256 pin no longer matches, so the call is blocked as a rug pull.",
    "Secrets a tool returns are masked before the agent sees them, and the session is marked sensitive, so the next "
    "attempt to send data out is denied. When an insider rewrites the log and recomputes the hash chain, "
    "the on-chain root no longer matches.",
    "Every decision is hashed, chained and sealed into a Merkle batch, and the batch root is anchored on chain. "
    "In our tamper trials, every edit to an anchored record was detected.",
    "On one hundred real cases from MCPTox, AgentDojo and MSB, tool poisoning and attack chains were stopped "
    "every time, at under two milliseconds of median overhead. OmniGuard MCP. Tamper-evident trust for agentic AI.",
]


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode:
        sys.exit(f"command failed: {' '.join(cmd[:6])} ...\n{r.stderr[-1500:]}")
    return r


def dur(path: Path) -> float:
    return float(run([FFPROBE, "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(path)]).stdout)


# =============================================================================== narration
def narration(work: Path, key_file: str | None, skip: bool) -> list[float]:
    out = work / "vo"
    out.mkdir(parents=True, exist_ok=True)
    if not skip:
        import requests
        from make_voiceover import load_key, synth, to_wav

        key = load_key(key_file)
        cfg = {"voice": "Avinash", "model": "timbre-v3.0", "language": "en-IN", "sample_rate": 24000, "speed": 1.0}
        with requests.Session() as s:
            for i, text in enumerate(NARRATION):
                p = out / f"act{i + 1}.wav"
                if p.exists() and (out / f"act{i + 1}.txt").read_text(encoding="utf-8") == text:
                    continue
                p.write_bytes(to_wav(synth(s, key, text, cfg), cfg["sample_rate"]))
                (out / f"act{i + 1}.txt").write_text(text, encoding="utf-8")
                print("tts", p.name, flush=True)
    return [round(dur(out / f"act{i + 1}.wav"), 3) for i in range(5)]


# =============================================================================== motion cards
CARD_HEAD = """<!doctype html><html><head><meta charset="utf-8">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
 :root{--bg:#07090d;--ink:#eef2f6;--mut:#8792a2;--line:#1d2530;--teal:#2ec4a6;--red:#ff5d5d;--amber:#f2b134;--blue:#6aa8ff}
 *{box-sizing:border-box} html,body{margin:0;width:1920px;height:1080px;overflow:hidden;background:var(--bg);color:var(--ink);font-family:Inter,sans-serif}
 .mono{font-family:'JetBrains Mono',monospace}
 .grid{position:absolute;inset:-200px;background-image:linear-gradient(var(--line) 1px,transparent 1px),linear-gradient(90deg,var(--line) 1px,transparent 1px);
   background-size:64px 64px;opacity:.35;animation:drift 30s linear both}
 @keyframes drift{to{transform:translate(64px,64px)}}
 .glow{position:absolute;width:1100px;height:1100px;border-radius:50%;filter:blur(120px);opacity:.22}
 @keyframes up{from{opacity:0;transform:translateY(46px);filter:blur(10px)}to{opacity:1;transform:none;filter:blur(0)}}
 @keyframes fade{from{opacity:0}to{opacity:1}}
 @keyframes out{to{opacity:0;transform:translateY(-30px);filter:blur(8px)}}
 @keyframes pop{0%{opacity:0;transform:scale(.6)}70%{opacity:1;transform:scale(1.06)}100%{opacity:1;transform:scale(1)}}
 @keyframes draw{to{stroke-dashoffset:0}}
 @keyframes wipe{from{clip-path:inset(0 100% 0 0)}to{clip-path:inset(0 0 0 0)}}
 .a{animation:up .9s cubic-bezier(.2,.8,.2,1) both}
</style></head><body>"""


def card_act1(d: float) -> str:
    words = [("AI agents now execute", ""), ("real tools.", "teal")]
    lines = [("One poisoned schema,", "red", 3.2), ("one leaked secret,", "amber", 4.4),
             ("or one silent database edit", "blue", 5.6)]
    end = d - 1.2
    return CARD_HEAD + f"""
<div class="grid"></div><div class="glow" style="background:#2ec4a6;left:-300px;top:-400px"></div>
<div class="glow" style="background:#ff5d5d;right:-420px;bottom:-520px;animation:fade 2s 6s both"></div>
<div style="position:absolute;left:160px;top:150px;font:600 22px 'JetBrains Mono';letter-spacing:.3em;color:var(--mut);animation:fade 1s .2s both">MODEL CONTEXT PROTOCOL · 2026</div>
<div style="position:absolute;left:160px;top:250px;font:800 104px/1.04 Inter;letter-spacing:-.04em">
  <div class="a" style="animation-delay:.4s">{words[0][0]}</div>
  <div class="a" style="animation-delay:1.1s;color:var(--teal)">{words[1][0]}</div>
</div>
<div style="position:absolute;left:160px;top:560px;font:700 58px/1.25 Inter;letter-spacing:-.02em">
  {''.join(f'<div class="a" style="animation-delay:{t}s;color:var(--{c})">{s}</div>' for s, c, t in lines)}
</div>
<div style="position:absolute;left:160px;top:830px;font:800 74px Inter;letter-spacing:-.03em;animation:wipe 1s {6.9}s cubic-bezier(.6,0,.2,1) both">
  compromises the <span style="color:var(--red)">entire chain.</span></div>
<svg style="position:absolute;right:150px;top:250px" width="520" height="520" viewBox="0 0 520 520">
  {''.join(f'<rect x="{40 + (k % 3) * 160}" y="{40 + (k // 3) * 160}" width="120" height="120" rx="22" fill="none" stroke="{"#ff5d5d" if k == 4 else "#2b3644"}" stroke-width="3" style="animation:pop .6s {0.3 + k * 0.12:.2f}s both;transform-origin:{100 + (k % 3) * 160}px {100 + (k // 3) * 160}px"/>' for k in range(9))}
  <path d="M100 100 L260 260 L420 420 M420 100 L260 260 L100 420 M260 100 V420 M100 260 H420" stroke="#2ec4a6" stroke-width="3" fill="none" stroke-dasharray="1400" stroke-dashoffset="1400" style="animation:draw 2.4s 1.4s ease-out forwards;opacity:.7"/>
  <circle cx="260" cy="260" r="34" fill="#ff5d5d" style="animation:pop .5s 7.2s both;transform-origin:260px 260px"/>
</svg>
<div style="position:absolute;inset:0;background:var(--bg);animation:fade .9s {end:.2f}s both"></div>
</body></html>"""


def card_title(num: str, title: str, sub: str, d: float) -> str:
    return CARD_HEAD + f"""<div class="grid"></div><div class="glow" style="background:#2ec4a6;left:30%;top:-30%"></div>
<div style="position:absolute;left:160px;top:380px">
 <div class="mono" style="font-size:26px;color:var(--teal);letter-spacing:.3em;animation:fade .6s .1s both">{num}</div>
 <div class="a" style="font:800 96px Inter;letter-spacing:-.04em;margin-top:18px;animation-delay:.2s">{title}</div>
 <div class="a" style="font:500 34px Inter;color:var(--mut);margin-top:16px;animation-delay:.45s">{sub}</div>
 <div style="height:4px;width:520px;background:var(--teal);margin-top:40px;transform-origin:left;animation:wipe .8s .6s both"></div>
</div></body></html>"""


def card_pipeline(d: float) -> str:
    nodes = [("Ingress", "schema pin · lexers · ABAC", "#6aa8ff"), ("Execution", "tool call, sandboxed", "#2ec4a6"),
             ("Redaction", "DLP · taint label", "#f2b134"), ("Merkle Batch Root", "anchored on AuditAnchor.sol", "#ff5d5d")]
    xs = [150, 590, 1030, 1470]
    boxes = "".join(f"""
 <g style="animation:pop .7s {0.3 + i * 0.9:.1f}s both;transform-origin:{x + 150}px 330px">
  <rect x="{x}" y="250" width="300" height="160" rx="26" fill="#0e141c" stroke="{c}" stroke-width="3"/>
  <text x="{x + 150}" y="322" fill="#eef2f6" font-family="Inter" font-weight="700" font-size="{30 if i < 3 else 26}" text-anchor="middle">{n}</text>
  <text x="{x + 150}" y="362" fill="#8792a2" font-family="JetBrains Mono" font-size="17" text-anchor="middle">{s}</text>
 </g>""" for i, ((n, s, c), x) in enumerate(zip(nodes, xs)))
    arrows = "".join(f"""<path d="M{xs[i] + 305} 330 H{xs[i + 1] - 5}" stroke="#3a4757" stroke-width="3" stroke-dasharray="140" stroke-dashoffset="140" style="animation:draw .6s {0.8 + i * 0.9:.1f}s forwards"/>
 <circle r="9" fill="{nodes[i + 1][2]}"><animateMotion dur="1.1s" begin="{1.0 + i * 0.9:.1f}s" repeatCount="indefinite" path="M{xs[i] + 305} 330 H{xs[i + 1] - 5}"/></circle>""" for i in range(3))
    leaves = [f"h{k}" for k in range(8)]
    tree = "".join(f"""<g style="animation:pop .4s {3.9 + k * 0.08:.2f}s both;transform-origin:{260 + k * 200}px 760px">
  <rect x="{200 + k * 200}" y="735" width="120" height="50" rx="10" fill="#0e141c" stroke="#2b3644" stroke-width="2"/>
  <text x="{260 + k * 200}" y="767" fill="#8792a2" font-family="JetBrains Mono" font-size="18" text-anchor="middle">{leaves[k]}</text></g>""" for k in range(8))
    l2 = "".join(f"""<path d="M{260 + 2 * k * 200} 735 L{360 + 2 * k * 200} 665 L{460 + 2 * k * 200} 735" fill="none" stroke="#2ec4a6" stroke-width="2" stroke-dasharray="300" stroke-dashoffset="300" style="animation:draw .5s {4.7 + k * .1:.1f}s forwards"/>
  <rect x="{310 + 2 * k * 200}" y="640" width="100" height="44" rx="10" fill="#0e141c" stroke="#2ec4a6" stroke-width="2" style="animation:pop .4s {5.0 + k * .1:.1f}s both;transform-origin:{360 + 2 * k * 200}px 662px"/>""" for k in range(4))
    l3 = "".join(f"""<path d="M{360 + 4 * k * 200} 640 L{560 + 4 * k * 200} 575 L{760 + 4 * k * 200} 640" fill="none" stroke="#2ec4a6" stroke-width="2" stroke-dasharray="500" stroke-dashoffset="500" style="animation:draw .5s {5.6 + k * .1:.1f}s forwards"/>""" for k in range(2))
    root = """<path d="M560 575 L960 520 L1360 575" fill="none" stroke="#ff5d5d" stroke-width="3" stroke-dasharray="900" stroke-dashoffset="900" style="animation:draw .6s 6.2s forwards"/>
  <g style="animation:pop .6s 6.7s both;transform-origin:960px 500px"><rect x="800" y="470" width="320" height="60" rx="14" fill="#2a0f12" stroke="#ff5d5d" stroke-width="3"/>
  <text x="960" y="509" fill="#ffd9d9" font-family="JetBrains Mono" font-weight="600" font-size="22" text-anchor="middle">root 0x9f3c…a71e</text></g>
  <g style="animation:pop .6s 7.4s both;transform-origin:1660px 500px"><rect x="1480" y="460" width="360" height="80" rx="16" fill="#0e141c" stroke="#f2b134" stroke-width="3"/>
  <text x="1660" y="495" fill="#f2b134" font-family="JetBrains Mono" font-size="20" text-anchor="middle">AuditAnchor.sol</text>
  <text x="1660" y="524" fill="#8792a2" font-family="JetBrains Mono" font-size="16" text-anchor="middle">anchor(batchId, root)</text></g>
  <path d="M1125 500 H1475" stroke="#f2b134" stroke-width="3" stroke-dasharray="360" stroke-dashoffset="360" style="animation:draw .5s 7.2s forwards"/>"""
    return CARD_HEAD + f"""<div class="grid"></div>
<div class="mono" style="position:absolute;left:150px;top:120px;font-size:24px;color:var(--teal);letter-spacing:.3em;animation:fade .6s both">03 · PROOF</div>
<div class="a" style="position:absolute;left:150px;top:160px;font:800 56px Inter;letter-spacing:-.03em">Every decision ends in a hash the host cannot rewrite.</div>
<svg width="1920" height="1080" style="position:absolute;inset:0">{boxes}{arrows}{tree}{l2}{l3}{root}
<path d="M1620 410 V460" stroke="#ff5d5d" stroke-width="3" stroke-dasharray="60" stroke-dashoffset="60" style="animation:draw .4s 3.4s forwards"/></svg>
<div class="mono" style="position:absolute;left:150px;bottom:110px;font-size:22px;color:var(--mut);animation:fade .8s 7.8s both">entry_hash = SHA256(seq ‖ prev_hash ‖ canonical_record) · RFC 6962 Merkle tree · root on chain</div>
</body></html>"""


def badge_html() -> str:
    return """<!doctype html><html><head><link href="https://fonts.googleapis.com/css2?family=Inter:wght@800&family=JetBrains+Mono:wght@500&display=swap" rel="stylesheet">
<style>html,body{margin:0;background:transparent;width:1920px;height:1080px}</style></head><body>
<div style="position:absolute;right:70px;top:70px;background:rgba(7,9,13,.92);border:3px solid #2ec4a6;border-radius:26px;padding:26px 40px;font-family:Inter;color:#eef2f6;box-shadow:0 20px 60px rgba(0,0,0,.5)">
 <div style="font:800 76px Inter;color:#2ec4a6;letter-spacing:-.03em">100%</div>
 <div style="font:800 34px Inter">Tamper Detected</div>
 <div style="font:500 18px 'JetBrains Mono';color:#8792a2;margin-top:8px">10 / 10 post-hoc edits · Mode C (anchored)</div>
</div></body></html>"""


def card_counters(d: float, R: dict) -> str:
    cat, lat = R["categories"], R["latency_ms"]
    tiles = [
        (100, "", "real benchmark cases", "MCPTox · AgentDojo · MSB", None),
        (int(cat["poisoning"]["C"]), "%", "tool-poisoning success", f"Mode B without pins: {cat['poisoning']['B']:g}%", "teal"),
        (int(cat["chain"]["C"]), "%", "multi-step chain success", f"unprotected: {cat['chain']['A']:g}%", "teal"),
        (int(cat["tamper"]["C"]), "%", "tampering detected", f"mutable log: {cat['tamper']['B']:g}%", "teal"),
    ]
    end = d - 5.2
    css = "".join(f"""@property --n{i}{{syntax:'<integer>';inherits:true;initial-value:{0 if v < 50 else 0}}}
 @keyframes c{i}{{from{{--n{i}:{100 if v == 0 else 0}}}to{{--n{i}:{v}}}}}
 .t{i} .num::before{{counter-reset:n{i} var(--n{i});content:counter(n{i});}}
 .t{i}{{animation:c{i} 1.6s {0.6 + i * 0.5:.1f}s cubic-bezier(.2,.8,.2,1) both}}""" for i, (v, *_r) in enumerate(tiles))
    html = "".join(f"""<div class="tile t{i} a" style="animation-delay:{0.4 + i * 0.5:.1f}s, {0.6 + i * 0.5:.1f}s;animation-name:up,c{i};animation-duration:.9s,1.6s">
  <div class="num" style="color:var(--{c or 'ink'})"><span class="u">{u}</span></div><div class="lab">{l}</div><div class="sub mono">{s}</div></div>"""
                   for i, (v, u, l, s, c) in enumerate(tiles))
    return CARD_HEAD.replace("</style>", f"""
 {css}
 .tile{{background:#0e141c;border:2px solid #1f2935;border-radius:28px;padding:40px 38px;width:380px}}
 .num{{font:800 120px/1 Inter;letter-spacing:-.05em;display:flex;align-items:baseline}}
 .num .u{{font-size:64px;order:2;margin-left:4px}}
 .lab{{font:700 28px Inter;margin-top:20px}} .sub{{font-size:18px;color:var(--mut);margin-top:10px}}
</style>""") + f"""<div class="grid"></div><div class="glow" style="background:#2ec4a6;left:-200px;top:-300px"></div>
<div style="position:absolute;inset:0;animation:out .8s {end:.2f}s both">
 <div class="mono" style="position:absolute;left:150px;top:150px;font-size:24px;color:var(--teal);letter-spacing:.3em;animation:fade .6s both">04 · RESULTS · LIVE API · benchmarks/results.json</div>
 <div style="position:absolute;left:150px;top:290px;display:flex;gap:36px">{html}</div>
 <div class="mono" style="position:absolute;left:150px;top:720px;font-size:26px;color:var(--ink);animation:fade .8s 3.2s both">
  median gateway overhead <b style="color:var(--teal)">{lat['C']['p50']:.2f} ms</b> · p95 {lat['C']['p95']:.0f} ms on calls that seal + anchor a batch</div>
 <div class="mono" style="position:absolute;left:150px;top:780px;font-size:20px;color:var(--mut);animation:fade .8s 3.8s both;max-width:1600px;line-height:1.6">
  prompt injection: {cat['injection_ml']['C']:g}% success with the pinned guard model (local GPU, {100 - cat['benign_ml']['C']:g}% benign false positives) ·
  {cat['injection']['C']:g}% with rules alone on the free-tier deployment</div>
</div>
<div style="position:absolute;inset:0;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;animation:fade 1s {end + 0.5:.2f}s both">
 <svg width="120" height="120" viewBox="0 0 24 24" fill="none" style="animation:pop .8s {end + 0.6:.2f}s both"><path d="M12 2.5 4 5.6v6.2c0 4.6 3.4 8.6 8 9.7 4.6-1.1 8-5.1 8-9.7V5.6L12 2.5Z" stroke="#eef2f6" stroke-width="1.1"/><path d="m8.5 12 2.4 2.4 4.6-4.8" stroke="#2ec4a6" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" stroke-dasharray="14" stroke-dashoffset="14" style="animation:draw .7s {end + 1.1:.2f}s forwards"/></svg>
 <div style="font:800 110px Inter;letter-spacing:-.045em;margin-top:30px;animation:up 1s {end + 0.8:.2f}s both">OmniGuard-MCP</div>
 <div style="font:500 44px Inter;color:var(--mut);margin-top:14px;animation:up 1s {end + 1.3:.2f}s both">Tamper-Evident Trust for <span style="color:var(--teal)">Agentic AI</span></div>
 <div class="mono" style="font-size:22px;color:var(--mut);margin-top:46px;animation:fade 1s {end + 2.0:.2f}s both">omniguard-mcp.vercel.app · github.com/lucky07-07/omniguard-mcp</div>
</div></body></html>"""


def render_card(page, html: str, d: float, out: Path) -> Path:
    stamp = out.with_suffix(".src")
    key = f"{d:.4f}|{html}"
    if out.exists() and stamp.exists() and stamp.read_text(encoding="utf-8") == key:
        return out
    page.set_content(html, wait_until="networkidle")
    page.evaluate("document.fonts.ready")
    page.wait_for_timeout(250)
    n = int(round(d * FPS))
    ff = subprocess.Popen([FFMPEG, "-y", "-loglevel", "error", "-f", "image2pipe", "-framerate", str(FPS), "-c:v", "mjpeg",
                           "-i", "-", "-c:v", "libx264", "-preset", "medium", "-crf", "14", "-pix_fmt", "yuv420p",
                           "-r", str(FPS), str(out)], stdin=subprocess.PIPE)
    svg_pause = "document.querySelectorAll('svg').forEach(s => s.pauseAnimations && s.pauseAnimations());"
    page.evaluate(svg_pause)
    for i in range(n):
        t = i * 1000 / FPS
        page.evaluate(f"""(() => {{ document.getAnimations().forEach(a => {{ a.pause(); a.currentTime = {t}; }});
            document.querySelectorAll('svg').forEach(s => s.setCurrentTime && s.setCurrentTime({t / 1000})); }})()""")
        ff.stdin.write(page.screenshot(type="jpeg", quality=94))
    ff.stdin.close()
    ff.wait()
    stamp.write_text(key, encoding="utf-8")
    print("card", out.name, f"{d:.2f}s", flush=True)
    return out


# =============================================================================== live recording
CURSOR_JS = """
(() => { const add = () => { if (document.getElementById('__cur')) return;
  const c = document.createElement('div'); c.id = '__cur';
  c.style.cssText = 'position:fixed;z-index:2147483647;left:-40px;top:-40px;pointer-events:none;transition:none';
  c.innerHTML = '<svg width="30" height="30" viewBox="0 0 24 24"><path d="M4 2.5 19 12l-6.6 1.4 3.9 7.2-2.6 1.4-3.9-7.3L4 19.5z" fill="#fff" stroke="#111" stroke-width="1.3" stroke-linejoin="round"/></svg>';
  const r = document.createElement('div'); r.id = '__rip';
  r.style.cssText = 'position:fixed;z-index:2147483646;width:46px;height:46px;margin:-23px 0 0 -23px;border-radius:50%;border:3px solid #2ec4a6;pointer-events:none;opacity:0;transform:scale(.3);transition:transform .45s ease-out,opacity .45s ease-out';
  document.body.append(c, r);
  document.addEventListener('mousemove', e => { c.style.left = e.clientX + 'px'; c.style.top = e.clientY + 'px'; }, true);
  document.addEventListener('mousedown', e => { r.style.transition = 'none'; r.style.left = e.clientX + 'px'; r.style.top = e.clientY + 'px';
    r.style.opacity = '1'; r.style.transform = 'scale(.3)'; requestAnimationFrame(() => requestAnimationFrame(() => {
    r.style.transition = 'transform .45s ease-out,opacity .45s ease-out'; r.style.opacity = '0'; r.style.transform = 'scale(1.6)'; })); }, true); };
  if (document.body) add(); else document.addEventListener('DOMContentLoaded', add); })();
"""


def record_live(site: str, api: str, work: Path) -> tuple[Path, dict[str, float]]:
    from playwright.sync_api import sync_playwright

    vid_dir = work / "rec"
    shutil.rmtree(vid_dir, ignore_errors=True)
    marks: dict[str, float] = {}
    with sync_playwright() as p:
        browser = p.chromium.launch(channel="chrome", headless=True)
        ctx = browser.new_context(viewport={"width": W, "height": H}, record_video_dir=str(vid_dir),
                                  record_video_size={"width": W, "height": H})
        ctx.add_init_script(CURSOR_JS)
        page = ctx.new_page()
        t0 = time.monotonic()
        mark = lambda k: marks.__setitem__(k, round(time.monotonic() - t0, 3))  # noqa: E731
        page.request.post(f"{api}/api/ledger/reset", timeout=120_000)
        page.goto(f"{site}/?theme=dark&api={api}", wait_until="networkidle")
        page.evaluate("document.fonts.ready")
        page.wait_for_function("document.querySelector('#status-txt').textContent === 'Live'", timeout=180_000)
        page.mouse.move(960, 600)

        def glide(sel: str, click: bool = True, nth: int = 0, has_text: str | None = None) -> None:
            loc = page.locator(sel, has_text=has_text).nth(nth) if has_text else page.locator(sel).nth(nth)
            loc.scroll_into_view_if_needed()
            b = loc.bounding_box()
            page.mouse.move(b["x"] + min(b["width"] * 0.5, 160), b["y"] + b["height"] / 2, steps=35)
            page.wait_for_timeout(120)
            if click:
                page.mouse.down()
                page.mouse.up()

        def smooth(sel: str, off: int = 90, wait: int = 900) -> None:
            page.evaluate(f"""(() => {{ const e = document.querySelector({json.dumps(sel)});
                window.scrollTo({{top: e.getBoundingClientRect().top + window.scrollY - {off}, behavior: 'smooth'}}); }})()""")
            page.wait_for_timeout(wait)

        # ---------------- act 2: SQL injection typed live, then the mid-session rug pull
        smooth("#v-gateway .section-h", 70, 700)
        mark("a2_start")
        glide("#custom summary")
        page.wait_for_timeout(300)
        page.select_option("#f-role", "analyst")
        glide("#f-tool", click=False)
        page.select_option("#f-tool", "query_db")
        glide("#f-args")
        page.keyboard.press("Control+A")
        page.keyboard.press("Delete")
        page.keyboard.type('{"query": "SELECT * FROM analytics_sales WHERE region = \'x\' OR 1=1 LIMIT 5"}', delay=30)
        page.wait_for_timeout(250)
        glide("#send")
        page.wait_for_function("document.querySelector('#t-where').textContent.includes('ingress')", timeout=90_000)
        mark("sqli_denied")
        smooth("#trace", 80, 1000)
        page.mouse.move(1180, 520, steps=35)
        page.wait_for_timeout(1800)
        mark("a2_mid")
        glide("#custom summary")  # close the form again
        smooth("#v-gateway .section-h", 70, 800)
        glide(".scn", has_text="Tool rug-pull")
        page.wait_for_function("document.querySelector('#trace').textContent.includes('SCHEMA_DRIFT_RUG_PULL')", timeout=90_000)
        mark("drift_denied")
        page.wait_for_timeout(300)
        smooth("#trace", 80, 1000)
        page.mouse.move(1300, 470, steps=35)
        page.wait_for_timeout(2400)
        mark("a2_end")

        # ---------------- act 3: redaction + taint, then the R3 chain-rewrite in the tamper lab
        smooth("#v-gateway .section-h", 70, 700)
        mark("a3_start")
        glide(".scn", has_text="Reading secrets")
        page.wait_for_function("document.querySelector('#t-dec').textContent.includes('redacted')", timeout=90_000)
        mark("redacted")
        glide("details.raw summary")
        page.wait_for_timeout(300)
        smooth("details.raw", 160, 700)
        page.evaluate("""(() => { const pre = document.querySelector('#t-raw'); const i = pre.textContent.indexOf('[REDACTED');
            const line = pre.textContent.slice(0, i).split('\\n').length; pre.scrollTo({top: Math.max(0, line * 17.25 - 60), behavior: 'smooth'}); })()""")
        page.wait_for_timeout(1700)
        smooth("#v-gateway .section-h", 70, 700)
        glide(".scn", has_text="Cross-tool exfiltration")
        page.wait_for_function("document.querySelector('#t-where').textContent.includes('abac')", timeout=90_000)
        mark("exfil_denied")
        page.wait_for_timeout(300)
        smooth("#trace", 80, 900)
        page.mouse.move(1200, 480, steps=35)
        page.wait_for_timeout(1800)
        mark("a3_lab")
        page.evaluate("window.scrollTo({top: 0, behavior: 'smooth'})")
        page.wait_for_timeout(500)
        for _ in range(6):
            page.request.post(f"{api}/api/gateway/call", data=json.dumps(
                {"role": "operator", "tool": "read_file", "arguments": {"path": "/workspace/../etc/passwd"}}),
                headers={"Content-Type": "application/json"})
        glide(".top .seg [data-view='lab']")
        page.wait_for_timeout(600)
        glide("#sweep")
        page.wait_for_function("document.querySelectorAll('.shield.sh-clean').length === 3", timeout=90_000)
        page.wait_for_timeout(700)
        glide("[data-attack='rewrite_chain']")
        page.wait_for_function("document.querySelector('#atk-log').textContent.includes('recomputed')", timeout=90_000)
        page.wait_for_timeout(900)
        glide("#sweep")
        page.wait_for_function("document.querySelector('.shield.sh-alert') !== null", timeout=90_000)
        mark("r3_alert")
        page.wait_for_timeout(400)
        smooth("#regimes", 110, 1000)
        page.mouse.move(1500, 560, steps=35)
        page.wait_for_timeout(2600)
        mark("a3_end")

        # ---------------- act 4: the live ledger, Merkle batches with on-chain roots
        smooth("#batches", 150, 1100)
        mark("a4_start")
        page.mouse.move(1300, 600, steps=35)
        page.wait_for_timeout(4500)
        mark("a4_end")
        page.wait_for_timeout(500)
        page.request.post(f"{api}/api/ledger/reset", timeout=120_000)
        video = page.video.path()
        ctx.close()
        browser.close()
    raw = work / "live_raw.webm"
    shutil.move(video, raw)
    (work / "marks.json").write_text(json.dumps(marks, indent=1))
    print("recorded", raw, marks, flush=True)
    return raw, marks


def cut_live(raw: Path, a: float, b: float, d: float, out: Path, zoom: bool = False) -> Path:
    """Cut [a, b] from the recording and conform it to exactly d seconds at 1080p60 (speed = (b-a)/d)."""
    k = d / (b - a)
    vf = f"setpts={k:.5f}*(PTS-STARTPTS),fps={FPS}"
    if zoom:
        n = int(d * FPS)
        vf += (f",scale=3840:2160:flags=lanczos,zoompan=z='1+0.14*on/{n}':x='iw/2-(iw/zoom/2)+iw*0.04*on/{n}'"
               f":y='ih/2-(ih/zoom/2)':d=1:s={W}x{H}:fps={FPS}")
    else:
        vf += f",scale={W}:{H}:flags=lanczos"
    run([FFMPEG, "-y", "-loglevel", "error", "-ss", f"{a:.3f}", "-to", f"{b:.3f}", "-i", str(raw), "-vf", vf + ",format=yuv420p",
         "-t", f"{d:.3f}", "-c:v", "libx264", "-preset", "medium", "-crf", "14", "-r", str(FPS), "-an", str(out)])
    print("live", out.name, f"{b - a:.1f}s -> {d:.2f}s (x{1 / k:.2f})", flush=True)
    return out


def overlay_badge(page, clip: Path, d: float, out: Path, start: float) -> Path:
    png = clip.with_name("badge.png")
    page.set_content(badge_html(), wait_until="networkidle")
    page.evaluate("document.fonts.ready")
    page.screenshot(path=str(png), omit_background=True)
    run([FFMPEG, "-y", "-loglevel", "error", "-i", str(clip), "-loop", "1", "-t", f"{d:.3f}", "-i", str(png), "-filter_complex",
         f"[1:v]format=rgba,fade=t=in:st={start}:d=0.5:alpha=1[b];[0:v][b]overlay=0:0:shortest=1,format=yuv420p",
         "-c:v", "libx264", "-preset", "medium", "-crf", "14", "-r", str(FPS), "-an", str(out)])
    return out


# =============================================================================== edit + audio
def xfade_chain(clips: list[tuple[Path, float]], out: Path) -> float:
    ins, fc, prev, offset = [], [], "[0:v]", 0.0
    for p, _ in clips:
        ins += ["-i", str(p)]
    for i in range(1, len(clips)):
        offset += clips[i - 1][1] - XF
        tr = "fade" if i % 2 else "smoothleft"
        tag = f"[v{i}]"
        fc.append(f"{prev}[{i}:v]xfade=transition={tr}:duration={XF}:offset={offset:.3f}{tag}")
        prev = tag
    run([FFMPEG, "-y", "-loglevel", "error", *ins, "-filter_complex", ";".join(fc), "-map", prev, "-c:v", "libx264",
         "-preset", "slow", "-crf", "17", "-pix_fmt", "yuv420p", "-r", str(FPS), str(out)])
    return offset + clips[-1][1]


def audio(work: Path, total: float, act_starts: list[float], hits: list[float], whooshes: list[float], out: Path) -> Path:
    vo = work / "vo"
    ins, fc, mix = [], [], []
    for i in range(5):
        ins += ["-i", str(vo / f"act{i + 1}.wav")]
        ms = int((act_starts[i] + 0.35) * 1000)
        fc.append(f"[{i}:a]aresample=48000,aformat=channel_layouts=stereo,adelay={ms}|{ms}[n{i}]")
        mix.append(f"[n{i}]")
    # synth pulse bed: soft 55 Hz + 110 Hz pulse at 100 BPM with a slow filter sweep, -22 dB under the voice
    bed = (f"aevalsrc='0.6*sin(2*PI*55*t)*pow(0.5+0.5*cos(2*PI*1.6667*t),6)+0.25*sin(2*PI*110*t)*pow(0.5+0.5*cos(2*PI*1.6667*t),10)"
           f"+0.08*sin(2*PI*220*t+sin(2*PI*0.1*t))':s=48000:d={total:.3f},lowpass=f=900,volume=-22dB,"
           f"afade=t=in:d=2,afade=t=out:st={total - 3:.3f}:d=3,aformat=channel_layouts=stereo[bed]")
    fc.append(bed)
    mix.append("[bed]")
    for j, t in enumerate(whooshes):
        ms = int(max(0, t - 0.25) * 1000)
        fc.append(f"anoisesrc=d=0.7:c=pink:a=0.5:r=48000,highpass=f=400,lowpass=f=5000,afade=t=in:d=0.35,afade=t=out:st=0.35:d=0.35,"
                  f"volume=-17dB,aformat=channel_layouts=stereo,adelay={ms}|{ms}[w{j}]")
        mix.append(f"[w{j}]")
    for j, t in enumerate(hits):
        ms = int(t * 1000)
        fc.append(f"aevalsrc='sin(2*PI*(62+60*exp(-18*t))*t)*exp(-7*t)':s=48000:d=0.6,volume=-9dB,aformat=channel_layouts=stereo,adelay={ms}|{ms}[h{j}]")
        mix.append(f"[h{j}]")
    fc.append(f"{''.join(mix)}amix=inputs={len(mix)}:normalize=0:duration=longest,atrim=0:{total:.3f}[pre]")
    pre = work / "mix_pre.wav"
    run([FFMPEG, "-y", "-loglevel", "error", *ins, "-filter_complex", ";".join(fc), "-map", "[pre]", str(pre)])
    # two-pass loudnorm to -16 LUFS integrated, -1.5 dBTP
    r = subprocess.run([FFMPEG, "-hide_banner", "-i", str(pre), "-af", "loudnorm=I=-16:TP=-1.5:LRA=11:print_format=json",
                        "-f", "null", "-"], capture_output=True, text=True)
    import re as _re
    m = json.loads(_re.findall(r"\{[^{}]*\}", r.stderr)[-1])
    ln = (f"loudnorm=I=-16:TP=-1.5:LRA=11:measured_I={m['input_i']}:measured_TP={m['input_tp']}:measured_LRA={m['input_lra']}"
          f":measured_thresh={m['input_thresh']}:offset={m['target_offset']}:linear=true")
    run([FFMPEG, "-y", "-loglevel", "error", "-i", str(pre), "-af", ln + ",aresample=48000", str(out)])
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--site", default="https://omniguard-mcp.vercel.app")
    ap.add_argument("--api", default="https://omniguard-mcp-api.onrender.com")
    ap.add_argument("--work", default=str(ROOT / "demo_media" / "trailer"))
    ap.add_argument("--key-file", default=None)
    ap.add_argument("--skip-tts", action="store_true")
    ap.add_argument("--skip-live", action="store_true", help="reuse the last live recording + marks")
    ap.add_argument("--out", default=str(ROOT / "docs" / "OmniGuard-MCP_Trailer.mp4"))
    ap.add_argument("--copy-to", default=str(ROOT.parent / "OmniGuard-MCP_Trailer.mp4"))
    a = ap.parse_args()
    work = Path(a.work)
    (work / "seg").mkdir(parents=True, exist_ok=True)
    R = json.loads((ROOT / "benchmarks" / "results.json").read_text(encoding="utf-8"))

    vo = narration(work, a.key_file, a.skip_tts)
    act = [max(t, v + 1.1) for t, v in zip(TARGET, vo)]  # perceived act lengths
    print("narration", vo, "acts", [round(x, 2) for x in act], flush=True)

    if a.skip_live:
        raw, marks = work / "live_raw.webm", json.loads((work / "marks.json").read_text())
    else:
        raw, marks = record_live(a.site, a.api, work)

    # shot list: (path, clip duration). A clip of duration d occupies d - XF on the timeline (except the last).
    T1 = 2.4  # title cards
    s = work / "seg"
    a2_live = act[1] - T1
    a3_live = act[2] - T1
    a4_svg = 8.6
    a4_live = act[3] - a4_svg
    a5 = act[4] + XF  # the last clip has no outgoing transition
    plan = [("act1", act[0] + XF), ("t2", T1 + XF), ("a2", a2_live + XF), ("t3", T1 + XF), ("a3", a3_live + XF),
            ("svg", a4_svg + XF), ("ledger", a4_live + XF), ("act5", a5)]
    D = dict(plan)
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        b = p.chromium.launch(channel="chrome", headless=True)
        page = b.new_context(viewport={"width": W, "height": H}).new_page()
        render_card(page, card_act1(D["act1"]), D["act1"], s / "act1.mp4")
        render_card(page, card_title("01 · INGRESS", "Inspected before it runs.", "SQL lexer · SHA-256 tool-schema pinning (OWASP MCP03)", D["t2"]), D["t2"], s / "t2.mp4")
        render_card(page, card_title("02 · CONTAINMENT", "Contained, then proven.", "egress redaction · session taint · R3 tamper lab", D["t3"]), D["t3"], s / "t3.mp4")
        render_card(page, card_pipeline(D["svg"]), D["svg"], s / "svg.mp4")
        render_card(page, card_counters(D["act5"], R), D["act5"], s / "act5.mp4")
        cut_live(raw, marks["a2_start"], marks["a2_end"], D["a2"], s / "a2.mp4", zoom=True)
        cut_live(raw, marks["a3_start"], marks["a3_end"], D["a3"], s / "a3.mp4")
        cut_live(raw, marks["a4_start"], marks["a4_end"], D["ledger"], s / "ledger_raw.mp4")
        overlay_badge(page, s / "ledger_raw.mp4", D["ledger"], s / "ledger.mp4", start=1.0)
        b.close()

    clips = [(s / f"{k}.mp4", d) for k, d in plan]
    video = work / "video.mp4"
    total = xfade_chain(clips, video)
    starts, t = [], 0.0
    for k, d in plan:
        starts.append(t)
        t += d - XF
    st = dict(zip([k for k, _ in plan], starts))
    act_starts = [st["act1"], st["t2"], st["t3"], st["svg"], st["act5"]]

    def live_t(key: str, seg: str, a_mark: str, b_mark: str) -> float:  # map a recording mark onto the timeline
        k = D[seg] / (marks[b_mark] - marks[a_mark])
        return st[seg] + (marks[key] - marks[a_mark]) * k

    hits = [st["act1"] + 7.2, live_t("sqli_denied", "a2", "a2_start", "a2_end"), live_t("drift_denied", "a2", "a2_start", "a2_end"),
            live_t("exfil_denied", "a3", "a3_start", "a3_end"), live_t("r3_alert", "a3", "a3_start", "a3_end"), st["ledger"] + 1.0]
    whooshes = starts[1:]
    mix = audio(work, total, act_starts, hits, whooshes, work / "audio.wav")
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    run([FFMPEG, "-y", "-loglevel", "error", "-i", str(video), "-i", str(mix), "-map", "0:v", "-map", "1:a", "-c:v", "copy",
         "-c:a", "aac", "-b:a", "192k", "-shortest", "-movflags", "+faststart", str(out)])
    if a.copy_to:
        shutil.copyfile(out, a.copy_to)
    (work / "timeline.json").write_text(json.dumps({"plan": plan, "starts": starts, "act_starts": act_starts,
                                                    "narration_s": vo, "total_s": total, "hits": hits}, indent=1))
    print(f"done {out} ({total:.2f}s)")


if __name__ == "__main__":
    main()

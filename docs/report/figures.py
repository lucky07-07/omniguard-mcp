"""Render the report's architecture figures (HTML/SVG -> PNG at 3x) with headless Chrome via Playwright."""

from __future__ import annotations

from pathlib import Path

from playwright.sync_api import sync_playwright

OUT = Path(__file__).resolve().parent / "fig"

BASE = """<!doctype html><html><head><meta charset="utf-8"><style>
body{margin:0;font-family:'Segoe UI',Arial,sans-serif;color:#1d232b;background:#fff}
.mono{font-family:Consolas,'Courier New',monospace}
</style></head><body>"""

ARCH = BASE + """
<svg width="1500" height="760" viewBox="0 0 1500 760" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, Arial">
 <defs><marker id="ar" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#4a5563"/></marker></defs>
 <rect x="20" y="300" width="170" height="110" rx="14" fill="#eef3f8" stroke="#4a5563" stroke-width="2"/>
 <text x="105" y="345" text-anchor="middle" font-size="22" font-weight="700">AI agent</text>
 <text x="105" y="375" text-anchor="middle" font-size="16" fill="#4a5563">MCP client</text>
 <rect x="230" y="40" width="1000" height="560" rx="20" fill="#f7fbfa" stroke="#1f7a6d" stroke-width="3"/>
 <text x="250" y="78" font-size="24" font-weight="700" fill="#1f7a6d">OmniGuard-MCP gateway (FastAPI, JSON-RPC tools/call)</text>
 <g font-size="17">
  <g transform="translate(255,110)">
   <rect width="125" height="90" rx="10" fill="#fff" stroke="#4a5563"/><text x="62" y="38" text-anchor="middle" font-weight="700">1 identity</text><text x="62" y="62" text-anchor="middle" font-size="14" fill="#4a5563">token → role</text></g>
  <g transform="translate(395,110)">
   <rect width="125" height="90" rx="10" fill="#fff" stroke="#4a5563"/><text x="62" y="38" text-anchor="middle" font-weight="700">2 integrity</text><text x="62" y="62" text-anchor="middle" font-size="14" fill="#4a5563">known · pinned</text></g>
  <g transform="translate(535,110)">
   <rect width="125" height="90" rx="10" fill="#fff" stroke="#4a5563"/><text x="62" y="38" text-anchor="middle" font-weight="700">3 abac</text><text x="62" y="62" text-anchor="middle" font-size="14" fill="#4a5563">role · params</text></g>
  <g transform="translate(675,110)">
   <rect width="125" height="90" rx="10" fill="#fdecea" stroke="#b23a3a" stroke-width="2"/><text x="62" y="38" text-anchor="middle" font-weight="700">4 ingress</text><text x="62" y="62" text-anchor="middle" font-size="14" fill="#4a5563">pin check · engine</text></g>
  <g transform="translate(815,110)">
   <rect width="125" height="90" rx="10" fill="#fff" stroke="#4a5563"/><text x="62" y="38" text-anchor="middle" font-weight="700">5 downstream</text><text x="62" y="62" text-anchor="middle" font-size="14" fill="#4a5563">forward call</text></g>
  <g transform="translate(955,110)">
   <rect width="125" height="90" rx="10" fill="#fff6e5" stroke="#c98a1c" stroke-width="2"/><text x="62" y="38" text-anchor="middle" font-weight="700">6 egress</text><text x="62" y="62" text-anchor="middle" font-size="14" fill="#4a5563">DLP · redact</text></g>
  <g transform="translate(1095,110)">
   <rect width="115" height="90" rx="10" fill="#e8f4f1" stroke="#1f7a6d" stroke-width="2"/><text x="57" y="38" text-anchor="middle" font-weight="700">7 audit</text><text x="57" y="62" text-anchor="middle" font-size="14" fill="#4a5563">every decision</text></g>
 </g>
 <g stroke="#4a5563" stroke-width="2" marker-end="url(#ar)">
  <line x1="380" y1="155" x2="393" y2="155"/><line x1="520" y1="155" x2="533" y2="155"/><line x1="660" y1="155" x2="673" y2="155"/>
  <line x1="800" y1="155" x2="813" y2="155"/><line x1="940" y1="155" x2="953" y2="155"/><line x1="1080" y1="155" x2="1093" y2="155"/>
 </g>
 <rect x="255" y="235" width="545" height="185" rx="12" fill="#fff" stroke="#b23a3a" stroke-dasharray="6 4"/>
 <text x="272" y="265" font-size="18" font-weight="700" fill="#b23a3a">Ingress inspection engine</text>
 <g font-size="15" fill="#1d232b">
  <text x="272" y="295">• SHA-256 tool-schema pin: SHA256(name ‖ description ‖ inputSchema)</text>
  <text x="272" y="320">• canonicalizer: URL / Base64 / hex / NFKC decoding</text>
  <text x="272" y="345">• SQL lexer (breakout contexts) · shell lexer · PathJail · SSRF</text>
  <text x="272" y="370">• signatures · entropy DLP · session taint (CLEAN / UNTRUSTED / SENSITIVE)</text>
  <text x="272" y="395">• optional Horizon guard ONNX (digest-pinned), cascade τ 0.26 / 0.19</text>
 </g>
 <rect x="830" y="235" width="380" height="185" rx="12" fill="#fff" stroke="#1f7a6d" stroke-dasharray="6 4"/>
 <text x="847" y="265" font-size="18" font-weight="700" fill="#1f7a6d">Audit anchor agent</text>
 <g font-size="15"><text x="847" y="295">R1 plain table (baseline)</text>
  <text x="847" y="320">R2 hash chain: SHA256(seq ‖ prev ‖ record)</text>
  <text x="847" y="345">R3 chain + RFC 6962 Merkle batches</text>
  <text x="847" y="370">batch root → AuditAnchor.sol</text>
  <text x="847" y="395">anchorBatch(batchId, root, start, end)</text></g>
 <rect x="255" y="450" width="955" height="125" rx="12" fill="#eef3f8" stroke="#4a5563"/>
 <text x="272" y="482" font-size="18" font-weight="700">Decision → JSON-RPC result or error, with trace</text>
 <text x="272" y="512" font-size="15">ALLOW · REDACT · DENY(stage, rule ids) · risk score · taint state · canonical input hash · tool_schema_sha256 · schema_drift</text>
 <text x="272" y="540" font-size="15">audit seq + R2/R3 entry_hash + prev_hash + Merkle batch id + anchor tx hash</text>
 <line x1="190" y1="355" x2="228" y2="355" stroke="#4a5563" stroke-width="2.5" marker-end="url(#ar)"/>
 <rect x="1290" y="80" width="190" height="110" rx="14" fill="#eef3f8" stroke="#4a5563" stroke-width="2"/>
 <text x="1385" y="125" text-anchor="middle" font-size="22" font-weight="700">MCP tools</text>
 <text x="1385" y="155" text-anchor="middle" font-size="15" fill="#4a5563">file · SQL · web · shell</text>
 <path d="M1210 155 H1288" stroke="#4a5563" stroke-width="2.5" marker-end="url(#ar)"/>
 <rect x="1290" y="290" width="190" height="120" rx="14" fill="#fff6e5" stroke="#c98a1c" stroke-width="2"/>
 <text x="1385" y="335" text-anchor="middle" font-size="20" font-weight="700">EVM chain</text>
 <text x="1385" y="362" text-anchor="middle" font-size="15">AuditAnchor.sol</text>
 <text x="1385" y="386" text-anchor="middle" font-size="14" fill="#4a5563">append-only roots</text>
 <path d="M1210 350 H1288" stroke="#c98a1c" stroke-width="2.5" marker-end="url(#ar)"/>
 <rect x="1290" y="470" width="190" height="120" rx="14" fill="#e8f4f1" stroke="#1f7a6d" stroke-width="2"/>
 <text x="1385" y="512" text-anchor="middle" font-size="20" font-weight="700">IntegrityWatcher</text>
 <text x="1385" y="540" text-anchor="middle" font-size="14">separate process</text>
 <text x="1385" y="562" text-anchor="middle" font-size="14">read-only DB + RPC</text>
 <path d="M1385 468 V412" stroke="#1f7a6d" stroke-width="2" stroke-dasharray="5 4" marker-end="url(#ar)"/>
 <path d="M1288 520 H1212" stroke="#1f7a6d" stroke-width="2" stroke-dasharray="5 4" marker-end="url(#ar)"/>
 <rect x="230" y="640" width="1000" height="95" rx="14" fill="#fff" stroke="#4a5563"/>
 <text x="250" y="675" font-size="18" font-weight="700">Deployment</text>
 <text x="250" y="705" font-size="15">Dashboard: static HTML on Vercel (omniguard-mcp.vercel.app) → REST → live API on Render (FastAPI, eth-tester chain node, SQLite stores)</text>
</svg></body></html>"""

ANCHOR = BASE + """
<svg width="1500" height="560" viewBox="0 0 1500 560" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, Arial">
 <defs><marker id="ar" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#4a5563"/></marker></defs>
 <text x="30" y="40" font-size="22" font-weight="700">Audit records (R3)</text>
 """ + "".join(f"""<g transform="translate({30 + i * 175},70)"><rect width="150" height="100" rx="10" fill="#fff" stroke="#4a5563"/>
 <text x="75" y="30" text-anchor="middle" font-size="17" font-weight="700">seq {i + 1}</text>
 <text x="75" y="56" text-anchor="middle" font-size="13" class="mono" fill="#4a5563">prev = h{i}</text>
 <text x="75" y="80" text-anchor="middle" font-size="13" fill="#4a5563">h{i + 1} = SHA256(…)</text></g>""" for i in range(8)) + """
 """ + "".join(f'<line x1="{180 + i * 175}" y1="120" x2="{203 + i * 175}" y2="120" stroke="#4a5563" stroke-width="2" marker-end="url(#ar)"/>' for i in range(7)) + """
 <text x="40" y="390" font-size="18" font-weight="700" fill="#1f7a6d">Merkle batch 0 (records 1–4)</text>
 <text x="720" y="390" font-size="18" font-weight="700" fill="#1f7a6d">Merkle batch 1 (records 5–8)</text>
 <g stroke="#1f7a6d" stroke-width="2" fill="none">
  <path d="M105 170 L190 260 L280 170"/><path d="M455 170 L540 260 L630 170"/><path d="M190 300 L365 360 L540 300"/>
  <path d="M805 170 L890 260 L980 170"/><path d="M1155 170 L1240 260 L1330 170"/><path d="M890 300 L1065 360 L1240 300"/>
 </g>
 <g font-size="15" class="mono">
  <rect x="140" y="262" width="100" height="38" rx="8" fill="#e8f4f1" stroke="#1f7a6d"/><text x="190" y="287" text-anchor="middle">H(1,2)</text>
  <rect x="490" y="262" width="100" height="38" rx="8" fill="#e8f4f1" stroke="#1f7a6d"/><text x="540" y="287" text-anchor="middle">H(3,4)</text>
  <rect x="840" y="262" width="100" height="38" rx="8" fill="#e8f4f1" stroke="#1f7a6d"/><text x="890" y="287" text-anchor="middle">H(5,6)</text>
  <rect x="1190" y="262" width="100" height="38" rx="8" fill="#e8f4f1" stroke="#1f7a6d"/><text x="1240" y="287" text-anchor="middle">H(7,8)</text>
  <rect x="285" y="360" width="160" height="44" rx="10" fill="#fdecea" stroke="#b23a3a" stroke-width="2"/><text x="365" y="388" text-anchor="middle">root₀</text>
  <rect x="985" y="360" width="160" height="44" rx="10" fill="#fdecea" stroke="#b23a3a" stroke-width="2"/><text x="1065" y="388" text-anchor="middle">root₁</text>
 </g>
 <path d="M365 406 V455" stroke="#c98a1c" stroke-width="2.5" marker-end="url(#ar)"/><path d="M1065 406 V455" stroke="#c98a1c" stroke-width="2.5" marker-end="url(#ar)"/>
 <rect x="200" y="458" width="1030" height="80" rx="14" fill="#fff6e5" stroke="#c98a1c" stroke-width="2"/>
 <text x="715" y="490" text-anchor="middle" font-size="19" font-weight="700">AuditAnchor.sol  ·  anchors[batchId] = (root, startSeq, endSeq, timestamp, submitter)</text>
 <text x="715" y="520" text-anchor="middle" font-size="15" fill="#4a5563">batchId must equal batchCount · startSeq must follow the previous endSeq · no update or delete function</text>
 <text x="1260" y="490" font-size="15" fill="#1f7a6d">watcher recomputes</text>
 <text x="1260" y="512" font-size="15" fill="#1f7a6d">chain + roots and</text>
 <text x="1260" y="534" font-size="15" fill="#1f7a6d">compares on-chain</text>
</svg></body></html>"""


def main() -> None:
    OUT.mkdir(exist_ok=True)
    with sync_playwright() as p:
        b = p.chromium.launch(channel="chrome", headless=True)
        pg = b.new_context(viewport={"width": 1500, "height": 760}, device_scale_factor=3).new_page()
        for name, html, h in (("architecture", ARCH, 760), ("anchoring", ANCHOR, 560)):
            pg.set_viewport_size({"width": 1500, "height": h})
            pg.set_content(html)
            pg.screenshot(path=str(OUT / f"{name}.png"))
        b.close()
    print("figures ->", OUT)


if __name__ == "__main__":
    main()

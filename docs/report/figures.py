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


DEFS = '<defs><marker id="ar" markerWidth="10" markerHeight="10" refX="9" refY="5" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="#4a5563"/></marker></defs>'
EMO = "font-family=\"Segoe UI Emoji\""


def _svg(w, h, inner):
    return BASE + f'<svg width="{w}" height="{h}" viewBox="0 0 {w} {h}" xmlns="http://www.w3.org/2000/svg" font-family="Segoe UI, Arial">{DEFS}{inner}</svg></body></html>'


def _card(x, y, w, h, icon, title, sub, num=None, fill="#fff", stroke="#4a5563"):
    s = f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="14" fill="{fill}" stroke="{stroke}" stroke-width="2"/>'
    if num:
        s += f'<circle cx="{x + 24}" cy="{y + 24}" r="15" fill="#1f7a6d"/><text x="{x + 24}" y="{y + 30}" text-anchor="middle" font-size="16" font-weight="700" fill="#fff">{num}</text>'
    s += f'<text x="{x + w / 2}" y="{y + 52}" text-anchor="middle" font-size="34" {EMO}>{icon}</text>'
    s += f'<text x="{x + w / 2}" y="{y + 92}" text-anchor="middle" font-size="21" font-weight="700">{title}</text>'
    s += f'<text x="{x + w / 2}" y="{y + 120}" text-anchor="middle" font-size="16" fill="#4a5563">{sub}</text>'
    return s


def _line(x1, y1, x2, y2, col="#4a5563", dash=False):
    d = ' stroke-dasharray="6 4"' if dash else ""
    return f'<line x1="{x1}" y1="{y1}" x2="{x2}" y2="{y2}" stroke="{col}" stroke-width="2.5"{d} marker-end="url(#ar)"/>'


def workflow():
    steps = [("📨", "Request in", "agent asks for a tool"), ("🪪", "Who are you?", "token → role"),
             ("🧬", "Genuine tool?", "SHA-256 fingerprint"), ("📋", "Allowed?", "role, limits, taint"),
             ("🔍", "Inspect", "rules (+ ML on prose)"), ("⚙️", "Run tool", "only if all passed"),
             ("🧹", "Clean output", "mask secrets, taint"), ("🧾", "Receipt", "hash-chained record")]
    s, pos = "", []
    for i, (ic, t, b) in enumerate(steps):
        row, col = divmod(i, 4)
        col = col if row == 0 else 3 - col
        x, y = 30 + col * 370, 20 + row * 200
        pos.append((x, y))
        s += _card(x, y, 300, 145, ic, t, b, str(i + 1), "#fff", "#1f7a6d" if i != 4 else "#b23a3a")
    for i in range(3):
        s += _line(pos[i][0] + 302, pos[i][1] + 72, pos[i + 1][0] - 4, pos[i + 1][1] + 72)
        s += _line(pos[4 + i][0] - 2, pos[4 + i][1] + 72, pos[5 + i][0] + 304, pos[5 + i][1] + 72)
    s += _line(pos[3][0] + 150, pos[3][1] + 147, pos[4][0] + 150, pos[4][1] - 4)
    outs = [("ALLOW", "#2e7d4f", "safe: result returned"), ("REDACT", "#c98a1c", "allowed, secrets masked"),
            ("DENY", "#b23a3a", "blocked, reason given"), ("ANCHOR", "#6b4f1d", "every 4 receipts → chain")]
    for i, (h, c, b) in enumerate(outs):
        x = 30 + i * 370
        s += f'<rect x="{x}" y="415" width="300" height="62" rx="12" fill="{c}"/>'
        s += f'<text x="{x + 150}" y="442" text-anchor="middle" font-size="20" font-weight="700" fill="#fff">{h}</text>'
        s += f'<text x="{x + 150}" y="466" text-anchor="middle" font-size="15" fill="#fff">{b}</text>'
    s += '<text x="750" y="402" text-anchor="middle" font-size="15" fill="#4a5563">any of steps 2–5 can stop the request; every outcome writes a receipt (step 8)</text>'
    return _svg(1500, 490, s)


def rules():
    flow = [("Decode input", "URL · Base64 · hex · Unicode (≤ 6 layers)", "#fff"),
            ("Run all 49 rules", "collect triggered rule IDs + weights", "#fff"),
            ("Score = Σ weights × taint", "CLEAN 1.0 · UNTRUSTED 1.5 · SENSITIVE 1.25", "#fdecea"),
            ("Free-form prose?", "if yes, the pinned ML guard also scores it", "#fff"),
            ("Decision", "score ≥ 1.0 → DENY, else ALLOW / REDACT", "#e8f4f1")]
    s = '<text x="30" y="34" font-size="22" font-weight="700" fill="#1f7a6d">Decision flow inside step 5</text>'
    for i, (h, b, f) in enumerate(flow):
        y = 55 + i * 105
        s += f'<rect x="30" y="{y}" width="560" height="78" rx="12" fill="{f}" stroke="#4a5563" stroke-width="2"/>'
        s += f'<text x="310" y="{y + 33}" text-anchor="middle" font-size="21" font-weight="700">{h}</text>'
        s += f'<text x="310" y="{y + 60}" text-anchor="middle" font-size="16" fill="#4a5563">{b}</text>'
        if i < 4:
            s += _line(310, y + 80, 310, y + 101)
    s += '<text x="660" y="34" font-size="22" font-weight="700" fill="#b23a3a">Three worked examples</text>'
    ex = [("SELECT * … WHERE region='x' OR 1=1", [("SQL_TAUTOLOGY", "1.0")], "1.0 ≥ 1.0", "DENY", "#b23a3a"),
          ("… WHERE id=1 -- AND 1=1", [("SQL_COMMENT", "0.5"), ("SQL_BOOLEAN_PROBE", "0.5")], "1.0 ≥ 1.0", "DENY", "#b23a3a"),
          ("echo $HOME", [("SHELL_VARIABLE_EXPANSION", "0.4")], "0.4 < 1.0", "ALLOW", "#2e7d4f")]
    for i, (inp, parts, tot, dec, col) in enumerate(ex):
        y = 55 + i * 175
        s += f'<rect x="660" y="{y}" width="810" height="150" rx="12" fill="#fff" stroke="#4a5563" stroke-width="2"/>'
        s += f'<text x="680" y="{y + 32}" font-size="16" fill="#4a5563">input:</text><text x="740" y="{y + 32}" font-size="17" class="mono" font-family="Consolas">{inp}</text>'
        for j, (n, w) in enumerate(parts):
            s += f'<text x="680" y="{y + 70 + j * 30}" font-size="18" font-family="Consolas">{n}</text><text x="1010" y="{y + 70 + j * 30}" font-size="18" font-weight="700" fill="#b23a3a">+{w}</text>'
        s += f'<text x="1150" y="{y + 90}" text-anchor="middle" font-size="22" font-weight="700">{tot}</text>'
        s += f'<rect x="1270" y="{y + 55}" width="170" height="54" rx="10" fill="{col}"/><text x="1355" y="{y + 90}" text-anchor="middle" font-size="22" font-weight="700" fill="#fff">{dec}</text>'
    s += '<text x="660" y="590" font-size="15" fill="#4a5563">The same input always gives the same score and the same decision; the triggered rule IDs are the explanation.</text>'
    return _svg(1500, 610, s)


def contract():
    steps = [("🧾", "4 receipts", "seq 9, 10, 11, 12"), ("🌳", "Merkle tree", "4 hashes → 1 root"),
             ("📤", "Transaction", "anchorBatch(2, root, 9, 12)"), ("🚦", "Contract checks", "in order? no gap? allowed?"),
             ("🔒", "Stored for good", "anchors[2] = root")]
    s = '<text x="30" y="34" font-size="22" font-weight="700" fill="#c98a1c">Sealing a batch (every 4 receipts on the live demo)</text>'
    for i, (ic, t, b) in enumerate(steps):
        x = 30 + i * 292
        s += _card(x, 55, 262, 145, ic, t, b, None, "#fff6e5" if i in (3, 4) else "#fff", "#c98a1c")
        if i < 4:
            s += _line(x + 264, 127, x + 288, 127, "#c98a1c")
    s += '<text x="30" y="250" font-size="22" font-weight="700" fill="#1f7a6d">Later: the independent watcher recomputes the root and compares it with the chain</text>'
    rows = [("✅", "Honest log", "root recomputed from today's receipts = root on chain → no alert", "#2e7d4f", "#e8f4ec"),
            ("❌", "Edited log", "receipt 10 changed DENY → ALLOW → new root ≠ chain root → ANCHOR_RECORDS_MISMATCH", "#b23a3a", "#fdecea"),
            ("❌", "Rewritten log", "every local hash recomputed, but the on-chain root is untouched → alert raised", "#b23a3a", "#fdecea"),
            ("❌", "Deleted tail", "newest anchored receipts removed → range on chain no longer covered → TAIL_TRUNCATION", "#b23a3a", "#fdecea")]
    for i, (ic, h, b, c, f) in enumerate(rows):
        y = 272 + i * 68
        s += f'<rect x="30" y="{y}" width="1440" height="56" rx="10" fill="{f}"/>'
        s += f'<text x="62" y="{y + 38}" text-anchor="middle" font-size="24" {EMO}>{ic}</text>'
        s += f'<text x="100" y="{y + 36}" font-size="20" font-weight="700" fill="{c}">{h}</text>'
        s += f'<text x="290" y="{y + 36}" font-size="17">{b}</text>'
    return _svg(1500, 550, s)


def solidity():
    code = [("contract AuditAnchor {   // simplified from contracts/AuditAnchor.sol", "#d4d4d4"),
            ("  struct Anchor { bytes32 merkleRoot; uint64 startSeq; uint64 endSeq;", "#d4d4d4"),
            ("                  uint64 timestamp; address submitter; }", "#d4d4d4"),
            ("  mapping(uint256 => Anchor) public anchors;   uint256 public batchCount;", "#9cdcfe"),
            ("  function anchorBatch(uint256 batchId, bytes32 root, uint64 startSeq,", "#d4d4d4"),
            ("                       uint64 endSeq) external onlyAnchorer {", "#d4d4d4"),
            ('    require(batchId == batchCount, "out-of-order");', "#f48fb1"),
            ('    require(startSeq == prevEnd + 1, "sequence gap");', "#f48fb1"),
            ("    anchors[batchId] = Anchor(root, startSeq, endSeq, block.timestamp, msg.sender);", "#9cdcfe"),
            ("    batchCount = batchId + 1;  emit BatchAnchored(batchId, root, ...);", "#b5cea8"),
            ("  }   // no update or delete function exists: write-once", "#6a9955"),
            ("}", "#d4d4d4")]
    s = '<rect x="30" y="20" width="1440" height="350" rx="14" fill="#1e1e24"/>'
    for i, (ln, c) in enumerate(code):
        s += f'<text x="60" y="{58 + i * 26}" font-size="19" font-family="Consolas" fill="{c}" xml:space="preserve">{ln.replace("<", "&lt;").replace(">", "&gt;")}</text>'
    flow = [("📄", "AuditAnchor.sol", "Solidity ^0.8.24 source"), ("🛠️", "solc compiler", "→ EVM bytecode + ABI"),
            ("⛓️", "Deploy", "contract gets an address"), ("🐍", "Python web3.py", "gateway calls anchorBatch()")]
    for i, (ic, t, b) in enumerate(flow):
        x = 30 + i * 370
        s += _card(x, 400, 320, 140, ic, t, b, None, "#fff", "#1f7a6d")
        if i < 3:
            s += _line(x + 322, 470, x + 366, 470)
    return _svg(1500, 560, s)


def f1_chart():
    import json
    ext = json.loads((OUT.parents[2] / "results" / "external_dataset_eval.json").read_text(encoding="utf-8"))["streams"]
    keys = [("PI inputs", "prompt_injection_ingress", "clean"), ("PI outputs", "prompt_injection_egress", "clean"),
            ("Jailbreak", "jailbreak_ingress", "clean"), ("SQL injection", "sql_injection", "full"),
            ("Cmd injection", "command_injection", "full")]
    engines = [("v1.0", "Rules only", "#9aa3ad"), ("v1.1", "ProtectAI DeBERTa", "#e8a5b8"),
               ("v1.2-small", "Horizon-small", "#d16a8f"), ("v1.2", "Ours (v1.2)", "#b8114f")]

    def f1(m):
        p = m["tp"] / (m["tp"] + m["fp"]) if m["tp"] + m["fp"] else 0
        r = m["tp"] / (m["tp"] + m["fn"]) if m["tp"] + m["fn"] else 0
        return 2 * p * r / (p + r) if p + r else 0

    x0, y0, H, gw = 90, 470, 400, 270
    s = '<text x="750" y="30" text-anchor="middle" font-size="22" font-weight="700">F1 (%) on held-out rows, every approach re-run on the same data</text>'
    for v in range(0, 101, 20):
        y = y0 - H * v / 100
        s += f'<line x1="{x0}" y1="{y}" x2="1470" y2="{y}" stroke="#e3e6ea"/><text x="{x0 - 12}" y="{y + 6}" text-anchor="end" font-size="16" fill="#4a5563">{v}</text>'
    for i, (lab, k, view) in enumerate(keys):
        gx = x0 + 20 + i * gw
        for j, (e, _, c) in enumerate(engines):
            v = 100 * f1(ext[k]["views"][view][e])
            bx, bh = gx + j * 56, H * v / 100
            s += f'<rect x="{bx}" y="{y0 - bh}" width="48" height="{bh}" fill="{c}"/>'
            s += f'<text x="{bx + 24}" y="{y0 - bh - 7}" text-anchor="middle" font-size="14" font-weight="{700 if e == "v1.2" else 400}">{v:.0f}</text>'
        s += f'<text x="{gx + 110}" y="{y0 + 30}" text-anchor="middle" font-size="18" font-weight="700">{lab}</text>'
    for j, (_, n, c) in enumerate(engines):
        x = 260 + j * 280
        s += f'<rect x="{x}" y="525" width="22" height="22" fill="{c}"/><text x="{x + 32}" y="542" font-size="17">{n}</text>'
    return _svg(1500, 565, s)


def main() -> None:
    OUT.mkdir(exist_ok=True)
    with sync_playwright() as p:
        b = p.chromium.launch(channel="chrome", headless=True)
        pg = b.new_context(viewport={"width": 1500, "height": 760}, device_scale_factor=3).new_page()
        for name, html, h in (("architecture", ARCH, 760), ("anchoring", ANCHOR, 560), ("workflow", workflow(), 490),
                              ("rules_flow", rules(), 610), ("contract_flow", contract(), 550), ("solidity", solidity(), 560),
                              ("f1_compare", f1_chart(), 565)):
            pg.set_viewport_size({"width": 1500, "height": h})
            pg.set_content(html)
            pg.screenshot(path=str(OUT / f"{name}.png"))
        b.close()
    print("figures ->", OUT)


if __name__ == "__main__":
    main()

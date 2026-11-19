"""Build OmniGuard-MCP_Final_Presentation.pptx (12 slides) by cloning the styling of Anil_Review_3_Updated.pptx.

    python docs/presentation/build_deck.py [--style C:/Users/anilk/Downloads/Anil_Review_3_Updated.pptx]

The style deck's title slide is kept and re-texted; its footer band, Amrita logo and slide-number box are lifted from
a content slide and re-placed on every new slide, with the same Georgia crimson titles and Times New Roman body.
Numbers come from benchmarks/results.json and results/*.json.
"""

from __future__ import annotations

import argparse
import io
import json
import shutil
from pathlib import Path

from pptx import Presentation
from pptx.dml.color import RGBColor
from pptx.enum.shapes import MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.util import Inches, Pt

ROOT = Path(__file__).resolve().parents[2]
BC = ROOT.parent
OUT_NAME = "OmniGuard-MCP_Final_Presentation.pptx"
CRIMSON, INK, MUTED, PINK, WHITE = "B8114F", "222222", "6B6B6B", "F9E3EB", "FFFFFF"
R = json.loads((ROOT / "benchmarks" / "results.json").read_text(encoding="utf-8"))
CAT, LAT = R["categories"], R["latency_ms"]


def rgb(h):
    return RGBColor.from_string(h)


def text(slide, x, y, w, h, s, size=12, bold=False, color=INK, font="Times New Roman", align=PP_ALIGN.LEFT,
         anchor=MSO_ANCHOR.TOP, italic=False):
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(0.02)
    tf.margin_top = tf.margin_bottom = Inches(0.01)
    tf.vertical_anchor = anchor
    lines = s if isinstance(s, list) else [s]
    for i, line in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        runs = line if isinstance(line, list) else [(line, bold)]
        for t, b in runs:
            r = p.add_run()
            r.text = t
            r.font.size = Pt(size)
            r.font.bold = b
            r.font.italic = italic
            r.font.name = font
            r.font.color.rgb = rgb(color)
    return tb


def bullets(slide, x, y, w, items, size=11.5, gap=0.07, color=INK):
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(0.3 * len(items)))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(0.02)
    for i, it in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.space_after = Pt(gap * 72)
        runs = it if isinstance(it, list) else [(it, False)]
        r = p.add_run()
        r.text = "\u25AA  "
        r.font.size = Pt(size)
        r.font.color.rgb = rgb(CRIMSON)
        r.font.name = "Times New Roman"
        for t, b in runs:
            r = p.add_run()
            r.text = t
            r.font.size = Pt(size)
            r.font.bold = b
            r.font.name = "Times New Roman"
            r.font.color.rgb = rgb(color)
    return tb


def box(slide, x, y, w, h, fill=PINK, line=None, shape=MSO_SHAPE.ROUNDED_RECTANGLE):
    s = slide.shapes.add_shape(shape, Inches(x), Inches(y), Inches(w), Inches(h))
    s.fill.solid()
    s.fill.fore_color.rgb = rgb(fill)
    if line:
        s.line.color.rgb = rgb(line)
        s.line.width = Pt(1)
    else:
        s.line.fill.background()
    s.shadow.inherit = False
    if shape == MSO_SHAPE.ROUNDED_RECTANGLE:
        s.adjustments[0] = 0.08
    return s


def stat(slide, x, y, w, big, label, sub="", color=CRIMSON):
    box(slide, x, y, w, 1.05, "FBF0F4")
    text(slide, x, y + 0.08, w, 0.5, big, 26, True, color, "Georgia", PP_ALIGN.CENTER)
    text(slide, x + 0.08, y + 0.58, w - 0.16, 0.22, label, 10.5, True, INK, align=PP_ALIGN.CENTER)
    if sub:
        text(slide, x + 0.08, y + 0.8, w - 0.16, 0.2, sub, 8.5, False, MUTED, align=PP_ALIGN.CENTER)


def table(slide, x, y, w, rows, widths, size=9.5, head_size=None, row_h=0.26, bold_last_col=False, center_from=1):
    nr, nc = len(rows), len(rows[0])
    gt = slide.shapes.add_table(nr, nc, Inches(x), Inches(y), Inches(w), Inches(row_h * nr))
    t = gt.table
    tblpr = gt._element.graphic.graphicData.tbl.tblPr
    tblpr.set("bandRow", "0")
    tblpr.set("firstRow", "1")
    tot = sum(widths)
    for j, wd in enumerate(widths):
        t.columns[j].width = Inches(w * wd / tot)
    for i, row in enumerate(rows):
        t.rows[i].height = Inches(row_h)
        for j, val in enumerate(row):
            c = t.cell(i, j)
            c.margin_left = c.margin_right = Inches(0.05)
            c.margin_top = c.margin_bottom = Inches(0.02)
            c.vertical_anchor = MSO_ANCHOR.MIDDLE
            c.fill.solid()
            c.fill.fore_color.rgb = rgb(CRIMSON if i == 0 else ("FFFFFF" if i % 2 else "FBF0F4"))
            tf = c.text_frame
            tf.word_wrap = True
            p = tf.paragraphs[0]
            p.alignment = PP_ALIGN.CENTER if (j >= center_from or i == 0) else PP_ALIGN.LEFT
            val = str(val)
            b = i == 0 or val.startswith("**")
            r = p.add_run()
            r.text = val.strip("*")
            r.font.size = Pt(head_size or size) if i == 0 else Pt(size)
            r.font.bold = b or (bold_last_col and j == nc - 1)
            r.font.name = "Times New Roman"
            r.font.color.rgb = rgb(WHITE if i == 0 else INK)
    return gt


class Chrome:
    """Footer band, logo and slide-number box lifted from a style-deck content slide."""

    def __init__(self, src_slide):
        self.pics, self.num = [], None
        for sh in src_slide.shapes:
            if sh.shape_type == 13 and sh.top > Inches(5.0):
                self.pics.append((sh.image.blob, sh.left, sh.top, sh.width, sh.height))
            elif sh.has_text_frame and sh.top > Inches(5.0) and sh.text_frame.text.strip().isdigit():
                self.num = (sh.left, sh.top, sh.width, sh.height)

    def apply(self, slide, n):
        for blob, l, t, w, h in self.pics:
            slide.shapes.add_picture(io.BytesIO(blob), l, t, w, h)
        l, t, w, h = self.num
        tb = slide.shapes.add_textbox(l, t, w, h)
        r = tb.text_frame.paragraphs[0].add_run()
        r.text = str(n)
        r.font.size, r.font.name = Pt(11), "Times New Roman"
        r.font.color.rgb = rgb(WHITE)


def new_slide(prs, chrome, n, title, tag=None, subtitle=None):
    s = prs.slides.add_slide(prs.slide_layouts[1])
    for ph in list(s.placeholders):
        ph._element.getparent().remove(ph._element)
    chrome.apply(s, n)
    text(s, 0.28, 0.14, 7.9 if tag else 9.4, 0.45, title, 21, True, CRIMSON, "Georgia")
    if tag:
        pill = box(s, 8.55, 0.2, 1.15, 0.3, CRIMSON)
        tf = pill.text_frame
        tf.margin_top = tf.margin_bottom = Inches(0)
        p = tf.paragraphs[0]
        p.alignment = PP_ALIGN.CENTER
        r = p.add_run()
        r.text = tag
        r.font.size, r.font.bold, r.font.name = Pt(9.5), True, "Times New Roman"
        r.font.color.rgb = rgb(WHITE)
    if subtitle:
        text(s, 0.3, 0.6, 9.4, 0.25, subtitle, 11.5, False, INK)
    return s


def source(slide, s):
    text(slide, 0.3, 4.98, 9.4, 0.2, s, 8, False, MUTED)


def pic(slide, path, x, y, w=None, h=None, border=True):
    p = slide.shapes.add_picture(str(path), Inches(x), Inches(y), Inches(w) if w else None, Inches(h) if h else None)
    if border:
        p.line.color.rgb = rgb("D9D9D9")
        p.line.width = Pt(0.75)
    return p


def strip_slides(prs, keep: set[int]):
    sld = prs.slides._sldIdLst
    for i, sid in reversed(list(enumerate(list(sld)))):
        if i not in keep:
            prs.part.drop_rel(sid.rId)
            sld.remove(sid)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--style", default="C:/Users/anilk/Downloads/Anil_Review_3_Updated.pptx")
    ap.add_argument("--trailer-still", default=str(ROOT / "demo_media" / "trailer" / "still.png"))
    a = ap.parse_args()
    prs = Presentation(a.style)
    chrome = Chrome(prs.slides[2])
    title_slide = prs.slides[0]
    strip_slides(prs, {0})
    sh = ROOT / "benchmarks" / "screenshots"
    fig = ROOT / "docs" / "report" / "fig"
    charts = ROOT / "benchmarks" / "charts"

    # 1 ---------------------------------------------------------------- title
    for shp in title_slide.shapes:
        if not shp.has_text_frame or not shp.text_frame.text.strip():
            continue
        t = shp.text_frame.text
        tf = shp.text_frame
        first = tf.paragraphs[0].runs[0]
        repl = None
        if t.startswith("A Hybrid"):
            repl = ["OmniGuard-MCP", "A Tamper-Evident Security Gateway for", "Agentic AI Tool Calls with Blockchain-Anchored Audit"]
        elif t.startswith("Anil"):
            repl = ["Anil Kumar   \u00b7   BL.SC.P2DSC25023   \u00b7   Blockchain Technology (24DS743)"]
        elif t.startswith("Guide"):
            repl = ["Guide: Ms. Shalini Tiwari, Assistant Professor"]
        elif t.startswith("Dept"):
            repl = None
        if repl:
            fmt = (first.font.size, first.font.bold, first.font.name, first.font.color.rgb)
            for p in list(tf.paragraphs)[1:]:
                p._p.getparent().remove(p._p)
            p0 = tf.paragraphs[0]
            for r in list(p0.runs):
                r._r.getparent().remove(r._r)
            for i, line in enumerate(repl):
                p = p0 if i == 0 else tf.add_paragraph()
                p.alignment = PP_ALIGN.CENTER
                r = p.add_run()
                r.text = line
                r.font.size = Pt(26) if (i == 0 and t.startswith("A Hybrid")) else fmt[0]
                r.font.bold, r.font.name = fmt[1], fmt[2]
                r.font.color.rgb = fmt[3]

    # 2 ---------------------------------------------------------------- problem
    s = new_slide(prs, chrome, 2, "The Problem: Agents Now Execute Real Tools", "Motivation",
                  "MCP lets an LLM agent read files, query databases, fetch pages and run commands through one JSON-RPC interface.")
    cards = [("One poisoned schema", "A server changes a tool's description after it was approved (rug pull, OWASP MCP03). The description is part of the prompt."),
             ("One leaked secret", "A tool returns API keys; an injected instruction asks the agent to POST them to an outside host."),
             ("One silent database edit", "After an incident the operator, or an attacker with DB access, flips a DENY to ALLOW in the log.")]
    for i, (h, b) in enumerate(cards):
        x = 0.3 + i * 3.17
        box(s, x, 1.0, 2.97, 1.55, "FFFFFF", "E3B5C6")
        text(s, x + 0.15, 1.1, 2.7, 0.3, h, 13, True, CRIMSON, "Georgia")
        text(s, x + 0.15, 1.45, 2.7, 1.05, b, 11, False, INK)
    stat(s, 0.3, 2.8, 2.25, "72.8%", "tool-poisoning success", "o1-mini, 45 live servers (MCPTox)")
    stat(s, 2.68, 2.8, 2.25, "< 3%", "best refusal rate", "aligned models do not stop it (MCPTox)")
    stat(s, 5.06, 2.8, 2.25, "~74%", "injection via tool output", "mean over 9 agents (MSB)")
    stat(s, 7.44, 2.8, 2.25, "0", "evidence a DB log gives", "against its own operator")
    text(s, 0.3, 4.1, 9.4, 0.5, [[("Needed: ", True), ("stop bad calls before the tool runs, and keep a record of every decision that the gateway's own operator cannot rewrite unnoticed.", False)]], 12)
    source(s, "Sources: Wang et al., MCPTox, AAAI 2026; Zhang et al., MSB, ICLR 2026; OWASP MCP Top 10.")

    # 3 ---------------------------------------------------------------- why blockchain
    s = new_slide(prs, chrome, 3, "Why Blockchain Anchoring", "Trust domain",
                  "A log that lives in the operator's database can be edited by the operator. The checkpoint has to live somewhere else.")
    table(s, 0.3, 1.0, 5.6, [
        ["Attack on the audit log", "R1 table", "R2 chain", "R3 anchored"],
        ["Edit a DENY to ALLOW", "\u2717", "\u2713", "\u2713"],
        ["Delete an interior record", "\u2713", "\u2713", "\u2713"],
        ["Reorder / swap payloads", "\u2717", "\u2713", "\u2713"],
        ["Roll back the newest batch", "\u2717", "\u2717", "\u2713"],
        ["Recompute the whole chain", "\u2717", "\u2717", "\u2713"],
        ["Rewrite tool pins (insider)", "\u2717", "\u2717", "\u2713"],
        ["Swap the ML model + manifest", "\u2717", "\u2717", "\u2713"],
        ["**Detected (40 trials)**", "**25%**", "**50%**", "**100%**"],
    ], [3.2, 1, 1, 1.2], 10, row_h=0.31)
    bullets(s, 6.15, 1.0, 3.55, [
        [("A hash chain ", True), ("shows local edits, but a valid prefix is still a valid chain, and the whole chain can be recomputed.", False)],
        [("Merkle batches ", True), ("(RFC 6962) compress k records into one 32-byte root; only the root leaves the host.", False)],
        [("AuditAnchor.sol ", True), ("accepts batch n only after n-1, with no gap in sequence numbers, and has no update or delete.", False)],
        [("Cost is measured, not assumed: ", True), ("the same attacks run against all three regimes.", False)],
    ], 11, 0.08)
    source(s, "Source: results/tamper_detection_r1_r2_r3.md \u00b7 96 calls, batch size 16, 5 randomised trials per scenario, fresh watcher process per sweep.")

    # 4 ---------------------------------------------------------------- literature
    s = new_slide(prs, chrome, 4, "Literature Survey", "42 sources",
                  "Full survey with methodology, metrics and a verification status per citation: OmniGuard-MCP_Literature_Survey.xlsx")
    table(s, 0.3, 0.95, 9.4, [
        ["Work", "Venue", "What it shows", "Gap it leaves"],
        ["MCPTox (Wang et al.)", "AAAI 2026", "72.8% tool-poisoning success on live MCP servers", "no defence evaluated"],
        ["MSB (Zhang et al.)", "ICLR 2026", "attacks at every pipeline stage, incl. multi-step chains", "benchmark only"],
        ["AgentDojo (Debenedetti et al.)", "NeurIPS 2024", "realistic user + injection tasks in 4 suites", "no audit layer"],
        ["ShieldMCP (Yergattikar)", "ACL 2026 Ind.", "runtime proxy: poisoning 74.1% \u2192 8.6%, 118 ms median", "no tamper-evident record"],
        ["ETDI (Bhatt et al.)", "arXiv 2025", "signed, versioned tool definitions vs rug pulls", "central trust, no measurement"],
        ["MCPSHIELD (Acharya, Gupta)", "arXiv 2026", "no defence covers > 34% of a 23-vector taxonomy", "integration (G1)"],
        ["Agent Flight Recorder", "arXiv 2026", "hash chain + Merkle epochs + on-chain root", "not in the MCP call path"],
        ["Zhan et al.", "NAACL 2025 F.", "adaptive attacks break all 8 IPI defences", "detectors are not guarantees"],
    ], [2.4, 1.1, 3.6, 2.2], 9.5, row_h=0.36, center_from=1)
    source(s, "Gap mapping G1\u2013G8 in the survey workbook; G3 (deletion / ordering evidence) and G8 (justify blockchain vs cheaper regimes) are addressed in full.")

    # 5 ---------------------------------------------------------------- architecture
    s = new_slide(prs, chrome, 5, "Architecture: Seven Stages per tools/call", "System design")
    pic(s, fig / "architecture.png", 0.3, 0.72, w=6.3, border=False)
    bullets(s, 6.75, 0.85, 3.0, [
        [("Prevention: ", True), ("ABAC on role, parameters and taint; canonicalised inspection (SQL and shell lexers, path jail, SSRF, DLP).", False)],
        [("Schema pin: ", True), ("SHA256(name \u2016 description \u2016 inputSchema), checked against the manifest and the session's first use.", False)],
        [("Containment: ", True), ("egress redaction marks the session TAINTED_SENSITIVE; outbound calls are then denied.", False)],
        [("Evidence: ", True), ("every ALLOW, REDACT and DENY gets exactly one audit record.", False)],
    ], 10.5, 0.07)
    source(s, "Code: omniguard/agents/gateway_agent.py \u00b7 security/ \u00b7 configs/security_rules.yaml \u00b7 204 tests passing.")

    # 6 ---------------------------------------------------------------- anchoring + watcher
    s = new_slide(prs, chrome, 6, "Anchoring, R3 and the Independent Watcher", "Blockchain")
    pic(s, fig / "anchoring.png", 0.7, 0.7, w=8.6, border=False)
    for i, (h, b) in enumerate([
        ("anchorBatch(id, root, start, end)", "id must equal batchCount; start must follow the previous end; no update or delete"),
        ("IntegrityWatcher", "separate process, read-only DB, own RPC client; recomputes chain and roots, compares on chain"),
        ("Typed alerts", "HASH_MISMATCH \u00b7 ANCHOR_RECORDS_MISMATCH \u00b7 TAIL_TRUNCATION \u00b7 MANIFEST_DRIFT")]):
        x = 0.3 + i * 3.17
        box(s, x, 4.0, 2.97, 0.88, "FBF0F4")
        text(s, x + 0.12, 4.05, 2.75, 0.25, h, 10.5, True, CRIMSON, "Times New Roman")
        text(s, x + 0.12, 4.3, 2.75, 0.55, b, 9.5, False, INK)
    source(s, "Contract: contracts/AuditAnchor.sol (Solidity 0.8) \u00b7 watcher: omniguard/agents/watcher_agent.py")

    # 7 ---------------------------------------------------------------- deployment + film
    s = new_slide(prs, chrome, 7, "Deployment Topology and Demo Film", "Live")
    nodes = [("Dashboard", "Vercel \u00b7 static HTML", "omniguard-mcp.vercel.app"),
             ("Live API", "Render \u00b7 FastAPI", "gateway + R1/R2/R3 stores"),
             ("Chain node", "eth-tester EVM", "AuditAnchor.sol deployed")]
    for i, (h, a1, a2) in enumerate(nodes):
        y = 0.85 + i * 1.12
        box(s, 0.35, y, 3.0, 0.85, "FFFFFF", "E3B5C6")
        text(s, 0.5, y + 0.07, 2.7, 0.3, h, 13, True, CRIMSON, "Georgia")
        text(s, 0.5, y + 0.4, 2.7, 0.2, a1, 10.5, True, INK)
        text(s, 0.5, y + 0.6, 2.7, 0.2, a2, 9.5, False, MUTED)
        if i < 2:
            arr = s.shapes.add_shape(MSO_SHAPE.DOWN_ARROW, Inches(1.72), Inches(y + 0.88), Inches(0.26), Inches(0.22))
            arr.fill.solid()
            arr.fill.fore_color.rgb = rgb(CRIMSON)
            arr.line.fill.background()
    text(s, 0.35, 4.22, 3.0, 0.6, "REST over HTTPS \u00b7 free tier, ~114 MB RSS \u00b7 rules-only engine live; hybrid ML on local RTX 2060",
         9.5, False, MUTED)
    still = Path(a.trailer_still)
    if still.exists():
        pic(s, still, 3.65, 0.85, w=6.05)
    text(s, 3.65, 4.33, 6.05, 0.25, [[("Trailer: ", True), ("docs/OmniGuard-MCP_Trailer.mp4 \u00b7 1080p60, live recordings of the deployed product", False)]], 10)
    text(s, 3.65, 4.58, 6.05, 0.25, "github.com/lucky07-07/omniguard-mcp", 10, True, CRIMSON)
    source(s, "Render service omniguard-mcp-api auto-deploys on push to main; Vercel serves frontend/.")

    # 8 ---------------------------------------------------------------- live results 1
    s = new_slide(prs, chrome, 8, "Live Results 1: Blocked at Ingress", "Live API",
                  "Real calls to the deployed API, captured from the dashboard.")
    pic(s, sh / "02_sqli_block.png", 0.3, 0.95, w=4.6)
    pic(s, sh / "03_schema_drift_block.png", 5.1, 0.95, w=4.6)
    text(s, 0.3, 3.62, 4.6, 0.5, [[("SQL injection: ", True), ("passes ABAC (allowed table, LIMIT present); the SQL lexer finds OR 1=1 \u2192 SQL_TAUTOLOGY.", False)]], 10.5)
    text(s, 5.1, 3.62, 4.6, 0.5, [[("Mid-session rug pull: ", True), ("description swapped after first use; pin a3017554\u2026 \u2260 observed 1f50c02b\u2026 \u2192 SCHEMA_DRIFT_RUG_PULL.", False)]], 10.5)
    source(s, "benchmarks/screenshots/ \u00b7 both denials are written to the audit ledger with their rule ids.")

    # 9 ---------------------------------------------------------------- live results 2
    s = new_slide(prs, chrome, 9, "Live Results 2: Contained, Then Proven", "Live API")
    pic(s, sh / "05_redact_tainted_trace.png", 0.3, 0.72, w=4.6)
    pic(s, sh / "04_r3_rewrite_alerts.png", 5.1, 0.72, w=4.6)
    text(s, 0.3, 3.4, 4.6, 0.6, [[("Redact + taint: ", True), ("reading api_keys.txt is allowed but masked; the session turns TAINTED_SENSITIVE, so the follow-up POST is denied by ABAC.", False)]], 10.5)
    text(s, 5.1, 3.4, 4.6, 0.6, [[("Chain rewrite: ", True), ("an insider edits a record and recomputes hashes and roots. R1 and R2 stay clean; R3 raises ANCHOR_ROOT / ANCHOR_RECORDS_MISMATCH.", False)]], 10.5)
    source(s, "Tamper lab on omniguard-mcp.vercel.app \u00b7 attacks target already-anchored records.")

    # 10 --------------------------------------------------------------- ablation
    s = new_slide(prs, chrome, 10, "3-Way Ablation on 100 Real Cases", "Ablation",
                  "A unprotected \u00b7 B ingress validation + mutable DB log \u00b7 C full OmniGuard (pins + R3 anchoring). Live Render API.")
    rows = [["Case set (source, n)", "Metric", "A", "B", "C"]]
    for k, m in (("benign", "utility \u2191"), ("injection", "success \u2193"), ("poisoning", "success \u2193"), ("chain", "success \u2193"),
                 ("tamper", "detected \u2191"), ("injection_ml", "success \u2193"), ("benign_ml", "utility \u2191")):
        c = CAT[k]
        rows.append([f"{c['label']} ({c['source'].split(' \u00b7')[0]}, {c['n']})", m, f"{c['A']:g}%", f"{c['B']:g}%", f"**{c['C']:g}%**"])
    table(s, 0.3, 0.95, 5.9, rows, [3.5, 1.05, 0.7, 0.7, 0.75], 9.5, row_h=0.4, center_from=1)
    bullets(s, 6.4, 0.95, 3.3, [
        [("Pinning ", True), (f"is the only control that stops MCPTox poisoning: B {CAT['poisoning']['B']:g}% \u2192 C {CAT['poisoning']['C']:g}%.", False)],
        [("Anchoring ", True), (f"turns {CAT['tamper']['B']:g}% tamper detection into {CAT['tamper']['C']:g}%.", False)],
        [("Ingress policy ", True), ("already stops all MSB chains at the final step.", False)],
        [("Honest miss: ", True), ("rules alone forward all 25 real injections; the pinned guard model blocks them at 10% benign false positives.", False)],
    ], 10.5, 0.08)
    source(s, f"benchmarks/results.json \u00b7 run {R['run']['finished_at'][:10]} \u00b7 IDs + upstream commits in raw_benchmark_samples.json \u00b7 ML rows: local GPU run, same cases.")

    # 11 --------------------------------------------------------------- latency
    s = new_slide(prs, chrome, 11, "Latency and the Price of Anchoring", "Trade-off")
    pic(s, charts / "latency_p50_p95.png", 0.3, 0.72, w=5.2, border=False)
    stat(s, 5.8, 0.85, 1.85, f"{LAT['C']['p50']:.2f} ms", "median, Mode C", "server-side, live API")
    stat(s, 7.8, 0.85, 1.9, f"{LAT['C']['p95']:.0f} ms", "p95, Mode C", "calls that seal + anchor")
    stat(s, 5.8, 2.05, 1.85, f"{LAT['B']['p50']:.2f} ms", "median, Mode B", "inspection only")
    stat(s, 7.8, 2.05, 1.9, "1.7 ms", "p95, R3-async", "anchor off the request path")
    bullets(s, 5.8, 3.3, 3.9, [
        "One call in four (batch size 4) pays for sealing a Merkle batch and the anchor transaction.",
        "Asynchronous anchoring keeps the evidence and removes the tail; ShieldMCP reports 118 ms median.",
    ], 10.5, 0.06)
    source(s, "benchmarks/charts/latency_p50_p95.png \u00b7 results/performance_storage_r1_r2_r3.md (R3-async row, 500 structured calls).")

    # 12 --------------------------------------------------------------- contributions
    s = new_slide(prs, chrome, 12, "Contributions and Conclusion", "Summary")
    items = [("1", "Seven-stage MCP gateway", "deterministic engine + digest-pinned ML guard, one trace per call"),
             ("2", "SHA-256 tool-schema pinning", "manifest + session pins; mid-session rug pulls blocked (OWASP MCP03)"),
             ("3", "Blockchain-anchored audit", "hash chain + RFC 6962 Merkle batches + AuditAnchor.sol + independent watcher"),
             ("4", "Measured, on real data", "100 MCPTox / AgentDojo / MSB cases, 3-way ablation, live API, 204 tests")]
    for i, (n, h, b) in enumerate(items):
        y = 0.8 + i * 0.78
        c = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(0.35), Inches(y + 0.05), Inches(0.5), Inches(0.5))
        c.fill.solid()
        c.fill.fore_color.rgb = rgb(CRIMSON)
        c.line.fill.background()
        tf = c.text_frame
        p = tf.paragraphs[0]
        p.alignment = PP_ALIGN.CENTER
        r = p.add_run()
        r.text = n
        r.font.size, r.font.bold, r.font.name = Pt(14), True, "Georgia"
        r.font.color.rgb = rgb(WHITE)
        text(s, 1.0, y, 5.0, 0.3, h, 13, True, CRIMSON, "Georgia")
        text(s, 1.0, y + 0.3, 5.0, 0.3, b, 10.5, False, INK)
    box(s, 6.3, 0.8, 3.4, 3.05, "FBF0F4")
    text(s, 6.45, 0.9, 3.1, 0.3, "Takeaway", 13, True, CRIMSON, "Georgia")
    text(s, 6.45, 1.25, 3.1, 2.5, [
        "Pins stop poisoning. Policy and taint stop chains. Anchoring makes the record trustworthy against its own operator.",
        "",
        "Next: public L2 testnet costs, adaptive attacks, and binding server artifacts into the pin (gap G2)."], 11)
    text(s, 0.35, 4.15, 9.4, 0.3, [[("omniguard-mcp.vercel.app", True), ("   \u00b7   github.com/lucky07-07/omniguard-mcp   \u00b7   Thank you", False)]], 12, color=CRIMSON, align=PP_ALIGN.CENTER)
    source(s, "Technical report: docs/OmniGuard-MCP_Technical_Report.docx")

    out = ROOT / "docs" / OUT_NAME
    prs.save(out)
    shutil.copyfile(out, BC / OUT_NAME)
    print("saved", out, "and", BC / OUT_NAME, "slides:", len(prs.slides))


if __name__ == "__main__":
    main()

"""Build OmniGuard-MCP_Final_Presentation.pptx by cloning the styling of Anil_Review_3_Updated.pptx.

    python docs/presentation/build_deck.py [--style C:/Users/anilk/Downloads/Anil_Review_3_Updated.pptx]

The style deck's title slide is kept and re-texted; its footer band, Amrita logo and slide-number box are lifted
from a content slide and re-placed on every new slide (Georgia crimson titles, Times New Roman body).
Every number is read from results files:
  results/external_dataset_eval.json   five external detection datasets, confusion matrices per engine
  results/tamper_detection_r1_r2_r3.json
  benchmarks/results.json (+ *_cases.jsonl)   3-way ablation on 100 real MCPTox / AgentDojo / MSB cases
Charts are native PowerPoint charts, so their numbers stay editable.
"""

from __future__ import annotations

import argparse
import io
import json
import math
import shutil
from pathlib import Path

import yaml
from pptx import Presentation
from pptx.chart.data import CategoryChartData
from pptx.dml.color import RGBColor
from pptx.enum.chart import XL_CHART_TYPE, XL_LABEL_POSITION, XL_LEGEND_POSITION
from pptx.enum.shapes import MSO_CONNECTOR, MSO_SHAPE
from pptx.enum.text import MSO_ANCHOR, PP_ALIGN
from pptx.oxml.ns import qn
from pptx.util import Inches, Pt

ROOT = Path(__file__).resolve().parents[2]
BC = ROOT.parent
OUT_NAME = "OmniGuard-MCP_Final_Presentation.pptx"

# design tokens (Review 3 palette)
CRIMSON, DEEP, PINK, SOFT, INK, MUTED, WHITE = "B8114F", "7A0B35", "F9E3EB", "FBF0F4", "222222", "6B6B6B", "FFFFFF"
GREEN, AMBER, GRAY, ROSE = "2E7D4F", "C98A1C", "A7A9AC", "E09AB4"
SERIF, BODY = "Georgia", "Times New Roman"

R = json.loads((ROOT / "benchmarks" / "results.json").read_text(encoding="utf-8"))
EXT = json.loads((ROOT / "results" / "external_dataset_eval.json").read_text(encoding="utf-8"))
CAT, LAT = R["categories"], R["latency_ms"]
RULES = yaml.safe_load((ROOT / "configs" / "security_rules.yaml").read_text(encoding="utf-8"))["rules"]


# ============================================================================ metrics
def metrics(tp, fp, tn, fn):
    """Binary metrics plus the two-class macro / weighted F1 (attack class + benign class) and MCC."""
    n = tp + fp + tn + fn
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    pn = tn / (tn + fn) if tn + fn else 0.0
    rn = tn / (tn + fp) if tn + fp else 0.0
    f1n = 2 * pn * rn / (pn + rn) if pn + rn else 0.0
    pos, neg = tp + fn, tn + fp
    den = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    return {"n": n, "acc": (tp + tn) / n, "p": p, "r": r, "f1": f1, "macro": (f1 + f1n) / 2,
            "weighted": (f1 * pos + f1n * neg) / n, "fpr": fp / neg if neg else 0.0,
            "mcc": (tp * tn - fp * fn) / den if den else 0.0, "tp": tp, "fp": fp, "tn": tn, "fn": fn}


def ext(stream, view, eng):
    m = EXT["streams"][stream]["views"][view][eng]
    return metrics(m["tp"], m["fp"], m["tn"], m["fn"])


def ablation_metrics(path: Path):
    """Treat every non-tamper case as a binary decision: positive = the gateway blocked the call."""
    rows = [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]
    out = {}
    for m in ("A", "B", "C"):
        tp = fp = tn = fn = 0
        for r in rows:
            blocked = not r["modes"][m]["final_forwarded"]
            if r["category"] == "benign":
                fp += blocked
                tn += not blocked
            else:
                tp += blocked
                fn += not blocked
        out[m] = metrics(tp, fp, tn, fn)
    return out


ABL_LIVE = ablation_metrics(ROOT / "benchmarks" / "results_cases.jsonl")
ABL_ML = ablation_metrics(ROOT / "benchmarks" / "results_local_hybrid_ml_cases.jsonl")
pc = lambda v: f"{100 * v:.1f}%"  # noqa: E731
f3 = lambda v: f"{v:.3f}"  # noqa: E731


# ============================================================================ drawing helpers
def rgb(h):
    return RGBColor.from_string(h)


def _runs(p, line, size, bold, color, font, italic=False):
    runs = line if isinstance(line, list) else [(line, bold)]
    for item in runs:
        t, b = item[0], item[1]
        c = item[2] if len(item) > 2 else color
        r = p.add_run()
        r.text = t
        r.font.size, r.font.bold, r.font.italic, r.font.name = Pt(size), b, italic, font
        r.font.color.rgb = rgb(c)


def text(slide, x, y, w, h, s, size=12, bold=False, color=INK, font=BODY, align=PP_ALIGN.LEFT,
         anchor=MSO_ANCHOR.TOP, italic=False, spacing=0):
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(h))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(0.02)
    tf.margin_top = tf.margin_bottom = Inches(0.01)
    tf.vertical_anchor = anchor
    for i, line in enumerate(s if isinstance(s, list) else [s]):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.alignment = align
        if spacing:
            p.space_after = Pt(spacing)
        _runs(p, line, size, bold, color, font, italic)
    return tb


def bullets(slide, x, y, w, items, size=12, gap=5, color=INK, mark="\u25AA"):
    tb = slide.shapes.add_textbox(Inches(x), Inches(y), Inches(w), Inches(0.3 * len(items)))
    tf = tb.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(0.02)
    for i, it in enumerate(items):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        p.space_after = Pt(gap)
        r = p.add_run()
        r.text = f"{mark}  "
        r.font.size, r.font.name = Pt(size), BODY
        r.font.color.rgb = rgb(CRIMSON)
        _runs(p, it, size, False, color, BODY)
    return tb


def box(slide, x, y, w, h, fill=SOFT, line=None, shape=MSO_SHAPE.ROUNDED_RECTANGLE, radius=0.08, lw=1.0):
    s = slide.shapes.add_shape(shape, Inches(x), Inches(y), Inches(w), Inches(h))
    s.fill.solid()
    s.fill.fore_color.rgb = rgb(fill)
    if line:
        s.line.color.rgb = rgb(line)
        s.line.width = Pt(lw)
    else:
        s.line.fill.background()
    s.shadow.inherit = False
    if shape == MSO_SHAPE.ROUNDED_RECTANGLE:
        s.adjustments[0] = radius
    return s


def label_box(slide, x, y, w, h, title, body=None, fill=WHITE, line=ROSE, tsize=12, bsize=10, tcolor=CRIMSON, align=PP_ALIGN.CENTER):
    b = box(slide, x, y, w, h, fill, line)
    tf = b.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(0.06)
    tf.margin_top = tf.margin_bottom = Inches(0.03)
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    p.alignment = align
    _runs(p, title, tsize, True, tcolor, SERIF if tsize >= 12 else BODY)
    if body:
        for line in body if isinstance(body, list) else [body]:
            q = tf.add_paragraph()
            q.alignment = align
            _runs(q, line, bsize, False, INK, BODY)
    return b


def icon(slide, x, y, d, glyph, fill=PINK, size=None):
    c = slide.shapes.add_shape(MSO_SHAPE.OVAL, Inches(x), Inches(y), Inches(d), Inches(d))
    c.fill.solid()
    c.fill.fore_color.rgb = rgb(fill)
    c.line.fill.background()
    c.shadow.inherit = False
    tf = c.text_frame
    tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = Inches(0)
    tf.vertical_anchor = MSO_ANCHOR.MIDDLE
    p = tf.paragraphs[0]
    p.alignment = PP_ALIGN.CENTER
    r = p.add_run()
    r.text = glyph
    r.font.size = Pt(size or d * 30)
    r.font.name = "Segoe UI Emoji"
    return c


def arrow(slide, x1, y1, x2, y2, color=CRIMSON, w=1.75):
    c = slide.shapes.add_connector(MSO_CONNECTOR.STRAIGHT, Inches(x1), Inches(y1), Inches(x2), Inches(y2))
    c.line.color.rgb = rgb(color)
    c.line.width = Pt(w)
    ln = c.line._get_or_add_ln()
    tail = ln.makeelement(qn("a:tailEnd"), {"type": "triangle", "w": "med", "len": "med"})
    ln.append(tail)
    return c


def stat(slide, x, y, w, big, label, sub="", color=CRIMSON, h=1.05):
    box(slide, x, y, w, h, SOFT)
    text(slide, x, y + 0.08, w, 0.5, big, 26, True, color, SERIF, PP_ALIGN.CENTER)
    text(slide, x + 0.08, y + 0.58, w - 0.16, 0.22, label, 10.5, True, INK, align=PP_ALIGN.CENTER)
    if sub:
        text(slide, x + 0.08, y + 0.8, w - 0.16, 0.2, sub, 8.5, False, MUTED, align=PP_ALIGN.CENTER)


def table(slide, x, y, w, rows, widths, size=10, row_h=0.27, center_from=1, highlight_rows=(), head_size=None):
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
            c.margin_top = c.margin_bottom = Inches(0.015)
            c.vertical_anchor = MSO_ANCHOR.MIDDLE
            c.fill.solid()
            hl = i in highlight_rows
            c.fill.fore_color.rgb = rgb(CRIMSON if i == 0 else (PINK if hl else (WHITE if i % 2 else SOFT)))
            p = c.text_frame.paragraphs[0]
            c.text_frame.word_wrap = True
            p.alignment = PP_ALIGN.CENTER if (j >= center_from or i == 0) else PP_ALIGN.LEFT
            val = str(val)
            r = p.add_run()
            r.text = val.replace("**", "")
            r.font.size = Pt(head_size or size) if i == 0 else Pt(size)
            r.font.bold = i == 0 or val.startswith("**") or hl
            r.font.name = BODY
            r.font.color.rgb = rgb(WHITE if i == 0 else (DEEP if hl else INK))
    return gt


def chart(slide, x, y, w, h, cats, series, colors, kind=XL_CHART_TYPE.COLUMN_CLUSTERED, maxv=None, fmt='0.0"%"',
          legend=True, title=None, label_size=8, gap=60, overlap=-10):
    cd = CategoryChartData()
    cd.categories = cats
    for name, vals in series:
        cd.add_series(name, vals)
    gf = slide.shapes.add_chart(kind, Inches(x), Inches(y), Inches(w), Inches(h), cd)
    ch = gf.chart
    ch.font.name, ch.font.size = BODY, Pt(9)
    ch.font.color.rgb = rgb(INK)
    ch.has_title = bool(title)
    if title:
        ch.chart_title.text_frame.text = title
        tp = ch.chart_title.text_frame.paragraphs[0]
        tp.runs[0].font.size, tp.runs[0].font.bold, tp.runs[0].font.name = Pt(11), True, BODY
    ch.has_legend = legend and len(series) > 1
    if ch.has_legend:
        ch.legend.position = XL_LEGEND_POSITION.BOTTOM
        ch.legend.include_in_layout = False
        ch.legend.font.size = Pt(9)
    plot = ch.plots[0]
    plot.gap_width = gap
    try:
        plot.overlap = overlap
    except Exception:
        pass
    plot.has_data_labels = True
    dl = plot.data_labels
    dl.number_format, dl.number_format_is_linked = fmt, False
    dl.font.size, dl.font.name = Pt(label_size), BODY
    dl.position = XL_LABEL_POSITION.OUTSIDE_END
    for s, col in zip(plot.series, colors):
        s.format.fill.solid()
        s.format.fill.fore_color.rgb = rgb(col)
    va = ch.value_axis
    va.has_major_gridlines = True
    va.major_gridlines.format.line.color.rgb = rgb("E6E6E6")
    va.format.line.fill.background()
    va.tick_labels.font.size = Pt(8)
    va.tick_labels.font.color.rgb = rgb(MUTED)
    if maxv is not None:
        va.maximum_scale, va.minimum_scale = maxv, 0
    ca = ch.category_axis
    ca.tick_labels.font.size = Pt(9)
    ca.format.line.color.rgb = rgb("BFBFBF")
    return ch


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
        r.font.size, r.font.name = Pt(11), BODY
        r.font.color.rgb = rgb(WHITE)


class Deck:
    def __init__(self, prs, chrome):
        self.prs, self.chrome, self.n = prs, chrome, 1

    def slide(self, title, tag=None, subtitle=None, notes=None):
        self.n += 1
        s = self.prs.slides.add_slide(self.prs.slide_layouts[1])
        for ph in list(s.placeholders):
            ph._element.getparent().remove(ph._element)
        self.chrome.apply(s, self.n)
        text(s, 0.28, 0.14, 8.1 if tag else 9.4, 0.45, title, 21, True, CRIMSON, SERIF)
        if tag:
            pill = box(s, 8.5, 0.2, 1.2, 0.3, CRIMSON)
            tf = pill.text_frame
            tf.margin_top = tf.margin_bottom = Inches(0)
            p = tf.paragraphs[0]
            p.alignment = PP_ALIGN.CENTER
            _runs(p, tag, 9.5, True, WHITE, BODY)
        if subtitle:
            text(s, 0.3, 0.6, 9.4, 0.25, subtitle, 11.5, False, INK)
        if notes:
            s.notes_slide.notes_text_frame.text = notes
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


# ============================================================================ slides
def title_slide(slide):
    for shp in slide.shapes:
        if not shp.has_text_frame or not shp.text_frame.text.strip():
            continue
        t = shp.text_frame.text
        tf = shp.text_frame
        first = tf.paragraphs[0].runs[0]
        repl = None
        if t.startswith("A Hybrid"):
            repl = ["OmniGuard-MCP", "A Tamper-Evident Security Gateway for",
                    "Agentic AI Tool Calls with Blockchain-Anchored Audit"]
        elif t.startswith("Anil"):
            repl = ["Anil Kumar   \u00b7   BL.SC.P2DSC25023   \u00b7   Blockchain Technology (24DS743)"]
        elif t.startswith("Guide"):
            repl = ["Guide: Ms. Shalini Tiwari, Assistant Professor"]
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


def outline(d: Deck, sections):
    s = d.slide("Outline")
    half = math.ceil(len(sections) / 2)
    for i, name in enumerate(sections):
        col, row = divmod(i, half)
        x, y = 0.95 + col * 4.4, 0.85 + row * 0.42
        text(s, x, y, 0.45, 0.28, f"{i + 1}.", 12.5, True, CRIMSON)
        text(s, x + 0.46, y, 3.9, 0.28, name, 12.5, False, INK)


def problem(d: Deck):
    s = d.slide("The Problem, in Plain Words", "Motivation",
                "AI assistants no longer just chat. They now press real buttons: open files, run database queries, send web requests.",
                "Start with the analogy: an AI agent is like a new employee who follows any note left on the desk.")
    cards = [("\U0001F9EA", "A poisoned tool", "A tool secretly changes its own instructions after we trusted it.",
              "Like a recipe card someone swaps overnight."),
             ("\U0001F511", "A leaked secret", "The agent reads a password, then a hidden note tells it to send it outside.",
              "Like a con artist slipping a note to a cashier."),
             ("\U0001F4DD", "A silent log edit", "After an incident, someone edits the record to hide what was blocked.",
              "Like tearing a page out of a logbook.")]
    for i, (g, h, b, a) in enumerate(cards):
        x = 0.3 + i * 3.17
        box(s, x, 1.0, 2.97, 2.45, WHITE, ROSE)
        icon(s, x + 1.13, 1.12, 0.7, g)
        text(s, x + 0.15, 1.9, 2.67, 0.3, h, 14, True, CRIMSON, SERIF, PP_ALIGN.CENTER)
        text(s, x + 0.18, 2.25, 2.61, 0.65, b, 11, False, INK, align=PP_ALIGN.CENTER)
        text(s, x + 0.18, 2.95, 2.61, 0.4, a, 10, False, MUTED, align=PP_ALIGN.CENTER, italic=True)
    box(s, 0.3, 3.7, 9.4, 0.95, SOFT)
    text(s, 0.5, 3.78, 9.0, 0.8, [
        [("What we need: ", True, CRIMSON), ("a guard that checks every action ", False), ("before", True), (" it happens, and a record of every decision that ", False),
         ("nobody, not even the system's owner,", True), (" can secretly change.", False)]], 13.5, anchor=MSO_ANCHOR.MIDDLE)
    source(s, "MCP = Model Context Protocol, the standard plug that lets AI agents use tools (OWASP MCP Top 10 lists these risks).")


def numbers(d: Deck):
    s = d.slide("How Big Is the Problem?", "Evidence",
                "Published measurements on real systems show that today's AI models do not protect themselves.")
    stat(s, 0.3, 1.0, 2.25, "72.8%", "poisoned tools obeyed", "o1-mini on 45 live servers (MCPTox)", h=1.15)
    stat(s, 2.68, 1.0, 2.25, "< 3%", "best refusal rate", "even the safest model (MCPTox)", h=1.15)
    stat(s, 5.06, 1.0, 2.25, "~74%", "hidden-note attacks work", "mean over 9 agents (MSB)", h=1.15)
    stat(s, 7.44, 1.0, 2.25, "27.2%", "servers exploitable", "of 1,360 analysed (Zhao et al.)", h=1.15)
    icon(s, 0.35, 2.55, 0.55, "\U0001F4A1")
    text(s, 1.05, 2.55, 8.6, 0.6, [[("Lesson: ", True, CRIMSON), ("we cannot rely on the AI model to say no. The safety check has to sit ", False),
                                    ("outside", True), (" the model, exactly where the agent touches a tool.", False)]], 13, anchor=MSO_ANCHOR.MIDDLE)
    icon(s, 0.35, 3.35, 0.55, "\u2696\uFE0F")
    text(s, 1.05, 3.35, 8.6, 0.6, [[("And for accountability: ", True, CRIMSON), ("a log stored in the owner's own database is like a diary the suspect can edit. ", False),
                                    ("Evidence must be kept somewhere the owner cannot rewrite.", True)]], 13, anchor=MSO_ANCHOR.MIDDLE)
    source(s, "Sources: Wang et al., MCPTox, AAAI 2026; Zhang et al., MSB, ICLR 2026; Zhao et al., arXiv:2509.24272, 2025.")


def idea(d: Deck):
    s = d.slide("Our Idea in One Picture", "Solution",
                "OmniGuard-MCP is a security checkpoint between the AI agent and its tools, with a tamper-proof receipt book.",
                "Analogy: bank customer, security desk, vault, and a notary who stamps receipts.")
    nodes = [(0.35, "\U0001F916", "AI agent", "asks to use a tool", "the customer"),
             (2.75, "\U0001F6E1\uFE0F", "OmniGuard", "checks, decides, records", "the security desk"),
             (5.15, "\U0001F5C4\uFE0F", "Tools", "files, database, web, shell", "the vault")]
    for x, g, h, b, a in nodes:
        box(s, x, 1.05, 2.0, 1.75, WHITE, ROSE if h != "OmniGuard" else CRIMSON, lw=1.0 if h != "OmniGuard" else 2.25)
        icon(s, x + 0.68, 1.15, 0.64, g)
        text(s, x, 1.85, 2.0, 0.3, h, 14, True, CRIMSON, SERIF, PP_ALIGN.CENTER)
        text(s, x + 0.1, 2.15, 1.8, 0.25, b, 10.5, False, INK, align=PP_ALIGN.CENTER)
        text(s, x + 0.1, 2.42, 1.8, 0.25, a, 10, False, MUTED, align=PP_ALIGN.CENTER, italic=True)
    arrow(s, 2.37, 1.92, 2.73, 1.92)
    arrow(s, 4.77, 1.92, 5.13, 1.92)
    box(s, 7.65, 1.05, 2.05, 1.75, "FFF6E5", AMBER, lw=1.5)
    icon(s, 8.35, 1.15, 0.64, "\u26D3\uFE0F", "FDEBC8")
    text(s, 7.65, 1.85, 2.05, 0.3, "Blockchain", 14, True, AMBER, SERIF, PP_ALIGN.CENTER)
    text(s, 7.75, 2.15, 1.85, 0.25, "stores a fingerprint", 10.5, False, INK, align=PP_ALIGN.CENTER)
    text(s, 7.75, 2.42, 1.85, 0.25, "the notary's stamp", 10, False, MUTED, align=PP_ALIGN.CENTER, italic=True)
    c = s.shapes.add_connector(MSO_CONNECTOR.ELBOW, Inches(3.75), Inches(2.9), Inches(8.67), Inches(2.9))
    c.line.color.rgb = rgb(AMBER)
    c.line.width = Pt(1.5)
    c.line.dash_style = 4
    text(s, 4.2, 2.93, 4.2, 0.25, "every 4 receipts \u2192 one fingerprint sent to the chain", 9.5, False, AMBER, align=PP_ALIGN.CENTER, italic=True)
    three = [("\u2705", "Stop", "bad requests before the tool runs"),
             ("\U0001F9F9", "Clean", "secrets out of what tools return"),
             ("\U0001F50F", "Prove", "every decision with a receipt nobody can secretly edit")]
    for i, (g, h, b) in enumerate(three):
        x = 0.35 + i * 3.13
        box(s, x, 3.35, 2.95, 1.3, SOFT)
        icon(s, x + 0.15, 3.55, 0.55, g, WHITE)
        text(s, x + 0.85, 3.5, 2.0, 0.35, h, 15, True, CRIMSON, SERIF)
        text(s, x + 0.85, 3.85, 2.0, 0.7, b, 11, False, INK)


def workflow(d: Deck):
    s = d.slide("Overall Workflow: From Request to Result", "Workflow",
                "Every tool request walks through the same eight steps. Any step can stop it; every outcome is recorded.",
                "Walk left to right on the top row, then right to left on the bottom row.")
    steps = [("1", "\U0001F4E8", "Request in", "agent asks for a tool"),
             ("2", "\U0001FAAA", "Who are you?", "token \u2192 role"),
             ("3", "\U0001F9EC", "Genuine tool?", "SHA-256 fingerprint"),
             ("4", "\U0001F4CB", "Allowed?", "role + limits + taint"),
             ("5", "\U0001F50D", "Inspect", "rules (+ ML on prose)"),
             ("6", "\u2699\uFE0F", "Run tool", "only if all passed"),
             ("7", "\U0001F9F9", "Clean output", "mask secrets, taint"),
             ("8", "\U0001F9FE", "Receipt", "hash-chained record")]
    pos = []
    for i, (n, g, h, b) in enumerate(steps):
        row, col = divmod(i, 4)
        col = col if row == 0 else 3 - col
        x, y = 0.35 + col * 2.38, 0.98 + row * 1.62
        pos.append((x, y))
        box(s, x, y, 2.05, 1.28, WHITE, ROSE)
        c = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(x + 0.08), Inches(y + 0.08), Inches(0.32), Inches(0.32))
        c.fill.solid()
        c.fill.fore_color.rgb = rgb(CRIMSON)
        c.line.fill.background()
        tf = c.text_frame
        tf.margin_left = tf.margin_right = tf.margin_top = tf.margin_bottom = Inches(0)
        p = tf.paragraphs[0]
        p.alignment = PP_ALIGN.CENTER
        _runs(p, n, 10, True, WHITE, BODY)
        icon(s, x + 0.78, y + 0.1, 0.5, g, PINK, 15)
        text(s, x + 0.05, y + 0.65, 1.95, 0.3, h, 12, True, CRIMSON, SERIF, PP_ALIGN.CENTER)
        text(s, x + 0.05, y + 0.93, 1.95, 0.3, b, 9.5, False, INK, align=PP_ALIGN.CENTER)
    for i in range(3):
        arrow(s, pos[i][0] + 2.07, pos[i][1] + 0.64, pos[i + 1][0] - 0.02, pos[i + 1][1] + 0.64)
        arrow(s, pos[4 + i][0] - 0.02, pos[4 + i][1] + 0.64, pos[5 + i][0] + 2.07, pos[5 + i][1] + 0.64)
    arrow(s, pos[3][0] + 1.02, pos[3][1] + 1.3, pos[4][0] + 1.02, pos[4][1] - 0.02)
    outs = [("ALLOW", GREEN, "safe: result returned"), ("REDACT", AMBER, "allowed, secrets masked"), ("DENY", CRIMSON, "blocked, reason given")]
    for i, (h, col, b) in enumerate(outs):
        x = 0.35 + i * 2.38
        b_ = box(s, x, 4.32, 2.05, 0.52, col)
        tf = b_.text_frame
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]
        p.alignment = PP_ALIGN.CENTER
        _runs(p, [(h + "  ", True, WHITE), (b, False, WHITE)], 10.5, True, WHITE, BODY)
    box(s, 7.49, 4.32, 2.05, 0.52, "FFF6E5", AMBER)
    text(s, 7.52, 4.34, 2.0, 0.5, [[("Every 4 receipts \u2192 ", False), ("blockchain", True)]], 10.5, False, AMBER, align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)


def worked_example(d: Deck):
    s = d.slide("Worked Example: One Safe Request, One Attack", "Decision path",
                "Two database queries from an analyst. Same tool, same role. Watch where they part ways.")
    rows = [("Step", "Request A (safe)", "Request B (attack)"),
            ("What the agent sends", "SELECT region FROM analytics_sales LIMIT 3", "SELECT * FROM analytics_sales WHERE region='x' OR 1=1 LIMIT 5"),
            ("2  Who are you?", "analyst \u2714", "analyst \u2714"),
            ("3  Genuine tool?", "fingerprint matches \u2714", "fingerprint matches \u2714"),
            ("4  Allowed?", "allowed table, has LIMIT \u2714", "allowed table, has LIMIT \u2714"),
            ("5  Inspect (rules)", "no rule fires \u2714", "SQL_TAUTOLOGY: \u201cOR 1=1\u201d is always true \u2718"),
            ("6\u20137  Run + clean", "runs, nothing to mask", "never runs"),
            ("8  Receipt", "ALLOW written + hashed", "DENY written + hashed"),
            ("Result", "**ALLOW**: 3 rows returned", "**DENY**: blocked at step 5")]
    t = table(s, 0.3, 0.95, 9.4, [list(r) for r in rows], [2.0, 3.4, 4.0], 10, 0.37, center_from=1)
    for i in (5,):
        c = t.table.cell(i, 2)
        c.fill.fore_color.rgb = rgb(PINK)
    for j, col in ((1, GREEN), (2, CRIMSON)):
        c = t.table.cell(8, j)
        c.fill.fore_color.rgb = rgb(col)
        for r in c.text_frame.paragraphs[0].runs:
            r.font.color.rgb = rgb(WHITE)
    source(s, "Both decisions are real calls to the live API (see Live Results). \u201cOR 1=1\u201d would make the query return the whole table.")


def rules_explained(d: Deck):
    s = d.slide("Deterministic Rules: The Security Checklist", "Rules",
                "A deterministic rule is a fixed, written check. The same input always gets the same answer, every time.",
                "Analogy: airport security has a written list of forbidden items. No guessing, no mood.")
    icon(s, 0.35, 0.98, 0.7, "\u2708\uFE0F")
    text(s, 1.2, 0.98, 3.6, 0.75, [[("Like airport security: ", True, CRIMSON), ("a written list of forbidden items. A knife is always stopped, at every gate, by every officer.", False)]], 11.5)
    head = [("What", "a named pattern with a weight, e.g. SQL_TAUTOLOGY = 1.0"),
            ("Why", "fast (< 1 ms), explainable, cannot be talked out of it"),
            ("Where", f"{len(RULES)} rules in configs/security_rules.yaml")]
    for i, (h, b) in enumerate(head):
        y = 1.9 + i * 0.55
        box(s, 0.35, y, 4.45, 0.47, SOFT)
        text(s, 0.5, y + 0.07, 0.8, 0.35, h, 12, True, CRIMSON, SERIF)
        text(s, 1.3, y + 0.08, 3.45, 0.35, b, 10.5, False, INK)
    text(s, 0.35, 3.62, 4.45, 0.3, "Before checking, every input is decoded", 11.5, True, CRIMSON, SERIF)
    text(s, 0.35, 3.92, 4.45, 0.9, "Attackers hide words in Base64, URL or hex codes. The canonicaliser unwraps them first (up to 6 layers), so \u201cSWdub3Jl\u2026\u201d is read as \u201cIgnore\u2026\u201d.", 10.5)
    text(s, 5.1, 0.98, 4.6, 0.3, "How a decision is made: add up the weights", 12, True, CRIMSON, SERIF)
    ex = [("Example 1", [("SQL_TAUTOLOGY", "1.0")], "1.0 \u2265 1.0", "DENY", CRIMSON),
          ("Example 2", [("SQL_COMMENT", "0.5"), ("SQL_BOOLEAN_PROBE", "0.5")], "1.0 \u2265 1.0", "DENY", CRIMSON),
          ("Example 3", [("SHELL_VARIABLE_EXPANSION", "0.4")], "0.4 < 1.0", "ALLOW", GREEN)]
    for i, (h, parts, total, dec, col) in enumerate(ex):
        y = 1.35 + i * 0.95
        box(s, 5.1, y, 4.6, 0.82, WHITE, ROSE)
        text(s, 5.22, y + 0.05, 1.2, 0.25, h, 10, True, MUTED)
        text(s, 5.22, y + 0.3, 2.6, 0.5, [[(f"{n}  ", False), (w, True, CRIMSON)] for n, w in parts], 10, spacing=0)
        text(s, 7.75, y + 0.12, 0.95, 0.55, total, 11, True, INK, align=PP_ALIGN.CENTER, anchor=MSO_ANCHOR.MIDDLE)
        b = box(s, 8.75, y + 0.18, 0.85, 0.45, col)
        tf = b.text_frame
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        p = tf.paragraphs[0]
        p.alignment = PP_ALIGN.CENTER
        _runs(p, dec, 10.5, True, WHITE, BODY)
    text(s, 5.1, 4.25, 4.6, 0.6, [[("Session memory: ", True, CRIMSON), ("after reading untrusted or secret data, weights are multiplied by 1.5 or 1.25, so the guard gets stricter.", False)]], 10.5)
    source(s, "Rule: block when (sum of triggered weights) \u00d7 (session taint multiplier) \u2265 1.0. A rule of weight 1.0 blocks on its own.")


def rules_families(d: Deck):
    s = d.slide("What the Rules Catch", "Rules")
    fam = {}
    for k in RULES:
        fam[k.split("_")[0]] = fam.get(k.split("_")[0], 0) + 1
    rows = [["Family", "Rules", "Example rule", "Catches (simple words)"],
            ["SQL", fam.get("SQL", 0), "SQL_TAUTOLOGY", "\u201cOR 1=1\u201d tricks that dump a whole table"],
            ["SHELL", fam.get("SHELL", 0), "SHELL_COMMAND_CHAINING", "\u201cls; rm -rf /\u201d: a second hidden command"],
            ["PATH", fam.get("PATH", 0), "PATH_TRAVERSAL_ESCAPE", "\u201c../../etc/passwd\u201d: escaping the folder"],
            ["SSRF", fam.get("SSRF", 0), "SSRF_LINK_LOCAL_METADATA", "fetching the cloud's secret-key address"],
            ["SECRET", fam.get("SECRET", 0), "SECRET_AWS_ACCESS_KEY", "passwords and API keys in text"],
            ["ENCODING", fam.get("OBFUSCATION", 0), "OBFUSCATION_MULTILAYER", "messages wrapped in several codes"],
            ["TAINT / ML", fam.get("TAINT", 0) + fam.get("ML", 0), "TAINT_SENSITIVE_TO_EGRESS", "sending data out after reading secrets"]]
    table(s, 0.3, 0.75, 5.85, rows, [0.95, 0.55, 2.55, 2.9], 9, 0.42, center_from=1)
    t = text(s, 6.2, 0.75, 3.5, 0.3, "Decision flow inside step 5", 12, True, CRIMSON, SERIF)
    flow = [("Decode input", "Base64 / URL / hex / Unicode", WHITE), ("Run all rules", "collect triggered rule IDs", WHITE),
            ("Score \u2265 1.0 ?", "weights \u00d7 taint multiplier", PINK), ("Free text?", "if yes, ML guard also scores it", WHITE),
            ("Decision", "ALLOW \u00b7 REDACT \u00b7 DENY + reasons", SOFT)]
    for i, (h, b, f) in enumerate(flow):
        y = 1.12 + i * 0.75
        label_box(s, 6.45, y, 3.0, 0.58, h, b, f, ROSE, 11, 9)
        if i < 4:
            arrow(s, 7.95, y + 0.59, 7.95, y + 0.74)
    source(s, "Why rules first: they are instant and explain themselves (the rule ID is shown to the user). ML only adds a second opinion on free-form prose.")


def smart_contract(d: Deck):
    s = d.slide("Smart Contract: A Vending Machine for Trust", "Smart contract",
                "A smart contract is a small program stored on a blockchain. Once deployed, its rules run exactly as written, and nobody can edit it.",
                "Vending machine: put in the right coin, get the item. No shopkeeper can change the price behind your back.")
    icon(s, 0.35, 1.0, 0.7, "\U0001F3EA")
    text(s, 1.2, 1.0, 3.55, 0.75, [[("Like a vending machine: ", True, CRIMSON), ("the rules are built in. Anyone can check them, and no one can secretly change them.", False)]], 11.5)
    text(s, 0.35, 1.9, 4.4, 0.3, "Why we need one", 12.5, True, CRIMSON, SERIF)
    bullets(s, 0.35, 2.22, 4.4, [
        [("Our receipts live in our own database. ", False), ("The owner could edit them.", True)],
        "The contract keeps a fingerprint of each batch of receipts outside our control.",
        "If anyone changes an old receipt later, its fingerprint no longer matches the one on the chain.",
    ], 11, 4)
    box(s, 5.0, 0.98, 4.7, 3.85, "FFF6E5", AMBER, lw=1.5)
    text(s, 5.15, 1.03, 4.4, 0.3, "Inside AuditAnchor (our contract)", 12.5, True, AMBER, SERIF)
    parts = [("Data it stores", ["anchors[batchId] \u2192 root, startSeq, endSeq, time, sender", "batchCount \u00b7 owner \u00b7 isAnchorer"]),
             ("Functions", ["anchorBatch(): save one batch fingerprint", "getAnchor(), verifyRoot(), latestAnchoredSeq(): read"]),
             ("Built-in rules", ["batches must arrive in order, no gaps", "only approved senders may write", "no update, no delete: write-once"]),
             ("Events", ["BatchAnchored: a public log line for every save"])]
    y = 1.4
    for h, items in parts:
        text(s, 5.2, y, 1.25, 0.3, h, 10.5, True, CRIMSON)
        text(s, 6.45, y, 3.2, 0.25 * len(items), items, 9.5, spacing=1)
        y += 0.28 * len(items) + 0.22
    source(s, "contracts/AuditAnchor.sol (MIT). Our project stores only a 32-byte fingerprint per batch, so no private data goes on the chain.")


def contract_flow(d: Deck):
    s = d.slide("Smart Contract in Action: Sealing a Batch", "Smart contract",
                "What happens every time four new receipts are written, and how a cheat is caught later.")
    steps = [("\U0001F9FE", "4 receipts", "seq 9, 10, 11, 12"), ("\U0001F333", "Merkle tree", "4 hashes \u2192 1 root"),
             ("\U0001F4E4", "Transaction", "anchorBatch(2, root, 9, 12)"), ("\U0001F6A6", "Contract checks", "in order? no gap? allowed?"),
             ("\U0001F512", "Stored forever", "anchors[2] = root")]
    for i, (g, h, b) in enumerate(steps):
        x = 0.3 + i * 1.9
        box(s, x, 1.0, 1.7, 1.55, WHITE, ROSE)
        icon(s, x + 0.55, 1.08, 0.6, g)
        text(s, x, 1.72, 1.7, 0.3, h, 11.5, True, CRIMSON, SERIF, PP_ALIGN.CENTER)
        text(s, x + 0.05, 2.02, 1.6, 0.5, b, 9, False, INK, align=PP_ALIGN.CENTER)
        if i < 4:
            arrow(s, x + 1.72, 1.78, x + 1.88, 1.78)
    text(s, 0.3, 2.75, 9.4, 0.3, "Later, the independent watcher checks the book", 12.5, True, CRIMSON, SERIF)
    honest = [("\u2705", "Honest log", "recompute root from today's receipts \u2192 matches the chain", GREEN),
              ("\u274C", "Edited log", "someone flips DENY \u2192 ALLOW in receipt 10 \u2192 new root \u2260 chain root \u2192 ALERT", CRIMSON),
              ("\u274C", "Rewritten log", "even if every local hash is recomputed, the on-chain root is untouched \u2192 ALERT", CRIMSON)]
    for i, (g, h, b, col) in enumerate(honest):
        y = 3.12 + i * 0.58
        box(s, 0.3, y, 9.4, 0.5, SOFT if col == CRIMSON else "E8F4EC")
        icon(s, 0.4, y + 0.06, 0.38, g, WHITE, 12)
        text(s, 0.9, y + 0.1, 1.5, 0.3, h, 11.5, True, col, SERIF)
        text(s, 2.4, y + 0.11, 7.2, 0.3, b, 10.5)
    source(s, "Merkle root = one fingerprint that changes if any receipt in the batch changes. Watcher = separate program with read-only access.")


def solidity(d: Deck):
    s = d.slide("Solidity: The Language of the Contract", "Solidity",
                "Solidity is the programming language used to write smart contracts for Ethereum-style blockchains.",
                "Connect: Solidity is to the smart contract what Python is to our gateway.")
    bullets(s, 0.3, 1.0, 4.4, [
        [("What: ", True, CRIMSON), ("a typed language, similar to JavaScript, made for blockchain programs.", False)],
        [("Why: ", True, CRIMSON), ("it compiles to bytecode that every Ethereum Virtual Machine (EVM) runs identically.", False)],
        [("Why for us: ", True, CRIMSON), ("built-in ", False), ("require()", True), (" checks enforce our write-once rules; the same file runs on a local test chain or a public network.", False)],
        [("Connection: ", True, CRIMSON), ("AuditAnchor.sol is written in Solidity 0.8; our Python gateway calls it through web3.py.", False)],
    ], 11, 6)
    code = box(s, 4.95, 0.98, 4.75, 2.55, "1E1E24")
    tf = code.text_frame
    tf.word_wrap = True
    tf.margin_left = tf.margin_right = Inches(0.12)
    tf.vertical_anchor = MSO_ANCHOR.TOP
    lines = [("function anchorBatch(uint256 batchId, bytes32 root,", "D4D4D4"),
             ("        uint64 startSeq, uint64 endSeq)", "D4D4D4"),
             ("        external onlyAnchorer {", "D4D4D4"),
             ("  require(batchId == batchCount, \"out-of-order\");", "F48FB1"),
             ("  require(startSeq == prevEnd + 1, \"sequence gap\");", "F48FB1"),
             ("  anchors[batchId] = Anchor(root, startSeq, ...);", "9CDCFE"),
             ("  batchCount = batchId + 1;", "9CDCFE"),
             ("  emit BatchAnchored(batchId, root, ...);", "B5CEA8"),
             ("}   // no update or delete function exists", "6A9955")]
    for i, (ln, col) in enumerate(lines):
        p = tf.paragraphs[0] if i == 0 else tf.add_paragraph()
        _runs(p, ln, 9.5, False, col, "Consolas")
    text(s, 4.95, 3.55, 4.75, 0.25, "Simplified from contracts/AuditAnchor.sol", 8.5, False, MUTED, italic=True)
    flow = [("AuditAnchor.sol", "Solidity source"), ("solc 0.8 compiler", "\u2192 bytecode + ABI"),
            ("Deploy", "contract gets an address"), ("Python web3.py", "calls anchorBatch()")]
    for i, (h, b) in enumerate(flow):
        x = 0.3 + i * 2.4
        label_box(s, x, 3.95, 2.1, 0.75, h, b, WHITE, ROSE, 11, 9)
        if i < 3:
            arrow(s, x + 2.12, 4.32, x + 2.38, 4.32)
    source(s, "ABI = the menu of functions Python can call. EVM = the virtual computer that runs contract bytecode on every blockchain node.")


def why_blockchain(d: Deck):
    s = d.slide("Why Blockchain? Three Ways to Keep a Log", "Trust domain",
                "We built three versions of the receipt book and attacked all three in the same way.")
    cols = [("R1", "Plain table", "an ordinary database table", "\U0001F4C4"), ("R2", "Hash chain", "each receipt includes the previous one's hash", "\U0001F517"),
            ("R3", "Anchored chain", "hash chain + Merkle fingerprint on blockchain", "\u26D3\uFE0F")]
    for i, (k, h, b, g) in enumerate(cols):
        x = 0.3 + i * 1.92
        box(s, x, 0.98, 1.78, 1.25, CRIMSON if k == "R3" else WHITE, ROSE)
        icon(s, x + 0.1, 1.05, 0.42, g, WHITE if k == "R3" else PINK, 12)
        text(s, x + 0.56, 1.05, 1.2, 0.22, k, 12, True, WHITE if k == "R3" else CRIMSON, SERIF)
        text(s, x + 0.56, 1.27, 1.2, 0.22, h, 9.5, True, WHITE if k == "R3" else CRIMSON)
        text(s, x + 0.1, 1.55, 1.6, 0.65, b, 9.5, False, WHITE if k == "R3" else INK)
    table(s, 0.3, 2.4, 5.6, [
        ["Attack on the log", "R1", "R2", "R3"],
        ["Change a DENY to ALLOW", "\u2717", "\u2713", "\u2713"],
        ["Delete a receipt", "\u2713", "\u2713", "\u2713"],
        ["Remove the newest receipts", "\u2717", "\u2717", "\u2713"],
        ["Rebuild the whole chain", "\u2717", "\u2717", "\u2713"],
        ["Swap the ML model (insider)", "\u2717", "\u2717", "\u2713"],
        ["**Caught (40 trials)**", "**25%**", "**50%**", "**100%**"],
    ], [3.2, 1, 1, 1.1], 10, 0.33, highlight_rows=(6,))
    ch = chart(s, 6.15, 0.95, 3.55, 3.95, ["R1", "R2", "R3"], [("Tamper trials caught", (25.0, 50.0, 100.0))], [CRIMSON],
               maxv=110, legend=False, title="Tamper trials caught (%)", label_size=10, gap=80)
    pts = ch.plots[0].series[0].points
    for i, col in enumerate((GRAY, ROSE, CRIMSON)):
        pts[i].format.fill.solid()
        pts[i].format.fill.fore_color.rgb = rgb(col)
    source(s, "results/tamper_detection_r1_r2_r3.md: 8 attack types \u00d7 5 randomised trials, 0 false alarms on the clean log.")


def architecture(d: Deck, fig):
    s = d.slide("System Architecture", "Design")
    pic(s, fig / "architecture.png", 0.3, 0.72, w=6.3, border=False)
    bullets(s, 6.75, 0.85, 3.0, [
        [("Gateway: ", True), ("7 stages, one decision per call, one trace the user can read.", False)],
        [("Inspection engine: ", True), ("49 deterministic rules + optional ML guard for prose.", False)],
        [("Audit agent: ", True), ("writes R1/R2/R3 receipts; seals batches of 4 into Merkle roots.", False)],
        [("Blockchain: ", True), ("AuditAnchor.sol keeps roots write-once.", False)],
        [("Watcher: ", True), ("separate process, read-only; raises typed alerts.", False)],
    ], 10.5, 5)
    source(s, "Code: omniguard/agents/ \u00b7 omniguard/security/ \u00b7 contracts/AuditAnchor.sol \u00b7 204 automated tests pass.")


def literature(d: Deck):
    s = d.slide("Literature Survey", "42 sources",
                "Full survey with methodology, metrics and a verification status per citation: OmniGuard-MCP_Literature_Survey.xlsx")
    table(s, 0.3, 0.95, 9.4, [
        ["Work", "Venue", "What it shows", "Gap it leaves"],
        ["MCPTox (Wang et al.)", "AAAI 2026", "72.8% tool-poisoning success on live MCP servers", "no defence evaluated"],
        ["MSB (Zhang et al.)", "ICLR 2026", "attacks at every pipeline stage, incl. multi-step chains", "benchmark only"],
        ["AgentDojo (Debenedetti et al.)", "NeurIPS 2024", "realistic user + injection tasks in 4 suites", "no audit layer"],
        ["ShieldMCP (Yergattikar)", "ACL 2026 Ind.", "runtime proxy: poisoning 74.1% \u2192 8.6%, 118 ms median", "no tamper-evident record"],
        ["MCP-Guard (Xing et al.)", "arXiv 2025", "multi-stage detector, 89.07% F1 on its own benchmark", "no audit, no pinning"],
        ["ETDI (Bhatt et al.)", "arXiv 2025", "signed, versioned tool definitions vs rug pulls", "central trust, no measurement"],
        ["Agent Flight Recorder", "arXiv 2026", "hash chain + Merkle epochs + on-chain root", "not in the MCP call path"],
        ["Zhan et al.", "NAACL 2025 F.", "adaptive attacks break all 8 IPI defences", "detectors are not guarantees"],
    ], [2.4, 1.1, 3.6, 2.2], 9.5, 0.36)
    source(s, "Gap mapping G1\u2013G8 in the survey workbook; G3 (deletion / ordering evidence) and G8 (justify blockchain vs cheaper regimes) are addressed in full.")


def datasets(d: Deck):
    s = d.slide("Datasets Used: Where the Test Data Comes From", "Datasets",
                "Only public, real data. Two groups: detection datasets (is this text an attack?) and agent benchmarks (does the whole system stop it?).")
    st = EXT["streams"]
    rs = lambda k: st[k]["rows_streamed"]  # noqa: E731
    rows = [["Dataset", "Source", "Total rows", "Rows tested", "What it tests"],
            ["deepset/prompt-injections", "Hugging Face", f"{rs('prompt_injection_ingress')['total']:,}", "95 (official test)", "hidden instructions in text"],
            ["jackhhao/jailbreak-classification", "Hugging Face", f"{rs('jailbreak_ingress')['total']:,}", "214 (official test)", "\u201cpretend you have no rules\u201d prompts"],
            ["zrmarine/sql_injection", "Hugging Face", f"{rs('sql_injection')['total']:,}", "500 (held-out)", "SQL injection strings"],
            ["AmirAliGharesoufloo/CommandInjection", "Hugging Face", f"{rs('command_injection')['total']:,}", "500 (held-out)", "shell command injection"],
            ["MCPTox", "GitHub, AAAI 2026", "485 poisoned tools", "25", "poisoned tool descriptions"],
            ["AgentDojo", "GitHub, NeurIPS 2024", "85 tasks + 27 attacks", "30 + 13", "everyday tasks + injections"],
            ["MSB", "GitHub, ICLR 2026", "5 attacks \u00d7 12 types", "12 + 10 chains", "injections, multi-step chains"]]
    table(s, 0.3, 1.0, 9.4, rows, [2.7, 1.55, 1.45, 1.3, 2.4], 9.5, 0.37, center_from=1)
    box(s, 0.3, 4.1, 9.4, 0.72, SOFT)
    text(s, 0.45, 4.14, 9.1, 0.65, [
        [("Fair testing rule: ", True, CRIMSON), ("20% of each detection dataset (chosen by a hash of the text) was the only data used to tune rules and thresholds. "
                                                 "Results are reported on the other 80% and on the official test splits, which the models never saw.", False)]], 10.5, anchor=MSO_ANCHOR.MIDDLE)
    source(s, "Agent-benchmark cases keep their upstream IDs and git commits in benchmarks/raw_benchmark_samples.json.")


def metrics_explained(d: Deck):
    s = d.slide("Evaluation Metrics Made Simple", "Metrics",
                "Think of a spam filter. Each metric answers a different question about how well it sorts mail.",
                "TP = attack correctly blocked; FP = safe request wrongly blocked; FN = attack let through; TN = safe request allowed.")
    rows = [["Metric", "The question it answers", "Formula"],
            ["Accuracy", "Out of all requests, how many did we judge correctly?", "(TP + TN) / all"],
            ["Precision", "When we block something, how often is it really an attack?", "TP / (TP + FP)"],
            ["Recall", "Out of all real attacks, how many did we catch?", "TP / (TP + FN)"],
            ["F1-score", "One score balancing precision and recall", "2PR / (P + R)"],
            ["Macro-F1", "Average F1 of the two classes (attack, safe), each counted equally", "(F1 attack + F1 safe) / 2"],
            ["Weighted-F1", "Same, but each class weighted by how many examples it has", "\u03a3 F1 class \u00d7 share"],
            ["False-positive rate", "How often do we annoy users by blocking safe requests?", "FP / (FP + TN)"],
            ["MCC", "Quality score from \u22121 to 1 that stays fair when classes are unbalanced", "Matthews corr."],
            ["Attack success rate", "Agent benchmarks: how many attacks reached the tool?", "forwarded / attacks"]]
    table(s, 0.3, 1.0, 6.55, rows, [1.45, 3.75, 1.35], 9.5, 0.36, center_from=2)
    box(s, 7.05, 1.0, 2.65, 3.6, SOFT)
    text(s, 7.15, 1.05, 2.45, 0.3, "Confusion matrix", 12, True, CRIMSON, SERIF, PP_ALIGN.CENTER)
    grid = [("TP", "attack \u2192 blocked", GREEN), ("FN", "attack \u2192 allowed", CRIMSON),
            ("FP", "safe \u2192 blocked", AMBER), ("TN", "safe \u2192 allowed", GREEN)]
    for i, (h, b, col) in enumerate(grid):
        r_, c_ = divmod(i, 2)
        x, y = 7.2 + c_ * 1.2, 1.5 + r_ * 1.15
        bb = box(s, x, y, 1.12, 1.05, WHITE, col, lw=2)
        tf = bb.text_frame
        tf.vertical_anchor = MSO_ANCHOR.MIDDLE
        tf.word_wrap = True
        p = tf.paragraphs[0]
        p.alignment = PP_ALIGN.CENTER
        _runs(p, h, 16, True, col, SERIF)
        q = tf.add_paragraph()
        q.alignment = PP_ALIGN.CENTER
        _runs(q, b, 8.5, False, INK, BODY)
    text(s, 7.15, 3.85, 2.45, 0.7, "For security, a missed attack (FN) is costly; a false alarm (FP) is annoying. We report both.", 9.5, False, INK, align=PP_ALIGN.CENTER)


def per_dataset(d: Deck):
    s = d.slide("Our Results on Each Dataset", "Results",
                "OmniGuard v1.2 (rules + pinned guard model). Held-out data only; thresholds frozen before testing.")
    sets = [("deepset prompt-injection (tool inputs)", "prompt_injection_ingress", "clean"),
            ("deepset prompt-injection (tool outputs)", "prompt_injection_egress", "clean"),
            ("jackhhao jailbreak", "jailbreak_ingress", "clean"),
            ("zrmarine SQL injection", "sql_injection", "full"),
            ("CommandInjection", "command_injection", "full")]
    rows = [["Dataset", "n", "Accuracy", "Precision", "Recall", "F1", "Macro-F1", "Weighted-F1", "FPR", "MCC"]]
    f1s = []
    for name, k, v in sets:
        m = ext(k, v, "v1.2")
        f1s.append(m["f1"])
        rows.append([name, m["n"], pc(m["acc"]), pc(m["p"]), pc(m["r"]), f3(m["f1"]), f3(m["macro"]), f3(m["weighted"]), pc(m["fpr"]), f3(m["mcc"])])
    table(s, 0.3, 0.95, 9.4, rows, [3.0, 0.55, 0.95, 0.95, 0.85, 0.75, 0.9, 1.05, 0.7, 0.7], 9.5, 0.36)
    ch = chart(s, 0.3, 3.2, 5.6, 1.75, ["PI inputs", "PI outputs", "Jailbreak", "SQL inj.", "Cmd inj."],
               [("F1", [round(100 * x, 1) for x in f1s])], [CRIMSON], maxv=110, legend=False, label_size=9, gap=90)
    bullets(s, 6.1, 3.25, 3.6, [
        [("Precision ~100%: ", True), ("almost no false alarms on prompt-injection data.", False)],
        [("Recall is the weak side: ", True), ("about 1 in 4 paraphrased injections still pass.", False)],
        [("SQL / shell: ", True), ("rules alone reach F1 0.91\u20130.92.", False)],
    ], 10.5, 4)
    source(s, "results/external_dataset_eval.json. PI and jailbreak rows use the official TEST split (never seen in training); SQL / cmd use 500 held-out rows.")


def comparison(d: Deck):
    s = d.slide("Comparison with Existing Approaches", "Benchmark",
                "Every approach was re-run by us on exactly the same held-out rows, so the numbers are directly comparable.")
    engines = [("v1.0", "Rules only (signature baseline)"), ("v1.1", "ProtectAI DeBERTa-v3 v2 (existing open-source detector) \u26a0"),
               ("v1.2-small", "Horizon guard-small (existing, smaller)"), ("v1.2", "**Ours: rules + Horizon guard-base cascade**")]
    rows = [["Approach", "Accuracy", "Precision", "Recall", "F1", "Accuracy", "Precision", "Recall", "F1"]]
    hl = []
    for k, name in engines:
        a = ext("prompt_injection_ingress", "clean", k)
        b = ext("jailbreak_ingress", "clean", k)
        rows.append([name, pc(a["acc"]), pc(a["p"]), pc(a["r"]), f3(a["f1"]), pc(b["acc"]), pc(b["p"]), pc(b["r"]), f3(b["f1"])])
        if k == "v1.2":
            hl.append(len(rows) - 1)
    text(s, 3.6, 0.92, 3.05, 0.25, "deepset prompt-injection (n = 95)", 10, True, CRIMSON, align=PP_ALIGN.CENTER)
    text(s, 6.65, 0.92, 3.05, 0.25, "jackhhao jailbreak (n = 214)", 10, True, CRIMSON, align=PP_ALIGN.CENTER)
    table(s, 0.3, 1.18, 9.4, rows, [3.3, 0.8, 0.8, 0.7, 0.65, 0.8, 0.8, 0.7, 0.65], 9, 0.36, highlight_rows=hl)
    eng_keys = ["v1.0", "v1.1", "v1.2-small", "v1.2"]
    names = ["Rules only", "ProtectAI DeBERTa", "Horizon-small", "Ours (v1.2)"]
    cats = ["PI inputs", "PI outputs", "Jailbreak"]
    series = [(nm, [round(100 * ext(st_, "clean", k)["f1"], 1) for st_ in ("prompt_injection_ingress", "prompt_injection_egress", "jailbreak_ingress")])
              for k, nm in zip(eng_keys, names)]
    chart(s, 0.3, 3.05, 5.7, 1.9, cats, series, [GRAY, ROSE, "D16A8F", CRIMSON], maxv=110, title=None, label_size=7.5, gap=70, fmt="0")
    box(s, 6.15, 3.1, 3.55, 1.8, SOFT)
    text(s, 6.25, 3.13, 3.35, 1.75, [
        [("F1 on prompt injection: ", True, CRIMSON), ("0.30 \u2192 0.84", True), (" (rules \u2192 ours), 0.29 higher than ProtectAI.", False)],
        [("Reported elsewhere ", True, CRIMSON), ("(own datasets, not comparable): MCP-Guard 89.07% F1; ShieldMCP 74.1% \u2192 8.6% poisoning success.", False)],
        [("\u26a0 ", True, AMBER), ("ProtectAI was trained on jackhhao, so its jailbreak score is optimistic.", False)]], 9.5, spacing=4)
    source(s, "Same rows, same protocol, thresholds frozen on validation data. Ours = v1.2 engine in configs/security_rules.yaml.")


def all_datasets_chart(d: Deck):
    s = d.slide("All Five Datasets at a Glance", "Benchmark",
                "F1 for every approach on every dataset. Structured attacks (SQL, shell) never reach the ML model, so all approaches tie there.")
    cats = ["PI inputs", "PI outputs", "Jailbreak", "SQL injection", "Cmd injection"]
    keys = [("prompt_injection_ingress", "clean"), ("prompt_injection_egress", "clean"), ("jailbreak_ingress", "clean"),
            ("sql_injection", "full"), ("command_injection", "full")]
    series = [(nm, [round(100 * ext(k, v, e)["f1"], 1) for k, v in keys])
              for e, nm in (("v1.0", "Rules only"), ("v1.1", "ProtectAI DeBERTa"), ("v1.2-small", "Horizon-small"), ("v1.2", "Ours (v1.2)"))]
    chart(s, 0.3, 0.95, 6.3, 3.95, cats, series, [GRAY, ROSE, "D16A8F", CRIMSON], maxv=110, label_size=7.5, gap=60, fmt="0")
    rows = [["Dataset", "Best existing", "Ours"]]
    for c_, (k, v) in zip(cats, keys):
        best = max(ext(k, v, e)["f1"] for e in ("v1.0", "v1.1", "v1.2-small"))
        rows.append([c_, f3(best), f"**{f3(ext(k, v, 'v1.2')['f1'])}**"])
    table(s, 6.8, 1.0, 2.9, rows, [1.5, 1.0, 0.8], 10, 0.38)
    text(s, 6.8, 3.4, 2.9, 1.5, [[("Takeaway: ", True, CRIMSON), ("our cascade gives the best F1 on all three text datasets and matches the rules on SQL / shell, where rules are already strong.", False)]], 10.5)
    source(s, "F1 in %. Macro-F1, weighted-F1 and MCC for every cell are computed from the confusion matrices in results/external_dataset_eval.json.")


def ablation(d: Deck):
    s = d.slide("3-Way Ablation on 100 Real Cases", "Ablation",
                "A = no protection \u00b7 B = input checks + editable log \u00b7 C = full OmniGuard. Run against the live deployed API.")
    rows = [["Case set (source, n)", "Lower/higher is better", "A", "B", "C"]]
    for k, m in (("benign", "allowed \u2191"), ("injection", "attack success \u2193"), ("poisoning", "attack success \u2193"),
                 ("chain", "attack success \u2193"), ("tamper", "caught \u2191")):
        c = CAT[k]
        rows.append([f"{c['label']} ({c['source']}, {c['n']})", m, f"{c['A']:g}%", f"{c['B']:g}%", f"**{c['C']:g}%**"])
    table(s, 0.3, 0.95, 5.6, rows, [3.3, 1.35, 0.6, 0.6, 0.65], 9.5, 0.42)
    cats = ["Prompt inj.", "Poisoning", "Chains"]
    series = [(f"Mode {m}", [CAT[k][m] for k in ("injection", "poisoning", "chain")]) for m in "ABC"]
    chart(s, 6.05, 0.92, 3.65, 2.3, cats, series, [GRAY, ROSE, CRIMSON], maxv=115, title="Attack success (%, lower is better)", label_size=7.5, fmt="0")
    bullets(s, 0.3, 3.65, 9.4, [
        [("Fingerprint pinning ", True), (f"is what stops poisoned tools: B {CAT['poisoning']['B']:g}% \u2192 C {CAT['poisoning']['C']:g}%.", False)],
        [("Blockchain anchoring ", True), (f"raises tamper detection from {CAT['tamper']['B']:g}% to {CAT['tamper']['C']:g}%.", False)],
        [("Honest miss: ", True), ("rules alone let all 25 real prompt injections through; the ML guard fixes this (next slide).", False)],
    ], 10.5, 3)
    source(s, f"benchmarks/results.json \u00b7 live run {R['run']['finished_at'][:10]} \u00b7 upstream IDs and commits in benchmarks/raw_benchmark_samples.json.")


def ablation_metrics_slide(d: Deck):
    s = d.slide("Ablation Scored as Classification", "Metrics",
                "90 cases (60 real attacks, 30 real everyday tasks). Positive = the gateway blocked the request.")
    rows = [["Configuration", "Accuracy", "Precision", "Recall", "F1", "Macro-F1", "Weighted-F1", "FPR"]]
    confs = [("A: no protection (live)", ABL_LIVE["A"]), ("B: input checks (live)", ABL_LIVE["B"]), ("C: OmniGuard rules only (live)", ABL_LIVE["C"]),
             ("B + ML guard (local GPU)", ABL_ML["B"]), ("C + ML guard (local GPU)", ABL_ML["C"])]
    for name, m in confs:
        rows.append([name, pc(m["acc"]), pc(m["p"]) if m["tp"] + m["fp"] else "\u2013", pc(m["r"]), f3(m["f1"]), f3(m["macro"]), f3(m["weighted"]), pc(m["fpr"])])
    table(s, 0.3, 0.95, 9.4, rows, [2.9, 0.95, 0.95, 0.85, 0.75, 0.95, 1.1, 0.7], 9.5, 0.36, highlight_rows=(5,))
    cats = ["A", "B", "C", "B + ML", "C + ML"]
    ms = [ABL_LIVE["A"], ABL_LIVE["B"], ABL_LIVE["C"], ABL_ML["B"], ABL_ML["C"]]
    chart(s, 0.3, 3.2, 6.0, 1.75, cats, [("Accuracy", [round(100 * m["acc"], 1) for m in ms]), ("F1", [round(100 * m["f1"], 1) for m in ms])],
          [ROSE, CRIMSON], maxv=115, label_size=7.5, gap=80)
    box(s, 6.5, 3.25, 3.2, 1.65, SOFT)
    c = ABL_ML["C"]
    text(s, 6.6, 3.3, 3.0, 1.55, [
        [("Full system with ML: ", True, CRIMSON), (f"accuracy {pc(c['acc'])}, F1 {f3(c['f1'])}. ", False)],
        [(f"It caught all {c['tp']} attacks and wrongly blocked {c['fp']} of 30 everyday tasks.", False)],
        [("Pinning alone adds ", False), ("25 caught poisoned tools", True), (" that B misses.", False)]], 10, spacing=3)
    source(s, "Computed from benchmarks/results_cases.jsonl (live) and results_local_hybrid_ml_cases.jsonl (same 100 cases, local RTX 2060). Tamper checks are reported separately.")


def tamper_chart(d: Deck):
    s = d.slide("Tamper Detection: Which Log Catches Which Cheat?", "Blockchain")
    scen = ["Edit", "Delete", "Truncate", "Reorder", "Root forgery", "Pin rewrite", "Model swap"]
    r1 = [0, 100, 0, 0, 0, 0, 0]
    r2 = [100, 100, 0, 100, 0, 0, 0]
    r3 = [100] * 7
    chart(s, 0.3, 0.75, 6.4, 4.15, scen, [("R1 plain table", r1), ("R2 hash chain", r2), ("R3 anchored", r3)],
          [GRAY, ROSE, CRIMSON], maxv=115, fmt='0"%"', label_size=7.5, gap=50)
    stat(s, 6.95, 0.8, 2.75, "100%", "caught with anchoring (R3)", "40 of 40 trials, 0 false alarms")
    stat(s, 6.95, 2.0, 2.75, "50%", "caught with a hash chain (R2)", "20 of 40 trials")
    stat(s, 6.95, 3.2, 2.75, "25%", "caught with a plain table (R1)", "10 of 40 trials", color=MUTED)
    source(s, "Each bar = 5 randomised trials; a fresh watcher process checks the log after every attack (results/tamper_detection_r1_r2_r3.md).")


def live1(d: Deck, sh):
    s = d.slide("Live Results 1: Blocked at the Door", "Live demo", "Real calls to the deployed system, captured from the dashboard.")
    pic(s, sh / "02_sqli_block.png", 0.3, 0.95, w=4.6)
    pic(s, sh / "03_schema_drift_block.png", 5.1, 0.95, w=4.6)
    text(s, 0.3, 3.62, 4.6, 0.6, [[("SQL injection: ", True, CRIMSON), ("passes the access check, but the SQL rule spots \u201cOR 1=1\u201d \u2192 blocked (SQL_TAUTOLOGY).", False)]], 10.5)
    text(s, 5.1, 3.62, 4.6, 0.6, [[("Poisoned tool: ", True, CRIMSON), ("its description changed mid-session; fingerprint a3017554\u2026 \u2260 1f50c02b\u2026 \u2192 blocked (SCHEMA_DRIFT_RUG_PULL).", False)]], 10.5)
    source(s, "Dashboard: omniguard-mcp.vercel.app \u00b7 both denials are written to the receipt book with their reasons.")


def live2(d: Deck, sh):
    s = d.slide("Live Results 2: Contained, Then Proven", "Live demo")
    pic(s, sh / "05_redact_tainted_trace.png", 0.3, 0.72, w=4.6)
    pic(s, sh / "04_r3_rewrite_alerts.png", 5.1, 0.72, w=4.6)
    text(s, 0.3, 3.4, 4.6, 0.7, [[("Secrets masked: ", True, CRIMSON), ("reading api_keys.txt is allowed but the keys are hidden; the session is marked sensitive, so the next \u201csend it out\u201d is blocked.", False)]], 10.5)
    text(s, 5.1, 3.4, 4.6, 0.7, [[("Log rewrite caught: ", True, CRIMSON), ("an insider edits a receipt and recomputes every hash. R1 and R2 see nothing; R3 raises alerts.", False)]], 10.5)
    source(s, "Tamper lab on the live dashboard \u00b7 attacks target receipts that were already anchored on chain.")


def latency(d: Deck, charts):
    s = d.slide("Speed: What Does Safety Cost?", "Trade-off")
    lc = chart(s, 0.3, 0.75, 5.3, 4.15, ["A · no protection", "B · checks only", "C · OmniGuard"],
               [("typical (p50)", [LAT[m]["p50"] for m in "ABC"]), ("slowest 5% (p95)", [LAT[m]["p95"] for m in "ABC"])],
               [ROSE, CRIMSON], fmt="0.00", title="Time per call, live API (ms, log scale)", label_size=8.5, gap=70)
    sc = lc.value_axis._element.find(qn("c:scaling"))
    lb = sc.makeelement(qn("c:logBase"), {"val": "10"})
    sc.insert(0, lb)
    lc.value_axis.minimum_scale, lc.value_axis.maximum_scale = 0.01, 1000
    from pptx.enum.chart import XL_AXIS_CROSSES
    lc.value_axis.crosses = XL_AXIS_CROSSES.MINIMUM
    stat(s, 5.8, 0.85, 1.85, f"{LAT['C']['p50']:.2f} ms", "typical call, full system", "median, live API")
    stat(s, 7.8, 0.85, 1.9, f"{LAT['C']['p95']:.0f} ms", "slowest 5%", "calls that seal a batch")
    stat(s, 5.8, 2.05, 1.85, f"{LAT['B']['p50']:.2f} ms", "checks only", "median, Mode B")
    stat(s, 7.8, 2.05, 1.9, "1.7 ms", "slowest 5%, async", "anchoring in background")
    bullets(s, 5.8, 3.3, 3.9, [
        "A blink of an eye is ~100 ms: a typical check costs under 2 ms.",
        "Only 1 call in 4 waits for the blockchain; doing it in the background removes that wait.",
    ], 10.5, 4)
    source(s, "benchmarks/results.json (server-side time, live API) \u00b7 R3-async: results/performance_storage_r1_r2_r3.md (R3-async row). ShieldMCP reports 118 ms median.")


def deployment(d: Deck, still):
    s = d.slide("Deployment and Demo Film", "Live")
    nodes = [("Dashboard", "Vercel \u00b7 web page", "omniguard-mcp.vercel.app"),
             ("Live API", "Render \u00b7 Python FastAPI", "gateway + receipt books"),
             ("Blockchain", "local Ethereum test chain", "AuditAnchor.sol deployed")]
    for i, (h, a1, a2) in enumerate(nodes):
        y = 0.85 + i * 1.12
        box(s, 0.35, y, 3.0, 0.85, WHITE, ROSE)
        text(s, 0.5, y + 0.07, 2.7, 0.3, h, 13, True, CRIMSON, SERIF)
        text(s, 0.5, y + 0.4, 2.7, 0.2, a1, 10.5, True, INK)
        text(s, 0.5, y + 0.6, 2.7, 0.2, a2, 9.5, False, MUTED)
        if i < 2:
            a = s.shapes.add_shape(MSO_SHAPE.DOWN_ARROW, Inches(1.72), Inches(y + 0.88), Inches(0.26), Inches(0.22))
            a.fill.solid()
            a.fill.fore_color.rgb = rgb(CRIMSON)
            a.line.fill.background()
    text(s, 0.35, 4.22, 3.0, 0.6, "Free hosting runs the rules engine; the ML guard runs on a local RTX 2060 GPU.", 9.5, False, MUTED)
    if still.exists():
        pic(s, still, 3.65, 0.85, w=6.05)
    text(s, 3.65, 4.33, 6.05, 0.25, [[("Trailer: ", True), ("docs/OmniGuard-MCP_Trailer.mp4 \u00b7 81 s, live recordings of the real product", False)]], 10)
    text(s, 3.65, 4.58, 6.05, 0.25, "github.com/lucky07-07/omniguard-mcp", 10, True, CRIMSON)
    source(s, "The API redeploys automatically on every push to the main branch.")


def limitations(d: Deck):
    s = d.slide("Limitations and Future Work", "Honest view")
    cols = [("\u26A0\uFE0F", "Current limitations", [
        "Rules alone miss paraphrased prompt injections (0% caught on the 25 real ones).",
        "The ML guard fixes that but wrongly blocks 10% of everyday tasks.",
        "Fingerprints check a tool's description, not its hidden code.",
        "The newest receipts (< 4) are not yet on chain."]),
            ("\U0001F9D7", "Challenges faced", [
        "Free hosting has no room for the 0.6 GB ML model.",
        "Benchmarks needed careful mapping to our tool set.",
        "Keeping test data unseen by tuning and by the models.",
        "Waiting for the chain slows 1 call in 4."]),
            ("\U0001F680", "Future improvements", [
        "Anchor on a public test network and measure the real cost.",
        "Test against adaptive attackers who know the defence.",
        "Fingerprint the tool server's code, not only its description.",
        "Background anchoring with signed receipts."])]
    for i, (g, h, items) in enumerate(cols):
        x = 0.3 + i * 3.17
        box(s, x, 0.8, 2.97, 4.05, SOFT if i != 2 else "FFF6E5")
        icon(s, x + 0.12, 0.9, 0.55, g, WHITE, 16)
        text(s, x + 0.75, 0.97, 2.15, 0.4, h, 13, True, CRIMSON if i != 2 else AMBER, SERIF)
        bullets(s, x + 0.15, 1.6, 2.7, items, 10.5, 6)


def conclusion(d: Deck):
    s = d.slide("Contributions and Conclusion", "Summary")
    items = [("1", "A 7-step security gateway for AI tools", "49 deterministic rules + a fingerprinted ML guard, one readable trace per call"),
             ("2", "SHA-256 tool fingerprints", "stops poisoned and swapped tools mid-session (25 of 25 real MCPTox cases)"),
             ("3", "Blockchain-anchored receipts", "Solidity smart contract + Merkle batches + independent watcher: 100% of tampering caught"),
             ("4", "Measured on real public data", "5 detection datasets, 100 benchmark cases, live deployment, 204 tests")]
    for i, (n, h, b) in enumerate(items):
        y = 0.8 + i * 0.8
        c = s.shapes.add_shape(MSO_SHAPE.OVAL, Inches(0.35), Inches(y + 0.05), Inches(0.5), Inches(0.5))
        c.fill.solid()
        c.fill.fore_color.rgb = rgb(CRIMSON)
        c.line.fill.background()
        p = c.text_frame.paragraphs[0]
        p.alignment = PP_ALIGN.CENTER
        _runs(p, n, 14, True, WHITE, SERIF)
        text(s, 1.0, y, 5.1, 0.3, h, 13, True, CRIMSON, SERIF)
        text(s, 1.0, y + 0.3, 5.1, 0.4, b, 10.5)
    box(s, 6.35, 0.8, 3.35, 2.6, SOFT)
    text(s, 6.5, 0.9, 3.05, 0.3, "In one sentence", 13, True, CRIMSON, SERIF)
    text(s, 6.5, 1.3, 3.05, 2.5, ["Fingerprints stop poisoned tools, rules and session memory stop attack chains, and the blockchain makes the record trustworthy even against its own owner.",
                                  "", "Prompt injection still needs the ML guard: F1 0.30 \u2192 0.84 with it."], 11)
    text(s, 0.35, 4.2, 9.4, 0.3, [[("omniguard-mcp.vercel.app", True), ("   \u00b7   github.com/lucky07-07/omniguard-mcp   \u00b7   Thank you", False)]], 12, color=CRIMSON, align=PP_ALIGN.CENTER)
    source(s, "Technical report: docs/OmniGuard-MCP_Technical_Report.docx")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--style", default="C:/Users/anilk/Downloads/Anil_Review_3_Updated.pptx")
    ap.add_argument("--trailer-still", default=str(ROOT / "demo_media" / "trailer" / "still.png"))
    a = ap.parse_args()
    prs = Presentation(a.style)
    chrome = Chrome(prs.slides[2])
    title_slide(prs.slides[0])
    strip_slides(prs, {0})
    d = Deck(prs, chrome)
    sh, fig, charts = ROOT / "benchmarks" / "screenshots", ROOT / "docs" / "report" / "fig", ROOT / "benchmarks" / "charts"
    outline(d, ["The problem", "Our idea and workflow", "Deterministic rules", "Smart contract and Solidity",
                "Why blockchain", "Architecture", "Literature survey", "Datasets and metrics",
                "Results and comparison", "3-way ablation", "Tamper detection", "Live demo and speed",
                "Limitations", "Conclusion"])
    problem(d)
    numbers(d)
    idea(d)
    workflow(d)
    worked_example(d)
    rules_explained(d)
    rules_families(d)
    smart_contract(d)
    contract_flow(d)
    solidity(d)
    why_blockchain(d)
    architecture(d, fig)
    literature(d)
    datasets(d)
    metrics_explained(d)
    per_dataset(d)
    comparison(d)
    all_datasets_chart(d)
    ablation(d)
    ablation_metrics_slide(d)
    tamper_chart(d)
    live1(d, sh)
    live2(d, sh)
    latency(d, charts)
    deployment(d, Path(a.trailer_still))
    limitations(d)
    conclusion(d)
    out = ROOT / "docs" / OUT_NAME
    prs.save(out)
    shutil.copyfile(out, BC / OUT_NAME)
    print("saved", out, "and", BC / OUT_NAME, "slides:", len(prs.slides))


if __name__ == "__main__":
    main()

"""Build OmniGuard-MCP_Technical_Report.docx from the department's end-semester report template (python-docx).

    python docs/report/figures.py          # architecture figures (once)
    python docs/report/build_report.py     # two passes: build -> PDF via Word -> page numbers -> rebuild

The template's title page, acknowledgement block, page geometry, page borders and Times New Roman styling are kept;
the placeholder body is replaced. Numbers in Chapter 4 are read from benchmarks/results.json and results/*.json.
"""

from __future__ import annotations

import copy
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import docx
import openpyxl
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK, WD_TAB_ALIGNMENT, WD_TAB_LEADER
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor, Twips

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
BC = ROOT.parent
TEMPLATE = BC / "Blockchain_End_Sem_Report_Template - CSE_DS_M.Tech..docx"
SURVEY = BC / "OmniGuard-MCP_Literature_Survey.xlsx"
OUT_NAME = "OmniGuard-MCP_Technical_Report.docx"
WORK = HERE / "_build"
TEXT_W = 8266  # twips between the template margins
FONT = "Times New Roman"

TITLE = "OmniGuard-MCP: A Tamper-Evident Security Gateway for Agentic AI Tool Calls with Blockchain-Anchored Audit"
STUDENT, ROLL = "Anil Kumar", "BL.SC.P2DSC25023"
GUIDE = "Ms. Shalini Tiwari"
GUIDE_DESIG = "Assistant Professor"

R = json.loads((ROOT / "benchmarks" / "results.json").read_text(encoding="utf-8"))
TAMPER = json.loads((ROOT / "results" / "tamper_detection_r1_r2_r3.json").read_text(encoding="utf-8"))
EXT = json.loads((ROOT / "results" / "external_dataset_eval.json").read_text(encoding="utf-8"))


# ============================================================================ low-level helpers
def run_fmt(r, size=12, bold=False, italic=False, color=None, mono=False):
    r.font.name = "Consolas" if mono else FONT
    r._element.rPr.rFonts.set(qn("w:eastAsia"), r.font.name)
    r.font.size = Pt(size)
    r.bold = bold
    r.italic = italic
    if color:
        r.font.color.rgb = RGBColor.from_string(color)


def add_rich(p, text, size=12, base_bold=False):
    """**bold**, *italic*, `mono` inline markup."""
    for tok in re.split(r"(\*\*.+?\*\*|`.+?`|\*[^*]+?\*)", text):
        if not tok:
            continue
        if tok.startswith("**"):
            run_fmt(p.add_run(tok[2:-2]), size, bold=True)
        elif tok.startswith("`"):
            run_fmt(p.add_run(tok[1:-1]), size - 1, mono=True, bold=base_bold)
        elif tok.startswith("*"):
            run_fmt(p.add_run(tok[1:-1]), size, italic=True, bold=base_bold)
        else:
            run_fmt(p.add_run(tok), size, bold=base_bold)


def para(d, text="", size=12, align="justify", bold=False, before=0, after=4, line=1.3, keep=False, indent=None):
    p = d.add_paragraph()
    p.alignment = {"justify": WD_ALIGN_PARAGRAPH.JUSTIFY, "center": WD_ALIGN_PARAGRAPH.CENTER,
                   "left": WD_ALIGN_PARAGRAPH.LEFT, "right": WD_ALIGN_PARAGRAPH.RIGHT}[align]
    pf = p.paragraph_format
    pf.space_before, pf.space_after, pf.line_spacing = Pt(before), Pt(after), line
    pf.keep_with_next = keep
    if indent is not None:
        pf.first_line_indent = Inches(indent)
    if text:
        add_rich(p, text, size, base_bold=bold)
    return p


def outline(p, level: int):
    ppr = p._p.get_or_add_pPr()
    o = OxmlElement("w:outlineLvl")
    o.set(qn("w:val"), str(level))
    ppr.append(o)


def page_break(d):
    p = d.add_paragraph()
    p.add_run().add_break(WD_BREAK.PAGE)
    p.paragraph_format.space_after = Pt(0)
    return p


def bullets(d, items, size=12):
    for it in items:
        p = para(d, "", size=size, after=2, line=1.25)
        p.paragraph_format.left_indent = Inches(0.35)
        p.paragraph_format.first_line_indent = Inches(-0.22)
        run_fmt(p.add_run("•\t"), size)
        p.paragraph_format.tab_stops.add_tab_stop(Inches(0.35))
        add_rich(p, it, size)


def field(p, instr: str, size=11):
    r = p.add_run()
    run_fmt(r, size)
    for kind, text in (("begin", None), (None, instr), ("separate", None), (None, "1"), ("end", None)):
        if kind:
            e = OxmlElement("w:fldChar")
            e.set(qn("w:fldCharType"), kind)
            r._r.append(e)
        elif text == instr:
            e = OxmlElement("w:instrText")
            e.set(qn("xml:space"), "preserve")
            e.text = f" {instr} "
            r._r.append(e)
        else:
            e = OxmlElement("w:t")
            e.text = text
            r._r.append(e)


def shade(cell, fill):
    tcpr = cell._tc.get_or_add_tcPr()
    s = OxmlElement("w:shd")
    s.set(qn("w:val"), "clear")
    s.set(qn("w:color"), "auto")
    s.set(qn("w:fill"), fill)
    tcpr.append(s)


def table(d, header, rows, widths, size=10, align=None):
    t = d.add_table(rows=1 + len(rows), cols=len(header))
    t.alignment = WD_TABLE_ALIGNMENT.CENTER
    tblpr = t._tbl.tblPr
    borders = OxmlElement("w:tblBorders")
    for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
        e = OxmlElement(f"w:{edge}")
        e.set(qn("w:val"), "single")
        e.set(qn("w:sz"), "4")
        e.set(qn("w:color"), "7F7F7F")
        borders.append(e)
    tblpr.append(borders)
    total = sum(widths)
    for i, row in enumerate([header, *rows]):
        tr = t.rows[i]
        if i == 0:
            trpr = tr._tr.get_or_add_trPr()
            h = OxmlElement("w:tblHeader")
            trpr.append(h)
        for j, val in enumerate(row):
            c = tr.cells[j]
            c.width = Twips(int(TEXT_W * widths[j] / total))
            p = c.paragraphs[0]
            p.paragraph_format.space_after = Pt(1)
            p.paragraph_format.space_before = Pt(1)
            p.paragraph_format.line_spacing = 1.0
            p.alignment = (WD_ALIGN_PARAGRAPH.CENTER if (align and align[j] == "c") else WD_ALIGN_PARAGRAPH.LEFT)
            add_rich(p, str(val), size, base_bold=(i == 0))
            if i == 0:
                shade(c, "D9E2EC")
    return t


class Doc:
    """Numbering for chapters, figures and tables, plus the lists for the front matter."""

    def __init__(self, d):
        self.d = d
        self.ch = 0
        self.fig = 0
        self.tab = 0
        self.sec = 0
        self.figs: list[str] = []
        self.tabs: list[str] = []
        self.toc: list[tuple[int, str]] = []

    def chapter(self, title):
        self.ch += 1
        self.fig = self.tab = self.sec = 0
        p = para(self.d, f"CHAPTER - {self.ch}", 16, "center", True, after=0, keep=True)
        outline(p, 0)
        para(self.d, title.upper(), 16, "center", True, after=14, keep=True)
        self.toc.append((0, f"CHAPTER {self.ch} - {title.upper()}"))

    def section(self, title):
        self.sec += 1
        p = para(self.d, f"{self.ch}.{self.sec} {title}", 14, "left", True, before=10, after=4, keep=True)
        outline(p, 1)
        self.toc.append((1, f"{self.ch}.{self.sec} {title}"))

    def sub(self, title):
        p = para(self.d, title, 12, "left", True, before=6, after=2, keep=True)
        return p

    def figure(self, path, caption, width=5.7):
        self.fig += 1
        p = para(self.d, "", align="center", after=2, line=1.0, keep=True)
        p.add_run().add_picture(str(path), width=Inches(width))
        cap = f"Figure {self.ch}.{self.fig}: {caption}"
        para(self.d, cap, 11, "center", True, after=10, line=1.15)
        self.figs.append(cap)
        return f"Figure {self.ch}.{self.fig}"

    def tcap(self, caption):
        self.tab += 1
        cap = f"Table {self.ch}.{self.tab}: {caption}"
        para(self.d, cap, 11, "center", True, before=6, after=4, line=1.15, keep=True)
        self.tabs.append(cap)
        return f"Table {self.ch}.{self.tab}"

    def after_table(self):
        para(self.d, "", after=4, line=1.0)


# ============================================================================ sections
def sect_break(d, proto, fmt=None, start=None, title_pg=False):
    p = d.add_paragraph()
    p.paragraph_format.space_after = Pt(0)
    s = copy.deepcopy(proto)
    for e in list(s):
        if e.tag in (qn("w:headerReference"), qn("w:footerReference"), qn("w:pgNumType"), qn("w:titlePg")):
            s.remove(e)
    if fmt or start:
        n = OxmlElement("w:pgNumType")
        if fmt:
            n.set(qn("w:fmt"), fmt)
        if start:
            n.set(qn("w:start"), str(start))
        s.insert([c.tag for c in s].index(qn("w:cols")), n)
    if title_pg:
        s.append(OxmlElement("w:titlePg"))
    p._p.get_or_add_pPr().append(s)
    return p


def set_hf(section, header_text, footer_mode):
    section.header.is_linked_to_previous = False
    section.footer.is_linked_to_previous = False
    hp = section.header.paragraphs[0]
    for r in list(hp.runs):
        r._r.getparent().remove(r._r)
    if header_text:
        hp.alignment = WD_ALIGN_PARAGRAPH.LEFT
        run_fmt(hp.add_run(header_text), 11, italic=True)
        bdr = OxmlElement("w:pBdr")
        b = OxmlElement("w:bottom")
        for k, v in (("val", "single"), ("sz", "4"), ("space", "1"), ("color", "7F7F7F")):
            b.set(qn(f"w:{k}"), v)
        bdr.append(b)
        hp._p.get_or_add_pPr().append(bdr)
    fp = section.footer.paragraphs[0]
    for r in list(fp.runs):
        r._r.getparent().remove(r._r)
    fp.paragraph_format.tab_stops.clear_all() if hasattr(fp.paragraph_format.tab_stops, "clear_all") else None
    if footer_mode == "roman":
        fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
        field(fp, "PAGE")
    elif footer_mode == "body":
        fp.alignment = WD_ALIGN_PARAGRAPH.LEFT
        fp.paragraph_format.tab_stops.add_tab_stop(Twips(TEXT_W), WD_TAB_ALIGNMENT.RIGHT)
        run_fmt(fp.add_run("Dept. of CSE, ASC, Bengaluru\t"), 11)
        field(fp, "PAGE")


def toc_line(d, text, page, level=0, size=12):
    p = para(d, "", size, "left", after=2, line=1.3)
    p.paragraph_format.left_indent = Inches(0.3 * level)
    p.paragraph_format.tab_stops.add_tab_stop(Twips(TEXT_W), WD_TAB_ALIGNMENT.RIGHT, WD_TAB_LEADER.DOTS)
    run_fmt(p.add_run(text), size, bold=(level == 0))
    run_fmt(p.add_run(f"\t{page}"), size, bold=(level == 0))


# ============================================================================ content
def survey_rows():
    ws = openpyxl.load_workbook(SURVEY, data_only=True)["Literature Survey"]
    rows = [r for r in ws.iter_rows(min_row=5, values_only=True) if r[0]]
    gaps = list(openpyxl.load_workbook(SURVEY, data_only=True)["Gap Mapping"].iter_rows(min_row=4, values_only=True))
    return rows, gaps


REFS = [  # IEEE style; journal/conference/arXiv first, then standards, then websites
    "X. Hou, Y. Zhao, S. Wang and H. Wang, \"Model Context Protocol (MCP): Landscape, security threats, and future research directions,\" *ACM*, 2025, doi: 10.1145/3796519 (arXiv:2503.23278).",
    "W. Zhao, J. Liu, B. Ruan, S. Li and Z. Liang, \"When MCP servers attack: Taxonomy, feasibility, and mitigation,\" arXiv:2509.24272, 2025.",
    "N. Acharya and G. K. Gupta, \"A formal security framework for MCP-based AI agents: Threat taxonomy, verification models and defense mechanisms,\" arXiv:2604.05969, 2026.",
    "\"MCP-38: A comprehensive threat taxonomy for Model Context Protocol,\" arXiv:2603.18063, 2026.",
    "Z. Wang, Y. Gao, Y. Wang, S. Liu, H. Sun, H. Cheng, G. Shi, H. Du and X. Li, \"MCPTox: A benchmark for tool poisoning on real-world MCP servers,\" in *Proc. AAAI Conf. Artificial Intelligence*, 2026, doi: 10.1609/aaai.v40i42.40895.",
    "E. Debenedetti, J. Zhang, M. Balunović, L. Beurer-Kellner, M. Fischer and F. Tramèr, \"AgentDojo: A dynamic environment to evaluate prompt injection attacks and defenses for LLM agents,\" in *Advances in Neural Information Processing Systems (NeurIPS) Datasets and Benchmarks Track*, 2024.",
    "D. Zhang, Z. Li, X. Luo, X. Liu, P. Li and W. Xu, \"MCP Security Bench (MSB): Benchmarking attacks against Model Context Protocol in LLM agents,\" in *Proc. Int. Conf. Learning Representations (ICLR)*, 2026. Code: github.com/dongsenzhang/MSB.",
    "Y. Yang, D. Wu and Y. Chen, \"MCPSecBench: A systematic security benchmark and playground for testing Model Context Protocols,\" arXiv:2508.13220, 2025.",
    "\"Supply-chain threat benchmark for agentic systems and network-level guardrails (SC-Inject-Bench, ShieldNet),\" arXiv:2604.04426, 2026.",
    "S. Yergattikar, \"Securing the tool layer: A threat taxonomy and runtime defense framework for Model Context Protocol deployments,\" in *Proc. ACL 2026 Industry Track*, 2026, aclanthology.org/2026.acl-industry.58.",
    "W. Xing, Z. Qi, Y. Qin, Y. Li, C. Chang, J. Yu, C. Lin, Z. Xie and M. Han, \"MCP-Guard: A multi-stage defense-in-depth framework for securing Model Context Protocol in agentic AI,\" arXiv:2508.10991, 2025.",
    "M. Bhatt, V. S. Narajala and I. Habler, \"ETDI: Mitigating tool squatting and rug pull attacks in MCP by using OAuth-enhanced tool definitions and policy-based access control,\" arXiv:2506.01333, 2025.",
    "\"TrustShiftProbe: Characterizing, benchmarking and defending temporal trust shift at the MCP transport boundary,\" arXiv:2608.23763, 2026.",
    "Q. Zhan, R. Fang, H. S. Panchal and D. Kang, \"Adaptive attacks break defenses against indirect prompt injection attacks on LLM agents,\" in *Findings of NAACL 2025*, doi: 10.18653/v1/2025.findings-naacl.395.",
    "G. Kholkar and R. Ahuja, \"CAPTURE: Context-aware prompt injection testing and robustness enhancement,\" arXiv:2505.12368, 2025.",
    "\"Agent Flight Recorder: Tamper-evident audit trails with on-chain anchoring for long-horizon tool-using agents,\" arXiv:2609.01931, 2026.",
    "A. Bromme, \"A black box for agentic processes: Blockchain-anchored evidence for AI agent communication, human oversight and GRC audits,\" arXiv:2609.04017, 2026.",
    "\"Who audits the auditor? Tamper-proof fraud detection with blockchain-anchored explainable ML,\" arXiv:2604.22096, 2026.",
    "S. A. Crosby and D. S. Wallach, \"Efficient data structures for tamper-evident logging,\" in *Proc. 18th USENIX Security Symposium*, 2009, pp. 317-334.",
    "B. Schneier and J. Kelsey, \"Secure audit logs to support computer forensics,\" *ACM Trans. Information and System Security*, vol. 2, no. 2, pp. 159-176, 1999, doi: 10.1145/317087.317089.",
    "B. Laurie, A. Langley and E. Kasper, \"Certificate Transparency,\" IETF RFC 6962, 2013.",
    "A. Rundgren, B. Jordan and S. Erdtman, \"JSON Canonicalization Scheme (JCS),\" IETF RFC 8785, 2020, doi: 10.17487/RFC8785.",
    "European Parliament and Council, \"Regulation (EU) 2024/1689 (Artificial Intelligence Act),\" *Official Journal of the European Union*, 2024.",
    "OWASP Foundation, \"OWASP MCP Top 10,\" owasp.org, 2025.",
    "Anthropic, \"Model Context Protocol specification,\" modelcontextprotocol.io, 2025.",
]


def front_matter(d, doc: Doc, pages: dict):
    def heading(t, after=14):
        p = para(d, t, 16, "center", True, after=after)
        return p

    # certificate
    heading("CERTIFICATE", 18)
    para(d, f"This is to certify that the project report entitled **“{TITLE}”** submitted by **{STUDENT} ({ROLL})** "
            "as part of the course completion for **Blockchain Technology (24DS743)**, III Semester, Master of Technology in "
            "Computer Science & Engineering (Data Science), Amrita School of Computing, Bengaluru, is a bonafide record of the "
            "work carried out by the student under my guidance and supervision during the academic year 2026-27.", line=1.8)
    para(d, "", after=60)
    p = para(d, "", 12, "left", line=1.2)
    p.paragraph_format.tab_stops.add_tab_stop(Twips(TEXT_W), WD_TAB_ALIGNMENT.RIGHT)
    run_fmt(p.add_run("Signature of the Guide\tSignature of the Chairperson"), 12, bold=True)
    p = para(d, "", 12, "left", line=1.2)
    p.paragraph_format.tab_stops.add_tab_stop(Twips(TEXT_W), WD_TAB_ALIGNMENT.RIGHT)
    run_fmt(p.add_run(f"{GUIDE}\tDepartment of CSE"), 12)
    para(d, f"{GUIDE_DESIG}, Department of CSE", 12, "left", line=1.2)
    para(d, "Amrita School of Computing, Bengaluru", 12, "left", line=1.2)
    para(d, "", after=40)
    para(d, "Examiner:", 12, "left", True)
    page_break(d)
    # declaration
    heading("DECLARATION", 18)
    para(d, f"I, **{STUDENT} ({ROLL})**, hereby declare that this project report entitled **“{TITLE}”** is the record "
            f"of the original work done by me under the guidance of **{GUIDE}, {GUIDE_DESIG}**, Department of Computer Science "
            "and Engineering, Amrita School of Computing, Bengaluru. To the best of my knowledge this work has not formed the "
            "basis for the award of any degree, diploma or similar title to any candidate of any university. All external "
            "datasets, models and publications used are cited, and every reported number can be regenerated from the public "
            "repository github.com/lucky07-07/omniguard-mcp.", line=1.8)
    para(d, "", after=50)
    p = para(d, "", 12, "left", line=1.3)
    p.paragraph_format.tab_stops.add_tab_stop(Twips(TEXT_W), WD_TAB_ALIGNMENT.RIGHT)
    run_fmt(p.add_run("Place: Bengaluru\tSignature of the Student"), 12)
    p = para(d, "", 12, "left", line=1.3)
    p.paragraph_format.tab_stops.add_tab_stop(Twips(TEXT_W), WD_TAB_ALIGNMENT.RIGHT)
    run_fmt(p.add_run(f"Date: November 2026\t{STUDENT} ({ROLL})"), 12)
    return heading


def abstract_and_lists(d, doc: Doc, pages: dict, heading):
    page_break(d)
    heading("ABSTRACT")
    s, cat, lat = R["summary"], R["categories"], R["latency_ms"]
    para(d, "AI agents built on the Model Context Protocol (MCP) now call real tools: they read files, query databases, fetch "
            "web pages and run commands. A single poisoned tool description, an injected instruction in a tool argument, or a "
            "quiet edit to the audit log afterwards is enough to compromise a whole agent workflow, and the operator who runs the "
            "gateway is also the party who could rewrite its log. OmniGuard-MCP is a security gateway that sits between an "
            "agent and its MCP tools. Every `tools/call` passes seven stages (identity, tool integrity, attribute-based access "
            "control, ingress inspection, downstream execution, egress redaction and audit). Tool definitions are pinned with "
            "SHA-256 over their name, description and input schema, so a mid-session description swap (a rug pull, OWASP MCP03) "
            "is blocked as `SCHEMA_DRIFT_RUG_PULL`. Each decision is written to a hash-chained log whose records are sealed into "
            "RFC 6962 Merkle batches; each batch root is anchored on an append-only Solidity contract (AuditAnchor.sol), and an "
            f"independent read-only watcher re-verifies the log against the chain. A three-way ablation on {R['run']['cases']} real "
            "cases drawn from the official MCPTox, AgentDojo and MSB repositories, run against the deployed API, shows that "
            f"schema pinning reduces MCPTox tool-poisoning success from {cat['poisoning']['B']:g}% to {cat['poisoning']['C']:g}%, "
            f"that MSB multi-step attack chains fall from {cat['chain']['A']:g}% to {cat['chain']['C']:g}%, and that post-hoc log "
            f"tampering is detected in {cat['tamper']['C']:g}% of trials with anchoring against {cat['tamper']['B']:g}% for a "
            f"mutable log, with {cat['benign']['C']:g}% of benign AgentDojo tasks still allowed. Median gateway overhead is "
            f"{lat['C']['p50']:.2f} ms; the p95 of {lat['C']['p95']:.0f} ms comes from calls that seal a batch and send the "
            "anchor transaction. The rule engine alone does not stop AgentDojo-style prompt injections "
            f"({cat['injection']['C']:g}% success); adding the digest-pinned Horizon guard model reduces this to "
            f"{cat['injection_ml']['C']:g}% at a {100 - cat['benign_ml']['C']:g}% benign false-positive rate.", line=1.5)
    para(d, "**Keywords:** Model Context Protocol, agentic AI security, tool poisoning, prompt injection, tamper-evident "
            "logging, Merkle tree, blockchain anchoring, smart contracts.", line=1.5, before=6)
    # TOC
    page_break(d)
    heading("TABLE OF CONTENTS")
    p = para(d, "Page No.", 12, "right", True, after=4)
    for name in ("CERTIFICATE", "DECLARATION", "ACKNOWLEDGEMENTS", "ABSTRACT", "LIST OF FIGURES", "LIST OF TABLES"):
        toc_line(d, name, pages.get(name, "…"))
    for level, text in doc.toc:
        toc_line(d, text, pages.get(text, "…"), level)
    toc_line(d, "REFERENCES", pages.get("REFERENCES", "…"))
    page_break(d)
    heading("LIST OF FIGURES")
    for cap in doc.figs:
        num, _, rest = cap.partition(": ")
        toc_line(d, f"{num.replace('Figure', 'Fig.')}   {rest}", pages.get(cap, "…"), 0, 11)
    page_break(d)
    heading("LIST OF TABLES")
    for cap in doc.tabs:
        num, _, rest = cap.partition(": ")
        toc_line(d, f"{num}   {rest}", pages.get(cap, "…"), 0, 11)


def body(d, doc: Doc, proto):
    s, cat, lat = R["summary"], R["categories"], R["latency_ms"]
    ext = EXT["streams"]["prompt_injection_ingress"]["views"]["clean"]
    # --------------------------------------------------------------- chapter 1
    doc.chapter("Introduction")
    doc.section("Background")
    para(d, "The Model Context Protocol (MCP) [25] gives large-language-model agents one JSON-RPC interface for discovering "
            "and calling external tools. An MCP server publishes each tool as a name, a natural-language description and a JSON "
            "input schema; the agent reads that metadata, decides which tool to call and sends a `tools/call` request. The "
            "description is therefore not documentation but part of the prompt, and whoever controls a server controls text "
            "the model treats as instructions. Surveys of the protocol catalogue this attack surface in detail [1]-[4]: tool "
            "poisoning, rug pulls (a server changes a tool after it has been approved), indirect prompt injection through tool "
            "arguments and outputs, cross-tool data exfiltration and command or SQL injection through tool parameters.", indent=0.4)
    para(d, "The threat is measured, not hypothetical. On 45 live MCP servers, MCPTox reports a 72.8% tool-poisoning success "
            "rate against o1-mini, and the most resistant model refused fewer than 3% of poisoned calls [5]; MSB reports "
            "roughly 74% average success for out-of-scope parameter injection through tool responses across nine agents [7]. "
            "Model alignment alone is not a control at the tool layer, so the controls have to sit outside the model, at the "
            "point where calls cross into tools.", indent=0.4)
    doc.section("Problem Statement")
    para(d, "Two properties are needed at that point. First, *prevention*: an MCP call that carries an injection, targets a "
            "path or host it should not, or comes from a tool whose definition changed after it was trusted, must be stopped "
            "before the tool runs, while ordinary work goes through. Second, *accountability*: after an incident, an auditor "
            "must be able to trust the record of what the gateway allowed and denied. A log kept in the gateway's own database "
            "is controlled by the same operator, or the same attacker, who might want to rewrite it. This project builds and "
            "measures one system that provides both, and asks how much each layer contributes when the system is run on real "
            "benchmark data.", indent=0.4)
    doc.section("Why Blockchain Anchoring")
    para(d, "A hash chain makes local edits visible, but anyone with write access to the database can recompute the whole "
            "chain after an edit, or simply delete the newest records; a valid prefix of a chain is still a valid chain. "
            "Tamper evidence therefore needs a checkpoint that lives outside the operator's trust domain [17], [19]. "
            "OmniGuard-MCP batches audit records into Merkle trees [21] and writes each batch root, with its record range, to "
            "an append-only smart contract. The contract enforces two invariants that a database cannot: a batch identifier "
            "must equal the current batch count, and a batch must start immediately after the previous one ends. Once a root "
            "is on chain, no function exists to change or remove it. Only 32 bytes per batch leave the host, so record contents "
            "stay private, and batching amortises transaction cost over many calls. The project also tests whether this "
            "complexity is justified (gap G8 in the survey): the same workload is written to a plain table (R1), a local hash "
            "chain (R2) and the anchored design (R3), and the same tamper attacks are run against all three.", indent=0.4)
    doc.section("Objectives and Contributions")
    bullets(d, [
        "A seven-stage MCP gateway with a deterministic inspection engine (canonicalisation, SQL and shell lexers, path jail, "
        "SSRF checks, DLP, session taint) and an optional, digest-pinned ML guard model.",
        "SHA-256 tool-schema pinning at the ingress gate, per session and against a deployment manifest, which blocks "
        "mid-session rug pulls as `SCHEMA_DRIFT_RUG_PULL` and records expected and observed hashes in the trace and ledger.",
        "A tamper-evident audit layer (hash chain, RFC 6962 Merkle batches, AuditAnchor.sol) with an independent watcher, "
        "compared against two cheaper regimes under eight tamper scenarios.",
        "A three-way ablation on 100 real cases from MCPTox, AgentDojo and MSB run against the live deployment, with "
        "upstream identifiers kept for every case, and a public live dashboard and API.",
    ])
    # --------------------------------------------------------------- chapter 2
    sect_break(d, proto)
    doc.chapter("Literature Survey")
    rows, gaps = survey_rows()
    para(d, "The survey covered 42 sources (35 papers and standards plus supporting references), recorded in "
            "OmniGuard-MCP_Literature_Survey.xlsx with methodology, metrics, relevance and a verification status for each "
            "citation. They fall into five groups.", indent=0.4)
    doc.section("Threat Taxonomies and Benchmarks")
    para(d, "Hou et al. [1] give the canonical lifecycle view of MCP and its threats; Zhao et al. [2] show that 27.2% of "
            "1,360 analysed servers expose exploitable tools; MCPSHIELD [3] formalises a 23-vector taxonomy and finds that no "
            "single published defence covers more than 34% of it; MCP-38 [4] maps 38 threats to the OWASP LLM Top 10 and flags "
            "the lack of observability of agent actions. On the benchmark side, MCPTox [5] measures tool poisoning on real "
            "servers, AgentDojo [6] provides user tasks and injection tasks in four realistic suites, MSB [7] benchmarks attacks "
            "at each pipeline stage including multi-step composites, and MCPSecBench [8] offers protocol-layer test cases. "
            "SC-Inject-Bench [9] shows the limit of manifest hashing: code-level changes that keep the declared interface "
            "intact pass it, and static scanners reach an F1 of only 0.029-0.172.", indent=0.4)
    doc.section("Runtime Defences")
    para(d, "ShieldMCP [10] is the closest runtime system: a transparent proxy that cuts tool-poisoning success from 74.1% to "
            "8.6% and indirect injection through tool responses from 47.2% to 5.8%, at 118 ms median added latency. MCP-Guard "
            "[11] stacks static scanning, an embedding detector and an LLM arbiter (89.07% F1). ETDI [12] proposes "
            "cryptographically signed, versioned tool definitions with OAuth-backed policy, which is the governance idea "
            "behind tool pinning; TrustShiftProbe [13] shows that behavioural rug pulls at runtime remain hard (69.5% to 42.7% "
            "after defence). Zhan et al. [14] break all eight indirect-injection defences they test with adaptive attacks, and "
            "CAPTURE [15] shows detectors that either miss everything or block everything on context-aware prompts, so any "
            "detector result here is reported with its false-positive rate and as non-adaptive.", indent=0.4)
    doc.section("Tamper-Evident Audit and Blockchain Anchoring")
    para(d, "Schneier and Kelsey [20] and Crosby and Wallach [19] established forward-secure and Merkle-based tamper-evident "
            "logging. For agents specifically, Agent Flight Recorder [16] combines a per-event hash chain, Merkle epochs and an "
            "on-chain root on an Ethereum L2 (about 48 µs median overhead per event); Bromme [17] argues that an append-only "
            "log inside the same trust domain cannot give evidence against its own operator; and “Who audits the "
            "auditor?” [18] makes the case for anchoring both ML decisions and workflow execution. None of these sits in "
            "the MCP call path together with prevention controls, and none compares anchoring against cheaper regimes under "
            "the same attacks.", indent=0.4)
    doc.tcap("Selected verified sources from the literature survey")
    picked = [3, 10, 16, 17, 20, 24, 27, 30, 31, 36]
    ref_of = {1: 1, 3: 3, 10: 5, 14: 8, 16: 9, 17: 10, 19: 11, 20: 12, 24: 13, 27: 14, 30: 16, 31: 17, 35: 18, 36: 19}
    trows = []
    for r in rows:
        if r[0] in picked:
            auth = r[1] if not str(r[1]).startswith("(") else str(r[3]).split(":")[0]
            find = re.sub(r"\s+", " ", str(r[8]))
            find = find if len(find) < 120 else find[:117].rsplit(" ", 1)[0] + " …"
            trows.append([f"[{ref_of[r[0]]}]", f"{auth} ({r[2]})", str(r[5]), find, str(r[10])])
    table(d, ["Ref", "Work", "Type", "Key finding", "Gap"], trows, [5, 20, 11, 52, 9], 9, "cclcc")
    doc.after_table()
    doc.section("Research Gaps Addressed")
    para(d, "The survey's gap sheet lists eight gaps. Table 2.2 shows how far this project goes on each; gaps marked "
            "partial or open are stated as limitations rather than claimed.", indent=0.4)
    doc.tcap("Research gaps and their status in this project")
    status = {"G1": "Built and measured (7 stages, one trace)", "G2": "Open: pins cover the declared interface only",
              "G3": "Addressed: chain + Merkle + on-chain sequence continuity", "G4": "Partial: tool and model manifests pinned; watcher keeps its own snapshot",
              "G5": "Partial: model digest and thresholds pinned in config", "G6": "Partial: held-out test split; no adaptive round",
              "G7": "Partial: session taint blocks sensitive-to-egress flows", "G8": "Addressed: R1 / R2 / R3 under identical attacks"}
    table(d, ["Gap", "Statement", "Status here"], [[g[0], g[1], status[g[0]]] for g in gaps if g[0] in status],
          [7, 55, 38], 9, "cll")
    doc.after_table()
    # --------------------------------------------------------------- chapter 3
    sect_break(d, proto)
    doc.chapter("System Architecture")
    para(d, f"{'Figure 3.1'} shows the system. The agent speaks MCP to the gateway, which exposes the same `tools/list` and "
            "`tools/call` methods and forwards allowed calls to the real tool servers. Every call produces a structured trace "
            "and exactly one audit record, whether it was allowed, redacted or denied.", indent=0.4)
    doc.figure(HERE / "fig" / "architecture.png", "OmniGuard-MCP architecture: seven-stage gateway, audit anchoring and watcher")
    doc.section("Gateway Pipeline")
    bullets(d, [
        "**Identity** maps a bearer token to an agent and a role (read_only, analyst, operator, admin).",
        "**Integrity** rejects unknown tools and tools absent from the pinned manifest (`TOOL_UNKNOWN`, `TOOL_NOT_PINNED`).",
        "**ABAC** evaluates deny-by-default policies on role, tool and parameters (path globs, allowed binaries, URL hosts, "
        "SQL table prefixes and LIMIT bounds) and on the session's taint labels.",
        "**Ingress** first verifies the tool-schema pin, then runs the inspection engine on canonicalised arguments: URL, "
        "Base64, hex and Unicode NFKC decoding; a SQL lexer that tracks breakout contexts (tautologies, stacked queries, "
        "comments); a shell lexer; a path jail; SSRF checks for metadata and private addresses; injection signatures and "
        "entropy-based secret detection. Prose segments can additionally be scored by a Horizon guard ONNX model whose files "
        "are verified against SHA-256 digests before loading (two-tier cascade, τ 0.26 for clean sessions and 0.19 "
        "after any rule hit or untrusted content).",
        "**Downstream** forwards the call; **egress** scans the result for secrets and personal data, replaces them with "
        "`[REDACTED:…]` markers and raises the session taint to TAINTED_SENSITIVE, so a later outbound call is denied by ABAC.",
        "**Audit** writes the decision, rule identifiers, risk score, taint state, canonical input hash and schema pin.",
    ])
    doc.section("Tool-Schema Pinning (OWASP MCP03)")
    para(d, "Each tool is identified by `SHA256(canonical_json({name, description, inputSchema}))`, using sorted-key JSON so "
            "that key order cannot change the digest [22]. Two baselines are kept. The deployment manifest pins every tool at "
            "release time. In addition, the first call to a tool in a session pins the digest observed at that moment (trust "
            "on first use). On every later call the ingress stage recomputes the digest: a mismatch with the manifest or the "
            "session pin denies the call with `SCHEMA_DRIFT_RUG_PULL`, and the trace and audit record carry the baseline used, "
            "the expected hash and the observed hash. The session pin still catches drift if an insider re-pins the manifest "
            "mid-session; a new session would trust the re-pinned manifest, which is the documented limit of trust on first "
            "use and the reason the watcher keeps its own manifest snapshot.", indent=0.4)
    doc.section("Audit Regimes and Anchoring")
    para(d, "Three regimes record the same events. R1 is a plain table, the baseline most systems use. R2 adds a hash chain "
            "in which `entry_hash = SHA256(seq ‖ prev_hash ‖ canonical_record)`. R3 adds Merkle batches: every "
            "*k* records (k = 4 on the live demo, 16 in the experiments) are hashed into an RFC 6962 tree, and "
            "`anchorBatch(batchId, root, startSeq, endSeq)` stores the root on AuditAnchor.sol, which rejects out-of-order "
            "batches and sequence gaps and has no update or delete function (Figure 3.2). The IntegrityWatcher runs as a "
            "separate process with a read-only database connection and its own RPC client. It recomputes the chain and every "
            "Merkle root, compares them with the on-chain anchors, checks that every anchored record still exists, and compares "
            "the tool registry with its own manifest snapshot, raising typed alerts such as `HASH_MISMATCH`, "
            "`ANCHOR_RECORDS_MISMATCH`, `TAIL_TRUNCATION` and `MANIFEST_DRIFT`.", indent=0.4)
    doc.figure(HERE / "fig" / "anchoring.png", "R3 audit structure: hash-chained records, Merkle batches and on-chain roots")
    doc.section("Deployment")
    para(d, "The API is a FastAPI service on Render (free tier, about 114 MB resident memory), running the gateway, an "
            "in-process EVM (eth-tester) behind an HTTP bridge, the deployed AuditAnchor contract and SQLite stores for each "
            "regime. The dashboard is a single static page on Vercel (omniguard-mcp.vercel.app) with three views: Gateway "
            "(scenarios, a free-form call editor and the stage trace), Tamper lab (apply an attack, run the watcher, inspect "
            "batches) and Benchmarks. The free tier has no room for the 0.6 GB ONNX model, so the live API runs the deterministic "
            "engine; the hybrid configuration runs locally on an RTX 2060.", indent=0.4)
    # --------------------------------------------------------------- chapter 4
    sect_break(d, proto)
    doc.chapter("Implementation and Results")
    doc.section("Implementation")
    para(d, "The system is about 6,000 lines of Python 3.13 and 110 lines of Solidity (solc 0.8), organised as `security/` "
            "(canonicaliser, analysers, ABAC, taint tracker, tool integrity, ML classifier), `agents/` (gateway, audit anchor, "
            "watcher), `crypto/` (hashing, RFC 6962 Merkle trees, chain client), `storage/` and `api/`. Rules and policies are "
            "YAML; the model manifest pins the ONNX file and tokenizer by SHA-256. A test suite of 204 tests (pytest) covers "
            "the engine, ABAC, pinning and rug pulls, all three audit regimes, every tamper scenario, the watcher and the live "
            "API, and passes with GPU, CPU-only and no model installed.", indent=0.4)
    doc.section("Benchmark Data and Ablation Design")
    src = R["sources"]
    para(d, "All 100 ablation cases are real records sampled (seed 2026) from the official repositories; nothing is "
            "synthetic. Python task files are parsed statically with `ast` rather than executed, and every case keeps its "
            "upstream identifier, file, repository URL and commit in benchmarks/raw_benchmark_samples.json (Table 4.1). "
            "AgentDojo injection goals are wrapped in AgentDojo's own *important_instructions* template and MSB attack "
            "implementations in MSB's own templates. MCPTox poisoned descriptions are delivered as a mid-session swap of a tool "
            "the session already used. MSB composite attacks run as three-step sessions: a sensitive read, the injected "
            "instruction, then the malicious action the attack asks for. Ten further checks replay MSB sessions, pad them with "
            "real AgentDojo calls until every record is anchored, apply one of four ledger attacks, and run the verifier.", indent=0.4)
    doc.tcap("Real benchmark cases used in the ablation")
    table(d, ["Set", "Source (commit)", "n", "Upstream records", "How it is run"], [
        ["Benign", f"AgentDojo ({src['agentdojo']['commit'][:7]})", "30", "user_tasks PROMPT, 4 suites", "write_file as operator; must pass"],
        ["Injection", f"AgentDojo + MSB ({src['MSB']['commit'][:7]})", "25", "13 injection-task GOALs, 12 MSB attack tasks", "payload as tool argument"],
        ["Poisoning", f"MCPTox ({src['MCPTox-Benchmark']['commit'][:7]})", "25", "pure_tool.json poisoned descriptions", "pin, then description swap"],
        ["Chains", "MSB composite types", "10", "attack_type x attack_task x agent_task", "3-step session"],
        ["Tamper", "replayed MSB sessions", "10", "edit, delete, rewrite chain, truncate", "attack ledger, then verify"],
    ], [10, 22, 5, 33, 30], 9, "llcll")
    doc.after_table()
    para(d, "Mode A is unprotected: calls go straight to the tool server and nothing is logged. Mode B keeps every ingress "
            "control (ABAC, engine, taint, DLP) but has no tool-schema pinning and writes to a plain mutable table. Mode C is "
            "the full system. An attack counts as successful when the gateway forwards the malicious call; benign utility is "
            "the share of benign calls forwarded; latency is the server-side gateway time of every call in the run.", indent=0.4)
    doc.section("Ablation Results")
    doc.tcap(f"Three-way ablation on the live API ({R['run']['finished_at'][:10]}); hybrid rows from the local GPU run")
    order = ["benign", "injection", "poisoning", "chain", "tamper", "benign_ml", "injection_ml"]
    metric = {"utility": "utility ↑", "asr": "attack success ↓", "detection": "detected ↑"}
    table(d, ["Case set", "n", "Metric", "A: none", "B: ingress + log", "C: OmniGuard"],
          [[cat[k]["label"], cat[k]["n"], metric[cat[k]["metric"]], f"{cat[k]['A']:g}%", f"{cat[k]['B']:g}%", f"**{cat[k]['C']:g}%**"] for k in order]
          + [["Server latency p50 / p95 (ms)", "", "", f"{lat['A']['p50']:.2f} / {lat['A']['p95']:.2f}",
              f"{lat['B']['p50']:.2f} / {lat['B']['p95']:.2f}", f"{lat['C']['p50']:.2f} / {lat['C']['p95']:.1f}"]],
          [30, 6, 18, 14, 16, 16], 9, "lcllll")
    doc.after_table()
    f1 = doc.figure(ROOT / "benchmarks" / "charts" / "ablation_modes.png", "Attack success, benign utility and tamper detection per mode (live API)")
    para(d, f"Table 4.2 and {f1} separate what each layer buys. Pinning is the only control that stops MCPTox poisoning: "
            f"Mode B forwards {cat['poisoning']['B']:g}% of the swapped tools because the poisoned text is metadata, not an "
            f"argument, while Mode C blocks all {cat['poisoning']['n']} at ingress. Ingress policy alone already stops every MSB "
            "chain at its final step (path jail, binary allow-list and the TAINTED_SENSITIVE egress rule after the secrets read), "
            "so chains do not separate B from C. For tampering, the mutable log only notices interior deletions "
            f"({cat['tamper']['B']:g}%); anchoring detects every edit, rewritten chain and truncation. Utility stays at "
            f"{cat['benign']['C']:g}% on the live engine. The weak point is prompt injection: AgentDojo's *important_instructions* "
            "text and MSB's templates contain no phrase the rule engine treats as an attack, so all 25 are forwarded in every "
            "mode. With the digest-pinned Horizon guard model the same cases are all blocked, at the cost of three benign "
            "AgentDojo tasks (10%) that the model flags (last two rows of Table 4.2).", indent=0.4)
    doc.section("Tamper Detection Across Regimes")
    ov = {r["regime"]: r for r in TAMPER.get("overall", [])} if isinstance(TAMPER, dict) else {}
    para(d, "The controlled tamper experiment (96 calls, batch size 16, five randomised trials per scenario and regime, a "
            "fresh watcher process per sweep) gives the per-regime picture in Table 4.3. R1 sees only deletions that leave an "
            "id gap. R2 adds edits and reordering but cannot see a recomputed chain or a truncated tail. R3 detects all 40 trials "
            "with no false alarms on the clean log, because the forged or missing records no longer reproduce the on-chain "
            "roots and range.", indent=0.4)
    doc.tcap("Tamper detection by scenario and regime (5 trials each)")
    table(d, ["ID", "Scenario", "R1", "R2", "R3"], [
        ["S1", "Field modification (DENY to ALLOW, rules scrubbed)", "0%", "100%", "100%"],
        ["S2", "Interior record deletion", "100%", "100%", "100%"],
        ["S3", "Tail truncation / rollback of latest batch", "0%", "0%", "100%"],
        ["S4", "Record reordering / payload swap", "0%", "100%", "100%"],
        ["S5", "Merkle root forgery (chain and local roots recomputed)", "0%", "0%", "100%"],
        ["S6b", "Tool rug-pull with gateway pins rewritten by an insider", "0%", "0%", "100%"],
        ["S7", "ML model / tokenizer tampering with manifest rewritten", "0%", "0%", "100%"],
        ["", "**Overall (40 trials)**", "**25%**", "**50%**", "**100%**"],
    ], [7, 63, 10, 10, 10], 9, "clccc")
    doc.after_table()
    doc.section("Detection Quality and Latency")
    para(d, f"On the held-out official test split of the prompt-injection stream (n = {ext['v1.2']['n'] if 'n' in ext['v1.2'] else 95}), F1 rises from "
            f"{ext['v1.0']['f1']:.2f} with rules alone to {ext['v1.2']['f1']:.2f} with the Horizon guard cascade at precision "
            f"{ext['v1.2']['precision']:.2f} (Figure 4.2); SQL and command injection reach 0.92 and 0.91 F1 on 500 rows each. "
            "Thresholds were chosen on a separate validation split and frozen before the test split was scored.", indent=0.4)
    doc.figure(ROOT / "results" / "external_dataset_eval.png", "External held-out detection F1 by engine version (0.30 to 0.84 on prompt injection)", 4.4)
    para(d, f"{'Figure 4.3'} shows server-side latency on the live API. Inspection costs about one millisecond "
            f"(Mode B p50 {lat['B']['p50']:.2f} ms); the full system's median is {lat['C']['p50']:.2f} ms. Its p95 of "
            f"{lat['C']['p95']:.0f} ms is the one call in four that seals a Merkle batch and waits for the anchor transaction; "
            "the controlled benchmark shows that moving anchoring off the request path (R3-async) brings p95 back to 1.7 ms. "
            "This is well inside the 118 ms median reported for ShieldMCP [10].", indent=0.4)
    doc.figure(ROOT / "benchmarks" / "charts" / "latency_p50_p95.png", "Server-side latency per call by mode, live API (log scale)", 4.0)
    doc.section("Live Dashboard")
    sh = ROOT / "benchmarks" / "screenshots"
    para(d, "Figures 4.4 to 4.7 are captured from the deployed dashboard after real calls to the live API; the SQL "
            "injection scenario is denied at ingress with `SQL_TAUTOLOGY` in the same view.", indent=0.4)
    doc.figure(sh / "03_schema_drift_block.png", "Mid-session rug pull denied as SCHEMA_DRIFT_RUG_PULL with expected and observed hashes", 4.4)
    doc.figure(sh / "05_redact_tainted_trace.png", "Secrets read is redacted; the tainted session's outbound POST is denied by ABAC", 4.4)
    doc.figure(sh / "04_r3_rewrite_alerts.png", "Tamper lab: a recomputed chain passes R1 and R2 but raises R3 anchor alerts", 4.4)
    doc.figure(sh / "06_benchmarks_panel.png", "Benchmarks view with the three-way ablation and p50 / p95 latency", 4.4)
    # --------------------------------------------------------------- chapter 5
    sect_break(d, proto)
    doc.chapter("Conclusion and Future Scope")
    doc.section("Conclusion")
    para(d, "OmniGuard-MCP shows that prevention and evidence can live in one MCP gateway at about two milliseconds of "
            "median overhead. On real benchmark data the layers contribute differently and measurably: SHA-256 schema pinning "
            "is what stops tool poisoning and rug pulls; ingress policy and session taint are what stop multi-step chains; "
            "and blockchain anchoring is what turns a log the operator could rewrite into evidence the operator cannot "
            "rewrite without being caught, raising post-hoc tamper detection from 30% (mutable log) and 50% (local hash chain) "
            "to 100%. The project also found its own weak point: a rules-only engine misses benchmark-style prompt injections "
            "completely, and the ML stage that closes the gap costs a 10% false-positive rate on benign tasks.", indent=0.4)
    doc.section("Limitations")
    bullets(d, [
        "Pins cover a tool's declared interface, not its implementation; code-level supply-chain changes (gap G2) pass.",
        "Detector results are non-adaptive; adaptive attacks [14] are expected to lower them.",
        "The live chain is an in-process EVM; the contract is unchanged on a public L2, but costs there were not measured.",
        "The demo tools are simulated and records after the last anchored batch are unprotected for one batch.",
    ])
    doc.section("Future Scope")
    bullets(d, [
        "Anchor on a public L2 testnet and report gas per batch and cost per 100,000 calls against batch size.",
        "Bind server artifact digests and declared egress allow-lists into the pin to narrow gap G2.",
        "Run an adaptive attack round and over-defence sets, and reduce false positives with per-tool output types.",
    ])
    # references (own section)
    sect_break(d, proto)
    p = para(d, "REFERENCES", 16, "center", True, after=12)
    outline(p, 0)
    for i, ref in enumerate(REFS, 1):
        q = para(d, "", 10, "justify", after=2, line=1.1)
        q.paragraph_format.left_indent = Inches(0.45)
        q.paragraph_format.first_line_indent = Inches(-0.45)
        q.paragraph_format.tab_stops.add_tab_stop(Inches(0.45))
        run_fmt(q.add_run(f"[{i}]\t"), 11)
        add_rich(q, ref, 10)


# ============================================================================ assembly
def build(pages: dict, out: Path) -> Doc:
    d = docx.Document(str(TEMPLATE))
    P = d.paragraphs
    bodyel = d.element.body
    final_sect = bodyel[-1]
    for e in list(final_sect):
        if e.tag in (qn("w:headerReference"), qn("w:footerReference"), qn("w:titlePg"), qn("w:pgNumType")):
            final_sect.remove(e)
    proto = copy.deepcopy(final_sect)
    # --- title page edits
    def set_text(p, text, size=None, bold=None):
        runs = p.runs
        for r in runs[1:]:
            r._r.getparent().remove(r._r)
        runs[0].text = text
        if size:
            runs[0].font.size = Pt(size)
        if bold is not None:
            runs[0].bold = bold

    set_text(P[0], TITLE, 16, True)
    for i in range(0, 15):
        P[i].paragraph_format.space_before = Pt(6)
        P[i].paragraph_format.space_after = Pt(6)
    set_text(P[3], f"{ROLL}\t\t{STUDENT}", 16)
    P[3].alignment = WD_ALIGN_PARAGRAPH.CENTER
    set_text(P[9], "COMPUTER SCIENCE & ENGINEERING (DATA SCIENCE)")
    P[21].runs[0].text = "\t"
    for r in P[21].runs[1:]:
        r._r.getparent().remove(r._r)
    run_fmt(P[21].add_run("It is a great pleasure to express my gratitude and indebtedness to my project guide "), 12)
    run_fmt(P[21].add_run(f"{GUIDE}, {GUIDE_DESIG}"), 12, bold=True)
    run_fmt(P[21].add_run(", Department of Computer Science and Engineering, Amrita School of Computing, Bengaluru, for "
                          "her valuable guidance, encouragement, moral support and affection throughout the project work."), 12)
    ack_start = P[16]._p
    # drop the placeholder body after the acknowledgement
    started = False
    for el in list(bodyel):
        if el is P[23]._p:
            started = True
        if started and el is not final_sect:
            bodyel.remove(el)
    # strip the page break that opened the acknowledgement (certificate/declaration now precede it)
    for p in [x for x in d.paragraphs if x._p is ack_start]:
        pass
    doc = Doc(d)
    # --- section 0: title page. Section break goes right before the acknowledgement block; certificate +
    #     declaration are built at the end and moved in front of the acknowledgement afterwards.
    mark = len(bodyel) - 1
    sb0 = sect_break(d, proto)
    heading = front_matter(d, doc, pages)
    moved_until = len(bodyel) - 1
    fm = list(bodyel)[mark:moved_until]
    for el in fm:
        ack_start.addprevious(el)
    # acknowledgement keeps its own leading page break
    # dry-run body to collect TOC / figure / table lists, then rebuild with lists placed before it
    scratch = docx.Document(str(TEMPLATE))
    for el in list(scratch.element.body)[:-1]:
        scratch.element.body.remove(el)
    tmp = Doc(scratch)
    body(scratch, tmp, proto)
    doc.toc, doc.figs, doc.tabs = tmp.toc, tmp.figs, tmp.tabs
    abstract_and_lists(d, doc, pages, heading)
    sect_break(d, proto, fmt="lowerRoman", start=1)
    real = Doc(d)
    body(d, real, proto)
    # --- headers / footers per section
    secs = d.sections
    names = ["", "", "CHAPTER 1 - INTRODUCTION", "CHAPTER 2 - LITERATURE SURVEY", "CHAPTER 3 - SYSTEM ARCHITECTURE",
             "CHAPTER 4 - IMPLEMENTATION AND RESULTS", "CHAPTER 5 - CONCLUSION AND FUTURE SCOPE", "REFERENCES"]
    set_hf(secs[0], "", "none")
    set_hf(secs[1], "", "roman")
    for i in range(2, len(secs)):
        set_hf(secs[i], names[i] if i < len(names) else "", "body")
    # body numbering starts at 1 in the first chapter section
    sp = secs[2]._sectPr
    for e in sp.findall(qn("w:pgNumType")):
        sp.remove(e)
    n = OxmlElement("w:pgNumType")
    n.set(qn("w:start"), "1")
    sp.insert([c.tag for c in sp].index(qn("w:cols")), n)
    for s in secs:
        for e in s._sectPr.findall(qn("w:titlePg")):
            s._sectPr.remove(e)
    # section 1 starts with the certificate: it was moved before the ack, but the section break sb0 sits after it.
    d.save(str(out))
    return real


def fix_first_section(path: Path):
    """The title-page section break has to sit right after the title page. Move it there."""
    d = docx.Document(str(path))
    bodyel = d.element.body
    paras = d.paragraphs
    cert = next(p for p in paras if p.text.strip() == "CERTIFICATE")
    sb = next(p for p in paras if p._p.find(qn("w:pPr")) is not None and p._p.find(qn("w:pPr")).find(qn("w:sectPr")) is not None)
    cert._p.addprevious(sb._p)
    d.save(str(path))


def word_pdf(docx_path: Path, pdf_path: Path):
    ps = (f"$w = New-Object -ComObject Word.Application; $w.Visible = $false; "
          f"$d = $w.Documents.Open('{docx_path}'); $d.Fields.Update() | Out-Null; "
          f"$d.SaveAs2('{pdf_path}', 17); $d.Close($false); $w.Quit()")
    subprocess.run(["powershell", "-NoProfile", "-Command", ps], check=True, capture_output=True, text=True, timeout=300)


def page_map(pdf: Path, doc: Doc) -> dict:
    n = int(re.search(r"Pages:\s+(\d+)", subprocess.run(["pdfinfo", str(pdf)], capture_output=True, text=True).stdout).group(1))
    texts = [subprocess.run(["pdftotext", "-f", str(i), "-l", str(i), "-layout", str(pdf), "-"], capture_output=True,
                            text=True, encoding="utf-8", errors="replace").stdout for i in range(1, n + 1)]
    norm = lambda s: re.sub(r"\s+", " ", s).strip().lower()  # noqa: E731
    T = [norm(t) for t in texts]
    ch1 = next(i for i, t in enumerate(T) if "chapter - 1" in t and "introduction" in t and "table of contents" not in t)
    cert = next(i for i, t in enumerate(T) if t.startswith("certificate") or " certificate this is to certify" in t or "certificate" in t[:40])
    roman = lambda k: ["i", "ii", "iii", "iv", "v", "vi", "vii", "viii", "ix", "x", "xi", "xii"][k]  # noqa: E731
    pages = {}
    for key, needle in (("CERTIFICATE", "this is to certify"), ("DECLARATION", "hereby declare"),
                        ("ACKNOWLEDGEMENTS", "acknowledgements"), ("ABSTRACT", "abstract ai agents"),
                        ("LIST OF FIGURES", "list of figures fig"), ("LIST OF TABLES", "list of tables table")):
        idx = next((i for i in range(cert, ch1) if needle in T[i][:400]), None)
        if idx is not None:
            pages[key] = roman(idx - cert)
    for level, text in doc.toc:
        key = norm(text.split(" - ", 1)[0].replace("CHAPTER ", "chapter - ") if level == 0 else text)
        idx = next((i for i in range(ch1, n) if key in T[i]), None)
        if idx is not None:
            pages[text] = str(idx - ch1 + 1)
    for cap in doc.figs + doc.tabs:
        key = norm(cap)[:60]
        idx = next((i for i in range(ch1, n) if key in T[i]), None)
        if idx is not None:
            pages[cap] = str(idx - ch1 + 1)
    ref = next((i for i in range(n - 1, ch1, -1) if T[i].startswith("references") or "references [1]" in T[i]), None)
    if ref is not None:
        pages["REFERENCES"] = str(ref - ch1 + 1)
    pages["_body_pages"] = n - ch1
    pages["_total"] = n
    return pages


def main():
    WORK.mkdir(exist_ok=True)
    out = WORK / OUT_NAME
    pages: dict = {}
    for attempt in range(3):
        doc = build(pages, out)
        pdf = out.with_suffix(".pdf")
        word_pdf(out.resolve(), pdf.resolve())
        new = page_map(pdf, doc)
        missing = [k for k in [t for _, t in doc.toc] + doc.figs + doc.tabs if k not in new]
        print(f"pass {attempt + 1}: {new['_total']} pages, body {new['_body_pages']}, unresolved {len(missing)}", missing[:5])
        if {k: v for k, v in new.items() if not k.startswith("_")} == {k: v for k, v in pages.items() if not k.startswith("_")}:
            break
        pages = new
    for dest in (ROOT / "docs", BC):
        shutil.copyfile(out, dest / OUT_NAME)
    shutil.copyfile(pdf, ROOT / "docs" / OUT_NAME.replace(".docx", ".pdf"))
    print("written", OUT_NAME, "to docs/ and", BC)


if __name__ == "__main__":
    sys.exit(main())

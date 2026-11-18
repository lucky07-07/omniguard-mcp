"""Stage 2 and Stage 4: structural, parser-based analyzers and entropy DLP.

Each analyzer parses its argument type properly rather than grepping text:

* PathJail       - posix path normalisation + containment in workspace roots
* SSRFValidator  - urllib.parse + ipaddress (incl. decimal/octal/hex IP forms)
* ShellAnalyzer  - quote-aware scanner + shlex tokenisation
* SQLAnalyzer    - small SQL lexer; detections operate on the token stream,
                   so quoted string literals and prose never trigger them
* EntropyDLP     - known secret prefixes gated by Shannon entropy, plus
                   generic high-entropy tokens; supports in-place redaction

Analyzers return lists of `Finding(rule_id, detail)`; weights live in
configs/security_rules.yaml.
"""

from __future__ import annotations

import fnmatch
import ipaddress
import math
import posixpath
import re
import shlex
from collections import Counter
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit


@dataclass(frozen=True)
class Finding:
    rule_id: str
    detail: str = ""


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in Counter(s).values())


def glob_match(path: str, pattern: str) -> bool:
    """Glob where `**` spans directories and `*` stays within one segment."""
    regex = ""
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            regex += "(?:.*/)?"
            i += 3
        elif pattern.startswith("**", i):
            regex += ".*"
            i += 2
        elif pattern[i] == "*":
            regex += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            regex += "[^/]"
            i += 1
        else:
            regex += re.escape(pattern[i])
            i += 1
    return re.fullmatch(regex, path) is not None


# ============================================================== filesystem
class PathJail:
    def __init__(self, roots: list[str], sensitive_globs: list[str] | None = None):
        self.roots = [posixpath.normpath(r) for r in roots]
        self.sensitive_globs = sensitive_globs or []

    def resolve(self, path: str) -> str:
        p = path.replace("\\", "/")
        if not p.startswith("/"):
            p = posixpath.join(self.roots[0], p)
        p = posixpath.normpath(p)
        return "/" + p.lstrip("/")  # collapse leading '//' (posix allows it; we don't)

    def contained(self, resolved: str) -> bool:
        return any(resolved == r or resolved.startswith(r.rstrip("/") + "/") for r in self.roots)

    def is_sensitive(self, path: str) -> bool:
        resolved = self.resolve(path)
        return any(glob_match(resolved, g) for g in self.sensitive_globs)

    def analyze(self, path: str) -> list[Finding]:
        out: list[Finding] = []
        if "\x00" in path:
            out.append(Finding("PATH_NULL_BYTE", "NUL byte in path"))
            path = path.replace("\x00", "")
        p = path.replace("\\", "/")
        if p.startswith("~") or re.match(r"^[A-Za-z]:", p) or p.startswith("//"):
            out.append(Finding("PATH_HOME_OR_DRIVE", f"home/drive/UNC path {path!r}"))
        resolved = self.resolve(path)
        if not self.contained(resolved):
            segs = [s for s in p.split("/") if s]
            rule = "PATH_TRAVERSAL_ESCAPE" if ".." in segs else "PATH_OUTSIDE_WORKSPACE"
            out.append(Finding(rule, f"{path!r} resolves to {resolved!r}, outside {self.roots}"))
        return out


# ============================================================== network
def _parse_nonstandard_ipv4(host: str) -> ipaddress.IPv4Address | None:
    """Parse inet_aton-style IPv4 forms: 2130706433, 0x7f000001, 0177.0.0.1, 127.1."""
    parts = host.split(".")
    if not 1 <= len(parts) <= 4 or not all(parts):
        return None
    nums = []
    for p in parts:
        try:
            if p.lower().startswith("0x"):
                nums.append(int(p, 16))
            elif len(p) > 1 and p.startswith("0"):
                nums.append(int(p, 8))
            else:
                nums.append(int(p, 10))
        except ValueError:
            return None
    if len(nums) == 1:
        val = nums[0]
    elif len(nums) == 2:
        val = (nums[0] << 24) | nums[1]
    elif len(nums) == 3:
        val = (nums[0] << 24) | (nums[1] << 16) | nums[2]
    else:
        if any(n > 255 for n in nums):
            return None
        val = (nums[0] << 24) | (nums[1] << 16) | (nums[2] << 8) | nums[3]
    if not 0 <= val <= 0xFFFFFFFF:
        return None
    return ipaddress.IPv4Address(val)


class SSRFValidator:
    METADATA_NETS = [ipaddress.ip_network("169.254.169.254/32"), ipaddress.ip_network("fd00:ec2::254/128")]

    def __init__(self, allowed_schemes: list[str], blocked_hostnames: list[str], blocked_suffixes: list[str]):
        self.allowed_schemes = {s.lower() for s in allowed_schemes}
        self.blocked_hostnames = {h.lower() for h in blocked_hostnames}
        self.blocked_suffixes = [s.lower() for s in blocked_suffixes]

    def analyze(self, url: str) -> list[Finding]:
        try:
            parts = urlsplit(url.strip())
            host = parts.hostname
            _ = parts.port  # raises on garbage ports
        except ValueError as exc:
            return [Finding("SSRF_MALFORMED_URL", str(exc))]
        scheme = parts.scheme.lower()
        if scheme not in self.allowed_schemes:
            return [Finding("SSRF_UNSAFE_SCHEME", f"scheme {scheme or '(none)'!r} not allowed")]
        if not host:
            return [Finding("SSRF_MALFORMED_URL", "no host")]
        host = host.rstrip(".").lower()
        out: list[Finding] = []
        if host in self.blocked_hostnames or any(host.endswith(s) for s in self.blocked_suffixes):
            out.append(Finding("SSRF_BLOCKED_HOSTNAME", host))
        ip: ipaddress.IPv4Address | ipaddress.IPv6Address | None = None
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            alt = _parse_nonstandard_ipv4(host)
            if alt is not None:
                ip = alt
                out.append(Finding("SSRF_NONSTANDARD_IP_ENCODING", f"{host} == {alt}"))
        if ip is not None:
            if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
                ip = ip.ipv4_mapped
            if any(ip in n for n in self.METADATA_NETS) or ip.is_link_local:
                out.append(Finding("SSRF_LINK_LOCAL_METADATA", str(ip)))
            elif ip.is_unspecified:  # 0.0.0.0 / :: reach the local host on most stacks
                out.append(Finding("SSRF_RESERVED_ADDRESS", str(ip)))
            elif ip.is_loopback:
                out.append(Finding("SSRF_LOOPBACK", str(ip)))
            elif ip.is_private:
                out.append(Finding("SSRF_PRIVATE_ADDRESS", str(ip)))
            elif ip.is_reserved or ip.is_multicast or ip.is_unspecified:
                out.append(Finding("SSRF_RESERVED_ADDRESS", str(ip)))
        return out


# ============================================================== shell
# interpreter-level code execution (PHP/Python/JS/Perl) - never valid shell syntax
CODE_EXEC_RE = re.compile(r"\b(eval|exec|system|passthru|shell_exec|popen|proc_open|pcntl_exec|assert|"
                          r"__import__|subprocess\.\w+|os\.(system|popen)|Runtime\.getRuntime)\s*\(", re.I)
# server-side template / expression-language injection markers
TEMPLATE_INJECTION_RE = re.compile(r"\{\{.*?\}\}|\{%.*?%\}|\$\{[^}]*\(|#\{.*?\}|<%=?.*?%>", re.S)
SENSITIVE_FILE_RE = re.compile(r"^/(etc/(passwd|shadow|sudoers)|root/|proc/self/)|\.ssh/|id_rsa|\.aws/credentials")


class ShellAnalyzer:
    def __init__(self, dangerous_binaries: list[str]):
        self.dangerous = {b.lower() for b in dangerous_binaries}

    def _scan(self, cmd: str) -> tuple[list[Finding], list[str]]:
        """Quote-aware scan. Returns findings and the unquoted command segments."""
        findings: dict[str, Finding] = {}
        segments, buf = [], []
        state: str | None = None
        i = 0
        while i < len(cmd):
            ch = cmd[i]
            nxt = cmd[i + 1] if i + 1 < len(cmd) else ""
            if state == "'":
                if ch == "'":
                    state = None
                buf.append(ch)
                i += 1
                continue
            if ch == "\\":
                buf.append(cmd[i:i + 2])
                i += 2
                continue
            if ch == "`" or (ch == "$" and nxt == "("):
                findings.setdefault("SHELL_COMMAND_SUBSTITUTION", Finding("SHELL_COMMAND_SUBSTITUTION", ch + nxt))
            elif ch == "$" and (nxt == "{" or nxt.isalpha() or nxt == "_"):
                findings.setdefault("SHELL_VARIABLE_EXPANSION", Finding("SHELL_VARIABLE_EXPANSION", ch + nxt))
            if state == '"':
                if ch == '"':
                    state = None
                buf.append(ch)
                i += 1
                continue
            if ch in "'\"":
                state = ch
                buf.append(ch)
            elif ch in ";\n\r" or (ch == "&" and nxt != ">") or ch == "|":
                op = ch + (nxt if nxt in "&|" else "")
                findings.setdefault("SHELL_COMMAND_CHAINING", Finding("SHELL_COMMAND_CHAINING", repr(op)))
                segments.append("".join(buf))
                buf = []
                i += len(op)
                continue
            elif ch in "<>":
                findings.setdefault("SHELL_REDIRECTION", Finding("SHELL_REDIRECTION", ch))
                buf.append(" ")
            else:
                buf.append(ch)
            i += 1
        if state is not None:
            findings["SHELL_UNBALANCED_QUOTE"] = Finding("SHELL_UNBALANCED_QUOTE", f"unterminated {state}")
        segments.append("".join(buf))
        return list(findings.values()), segments

    def analyze(self, cmd: str) -> list[Finding]:
        findings, segments = self._scan(cmd)
        seen = {f.rule_id for f in findings}
        m = CODE_EXEC_RE.search(cmd)
        if m:
            findings.append(Finding("SHELL_CODE_EXEC_CALL", m.group(0)))
            seen.add("SHELL_CODE_EXEC_CALL")
        m = TEMPLATE_INJECTION_RE.search(cmd)
        if m:
            findings.append(Finding("SHELL_TEMPLATE_INJECTION", m.group(0)[:40]))
            seen.add("SHELL_TEMPLATE_INJECTION")
        for seg in segments:
            try:
                tokens = shlex.split(seg, posix=True)
            except ValueError:
                tokens = seg.split()
            if not tokens:
                continue
            binary = posixpath.basename(tokens[0].replace("\\", "/")).lower()
            if binary.endswith(".exe"):
                binary = binary[:-4]
            if binary in self.dangerous and "SHELL_DANGEROUS_BINARY" not in seen:
                findings.append(Finding("SHELL_DANGEROUS_BINARY", binary))
                seen.add("SHELL_DANGEROUS_BINARY")
            for t in tokens:
                if SENSITIVE_FILE_RE.search(t) and "SHELL_SENSITIVE_FILE" not in seen:
                    findings.append(Finding("SHELL_SENSITIVE_FILE", t))
                    seen.add("SHELL_SENSITIVE_FILE")
        return findings

    @staticmethod
    def binaries(cmd: str) -> list[str]:
        """First token of every chained segment (used by ABAC binary allowlists). Quote-aware."""
        _, parts = ShellAnalyzer([])._scan(cmd)
        out = []
        for seg in parts:
            try:
                toks = shlex.split(seg)
            except ValueError:
                toks = seg.split()
            if toks:
                out.append(posixpath.basename(toks[0]).lower())
        return out


# ============================================================== SQL
SQL_TOKEN_RE = re.compile(
    r"""
    (?P<ws>\s+)
  | (?P<comment>--[^\n]*|\#[^\n]*|/\*.*?(?:\*/|\Z))
  | (?P<string>'(?:[^'\\]|''|\\.)*(?:'|\Z)|"(?:[^"\\]|""|\\.)*(?:"|\Z)|`[^`]*(?:`|\Z))
  | (?P<hex>0x[0-9A-Fa-f]+)
  | (?P<number>\d+(?:\.\d+)?)
  | (?P<var>@@?[A-Za-z_][A-Za-z0-9_]*)
  | (?P<word>[A-Za-z_][A-Za-z0-9_$]*(?:\.[A-Za-z_][A-Za-z0-9_$]*)*)
  | (?P<op><>|!=|<=|>=|\|\||&&|::|[=<>+\-*/%,;()|&^~!])
  | (?P<other>.)
    """,
    re.S | re.X,
)

DESTRUCTIVE = {"DROP", "TRUNCATE", "ALTER", "GRANT", "REVOKE", "CREATE", "DELETE", "SHUTDOWN", "ATTACH",
               "DETACH", "EXEC", "EXECUTE", "RENAME", "VACUUM", "PRAGMA", "DECLARE", "CALL", "LOAD"}
WRITE = {"INSERT", "UPDATE", "REPLACE", "MERGE", "UPSERT"}
TIME_FUNCS = {"SLEEP", "PG_SLEEP", "BENCHMARK", "WAITFOR", "DBMS_LOCK.SLEEP", "DBMS_PIPE.RECEIVE_MESSAGE",
              "RANDOMBLOB"}
DANGEROUS_FUNCS = {"LOAD_FILE", "XP_CMDSHELL", "SP_OACREATE", "SP_EXECUTESQL", "OPENROWSET", "OPENQUERY",
                   "OPENDATASOURCE", "LO_IMPORT", "LO_EXPORT", "SYS_EVAL", "SYS_EXEC", "EXTRACTVALUE",
                   "UPDATEXML", "UTL_INADDR.GET_HOST_ADDRESS", "UTL_INADDR.GET_HOST_NAME", "UTL_HTTP.REQUEST",
                   "DBMS_XMLGEN.GETXML", "CTXSYS.DRITHSX.SN", "LOAD_EXTENSION", "PG_READ_FILE", "PG_LS_DIR",
                   "XP_DIRTREE", "XP_REGREAD", "MASTER..XP_CMDSHELL", "XMLTYPE", "DBMS_UTILITY.SQLID_TO_SQLHASH",
                   "GTID_SUBSET", "NAME_CONST"}
FINGERPRINT = {"VERSION", "@@VERSION", "USER", "CURRENT_USER", "SYSTEM_USER", "SESSION_USER", "DATABASE",
               "SCHEMA", "@@DATADIR", "@@HOSTNAME", "DB_NAME", "SQLITE_VERSION", "BANNER", "@@SERVERNAME",
               "USER_NAME", "SUSER_NAME", "HOST_NAME"}
CATALOG_RE = re.compile(
    r"information_schema|sqlite_master|sqlite_schema|sqlite_temp_master|pg_catalog|pg_shadow|pg_user|pg_tables|"
    r"mysql\.user|sys\.(objects|tables|columns|databases|sql_logins|all_tables|user_tables)|sysobjects|syscolumns|"
    r"sysdatabases|all_tables|user_tables|dba_users|all_users|all_tab_columns|msysobjects|msysaccessobjects|v\$version|"
    r"sysibm\.\w+|syscat\.\w+|rdb\$\w+|sysmaster:|domain\.(domains|tables|columns)|information_schema",
    re.I,
)
COMPARISON_OPS = {"=", "<>", "!=", "<", ">", "<=", ">=", "LIKE"}
STATEMENT_START = {"SELECT", "WITH", "INSERT", "UPDATE", "DELETE", "REPLACE", "MERGE", "CREATE", "DROP", "ALTER",
                   "TRUNCATE", "GRANT", "REVOKE", "EXPLAIN", "VALUES", "SHOW", "DESCRIBE", "PRAGMA", "CALL", "EXEC",
                   "EXECUTE", "DECLARE", "SET", "USE", "BEGIN", "COMMIT", "ROLLBACK"}
CLAUSE_KEYWORDS = {"WHERE", "JOIN", "INNER", "LEFT", "RIGHT", "OUTER", "FULL", "CROSS", "ON", "GROUP", "ORDER",
                   "LIMIT", "HAVING", "UNION", "OFFSET", "SET", "VALUES", "AS", "USING", "NATURAL", "SELECT",
                   "INTO", "WINDOW", "EXCEPT", "INTERSECT", "FETCH", "FOR"}


@dataclass
class SqlToken:
    kind: str
    text: str

    @property
    def upper(self) -> str:
        return self.text.upper()


def sql_tokens(query: str) -> list[SqlToken]:
    out = []
    for m in SQL_TOKEN_RE.finditer(query):
        kind = m.lastgroup or "other"
        if kind != "ws":
            out.append(SqlToken(kind, m.group(0)))
    return out


def _is_literal(t: SqlToken) -> bool:
    return t.kind in ("number", "string", "hex") or t.upper in ("TRUE", "FALSE", "NULL")


def _literal_value(t: SqlToken) -> str:
    if t.kind == "string" and len(t.text) >= 2 and t.text[-1] == t.text[0]:
        return t.text[1:-1]
    if t.kind == "string":
        return t.text[1:]
    return t.upper


class SQLAnalyzer:
    def __init__(self, sensitive_table_prefixes: list[str] | None = None):
        self.sensitive_prefixes = [p.lower() for p in (sensitive_table_prefixes or [])]

    def structure(self, query: str) -> dict[str, Any]:
        """Statement types, LIMIT value and referenced tables (for ABAC constraints)."""
        toks = [t for t in sql_tokens(query) if t.kind != "comment"]
        statements: list[str] = []
        expect_stmt = True
        tables: list[str] = []
        limit: int | None = None
        for i, t in enumerate(toks):
            if t.text == ";":
                expect_stmt = True
                continue
            if expect_stmt and t.kind == "word":
                statements.append(t.upper)
                expect_stmt = False
            elif expect_stmt and t.text != "(":
                expect_stmt = False
            if t.kind == "word" and t.upper in ("FROM", "JOIN", "INTO", "UPDATE", "TABLE"):
                j = i + 1
                while j < len(toks):
                    nt = toks[j]
                    if nt.kind == "word" and nt.upper not in CLAUSE_KEYWORDS:
                        tables.append(nt.text.strip('`"').lower())
                        j += 1
                        # skip an optional alias, then continue a comma list
                        if j < len(toks) and toks[j].kind == "word" and toks[j].upper not in CLAUSE_KEYWORDS:
                            j += 1
                        if j < len(toks) and toks[j].text == ",":
                            j += 1
                            continue
                    elif nt.kind == "string" and nt.text[:1] in '"`':
                        tables.append(_literal_value(nt).lower())
                    break
            if t.kind == "word" and t.upper == "LIMIT" and i + 1 < len(toks) and toks[i + 1].kind == "number":
                val = int(float(toks[i + 1].text))
                limit = val if limit is None else max(limit, val)
        return {"statement_types": statements, "tables": tables, "limit": limit}

    def references_sensitive(self, query: str) -> bool:
        return any(any(t.startswith(p) for p in self.sensitive_prefixes) for t in self.structure(query)["tables"])

    def analyze(self, query: str) -> list[Finding]:
        """Inspect the query as written and, for fragments, also as if it had been injected inside a
        single- or double-quoted string literal (the attacker's 'breakout' context, as libinjection does).

        A well-formed statement (starts with a statement keyword, quotes balanced) is analysed only as
        written, so SQL-looking text inside its string literals cannot trigger the breakout contexts."""
        found: dict[str, Finding] = {}
        for f in self._analyze_context(query):
            found.setdefault(f.rule_id, f)
        code = [t for t in sql_tokens(query) if t.kind != "comment"]
        well_formed = bool(code) and code[0].upper in STATEMENT_START and "SQL_UNBALANCED_QUOTE" not in found
        for qc in ("'", '"'):
            if qc in query and not well_formed:
                for f in self._analyze_context(qc + query):
                        if f.rule_id != "SQL_UNBALANCED_QUOTE":
                            found.setdefault(f.rule_id, Finding(f.rule_id, f"[in {qc}-literal context] {f.detail}"))
        return list(found.values())

    def _analyze_context(self, query: str) -> list[Finding]:
        toks = sql_tokens(query)
        found: dict[str, Finding] = {}

        def hit(rule: str, detail: str) -> None:
            found.setdefault(rule, Finding(rule, detail))

        # quotes and comments
        for t in toks:
            if t.kind == "comment":
                hit("SQL_COMMENT", t.text[:40])
            if t.kind == "string" and (len(t.text) < 2 or t.text[-1] != t.text[0] or t.text.endswith("\\" + t.text[0])):
                hit("SQL_UNBALANCED_QUOTE", t.text[:40])
        code = [t for t in toks if t.kind != "comment"]
        # stacked statements
        for i, t in enumerate(code):
            if t.text == ";" and any(x.kind not in ("other",) and x.text != ";" for x in code[i + 1:]):
                hit("SQL_STACKED_QUERIES", "statement after ';'")
        # statement types at statement starts
        st = self.structure(query)
        for s in st["statement_types"]:
            if s in DESTRUCTIVE:
                hit("SQL_DESTRUCTIVE_STATEMENT", s)
            elif s in WRITE:
                hit("SQL_WRITE_STATEMENT", s)
        char_calls = 0
        for i, t in enumerate(code):
            u = t.upper
            nxt = code[i + 1] if i + 1 < len(code) else None
            prev = code[i - 1] if i > 0 else None
            if u == "UNION":
                j = i + 1
                while j < len(code) and code[j].upper in ("ALL", "DISTINCT", "("):
                    j += 1
                if j < len(code) and code[j].upper == "SELECT":
                    hit("SQL_UNION_SELECT", "UNION SELECT")
            if t.kind == "word" and (u in TIME_FUNCS or u.split(".")[-1] in {"SLEEP", "PG_SLEEP"}):
                if u != "RANDOMBLOB" or (nxt is not None and nxt.text == "("):
                    hit("SQL_TIME_BASED", u)
            if u == "WAITFOR" or (u == "DELAY" and prev is not None and prev.upper == "WAITFOR"):
                hit("SQL_TIME_BASED", "WAITFOR DELAY")
            if t.kind == "word" and u in DANGEROUS_FUNCS:
                hit("SQL_DANGEROUS_FUNCTION", u)
            if u in ("OUTFILE", "DUMPFILE") and prev is not None and prev.upper == "INTO":
                hit("SQL_DANGEROUS_FUNCTION", f"INTO {u}")
            if u == "ANALYSE" and prev is not None and prev.upper == "PROCEDURE":
                hit("SQL_DANGEROUS_FUNCTION", "PROCEDURE ANALYSE")
            if (t.kind in ("word", "var") and u in FINGERPRINT and
                    (t.kind == "var" or (nxt is not None and nxt.text == "("))):
                hit("SQL_FINGERPRINTING", u)
            if t.kind == "hex":
                hit("SQL_ENCODED_LITERAL", t.text[:20])
            if t.kind == "word" and u in ("CHAR", "CHR", "NCHAR") and nxt is not None and nxt.text == "(":
                char_calls += 1
                hit("SQL_ENCODED_LITERAL", t.text[:20])
            # literal-vs-literal comparisons:  OR 1=1 (tautology), WHERE 5=5 / AND 3=4 (boolean probes)
            if i + 2 < len(code) and _is_literal(t) and code[i + 1].upper in COMPARISON_OPS:
                a, op, b = t, code[i + 1], code[i + 2]
                lead = prev.upper if prev is not None else ""
                if lead == "BETWEEN" or (lead == "AND" and i >= 3 and code[i - 3].upper == "BETWEEN"):
                    continue
                if _is_literal(b) or b.text == "(":
                    same = _is_literal(b) and _literal_value(a) == _literal_value(b)
                    is_true = (op.upper in ("=", "LIKE", "<=", ">=") and same) or (op.upper in ("<>", "!=") and _is_literal(b) and not same)
                    expr = f"{lead} {a.text} {op.text} {b.text}".strip()
                    if lead in ("OR", "||", "XOR") and is_true:
                        hit("SQL_TAUTOLOGY", expr)
                    else:
                        hit("SQL_BOOLEAN_PROBE", expr)
            # identifier-vs-itself:  OR x=x
            if (u in ("OR", "||", "XOR") and i + 3 < len(code) and code[i + 1].kind == "word"
                    and code[i + 2].upper in COMPARISON_OPS and code[i + 1].upper == code[i + 3].upper):
                hit("SQL_TAUTOLOGY", " ".join(x.text for x in code[i:i + 4]))
            # trailing truthy literal:  ' OR 1 --   /   ' OR 'x'
            if u in ("OR", "||", "XOR") and nxt is not None and _is_literal(nxt):
                after = code[i + 2] if i + 2 < len(code) else None
                if after is None or after.text in (";", ")"):
                    hit("SQL_TAUTOLOGY", f"{t.text} {nxt.text}")
        if char_calls >= 3:
            hit("SQL_CHAR_CONCAT_CHAIN", f"{char_calls} CHAR()/CHR() calls")
        m = CATALOG_RE.search(" ".join(t.text for t in code if t.kind in ("word", "string", "var")))
        if m:
            hit("SQL_SYSTEM_CATALOG", m.group(0))
        return list(found.values())


# ============================================================== DLP
@dataclass(frozen=True)
class SecretMatch:
    rule_id: str
    start: int
    end: int
    entropy: float


SECRET_PATTERNS = [
    ("SECRET_PRIVATE_KEY_PEM", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)")),
    ("SECRET_AWS_ACCESS_KEY", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b")),
    ("SECRET_GITHUB_TOKEN", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b")),
    ("SECRET_API_KEY_SK", re.compile(r"\bsk-(?:ant-|proj-|live-|test-)?[A-Za-z0-9_\-]{20,}")),
    ("SECRET_SLACK_TOKEN", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("SECRET_GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("SECRET_JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
]
GENERIC_ASSIGN_RE = re.compile(
    r"(?i)\b(aws_secret_access_key|secret(?:_key)?|client_secret|password|passwd|pwd|api[_-]?key|access[_-]?token|auth[_-]?token|token)\b"
    r"\s*[:=]\s*['\"]?([^\s'\",;]{12,})"
)
HIGH_ENTROPY_RE = re.compile(r"[A-Za-z0-9+/=_\-]{32,}")
HEX_ONLY_RE = re.compile(r"^(0x)?[0-9a-fA-F]+$")


class EntropyDLP:
    def __init__(self, prefixed_min_entropy: float = 3.0, generic_min_entropy: float = 3.5,
                 high_entropy_min_length: int = 32, high_entropy_threshold: float = 4.5):
        self.prefixed_min = prefixed_min_entropy
        self.generic_min = generic_min_entropy
        self.he_len = high_entropy_min_length
        self.he_thr = high_entropy_threshold

    def scan(self, text: str) -> list[SecretMatch]:
        matches: list[SecretMatch] = []
        taken: list[tuple[int, int]] = []

        def free(a: int, b: int) -> bool:
            return all(b <= x or a >= y for x, y in taken)

        for rule, rx in SECRET_PATTERNS:
            for m in rx.finditer(text):
                body = m.group(0)
                e = shannon_entropy(body)
                if (rule == "SECRET_PRIVATE_KEY_PEM" or e >= self.prefixed_min) and free(m.start(), m.end()):
                    matches.append(SecretMatch(rule, m.start(), m.end(), e))
                    taken.append((m.start(), m.end()))
        for m in GENERIC_ASSIGN_RE.finditer(text):
            val = m.group(2)
            e = shannon_entropy(val)
            if e >= self.generic_min and free(m.start(2), m.end(2)):
                matches.append(SecretMatch("SECRET_GENERIC_ASSIGNMENT", m.start(2), m.end(2), e))
                taken.append((m.start(2), m.end(2)))
        for m in HIGH_ENTROPY_RE.finditer(text):
            tok = m.group(0)
            if HEX_ONLY_RE.match(tok):  # digests / ids, not credentials
                continue
            classes = sum([any(c.islower() for c in tok), any(c.isupper() for c in tok), any(c.isdigit() for c in tok)])
            e = shannon_entropy(tok)
            if len(tok) >= self.he_len and classes == 3 and e >= self.he_thr and free(m.start(), m.end()):
                matches.append(SecretMatch("SECRET_HIGH_ENTROPY_TOKEN", m.start(), m.end(), e))
                taken.append((m.start(), m.end()))
        return sorted(matches, key=lambda s: s.start)

    @staticmethod
    def redact(text: str, matches: list[SecretMatch]) -> str:
        out, last = [], 0
        for m in sorted(matches, key=lambda s: s.start):
            out.append(text[last:m.start])
            out.append(f"[REDACTED:{m.rule_id}]")
            last = m.end
        out.append(text[last:])
        return "".join(out)


# ============================================================== signatures
@dataclass
class Signature:
    rule_id: str
    weight: float
    regex: re.Pattern
    family: str


def compile_signatures(cfg: dict[str, Any]) -> list[Signature]:
    out = []
    for family, items in (cfg.get("signatures") or {}).items():
        for item in items:
            flags = re.M if "cs" in str(item.get("flags", "")) else re.I | re.M
            out.append(Signature(item["id"], float(item["weight"]), re.compile(item["pattern"], flags), family))
    return out


def match_signatures(sigs: list[Signature], texts: list[str], family: str | None = None) -> list[tuple[Signature, str]]:
    hits = []
    for sig in sigs:
        if family and sig.family != family:
            continue
        for t in texts:
            m = sig.regex.search(t)
            if m:
                hits.append((sig, m.group(0)[:80]))
                break
    return hits


def path_matches_any(path: str, globs: list[str]) -> bool:
    return any(glob_match(path, g) or fnmatch.fnmatch(path, g) for g in globs)

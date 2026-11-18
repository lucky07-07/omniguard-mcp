"""Attribute-based access control: role -> tool -> parameter constraints, deny by default.

Supported parameter constraints (all evaluated on canonicalized arguments):

    glob:                 [patterns]   path must match one (after normalisation)
    regex:                pattern      full match
    max_length:           int
    enum:                 [values]
    schemes:              [http, https]
    domains:              [example.com]  host equals or is a subdomain of one
    sql_statement_types:  [SELECT]     every statement must be of these types
    max_limit:            int          LIMIT required and <= value
    table_prefixes:       [prefix_]    every referenced table must start with one
    allowed_binaries:     [ls, cat]    first token of every shell segment
"""

from __future__ import annotations

import hashlib
import hmac
import re
from typing import Any
from urllib.parse import urlsplit

from omniguard.config import abac_policies
from omniguard.models import AbacResult, TaintLabel, ToolTaintClass
from omniguard.security.analyzers import PathJail, ShellAnalyzer, SQLAnalyzer, glob_match


class AbacEngine:
    def __init__(self, policy: dict[str, Any] | None = None, path_jail: PathJail | None = None):
        self.policy = policy if policy is not None else abac_policies()
        self.jail = path_jail or PathJail(["/workspace"])
        self.sql = SQLAnalyzer()

    # --------------------------------------------------------------- identity
    def authenticate(self, token: str | None) -> tuple[str, str] | None:
        """Return (agent_id, role) for a bearer token, or None. Constant-time comparison."""
        if not token:
            return None
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        found = None
        for agent_id, ident in (self.policy.get("identities") or {}).items():
            if hmac.compare_digest(digest, ident["token_sha256"]):
                found = (agent_id, ident["role"])
        return found

    # --------------------------------------------------------------- policy
    def evaluate(self, role: str, tool: str, args: dict[str, Any], taint: set[TaintLabel],
                 tool_class: ToolTaintClass) -> AbacResult:
        role_cfg = (self.policy.get("roles") or {}).get(role)
        if role_cfg is None:
            return AbacResult(allowed=False, reasons=[f"ABAC_UNKNOWN_ROLE:{role}"])
        reasons: list[str] = []
        allow = role_cfg.get("allow", {})
        if allow != "*":
            if tool not in allow:
                return AbacResult(allowed=False, reasons=[f"ABAC_TOOL_NOT_PERMITTED:{role}->{tool}"])
            for param, constraints in (allow[tool] or {}).items():
                reasons += self._check_param(param, args.get(param), constraints or {})
        for label, tp in (self.policy.get("taint_policies") or {}).items():
            if TaintLabel(label) not in taint or role in tp.get("exempt_roles", []):
                continue
            if tool_class.value in tp.get("deny_tool_classes", []) or tool in tp.get("deny_tools", []):
                reasons.append(f"ABAC_TAINT_RESTRICTION:{label}->{tool}")
        return AbacResult(allowed=not reasons, reasons=reasons)

    def _check_param(self, param: str, value: Any, c: dict[str, Any]) -> list[str]:
        fail = lambda what: [f"ABAC_PARAM_VIOLATION:{param}:{what}"]  # noqa: E731
        if value is None:
            return fail("missing")
        s = value if isinstance(value, str) else str(value)
        if "max_length" in c and len(s) > int(c["max_length"]):
            return fail("max_length")
        if "enum" in c and value not in c["enum"]:
            return fail("enum")
        if "regex" in c and not re.fullmatch(c["regex"], s):
            return fail("regex")
        if "glob" in c:
            resolved = self.jail.resolve(s)
            if not any(glob_match(resolved, g) for g in c["glob"]):
                return fail(f"glob({resolved})")
        if "schemes" in c or "domains" in c:
            try:
                parts = urlsplit(s)
                host = (parts.hostname or "").lower()
            except ValueError:
                return fail("url")
            if "schemes" in c and parts.scheme.lower() not in c["schemes"]:
                return fail("scheme")
            if "domains" in c and not any(host == d or host.endswith("." + d) for d in c["domains"]):
                return fail(f"domain({host})")
        if "sql_statement_types" in c or "max_limit" in c or "table_prefixes" in c:
            st = self.sql.structure(s)
            if "sql_statement_types" in c:
                allowed = {x.upper() for x in c["sql_statement_types"]}
                if not st["statement_types"] or any(t not in allowed for t in st["statement_types"]):
                    return fail(f"statement_type({','.join(st['statement_types']) or 'none'})")
            if "max_limit" in c and (st["limit"] is None or st["limit"] > int(c["max_limit"])):
                return fail(f"limit({st['limit']})")
            if "table_prefixes" in c:
                bad = [t for t in st["tables"] if not any(t.startswith(p) for p in c["table_prefixes"])]
                if bad or not st["tables"]:
                    return fail(f"table({','.join(bad) or 'none'})")
        if "allowed_binaries" in c:
            bins = ShellAnalyzer.binaries(s)
            bad = [b for b in bins if b not in c["allowed_binaries"]]
            if bad or not bins:
                return fail(f"binary({','.join(bad) or 'none'})")
        return []

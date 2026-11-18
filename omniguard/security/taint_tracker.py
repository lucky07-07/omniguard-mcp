"""Stage 3: stateful cross-tool taint tracking (session-level information-flow control).

Labels only ever accumulate within a session (monotone), so a sequence like
`read_file(.env) -> summarize -> http_post(...)` cannot launder sensitive data
through an intermediate neutral tool call.

* reading untrusted external content      -> TAINTED_UNTRUSTED
* reading sensitive local files / records -> TAINTED_SENSITIVE
* TAINTED_SENSITIVE + outbound_egress tool -> deterministic DENY
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field

from omniguard.models import TaintLabel, ToolTaintClass


@dataclass
class TaintTransition:
    session_id: str
    before: list[str]
    after: list[str]
    cause_tool: str
    reason: str
    ts: float = field(default_factory=time.time)


class SessionTaintTracker:
    def __init__(self) -> None:
        self._labels: dict[str, set[TaintLabel]] = {}
        self._lock = threading.Lock()
        self.transitions: list[TaintTransition] = []

    def get(self, session_id: str) -> set[TaintLabel]:
        with self._lock:
            return set(self._labels.get(session_id, set()))

    def state(self, session_id: str) -> list[TaintLabel]:
        labels = self.get(session_id)
        return sorted(labels, key=lambda l: l.value) if labels else [TaintLabel.CLEAN]

    def state_str(self, session_id: str) -> str:
        return "|".join(l.value for l in self.state(session_id))

    def check_flow(self, session_id: str, tool_class: ToolTaintClass) -> str | None:
        """Return a violation reason if this tool class may not run in the current taint state."""
        if tool_class == ToolTaintClass.OUTBOUND_EGRESS and TaintLabel.TAINTED_SENSITIVE in self.get(session_id):
            return "session holds sensitive data; outbound egress tools are blocked"
        return None

    def mark(self, session_id: str, label: TaintLabel, cause_tool: str, reason: str) -> TaintTransition | None:
        with self._lock:
            labels = self._labels.setdefault(session_id, set())
            if label in labels or label == TaintLabel.CLEAN:
                return None
            before = sorted(l.value for l in labels) or [TaintLabel.CLEAN.value]
            labels.add(label)
            tr = TaintTransition(session_id, before, sorted(l.value for l in labels), cause_tool, reason)
            self.transitions.append(tr)
            return tr

    def on_tool_result(self, session_id: str, tool_name: str, tool_class: ToolTaintClass,
                       sensitive_access: bool = False) -> list[TaintTransition]:
        out = []
        if tool_class == ToolTaintClass.UNTRUSTED_EXTERNAL:
            tr = self.mark(session_id, TaintLabel.TAINTED_UNTRUSTED, tool_name, "read untrusted external content")
            if tr:
                out.append(tr)
        if tool_class == ToolTaintClass.SENSITIVE_INTERNAL or sensitive_access:
            tr = self.mark(session_id, TaintLabel.TAINTED_SENSITIVE, tool_name, "read sensitive internal data")
            if tr:
                out.append(tr)
        return out

    def reset(self, session_id: str) -> None:
        with self._lock:
            self._labels.pop(session_id, None)

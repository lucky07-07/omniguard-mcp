"""OmniGuard-MCP: a tamper-evident security gateway and deterministic
information-flow firewall for Model Context Protocol (MCP) agent systems.

Every security decision comes from deterministic, explainable rules, optionally
followed by a SHA-256-pinned ONNX prompt-injection classifier on free-text prose
(inference only; nothing is trained here). All decisions are recorded in a
cryptographically verifiable audit trail.
"""

__version__ = "1.2.0"

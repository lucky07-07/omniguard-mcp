import os
import sys
import warnings
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
warnings.filterwarnings("ignore")

from omniguard.agents.gateway_agent import build_stack  # noqa: E402
from omniguard.crypto.blockchain import compile_contract  # noqa: E402
from omniguard.security.security_engine import SecurityEngine  # noqa: E402
from omniguard.security.tool_integrity import ToolIntegrityRegistry  # noqa: E402

OPERATOR = "dev-token-operator"
ANALYST = "dev-token-analyst"
READ_ONLY = "dev-token-read_only"
ADMIN = "dev-token-admin"


@pytest.fixture(scope="session", autouse=True)
def _compiled_contract():
    compile_contract()


@pytest.fixture(scope="session")
def engine() -> SecurityEngine:
    return SecurityEngine(tool_meta=ToolIntegrityRegistry.load().tools)


@pytest.fixture
def stack_factory(tmp_path):
    stacks = []

    def make(regime="R3", **kw):
        st = build_stack(regime, tmp_path / f"audit_{regime}_{len(stacks)}.db", **kw)
        stacks.append(st)
        return st

    yield make
    for st in stacks:
        try:
            st.store.close()
        except Exception:
            pass


def call(gw, token, tool, args, session="s1", rid=1):
    return gw.handle({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                      "params": {"name": tool, "arguments": args}}, token=token, session_id=session)


def decision(resp):
    if "error" in resp:
        return resp["error"]["data"]["decision"] if "data" in resp["error"] else "ERROR"
    return resp["result"]["_meta"]["omniguard"]["decision"]


@pytest.fixture
def subprocess_env():
    env = dict(os.environ)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    env["PYTHONWARNINGS"] = "ignore"
    return env

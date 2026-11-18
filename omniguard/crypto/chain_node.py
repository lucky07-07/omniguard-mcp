"""Standalone local EVM node: eth-tester/py-evm served over HTTP JSON-RPC.

eth-tester keeps chain state in memory inside one Python process. To let the
gateway (Agent 2) and the independent watcher (Agent 3) use *separate* RPC
connections, this module runs the chain in its own OS process and bridges
standard JSON-RPC requests into it via web3's request formatters.

    python -m omniguard.crypto.chain_node --port 8545

Prints `READY <url>` on stdout once listening. Chain state lives only as long
as this process does (a development chain, not a public network).
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from web3 import EthereumTesterProvider, Web3


def make_server(host: str = "127.0.0.1", port: int = 0) -> ThreadingHTTPServer:
    w3 = Web3(EthereumTesterProvider())
    lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # silence per-request logging
            pass

        def _handle_one(self, req: dict) -> dict:
            try:
                with lock:
                    res = w3.manager.request_blocking(req["method"], req.get("params", []))
                return {"jsonrpc": "2.0", "id": req.get("id"), "result": json.loads(Web3.to_json(res))}
            except Exception as exc:  # surfaced to the client as a JSON-RPC error
                msg = exc.args[0] if exc.args and isinstance(exc.args[0], str) else repr(exc)
                return {"jsonrpc": "2.0", "id": req.get("id"), "error": {"code": -32000, "message": msg}}

        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            req = json.loads(raw)
            body = [self._handle_one(r) for r in req] if isinstance(req, list) else self._handle_one(req)
            data = json.dumps(body).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

    return ThreadingHTTPServer((host, port), Handler)


class ChainNodeProcess:
    """Spawn the chain node as a separate OS process (context manager)."""

    def __init__(self, port: int = 0):
        self.port = port
        self.proc: subprocess.Popen | None = None
        self.url: str | None = None

    def start(self) -> str:
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "omniguard.crypto.chain_node", "--port", str(self.port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        line = self.proc.stdout.readline().strip()
        if not line.startswith("READY "):
            self.stop()
            raise RuntimeError(f"chain node failed to start: {line!r}")
        self.url = line.split(" ", 1)[1]
        return self.url

    def stop(self) -> None:
        if self.proc and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def __enter__(self) -> "ChainNodeProcess":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.stop()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="OmniGuard local EVM JSON-RPC node (eth-tester)")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8545)
    args = ap.parse_args(argv)
    srv = make_server(args.host, args.port)
    host, port = srv.server_address[:2]
    print(f"READY http://{host}:{port}", flush=True)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

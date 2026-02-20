#!/usr/bin/env python3
"""
Run local WSS server/client examples, launch clients in parallel, and clean up processes reliably.

Default behavior:
- starts build/example/ixwebsocket_wss_server_example.exe
- runs build/example/ixwebsocket_example.exe against both:
    wss://localhost:<port>
    wss://127.0.0.1:<port>
- repeats for --runs
- prints handshake/echo timing summary
"""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import os
import re
import socket
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


HANDSHAKE_RE = re.compile(r"handshake=(\d+)ms")
ECHO_RE = re.compile(r"echo=(\d+)ms")


@dataclass
class ClientResult:
    url: str
    returncode: int
    output: str
    handshake_ms: Optional[int]
    echo_ms: Optional[int]
    elapsed_ms: int


class ManagedProcess:
    def __init__(self, cmd: list[str], cwd: Path):
        self.cmd = cmd
        self.cwd = cwd
        self.lines: list[str] = []
        self._lock = threading.Lock()

        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

        self.proc = subprocess.Popen(
            cmd,
            cwd=str(cwd),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            creationflags=creationflags,
        )

        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self) -> None:
        if not self.proc.stdout:
            return
        for line in self.proc.stdout:
            with self._lock:
                self.lines.append(line.rstrip("\n"))

    def output_tail(self, n: int = 60) -> str:
        with self._lock:
            return "\n".join(self.lines[-n:])

    def stop(self) -> None:
        if self.proc.poll() is not None:
            return

        # Graceful path: server example exits on Enter.
        try:
            if self.proc.stdin:
                self.proc.stdin.write("\n")
                self.proc.stdin.flush()
        except Exception:
            pass

        try:
            self.proc.wait(timeout=2)
            return
        except subprocess.TimeoutExpired:
            pass

        # Soft terminate
        try:
            self.proc.terminate()
        except Exception:
            pass

        try:
            self.proc.wait(timeout=3)
            return
        except subprocess.TimeoutExpired:
            pass

        # Hard kill (+ children on Windows)
        if os.name == "nt":
            subprocess.run(
                ["taskkill", "/PID", str(self.proc.pid), "/T", "/F"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        else:
            try:
                self.proc.kill()
            except Exception:
                pass


def wait_port_open(host: str, port: int, timeout_s: float) -> bool:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def run_client(client_bin: Path, url: str, ca_file: str, message: str, timeout_s: int, cwd: Path) -> ClientResult:
    cmd = [str(client_bin), url, ca_file, message]
    t0 = time.perf_counter()
    try:
        cp = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            check=False,
        )
        out = (cp.stdout or "") + (cp.stderr or "")
        rc = cp.returncode
    except subprocess.TimeoutExpired as e:
        out = ((e.stdout or "") + (e.stderr or "")) if (e.stdout or e.stderr) else "timeout"
        rc = 124

    elapsed_ms = int((time.perf_counter() - t0) * 1000)

    h = HANDSHAKE_RE.search(out)
    e = ECHO_RE.search(out)
    return ClientResult(
        url=url,
        returncode=rc,
        output=out,
        handshake_ms=int(h.group(1)) if h else None,
        echo_ms=int(e.group(1)) if e else None,
        elapsed_ms=elapsed_ms,
    )


def summarize(url: str, items: list[ClientResult]) -> str:
    oks = [x for x in items if x.returncode == 0]
    h = [x.handshake_ms for x in oks if x.handshake_ms is not None]
    e = [x.echo_ms for x in oks if x.echo_ms is not None]

    parts = [f"{url}: {len(oks)}/{len(items)} ok"]
    if h:
        parts.append(f"handshake avg={statistics.mean(h):.1f}ms min={min(h)} max={max(h)}")
    if e:
        parts.append(f"echo avg={statistics.mean(e):.1f}ms min={min(e)} max={max(e)}")
    return " | ".join(parts)


def main() -> int:
    root = Path(__file__).resolve().parents[1]

    p = argparse.ArgumentParser(description="Run local WSS benchmark harness")
    p.add_argument("--build-dir", default="build")
    p.add_argument("--server-bin", default=None)
    p.add_argument("--client-bin", default=None)
    p.add_argument("--port", type=int, default=9450)
    p.add_argument("--ca", default="test/fixtures/trusted-ca-crt.pem")
    p.add_argument("--message", default="hello")
    p.add_argument("--runs", type=int, default=5)
    p.add_argument("--client-timeout", type=int, default=20)
    p.add_argument("--startup-timeout", type=int, default=10)
    p.add_argument("--sequential", action="store_true", help="run URLs one by one instead of parallel")
    p.add_argument(
        "--url",
        action="append",
        dest="urls",
        help="repeatable; default: localhost and 127.0.0.1",
    )
    args = p.parse_args()

    server_bin = Path(args.server_bin) if args.server_bin else root / args.build_dir / "example" / "ixwebsocket_wss_server_example.exe"
    client_bin = Path(args.client_bin) if args.client_bin else root / args.build_dir / "example" / "ixwebsocket_example.exe"
    ca_file = str((root / args.ca).resolve()) if not Path(args.ca).is_absolute() else args.ca

    urls = args.urls or [
        f"wss://localhost:{args.port}",
        f"wss://127.0.0.1:{args.port}",
    ]

    for b in (server_bin, client_bin):
        if not b.exists():
            print(f"missing binary: {b}", file=sys.stderr)
            return 2

    if not Path(ca_file).exists():
        print(f"missing CA file: {ca_file}", file=sys.stderr)
        return 2

    print(f"server: {server_bin}")
    print(f"client: {client_bin}")
    print(f"ca    : {ca_file}")
    print(f"urls  : {', '.join(urls)}")

    server = ManagedProcess([str(server_bin), str(args.port)], cwd=root)
    try:
        if not wait_port_open("127.0.0.1", args.port, args.startup_timeout):
            print("server did not open port in time", file=sys.stderr)
            tail = server.output_tail()
            if tail:
                print("--- server output ---", file=sys.stderr)
                print(tail, file=sys.stderr)
            return 3

        print("server is up\n")

        by_url: dict[str, list[ClientResult]] = {u: [] for u in urls}
        any_fail = False

        for i in range(1, args.runs + 1):
            print(f"run {i}/{args.runs}")
            results: list[ClientResult] = []

            if args.sequential or len(urls) == 1:
                for url in urls:
                    results.append(run_client(client_bin, url, ca_file, args.message, args.client_timeout, root))
            else:
                with futures.ThreadPoolExecutor(max_workers=len(urls)) as ex:
                    fs = [
                        ex.submit(run_client, client_bin, url, ca_file, args.message, args.client_timeout, root)
                        for url in urls
                    ]
                    for f in fs:
                        results.append(f.result())

            for r in results:
                by_url[r.url].append(r)
                ok = r.returncode == 0
                any_fail = any_fail or not ok
                print(
                    f"  [{ 'OK' if ok else 'FAIL'}] {r.url} rc={r.returncode} "
                    f"handshake={r.handshake_ms} echo={r.echo_ms} elapsed={r.elapsed_ms}ms"
                )
                if not ok:
                    print("  --- client output ---")
                    print("\n".join((r.output or "").splitlines()[-30:]))
            print()

        print("summary")
        for u in urls:
            print("  " + summarize(u, by_url[u]))

        if any_fail:
            print("\nresult: FAIL")
            return 1

        print("\nresult: PASS")
        return 0
    finally:
        server.stop()


if __name__ == "__main__":
    raise SystemExit(main())

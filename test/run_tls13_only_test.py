#!/usr/bin/env python3
import argparse
import os
import socket
import subprocess
import sys
import time
from pathlib import Path


def exe_path(path: Path) -> Path:
    if sys.platform.startswith("win"):
        if path.suffix.lower() != ".exe":
            return path.with_suffix(path.suffix + ".exe")
    return path


def wait_for_port(host: str, port: int, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def venv_python(venv_dir: Path) -> Path:
    if sys.platform.startswith("win"):
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def ensure_venv(venv_dir: Path) -> Path:
    python_exe = venv_python(venv_dir)
    if not python_exe.exists():
        subprocess.check_call([sys.executable, "-m", "venv", str(venv_dir)])
    try:
        subprocess.check_call([str(python_exe), "-c", "import jsonschema, jinja2"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        subprocess.check_call([str(python_exe), "-m", "pip", "install", "--upgrade", "pip",
                               "jsonschema", "jinja2"])
    return python_exe


def run():
    parser = argparse.ArgumentParser()
    parser.add_argument("--build-dir", required=True)
    parser.add_argument("--source-dir", required=True)
    parser.add_argument("--port", type=int, default=9471)
    args = parser.parse_args()

    build_dir = Path(args.build_dir)
    source_dir = Path(args.source_dir)

    server_source = source_dir / "test" / "tls13_server"
    server_build = build_dir / "tls13_server"
    venv_dir = server_build / ".venv"

    python_exe = ensure_venv(venv_dir)
    cmake_config = [
        "cmake",
        "-S",
        str(server_source),
        "-B",
        str(server_build),
        f"-DPython3_EXECUTABLE={python_exe}",
        "-DCMAKE_BUILD_TYPE=Debug",
    ]
    cmake_build = ["cmake", "--build", str(server_build), "--config", "Debug", "--parallel"]

    subprocess.check_call(cmake_config)
    subprocess.check_call(cmake_build)

    server_bin = exe_path(server_build / "tls13_only_server")
    client_bin = exe_path(build_dir / "test" / "test_tls13_only_client")

    if not server_bin.exists():
        raise FileNotFoundError(f"Server binary not found: {server_bin}")
    if not client_bin.exists():
        raise FileNotFoundError(f"Client binary not found: {client_bin}")

    cert = source_dir / "test" / "fixtures" / "trusted-server-crt.pem"
    key = source_dir / "test" / "fixtures" / "trusted-server-key.pem"

    server_cmd = [
        str(server_bin),
        "--port",
        str(args.port),
        "--cert",
        str(cert),
        "--key",
        str(key),
    ]

    server_proc = subprocess.Popen(server_cmd)
    try:
        if not wait_for_port("127.0.0.1", args.port, timeout=15.0):
            server_proc.terminate()
            raise RuntimeError("TLS 1.3 server failed to start")

        client_cmd = [str(client_bin), str(args.port)]
        result = subprocess.run(client_cmd)
        if result.returncode != 0:
            raise RuntimeError("TLS 1.3 client test failed")
    finally:
        if server_proc.poll() is None:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server_proc.kill()
                server_proc.wait()


if __name__ == "__main__":
    run()

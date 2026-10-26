#!/usr/bin/env python3
"""Check that one blocked TCP connection can be permitted without changing its rule."""
import json
import pathlib
import socket
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def control(*args):
    result = subprocess.run(["omasnitchctl", *args], check=True, capture_output=True, text=True)
    if '"type": "error"' in result.stdout:
        raise RuntimeError(result.stdout)
    return json.loads(result.stdout)


with tempfile.TemporaryDirectory(prefix="omasnitch-once-") as directory:
    probe = pathlib.Path(directory) / "osnetprobe"
    subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-o", str(probe),
                    str(ROOT / "tests/net_probe.c")], check=True)
    rules = control("rules").get("data", [])
    if any(rule.get("application") == "osnetprobe" for rule in rules):
        raise SystemExit("Refusing to modify an existing osnetprobe rule")
    try:
        for family, mode in [(socket.AF_INET, "tcp4_delayed"), (socket.AF_INET6, "tcp6_delayed")]:
            server = socket.socket(family, socket.SOCK_STREAM)
            server.bind(("127.0.0.1" if family == socket.AF_INET else "::1", 0))
            server.listen(1)
            server.settimeout(2)
            child = subprocess.Popen([str(probe), mode, str(server.getsockname()[1])],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            peer = None
            try:
                assert child.stdout.readline().strip() == "READY"
                control("block", "osnetprobe")
                time.sleep(0.6)
                control("allow-once", "osnetprobe")
                child.stdin.write("\n")
                child.stdin.flush()
                result = child.stdout.readline().strip()
                assert result.startswith("RESULT 21 0"), (mode, result)
                peer, _ = server.accept()
                peer.settimeout(2)
                payload = peer.recv(256)
                assert payload.startswith(b"omasnitch-regression") and result.startswith("RESULT 21 0"), (mode, result, payload)
                print(f"PASS {mode}: one-time connection delivered its payload")
            finally:
                control("remove", "osnetprobe")
                child.kill()
                child.wait()
                if peer:
                    peer.close()
                server.close()
    finally:
        control("remove", "osnetprobe")

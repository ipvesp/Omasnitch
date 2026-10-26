#!/usr/bin/env python3
"""Run against a live OmaSnitch daemon; never changes existing user rules."""
import pathlib
import json
import socket
import subprocess
import tempfile
import time
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODES = [
    "udp4_unconnected", "udp6_unconnected", "udp4_sendmsg", "udp6_sendmsg",
    "udp4_sendmmsg", "udp4_connected", "udp6_connected",
    "tcp4_connected", "tcp6_connected",
]


def control(*args):
    result = subprocess.run(["omasnitchctl", *args], check=True, capture_output=True, text=True)
    if '"type": "error"' in result.stdout:
        raise RuntimeError(result.stdout)


with tempfile.TemporaryDirectory(prefix="omasnitch-regression-") as temporary:
    probe = pathlib.Path(temporary) / "osnetprobe"
    subprocess.run(["cc", "-O2", "-Wall", "-Wextra", "-o", str(probe), str(ROOT / "tests/net_probe.c")], check=True)
    existing = subprocess.run(["omasnitchctl", "rules"], check=True, capture_output=True, text=True).stdout
    rules = json.loads(existing).get("data", [])
    if any(rule.get("application") == "osnetprobe" for rule in rules):
        raise SystemExit("Refusing to modify an existing osnetprobe rule")

    failures = []
    try:
        for mode in (sys.argv[1:] or MODES):
            if mode not in MODES:
                raise SystemExit(f"Unknown test mode: {mode}")
            ipv6 = "6" in mode
            tcp = "tcp" in mode
            connected = mode in ("udp4_connected", "udp6_connected", "tcp4_connected", "tcp6_connected")
            family = socket.AF_INET6 if ipv6 else socket.AF_INET
            server = socket.socket(family, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("::1" if ipv6 else "127.0.0.1", 0))
            if tcp:
                server.listen(1)
            server.settimeout(0.7)
            child = subprocess.Popen([str(probe), mode, str(server.getsockname()[1])],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
            peer = None
            try:
                assert child.stdout.readline().strip() == "READY", mode
                if tcp:
                    peer, _ = server.accept()
                    peer.settimeout(0.7)
                control("block", "osnetprobe")
                time.sleep(0.6)
                child.stdin.write("\n")
                child.stdin.flush()
                result = child.stdout.readline().strip()
                assert result.startswith("RESULT "), (mode, result)
                try:
                    if tcp:
                        received = peer.recv(256)
                    else:
                        received, _ = server.recvfrom(256)
                except socket.timeout:
                    received = b""
                if received:
                    failures.append(mode)
                    print(f"FAIL {mode}: blocked payload reached receiver: {received!r} ({result})")
                else:
                    print(f"PASS {mode}: {result}; receiver got no payload")
            finally:
                control("remove", "osnetprobe")
                child.kill()
                child.wait()
                if peer:
                    peer.close()
                server.close()
    finally:
        control("remove", "osnetprobe")
    if failures:
        raise SystemExit(f"Blocked payload escaped in: {', '.join(failures)}")

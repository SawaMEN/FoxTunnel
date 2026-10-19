"""Isolated FoxTunnel -> sing-box TUN -> FoxTunnel TLS end-to-end lab.

Requires FOXTUNNEL_TUN_E2E=1, Linux root, iproute2, nftables, openssl,
and absolute FOXTUNNEL_LAB_SINGBOX / FOXTUNNEL_LAB_FOXTUNNEL binaries.
No Internet, no host network/firewall changes: two freshly created netns.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

import linux_tun_companion as companion


ECHO_SERVICES = r"""
import select
import socket
import struct

sockets = []
for family, host in ((socket.AF_INET, "198.18.0.9"),
                     (socket.AF_INET6, "fd42:2::9")):
    for kind, port in ((socket.SOCK_STREAM, 5657),
                       (socket.SOCK_DGRAM, 5656),
                       (socket.SOCK_DGRAM, 53)):
        sock = socket.socket(family, kind)
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.bind((host, port))
        if kind == socket.SOCK_STREAM:
            sock.listen(8)
        sockets.append((sock, kind, port))

print("READY", flush=True)
while True:
    ready, _, _ = select.select([s for s, _, _ in sockets], [], [], 0.5)
    for sock in ready:
        kind, port = next((kind, port) for s, kind, port in sockets if s is sock)
        if kind == socket.SOCK_STREAM:
            conn, _ = sock.accept()
            with conn:
                conn.settimeout(3)
                payload = conn.recv(256)
                if payload:
                    conn.sendall(payload)
            continue
        request, peer = sock.recvfrom(1500)
        if port != 53:
            sock.sendto(request, peer)
            continue
        if len(request) < 17:
            continue
        # Minimal, test-only A-response for fixed name "fox.lab".
        if request[12:21] != b"\x03fox\x03lab\x00":
            continue
        question_end = 25
        if request[question_end - 4:question_end] != b"\x00\x01\x00\x01":
            continue
        header = request[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x00\x00"
        answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04" + bytes([198,18,0,9])
        sock.sendto(header + request[12:question_end] + answer, peer)
"""


PROBE = r"""
import socket
import struct
import sys

kind = sys.argv[1]
host = sys.argv[2]
port = int(sys.argv[3])
family = socket.AF_INET6 if ':' in host else socket.AF_INET
if kind == "tcp":
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(2.5)
    try:
        s.connect((host, port))
        s.sendall(b"fox-tun-e2e")
        success = s.recv(64) == b"fox-tun-e2e"
    except OSError:
        success = False
elif kind == "udp":
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(2.5)
    try:
        s.sendto(b"fox-udp-e2e", (host, port))
        success = s.recv(100) == b"fox-udp-e2e"
    except OSError:
        success = False
elif kind == "dns":
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(3.0)
    question = b"\x03fox\x03lab\x00\x00\x01\x00\x01"
    wire = b"\x2a\x2b\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + question
    try:
        s.sendto(wire, (host, port))
        answer = s.recv(512)
        success = (len(answer) >= 41 and answer[:2] == b"\x2a\x2b"
                   and bytes([198,18,0,9]) in answer[25:])
    except OSError:
        success = False
else:
    raise SystemExit("unknown probe")
s.close()
sys.exit(0 if success else 2)
"""


def cmd(*args: str, timeout: float = 25) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=True, capture_output=True,
                          text=True, timeout=timeout)


def stop(proc: subprocess.Popen | None):
    if proc is None:
        return
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=5)


class TUNEndToEnd(unittest.TestCase):
    def test_real_tun_tcp_udp_dns_ipv4_ipv6_and_exit(self):
        if os.environ.get("FOXTUNNEL_TUN_E2E") != "1":
            self.skipTest("privileged isolated TUN test opt-in only")
        if sys.platform != "linux" or os.geteuid() != 0:
            self.fail("requires Linux root; refusing to run on host")
        for utility in ("ip", "nft", "openssl"):
            if not shutil.which(utility):
                self.fail(f"missing {utility}")
        box = os.environ.get("FOXTUNNEL_LAB_SINGBOX", "")
        fox = os.environ.get("FOXTUNNEL_LAB_FOXTUNNEL", "")
        if not box or not fox or not Path(box).is_file() or not Path(fox).is_file():
            self.fail("supply absolute FOXTUNNEL_LAB_SINGBOX and FOXTUNNEL_LAB_FOXTUNNEL")

        prefix = secrets.token_hex(3)
        cns, sns = "ftce" + prefix, "ftse" + prefix
        ca, sa = "ftca" + prefix, "ftsa" + prefix
        with tempfile.TemporaryDirectory(prefix="foxtunnel-tun-e2e-") as temp:
            root = Path(temp)
            processes: list[subprocess.Popen] = []
            created: list[str] = []
            try:
                # Only uniquely named namespaces and an ephemeral veth are touched.
                for ns in (cns, sns):
                    cmd("ip", "netns", "add", ns)
                    created.append(ns)
                cmd("ip", "link", "add", ca, "type", "veth", "peer", "name", sa)
                cmd("ip", "link", "set", ca, "netns", cns)
                cmd("ip", "link", "set", sa, "netns", sns)
                cmd("ip", "-n", cns, "link", "set", ca, "name", "fcwan0")
                cmd("ip", "-n", sns, "link", "set", sa, "name", "fswan0")
                for ns, name, addr4, addr6 in (
                    (cns, "fcwan0", "198.18.0.2/30", "fd42:1::2/64"),
                    (sns, "fswan0", "198.18.0.1/30", "fd42:1::1/64"),
                ):
                    cmd("ip", "-n", ns, "link", "set", "lo", "up")
                    cmd("ip", "-n", ns, "addr", "add", addr4, "dev", name)
                    cmd("ip", "-n", ns, "-6", "addr", "add", addr6, "dev", name, "nodad")
                    cmd("ip", "-n", ns, "link", "set", name, "up")
                # A production Linux host has a physical default route.
                # Give the isolated client the same prerequisite so sing-box
                # auto_detect_interface can locate the physical uplink.
                # The exit namespace does not forward these direct packets.
                cmd("ip", "-n", cns, "route", "add", "default", "via", "198.18.0.1", "dev", "fcwan0")
                cmd("ip", "-n", cns, "-6", "route", "add", "default", "via", "fd42:1::1", "dev", "fcwan0")
                # Isolated endpoints are reachable at the *exit*, but NOT on
                # the client's directly connected veth subnet.
                cmd("ip", "-n", sns, "addr", "add", "198.18.0.9/32", "dev", "lo")
                cmd("ip", "-n", sns, "-6", "addr", "add", "fd42:2::9/128", "dev", "lo", "nodad")

                cert, key = root / "cert.pem", root / "key.pem"
                cmd("openssl", "req", "-x509", "-nodes", "-newkey", "rsa:2048",
                    "-keyout", str(key), "-out", str(cert), "-days", "2",
                    "-subj", "/CN=lab.test", "-addext",
                    "subjectAltName=DNS:lab.test,IP:198.18.0.1")

                def start(ns: str, *args: str) -> subprocess.Popen:
                    fd = open(root / f"proc-{len(processes)}.log", "wb")
                    proc = subprocess.Popen(["ip", "netns", "exec", ns, *args],
                                            stdout=fd, stderr=subprocess.STDOUT)
                    fd.close()
                    processes.append(proc)
                    return proc

                service = start(sns, sys.executable, "-u", "-c", ECHO_SERVICES)
                self.wait_alive(service, 0.2, "echo")
                env = dict(os.environ, FOXTUNNEL_USER="lab", FOXTUNNEL_PASSWORD="test-only-secret")
                # Preserve credentials for both processes; do not pass secrets as CLI argv.
                def fox_start(ns: str, *args: str):
                    fd = open(root / f"proc-{len(processes)}.log", "wb")
                    p = subprocess.Popen(["ip", "netns", "exec", ns, fox, *args],
                                         env=env, stdout=fd, stderr=subprocess.STDOUT)
                    fd.close()
                    processes.append(p)
                    return p
                server = fox_start(sns, "server",
                                   "--listen", "198.18.0.1:8443",
                                   "--cert", str(cert), "--key", str(key),
                                   "--allow-private", "--enable-udp")
                self.wait_alive(server, 0.5, "FoxTunnel server")
                client = fox_start(cns, "client", "--server",
                                   "https://198.18.0.1:8443",
                                   "--listen", "127.0.0.1:1080",
                                   "--ca-cert", str(cert), "--sni", "lab.test",
                                   "--tls-backend", "go", "--enable-udp", "--udp-stream")
                self.wait_alive(client, 0.5, "FoxTunnel client")

                # Real sing-box validated config from *same* public generator.
                config, policy = companion.make_config(
                    ["198.18.0.1:8443"], "fcwan0", dns="198.18.0.9"
                )
                # A new namespace often has no systemd-resolved socket. A TUN
                # hijack rule still exercises the remote resolver via UDP SOCKS.
                profile = root / "sing-box.json"
                profile.write_text(json.dumps(config), encoding="utf-8")
                cmd(box, "check", "-c", str(profile))
                rules = root / "guard.nft"
                rules.write_text(policy, encoding="utf-8")
                cmd("ip", "netns", "exec", cns, "nft", "-c", "-f", str(rules))
                cmd("ip", "netns", "exec", cns, "nft", "-f", str(rules))
                sink = start(cns, box, "run", "-c", str(profile))
                self.wait_tun(cns, sink, timeout=15)

                self.assert_probe(cns, "tcp", "198.18.0.9", 5657, True)
                self.assert_probe(cns, "tcp", "fd42:2::9", 5657, True)
                self.assert_probe(cns, "udp", "198.18.0.9", 5656, True)
                self.assert_probe(cns, "dns", "9.9.9.9", 53, True)

                # A dropped tunnel must NOT fall back to direct Internet.
                stop(client)
                self.assert_probe(cns, "tcp", "198.18.0.9", 5657, False)
                self.assert_probe(cns, "udp", "198.18.0.9", 5656, False)
                output = cmd("ip", "netns", "exec", cns, "nft", "list",
                             "table", "inet", companion.TABLE).stdout
                self.assertIn("policy drop", output)
                self.assert_probe(cns, "dns", "9.9.9.9", 53, False)
            except Exception:
                for logfile in sorted(root.glob("proc-*.log")):
                    sys.stderr.write(
                        f"\n---- {logfile.name} ----\n"
                        + logfile.read_text(errors="replace")[-2500:]
                        + "\n"
                    )
                raise
            finally:
                for process in reversed(processes):
                    stop(process)
                # Dropping an entire unique namespace also removes all
                # sing-box routes and nftables rules; host is never modified.
                for ns in reversed(created):
                    subprocess.run(["ip", "netns", "del", ns], check=False,
                                   stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL)

    @staticmethod
    def wait_alive(proc: subprocess.Popen, seconds: float, label: str):
        time.sleep(seconds)
        if proc.poll() is not None:
            raise RuntimeError(f"{label} exited prematurely with {proc.returncode}")

    @staticmethod
    def wait_tun(ns: str, proc: subprocess.Popen, timeout: float):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                raise RuntimeError(f"sing-box exited: {proc.returncode}")
            result = subprocess.run(["ip", "-n", ns, "link", "show", "ftun0"],
                                    capture_output=True)
            if result.returncode == 0:
                time.sleep(0.5)
                return
            time.sleep(0.2)
        raise RuntimeError("sing-box did not create ftun0")

    def assert_probe(self, ns: str, kind: str, ip: str, port: int, expected: bool):
        result = subprocess.run(["ip", "netns", "exec", ns, sys.executable,
                                 "-c", PROBE, kind, ip, str(port)],
                                capture_output=True, text=True, timeout=12)
        self.assertEqual(result.returncode == 0, expected,
                         f"{kind} {ip}:{port} expected={expected}: "
                         f"exit={result.returncode} {result.stderr}")


if __name__ == "__main__":
    unittest.main()

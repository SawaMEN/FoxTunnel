"""Opt-in isolated Linux network namespace probes for FoxTunnel's nft guard.

Never touch the host firewall or host routes. The test creates two *new*
network namespaces joined by a veth pair. No Internet access is necessary.
This tests real kernel IPv4/IPv6 egress restrictions, not sing-box TUN or
end-to-end FoxTunnel encryption. Run only with FOXTUNNEL_TUN_NETNS=1 as root.
"""
from __future__ import annotations

import os
from pathlib import Path
import secrets
import select
import shutil
import subprocess
import sys
import tempfile
import unittest

import linux_tun_companion as tun

SERVER_CODE = r"""
import select
import socket
import sys

listeners = []
for family, host in ((socket.AF_INET, '198.18.0.1'),
                     (socket.AF_INET6, 'fd42:1::1')):
    for kind, port in ((socket.SOCK_STREAM, 8443),
                       (socket.SOCK_STREAM, 9443),
                       (socket.SOCK_DGRAM, 8443),
                       (socket.SOCK_DGRAM, 53)):
        s = socket.socket(family, kind)
        if family == socket.AF_INET6:
            s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((host, port))
        if kind == socket.SOCK_STREAM:
            s.listen(16)
        listeners.append((s, kind))
print('READY', flush=True)
while True:
    readable, _, _ = select.select([s for s, _ in listeners], [], [], 2.0)
    for s in readable:
        kind = next(k for sock, k in listeners if sock is s)
        if kind == socket.SOCK_STREAM:
            peer, _ = s.accept()
            with peer:
                peer.sendall(b'OK')
        else:
            data, peer = s.recvfrom(2048)
            s.sendto(b'PONG', peer)
"""

PROBE_CODE = r"""
import socket
import sys
family = socket.AF_INET6 if ':' in sys.argv[1] else socket.AF_INET
kind = socket.SOCK_DGRAM if sys.argv[3] == 'udp' else socket.SOCK_STREAM
sock = socket.socket(family, kind)
sock.settimeout(0.6)
try:
    sock.connect((sys.argv[1], int(sys.argv[2])))
    if kind == socket.SOCK_DGRAM:
        sock.send(b'PING')
        result = sock.recv(4)
        sys.exit(0 if result == b'PONG' else 3)
    else:
        sys.exit(0 if sock.recv(2) == b'OK' else 3)
except (OSError, TimeoutError):
    sys.exit(2)
finally:
    sock.close()
"""


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, check=True, timeout=15, capture_output=True, text=True
    )


class NamespaceGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.environ.get("FOXTUNNEL_TUN_NETNS") != "1":
            raise unittest.SkipTest(
                "opt-in privileged netns test; set FOXTUNNEL_TUN_NETNS=1"
            )
        if sys.platform != "linux" or os.geteuid() != 0:
            raise RuntimeError("requires Linux and root; test NOT executed")
        for tool in ("ip", "nft"):
            if shutil.which(tool) is None:
                raise RuntimeError(f"requires {tool}; test NOT executed")

        suffix = secrets.token_hex(3)
        cls.client_ns, cls.server_ns = "ftc" + suffix, "fts" + suffix
        veth_a, veth_b = "fta" + suffix, "ftb" + suffix
        cls.temp = tempfile.TemporaryDirectory(prefix="foxtunnel-netns-")
        cls.addClassCleanup(cls.temp.cleanup)
        # Cleanup is registered before creation: it only touches namespaces
        # with unpredictable, test-owned names. No host-wide nft/route changes.
        cls.addClassCleanup(subprocess.run, ["ip", "netns", "del", cls.server_ns],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cls.addClassCleanup(subprocess.run, ["ip", "netns", "del", cls.client_ns],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        run("ip", "netns", "add", cls.client_ns)
        run("ip", "netns", "add", cls.server_ns)
        run("ip", "link", "add", veth_a, "type", "veth", "peer", "name", veth_b)
        # If moving fails, any leftovers have unique names and are deleted.
        cls.addClassCleanup(subprocess.run, ["ip", "link", "del", veth_a],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        run("ip", "link", "set", veth_a, "netns", cls.client_ns)
        run("ip", "link", "set", veth_b, "netns", cls.server_ns)
        run("ip", "-n", cls.client_ns, "link", "set", veth_a, "name", "fcwan0")
        run("ip", "-n", cls.server_ns, "link", "set", veth_b, "name", "fswan0")
        for ns, dev, ipv4, ipv6 in (
            (cls.client_ns, "fcwan0", "198.18.0.2/30", "fd42:1::2/64"),
            (cls.server_ns, "fswan0", "198.18.0.1/30", "fd42:1::1/64"),
        ):
            run("ip", "-n", ns, "link", "set", "lo", "up")
            run("ip", "-n", ns, "addr", "add", ipv4, "dev", dev)
            run("ip", "-n", ns, "-6", "addr", "add", ipv6, "dev", dev)
            run("ip", "-n", ns, "link", "set", dev, "up")

        proc = subprocess.Popen(
            ["ip", "netns", "exec", cls.server_ns, sys.executable,
             "-u", "-c", SERVER_CODE],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        cls.addClassCleanup(cls.stop_server)
        cls.server = proc
        ready, _, _ = select.select([proc.stdout], [], [], 5.0)
        first_line = proc.stdout.readline().strip() if ready else "(no output within 5s)"
        if first_line != "READY":
            raise RuntimeError(
                f"isolated server failed to start: {first_line!r} "
                f"(exit={proc.poll()})"
            )

        cls.install("tcp")
        cls.addClassCleanup(cls.drop_guard)

    @classmethod
    def stop_server(cls):
        proc = getattr(cls, "server", None)
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
        if proc and proc.stdout:
            proc.stdout.close()

    @classmethod
    def drop_guard(cls):
        subprocess.run(
            ["ip", "netns", "exec", cls.client_ns, "nft", "delete",
             "table", "inet", tun.TABLE],
            capture_output=True, text=True
        )

    @classmethod
    def install(cls, carrier: str):
        _config, policy = tun.make_config(
            ["198.18.0.1:8443", "[fd42:1::1]:8443"],
            "fcwan0", proto=carrier
        )
        path = Path(cls.temp.name) / "guard.nft"
        path.write_text(policy, encoding="utf-8")
        run("ip", "netns", "exec", cls.client_ns, "nft", "-c", "-f", str(path))
        run("ip", "netns", "exec", cls.client_ns, "nft", "-f", str(path))

    def probe(self, address: str, port: int, kind: str, allowed: bool):
        result = subprocess.run(
            ["ip", "netns", "exec", self.client_ns, sys.executable,
             "-c", PROBE_CODE, address, str(port), kind],
            timeout=8, capture_output=True, text=True
        )
        self.assertEqual(
            result.returncode == 0, allowed,
            f"{kind} {address}:{port} expected allowed={allowed}, "
            f"status={result.returncode}: {result.stderr}"
        )

    def test_a_tcp_ipv4_ipv6_allow_only_explicit_servers(self):
        self.probe("198.18.0.1", 8443, "tcp", True)
        self.probe("fd42:1::1", 8443, "tcp", True)
        self.probe("198.18.0.1", 9443, "tcp", False)
        self.probe("fd42:1::1", 9443, "tcp", False)

    def test_b_dns_and_unsolicited_udp_are_blocked(self):
        self.probe("198.18.0.1", 53, "udp", False)
        self.probe("fd42:1::1", 53, "udp", False)
        self.probe("198.18.0.1", 8443, "udp", False)

    def test_c_quic_only_carrier_uses_udp_allowlist(self):
        self.drop_guard()
        self.install("udp")
        self.probe("198.18.0.1", 8443, "udp", True)
        self.probe("fd42:1::1", 8443, "udp", True)
        self.probe("198.18.0.1", 8443, "tcp", False)
        self.probe("198.18.0.1", 53, "udp", False)

    def test_z_guard_survives_server_process_exit(self):
        self.stop_server()
        rules = run("ip", "netns", "exec", self.client_ns, "nft",
                    "list", "table", "inet", tun.TABLE).stdout
        self.assertIn("policy drop", rules)
        self.probe("198.18.0.1", 53, "udp", False)
        self.probe("fd42:1::1", 9443, "tcp", False)


if __name__ == "__main__":
    unittest.main()

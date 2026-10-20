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
import signal
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
        # DNS header is exactly 12 bytes total, including the 2-byte ID.
        header = request[:2] + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
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
if kind == "socks":
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3.0)
    try:
        s.connect(("127.0.0.1", 1080))
        s.sendall(b"\x05\x01\x00")
        greeting = s.recv(2)
        s.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(host) + struct.pack("!H", port))
        reply = s.recv(10)
        if greeting != b"\x05\x00" or len(reply) != 10 or reply[1] != 0:
            raise OSError(f"SOCKS handshake refused: {greeting!r} {reply!r}")
        s.sendall(b"fox-tun-e2e")
        success = s.recv(64) == b"fox-tun-e2e"
    except OSError as exc:
        print(f"SOCKS probe failed: {exc!r}", file=sys.stderr)
        success = False
elif kind == "tcp":
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(2.5)
    try:
        s.connect((host, port))
        s.sendall(b"fox-tun-e2e")
        success = s.recv(64) == b"fox-tun-e2e"
    except OSError as exc:
        print(f"TCP probe failed: {exc!r}", file=sys.stderr)
        success = False
elif kind in ("udp", "udp-empty"):
    s = socket.socket(family, socket.SOCK_DGRAM)
    s.settimeout(2.5)
    try:
        payload = b"" if kind == "udp-empty" else b"fox-udp-e2e"
        s.sendto(payload, (host, port))
        success = s.recv(100) == payload
    except OSError as exc:
        print(f"UDP probe failed: {exc!r}", file=sys.stderr)
        success = False
elif kind == "resolve":
    s = socket.socket()
    try:
        success = socket.gethostbyname("fox.lab") == "198.18.0.9"
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
    except OSError as exc:
        print(f"DNS probe failed: {exc!r}", file=sys.stderr)
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
        native = os.environ.get("FOXTUNNEL_TUN_NATIVE") == "1"
        box = os.environ.get("FOXTUNNEL_LAB_SINGBOX", "")
        fox = os.environ.get("FOXTUNNEL_LAB_FOXTUNNEL", "")
        if (not fox or not Path(fox).is_file() or
                (not native and (not box or not Path(box).is_file()))):
            self.fail("supply absolute FOXTUNNEL_LAB_SINGBOX and FOXTUNNEL_LAB_FOXTUNNEL")

        prefix = secrets.token_hex(3)
        cns, sns = "ftce" + prefix, "ftse" + prefix
        ca, sa = "ftca" + prefix, "ftsa" + prefix
        with tempfile.TemporaryDirectory(prefix="foxtunnel-tun-e2e-") as temp:
            root = Path(temp)
            processes: list[subprocess.Popen] = []
            created: list[str] = []
            resolver_dir = None
            resolver_parent_created = False
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
                # No host/physical default route in the hermetic namespace:
                # only the TUN gets a default route; FoxTunnel endpoint uses
                # the directly connected veth route.
                # Isolated endpoints are reachable at the *exit*, but NOT on
                # the client's directly connected veth subnet.
                cmd("ip", "-n", sns, "addr", "add", "198.18.0.9/32", "dev", "lo")
                cmd("ip", "-n", sns, "-6", "addr", "add", "fd42:2::9/128", "dev", "lo", "nodad")

                if native:
                    # ip netns exec bind-mounts this resolver configuration only
                    # for this unique namespace. Host resolver stays untouched.
                    resolver_parent = Path('/etc/netns')
                    if not resolver_parent.exists():
                        resolver_parent.mkdir()
                        resolver_parent_created = True
                    candidate = resolver_parent / cns
                    candidate.mkdir()
                    resolver_dir = candidate
                    (resolver_dir / 'resolv.conf').write_text('nameserver 198.18.0.9\noptions timeout:1 attempts:1\n')
                    cmd('ip', '-n', cns, 'route', 'add', 'default', 'via', '198.18.0.1', 'dev', 'fcwan0')
                    cmd('ip', '-n', cns, '-6', 'route', 'add', 'default', 'via', 'fd42:1::1', 'dev', 'fcwan0')

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
                    launch = [fox, *args]
                    if native and ns == cns:
                        launch = [sys.executable, str(Path(__file__).with_name('linux_native_vpn.py').resolve()),
                                  '--endpoint', '198.18.0.1:8443', '--uplink', 'fcwan0',
                                  '--dns', '198.18.0.9', '--dns-mode', 'none', '--', *launch]
                    p = subprocess.Popen(["ip", "netns", "exec", ns, *launch],
                                         env=env, stdout=fd, stderr=subprocess.STDOUT)
                    fd.close()
                    processes.append(p)
                    return p
                server = fox_start(sns, "server",
                                   "--listen", "198.18.0.1:8443",
                                   "--cert", str(cert), "--key", str(key),
                                   "--allow-private", "--enable-udp")
                self.wait_alive(server, 0.5, "FoxTunnel server")
                client_args = ["client", "--server", "https://198.18.0.1:8443",
                               "--listen", "127.0.0.1:1080",
                               "--ca-cert", str(cert), "--sni", "lab.test",
                               "--tls-backend", "go", "--enable-udp", "--udp-stream"]
                if native:
                    client_args.extend(["--tun", "ftun0", "--tun-mtu", "1400"])
                client = fox_start(cns, *client_args)
                self.wait_alive(client, 0.5, "FoxTunnel client")
                self.assert_probe(cns, "socks", "198.18.0.9", 5657, True)

                # Real sing-box validated config from *same* public generator.
                config, policy = companion.make_config(
                    ["198.18.0.1:8443"], "fcwan0", dns="198.18.0.9"
                )
                # A new namespace often has no systemd-resolved socket. A TUN
                # hijack rule still exercises the remote resolver via UDP SOCKS.
                config["log"]["level"] = "debug" # isolated lab diagnostics only
                config["route"]["auto_detect_interface"] = False
                config["route"]["default_interface"] = "fcwan0"
                profile = root / "sing-box.json"
                profile.write_text(json.dumps(config), encoding="utf-8")
                if not native:
                    cmd(box, "check", "-c", str(profile))
                rules = root / "guard.nft"
                rules.write_text(policy, encoding="utf-8")
                if not native:
                    cmd("ip", "netns", "exec", cns, "nft", "-c", "-f", str(rules))
                    cmd("ip", "netns", "exec", cns, "nft", "-f", str(rules))
                self.assert_probe(cns, "socks", "198.18.0.9", 5657, True)
                sink = None
                if native:
                    self.wait_tun(cns, client, timeout=15)
                    deadline = time.monotonic() + 10
                    while time.monotonic() < deadline:
                        if '51821' in cmd('ip', '-n', cns, '-6', 'rule', 'show').stdout:
                            break
                        self.wait_alive(client, 0.1, 'native launcher')
                    else:
                        self.fail('native launcher did not install dual-stack policy routes')
                else:
                    sink = start(cns, box, "run", "-c", str(profile))
                    self.wait_tun(cns, sink, timeout=15)

                self.assert_probe(cns, "tcp", "198.18.0.9", 5657, True)
                self.assert_probe(cns, "tcp", "fd42:2::9", 5657, True)
                self.assert_probe(cns, "udp", "198.18.0.9", 5656, True)
                self.assert_probe(cns, "udp", "fd42:2::9", 5656, True)
                if native:
                    self.assert_probe(cns, "udp-empty", "198.18.0.9", 5656, True)
                    self.assert_probe(cns, "udp-empty", "fd42:2::9", 5656, True)
                    self.assert_probe(cns, "resolve", "198.18.0.9", 53, True)
                # Native stack forwards numeric DNS via UDP without rewriting
                # the original destination. sing-box offers DNS hijack.
                dns_target = "198.18.0.9" if native else "9.9.9.9"
                self.assert_probe(cns, "dns", dns_target, 53, True)
                if native:
                    self.assert_probe(cns, "dns", "fd42:2::9", 53, True)

                # A dropped tunnel must NOT fall back to direct Internet.
                if native:
                    children = Path(f'/proc/{client.pid}/task/{client.pid}/children').read_text().split()
                    self.assertEqual(len(children), 1, 'launcher should own one FoxTunnel child')
                    os.kill(int(children[0]), signal.SIGKILL)
                    client.wait(timeout=8)
                    self.assertNotIn('51821', cmd('ip', '-n', cns, 'rule', 'show').stdout)
                else:
                    stop(client)
                self.assert_probe(cns, "tcp", "198.18.0.9", 5657, False)
                self.assert_probe(cns, "udp", "198.18.0.9", 5656, False)
                output = cmd("ip", "netns", "exec", cns, "nft", "list",
                             "table", "inet", companion.TABLE).stdout
                self.assertIn("policy drop", output)
                self.assert_probe(cns, "dns", dns_target, 53, False)

                # Explicitly stop sing-box: its TUN routes disappear, but the
                # independently installed output guard must not disappear.
                stop(sink)
                rules_after_exit = cmd("ip", "netns", "exec", cns, "nft",
                                       "list", "table", "inet",
                                       companion.TABLE).stdout
                self.assertIn("policy drop", rules_after_exit)

                # Recreate a physical default route like a real link that
                # comes back while VPN is DOWN. The target is on the server
                # namespace; WITHOUT the guard, these probes would connect.
                cmd("ip", "-n", cns, "route", "replace", "default",
                    "via", "198.18.0.1", "dev", "fcwan0")
                cmd("ip", "-n", cns, "-6", "route", "replace", "default",
                    "via", "fd42:1::1", "dev", "fcwan0")
                self.assert_probe(cns, "tcp", "198.18.0.9", 5657, False)
                self.assert_probe(cns, "udp", "198.18.0.9", 5656, False)
                self.assert_probe(cns, "dns", "198.18.0.9", 53, False)
                cmd("ip", "-n", cns, "link", "set", "fcwan0", "down")
                self.assert_probe(cns, "tcp", "198.18.0.9", 5657, False)
                cmd("ip", "-n", cns, "link", "set", "fcwan0", "up")
                # Linux removes static defaults (and may remove IPv6 global
                # addresses) on link down. Recreate a usable physical path
                # before checking the firewall, then keep it for the positive
                # control. Otherwise ENETUNREACH would mimic a working guard.
                cmd('ip', '-n', cns, 'addr', 'replace', '198.18.0.2/30', 'dev', 'fcwan0')
                cmd('ip', '-n', cns, '-6', 'addr', 'replace', 'fd42:1::2/64', 'dev', 'fcwan0', 'nodad')
                cmd('ip', '-n', cns, 'route', 'replace', 'default', 'via', '198.18.0.1', 'dev', 'fcwan0')
                cmd('ip', '-n', cns, '-6', 'route', 'replace', 'default', 'via', 'fd42:1::1', 'dev', 'fcwan0')
                self.assert_probe(cns, "tcp", "198.18.0.9", 5657, False)
                self.assert_probe(cns, "dns", "198.18.0.9", 53, False)
                self.assert_probe(cns, "tcp", "fd42:2::9", 5657, False)
                self.assert_probe(cns, "udp", "fd42:2::9", 5656, False)
                # Positive control: identical physical routes and services
                # work once the guard is removed, only inside our namespace.
                cmd('ip', 'netns', 'exec', cns, 'nft', 'delete', 'table', 'inet', companion.TABLE)
                self.assert_probe(cns, 'tcp', '198.18.0.9', 5657, True)
                self.assert_probe(cns, 'tcp', 'fd42:2::9', 5657, True)
                self.assert_probe(cns, 'udp', '198.18.0.9', 5656, True)
                self.assert_probe(cns, 'udp', 'fd42:2::9', 5656, True)
                self.assert_probe(cns, 'dns', '198.18.0.9', 53, True)
            except Exception:
                for ns in created:
                    for suffix in (("route", "show", "table", "all"),
                                   ("-6", "route", "show", "table", "all"),
                                   ("rule", "show")):
                        probe = subprocess.run(
                            ["ip", "-n", ns, *suffix], capture_output=True,
                            text=True, timeout=5
                        )
                        sys.stderr.write(f"\n-- {ns} {suffix} --\n{probe.stdout[-3000:]}\n")
                    for target in ("198.18.0.9", "198.18.0.1"):
                        route_get = subprocess.run(
                            ["ip", "netns", "exec", ns, "ip", "route", "get", target],
                            capture_output=True, text=True, timeout=5
                        )
                        sys.stderr.write(f"\\n-- {ns} route get {target} --\\n{route_get.stdout} {route_get.stderr}\\n")
                    nft = subprocess.run(
                        ["ip", "netns", "exec", ns, "nft", "list", "ruleset"],
                        capture_output=True, text=True, timeout=5
                    )
                    sys.stderr.write(f"\n-- {ns} nft --\n{nft.stdout[-5500:]}\n")
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
                if resolver_dir is not None:
                    (resolver_dir / 'resolv.conf').unlink(missing_ok=True)
                    resolver_dir.rmdir()
                if resolver_parent_created:
                    Path('/etc/netns').rmdir()
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

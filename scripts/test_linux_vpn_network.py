#!/usr/bin/env python3
"""Privileged, offline VPN integration inside a disposable outer net namespace.

Invoke ONLY through sudo unshare --mount --net --pid --fork --mount-proc.
No Internet fixtures, host routes, host firewall or host resolver are used.
"""
import argparse
import ipaddress
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time

V6 = "2606:4700:abcd::2"
SCRIPT = str(Path(__file__).resolve())


def fixture():
    class TCP(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
    class TCP6(TCP):
        address_family = socket.AF_INET6
    class UDP(socketserver.ThreadingUDPServer):
        allow_reuse_address = True
        daemon_threads = True
    class UDP6(UDP):
        address_family = socket.AF_INET6
    class EchoTCP(socketserver.BaseRequestHandler):
        def handle(self):
            self.request.settimeout(5)
            while True:
                data = self.request.recv(4096)
                if not data:
                    return
                self.request.sendall(data)
    class EchoUDP(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            sock.sendto(data, self.client_address)
    class DNS(socketserver.BaseRequestHandler):
        def handle(self):
            data, sock = self.request
            if len(data) < 17 or data[4:6] != b"\x00\x01":
                return
            end = 12
            while end < len(data) and data[end]:
                end += 1 + data[end]
            end += 1
            if end + 4 > len(data):
                return
            qtype = struct.unpack("!H", data[end:end+2])[0]
            question = data[12:end+4]
            addr = "8.8.8.8" if qtype == 1 else V6
            if qtype not in (1, 28):
                return
            packed = ipaddress.ip_address(addr).packed
            header = data[:2] + struct.pack("!5H", 0x8180, 1, 1, 0, 0)
            answer = b"\xc0\x0c" + struct.pack("!HHIH", qtype, 1, 10, len(packed)) + packed
            sock.sendto(header + question + answer, self.client_address)
    servers = []
    for cls, host in ((TCP, "0.0.0.0"), (TCP6, "::")):
        servers.append(cls((host, 18080), EchoTCP))
    for cls, host in ((UDP, "0.0.0.0"), (UDP6, "::")):
        servers.append(cls((host, 18081), EchoUDP))
        servers.append(cls((host, 53), DNS))
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    print("ready", flush=True)
    threading.Event().wait()


def probe(blocked):
    def tcp(host):
        with socket.create_connection((host, 18080), timeout=1.5) as sock:
            sock.sendall(b"kernel-TCP-through-TUN")
            assert sock.recv(64) == b"kernel-TCP-through-TUN"
    def udp(host):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(1.5)
            sock.connect((host, 18081))
            for payload in (b"", b"one", b"two" * 350):
                sock.send(payload)
                assert sock.recv(1200) == payload
    def dns():
        addresses = socket.getaddrinfo("vpn.test", 18080, type=socket.SOCK_STREAM)
        assert {a[4][0] for a in addresses} == {"8.8.8.8", V6}
    for test in (lambda: tcp("8.8.8.8"), lambda: tcp(V6),
                 lambda: udp("8.8.8.8"), lambda: udp(V6), dns):
        try:
            test()
        except (OSError, AssertionError):
            if not blocked:
                raise
        else:
            if blocked:
                raise AssertionError("direct TCP/UDP/DNS egress survived blocking")


def integration(binary):
    if os.geteuid() != 0:
        raise SystemExit("requires isolated root network namespace")
    # Require an outer namespace with only lo; refuse running in a host network.
    links = json.loads(subprocess.check_output(["ip", "-j", "link", "show"]))
    if {item["ifname"] for item in links} != {"lo"}:
        raise SystemExit("refusing non-isolated network namespace")
    binary = str(Path(binary).resolve())
    names = ("ft-client", "ft-server", "ft-world")
    procs, logs = [], []
    def run(*cmd, env=None):
        return subprocess.run(cmd, check=True, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env=env)
    def ns(name, *cmd):
        return run("ip", "netns", "exec", name, *cmd)
    def private(path, data):
        path.write_text(data)
        path.chmod(0o600)
    def background(name, args, logpath, env=None):
        log = open(logpath, "w+")
        logs.append(log)
        p = subprocess.Popen(["ip", "netns", "exec", name, *args],
                             stdout=log, stderr=log, env=env)
        procs.append(p)
        return p
    def wait_log(path, word, proc):
        for _ in range(150):
            if word in path.read_text():
                return
            if proc.poll() is not None:
                raise AssertionError("fixture exited before readiness: " + path.read_text())
            time.sleep(0.1)
        raise AssertionError("fixture readiness timed out: " + path.read_text())
    resolv = Path("/etc/netns/ft-client")
    try:
        run("mount", "--make-rprivate", "/")
        for name in names:
            run("ip", "netns", "add", name)
            ns(name, "ip", "link", "set", "lo", "up")
        for a, b, left, right in (("c0", "s0", names[0], names[1]),
                                  ("s1", "w0", names[1], names[2])):
            run("ip", "link", "add", a, "type", "veth", "peer", "name", b)
            run("ip", "link", "set", a, "netns", left)
            run("ip", "link", "set", b, "netns", right)
        addresses = ((names[0], "c0", "192.0.2.1/24", "fd01::1/64"),
                     (names[1], "s0", "192.0.2.2/24", "fd01::2/64"),
                     (names[1], "s1", "198.18.0.1/24", "fd02::1/64"),
                     (names[2], "w0", "198.18.0.2/24", "fd02::2/64"))
        for name, dev, a, b in addresses:
            ns(name, "ip", "link", "set", dev, "up")
            ns(name, "ip", "addr", "add", a, "dev", dev)
            ns(name, "ip", "-6", "addr", "add", b, "dev", dev, "nodad")
        for name, gw, gw6 in ((names[0], "192.0.2.2", "fd01::2"),
                               (names[1], "198.18.0.2", "fd02::2"),
                               (names[2], "198.18.0.1", "fd02::1")):
            ns(name, "ip", "route", "add", "default", "via", gw)
            ns(name, "ip", "-6", "route", "add", "default", "via", gw6)
        for addr in ("8.8.8.8/32", "9.9.9.9/32"):
            ns(names[2], "ip", "addr", "add", addr, "dev", "lo")
        for addr in (V6+"/128", "2620:fe::fe/128"):
            ns(names[2], "ip", "-6", "addr", "add", addr, "dev", "lo", "nodad")
        ns(names[1], "sysctl", "-w", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1")
        resolv.mkdir(parents=True)
        (resolv/"resolv.conf").write_text("nameserver 9.9.9.9\noptions timeout:1 attempts:1\n")
        with tempfile.TemporaryDirectory(prefix="ft-vpn-test-") as tmp:
            root = Path(tmp)
            secret = secrets.token_urlsafe(32)
            users, state, servercfg, clientcfg = [root/n for n in ("users.json", "usage.json", "server.json", "client.json")]
            private(users, json.dumps({"v": 1, "users": [{"id": "alice", "username": "alice", "password": secret}]}))
            peer = {"id": "alice", "ipv4": "100.96.0.2", "ipv6": "fd62:666f:78::2"}
            private(servercfg, json.dumps({"v": 1, "underlay": "s1", "peers": [peer]}))
            private(clientcfg, json.dumps({"v": 1, "interface": "ftvpn0", "underlay": "c0", "gateway": "192.0.2.2", "ipv4": peer["ipv4"], "ipv6": peer["ipv6"], "dns4": "9.9.9.9", "dns6": "2620:fe::fe"}))
            cert, key = root/"cert.pem", root/"key.pem"
            run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=vpn.invalid", "-addext", "subjectAltName=DNS:vpn.invalid,IP:192.0.2.2", "-keyout", str(key), "-out", str(cert))
            env = {k: v for k, v in os.environ.items() if k not in ("FOXTUNNEL_USER", "FOXTUNNEL_PASSWORD")}
            share_env = dict(env, FOXTUNNEL_USER="alice", FOXTUNNEL_PASSWORD=secret)
            link = root/"link.txt"
            private(link, run(binary, "share", "--lang", "en", "--server", "https://192.0.2.2:18443", "--sni", "vpn.invalid", "--transport", "h2-connect", env=share_env).stdout.decode())
            worldlog, serverlog, clientlog = [root/n for n in ("world.log", "server.log", "client.log")]
            world = background(names[2], [sys.executable, SCRIPT, "--fixture"], worldlog)
            wait_log(worldlog, "ready", world)
            ns(names[1], binary, "vpn-network", "--config", str(servercfg))
            server = background(names[1], [binary, "server", "--lang", "en", "--listen", "192.0.2.2:18443", "--cert", str(cert), "--key", str(key), "--users-file", str(users), "--users-state", str(state), "--vpn-config", str(servercfg)], serverlog, env)
            wait_log(serverlog, "HTTPS", server)
            # A private netns resolver fixture replaces systemd-resolved only in
            # this test. Production uses real resolvectl; no host D-Bus is touched.
            fakebin = root/"bin"; fakebin.mkdir()
            (fakebin/"resolvectl").write_text("#!/bin/sh\nexit 0\n"); (fakebin/"resolvectl").chmod(0o700)
            clientenv = dict(env, PATH=str(fakebin)+":"+env["PATH"])
            args = [binary, "vpn-client", "--lang", "en", "--config", str(clientcfg), "--link-file", str(link), "--ca-cert", str(cert)]
            client = background(names[0], args, clientlog, clientenv)
            wait_log(clientlog, "IP session connected", client)
            ns(names[0], sys.executable, SCRIPT, "--probe")
            # Freeze/resume and carrier loss retain the blocking output policy.
            client.send_signal(signal.SIGSTOP)
            ns(names[0], sys.executable, SCRIPT, "--probe", "--blocked")
            client.send_signal(signal.SIGCONT)
            ns(names[0], sys.executable, SCRIPT, "--probe")
            ns(names[0], "ip", "link", "set", "c0", "down")
            ns(names[0], sys.executable, SCRIPT, "--probe", "--blocked")
            ns(names[0], "ip", "link", "set", "c0", "up")
            for attempt in range(10):
                try:
                    ns(names[0], sys.executable, SCRIPT, "--probe")
                    break
                except subprocess.CalledProcessError:
                    if attempt == 9:
                        raise
                    time.sleep(1)
            client.kill(); client.wait(timeout=5)
            ns(names[0], "nft", "list", "table", "inet", "foxtunnel_vpn_client")
            ns(names[0], sys.executable, SCRIPT, "--probe", "--blocked")
            # Prove that a direct route really exists and is usable only after
            # explicit operator removal of the persistent kill switch.
            ns(names[0], binary, "vpn-down", "--config", str(clientcfg), "--link-file", str(link))
            ns(names[0], sys.executable, SCRIPT, "--probe")
            print("PASS: real TUN TCP/UDP, IPv4/IPv6, tunneled DNS, freeze/resume, link loss/recovery, crash kill switch and explicit disconnect")
    finally:
        for p in reversed(procs):
            if p.poll() is None:
                p.kill()
            p.wait(timeout=5)
        for log in logs:
            log.close()
        for name in names:
            subprocess.run(["ip", "netns", "del", name], capture_output=True)
        if resolv.exists():
            (resolv/"resolv.conf").unlink(missing_ok=True)
            resolv.rmdir()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary")
    parser.add_argument("--fixture", action="store_true")
    parser.add_argument("--probe", action="store_true")
    parser.add_argument("--blocked", action="store_true")
    args = parser.parse_args()
    if args.fixture:
        fixture()
    elif args.probe:
        probe(args.blocked)
    elif args.binary:
        integration(args.binary)
    else:
        parser.error("select a mode")

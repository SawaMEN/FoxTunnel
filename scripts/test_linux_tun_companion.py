"""Offline, unprivileged tests for the optional Linux TUN companion generator."""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

import linux_tun_companion as tun


class GeneratorTests(unittest.TestCase):
    def test_ipv4_ipv6_endpoint_and_isolated_routes(self):
        cfg, nft = tun.make_config(
            ["198.51.100.17:443", "[2001:db8::17]:8443"],
            "enp3s0", tun_name="ftun0", socks_port=1180
        )
        inbound = cfg["inbounds"][0]
        self.assertEqual(inbound["type"], "tun")
        self.assertTrue(inbound["auto_route"])
        self.assertTrue(inbound["auto_redirect"])
        self.assertTrue(inbound["strict_route"])
        self.assertEqual(inbound["dns_mode"], "hijack")
        self.assertEqual(
            inbound["route_exclude_address"],
            ["198.51.100.17/32", "2001:db8::17/128"],
        )
        self.assertEqual(cfg["route"]["final"], "foxtunnel-socks")
        self.assertEqual(cfg["outbounds"][0]["server"], "127.0.0.1")
        self.assertEqual(cfg["outbounds"][0]["server_port"], 1180)
        self.assertEqual(cfg["dns"]["servers"][0]["detour"], "foxtunnel-socks")
        self.assertNotIn('"type": "direct"', json.dumps(cfg))
        self.assertIn("type filter hook output priority filter; policy drop;", nft)
        self.assertNotIn("priority -150", nft)
        self.assertIn('oifname "ftun0" accept', nft)
        self.assertIn('oifname "lo" accept', nft)
        self.assertIn('oifname "enp3s0" ip6 hoplimit 255 icmpv6 type', nft)
        self.assertIn("nd-neighbor-solicit", nft)
        self.assertIn("nd-neighbor-advert", nft)
        self.assertIn(
            'oifname "enp3s0" ip daddr 198.51.100.17 tcp dport 443 accept', nft
        )
        self.assertIn(
            'oifname "enp3s0" ip6 daddr 2001:db8::17 tcp dport 8443 accept', nft
        )
        self.assertNotIn("udp dport", nft)

    def test_udp_carrier_explicit(self):
        cfg, firewall = tun.make_config(["8.8.8.8:443"], "eth0", proto="udp")
        self.assertIn("udp dport 443 accept", firewall)
        self.assertNotIn("tcp dport 443 accept", firewall)
        self.assertEqual(cfg["dns"]["servers"][0]["server"], "1.1.1.1")

    def test_rejects_names_injection_and_unsafe_endpoints(self):
        cases = [
            (["server.example:443"], "eth0"),
            (["0.0.0.0:443"], "eth0"),
            (["127.0.0.1:443"], "eth0"),
            (["[::1]:443"], "eth0"),
            (["224.0.0.1:443"], "eth0"),
            (["fe80::1:443"], "eth0"),
            (["8.8.8.8:0"], "eth0"),
            (["8.8.8.8:65536"], "eth0"),
            (["8.8.8.8:443\nflush ruleset"], "eth0"),
            (["8.8.8.8:443"], "eth0\nflush"),
            (["8.8.8.8:443"], "lo"),
            (["8.8.8.8:443"], "ftun0"),
            (["8.8.8.8:443", "8.8.8.8:443"], "eth0"),
        ]
        for endpoints, uplink in cases:
            with self.subTest(endpoints=endpoints, uplink=uplink):
                with self.assertRaises(ValueError):
                    tun.make_config(endpoints, uplink)
        with self.assertRaises(ValueError):
            tun.make_config(["8.8.8.8:443"], "eth0", tun_name="x" * 16)
        with self.assertRaises(ValueError):
            tun.make_config(["8.8.8.8:443"], "eth0", dns="127.0.0.1")
        with self.assertRaises(ValueError):
            tun.make_config(["8.8.8.8:443"], "eth0", socks_port=0)
        with self.assertRaises(ValueError):
            tun.make_config(["8.8.8.8:443"], "eth0", proto="both")

    def test_exclusive_private_generation_and_no_overwrite(self):
        with tempfile.TemporaryDirectory() as root:
            out = Path(root) / "new-private-dir"
            argv = ["--endpoint", "8.8.4.4:443", "--uplink", "wlan0",
                    "--out", str(out)]
            self.assertEqual(tun.main(argv), 0)
            self.assertEqual(stat.S_IMODE(out.stat().st_mode), 0o700)
            files = {
                "sing-box.json": 0o600, "killswitch.nft": 0o600,
                "run.sh": 0o700, "README.txt": 0o600,
            }
            for name, mode in files.items():
                p = out / name
                self.assertTrue(p.is_file())
                self.assertEqual(stat.S_IMODE(p.stat().st_mode), mode)
            cfg = json.loads((out / "sing-box.json").read_text())
            self.assertEqual(cfg["outbounds"][0]["type"], "socks")
            self.assertIn("nft -f", (out / "run.sh").read_text())
            self.assertIn("exec sing-box run", (out / "run.sh").read_text())
            original = (out / "killswitch.nft").read_bytes()
            with self.assertRaises(SystemExit) as e:
                tun.main(argv)
            self.assertEqual(e.exception.code, 2)
            self.assertEqual((out / "killswitch.nft").read_bytes(), original)

    def test_dry_run_requires_no_linux_or_root(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "profile"
            subprocess.run(
                [sys.executable, str(Path(tun.__file__).resolve()),
                 "--endpoint", "8.8.8.8:443", "--uplink", "enp2s0",
                 "--out", str(path)],
                check=True, capture_output=True, text=True
            )
            config = json.loads((path / "sing-box.json").read_text())
            self.assertEqual(config["inbounds"][0]["interface_name"], "ftun0")
            self.assertFalse((path / "sing-box.json").stat().st_mode & stat.S_IWOTH)


if __name__ == "__main__":
    unittest.main()

"""Validate the independent offline fixtures without privileged namespaces."""
from pathlib import Path
import select
import socket
import struct
import subprocess
import sys
import unittest


class VPNFixtureTests(unittest.TestCase):
    def test_dual_stack_tcp_udp_and_dns(self):
        script = Path(__file__).with_name("test_linux_vpn_network.py")
        proc = subprocess.Popen([sys.executable, str(script), "--fixture", "--dns-port", "1053", "--loopback"],
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            ready, _, _ = select.select([proc.stdout], [], [], 4)
            self.assertTrue(ready, "fixture did not signal readiness")
            self.assertEqual(proc.stdout.readline().strip(), "ready")
            for host, family in (("127.0.0.1", socket.AF_INET), ("::1", socket.AF_INET6)):
                with socket.create_connection((host, 18080), timeout=2) as stream:
                    payload = b"independent TCP fixture" * 1000
                    stream.sendall(payload)
                    received = b""
                    while len(received) < len(payload):
                        received += stream.recv(len(payload)-len(received))
                    self.assertEqual(received, payload)
                with socket.socket(family, socket.SOCK_DGRAM) as udp:
                    udp.settimeout(2)
                    udp.connect((host, 18081))
                    for payload in (b"", b"first", b"second"*100):
                        udp.send(payload)
                        self.assertEqual(udp.recv(2048), payload)
                with socket.socket(family, socket.SOCK_DGRAM) as dns:
                    dns.settimeout(2)
                    qtype = 1 if family == socket.AF_INET else 28
                    query = b"\x12\x34" + struct.pack("!5H", 0x100, 1, 0, 0, 0)
                    query += b"\x03vpn\x04test\0" + struct.pack("!HH", qtype, 1)
                    dns.sendto(query, (host, 1053))
                    answer, _ = dns.recvfrom(512)
                    expected = "8.8.8.8" if qtype == 1 else "2606:4700:abcd::2"
                    self.assertEqual(answer[-(4 if qtype == 1 else 16):],
                                     socket.inet_pton(family, expected))
        finally:
            proc.terminate()
            proc.wait(timeout=3)
            proc.stdout.close()
            proc.stderr.close()


if __name__ == "__main__":
    unittest.main()

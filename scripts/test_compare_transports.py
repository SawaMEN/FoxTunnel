"""Offline tests for the independent FoxTunnel/VLESS measurement harness."""
from __future__ import annotations

import json
import socketserver
import tempfile
import threading
import unittest
from pathlib import Path

import compare_transports as bench


class SOCKSHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        s = self.request
        s.settimeout(3)
        if bench.exact(s, 3) != b'\x05\x01\x00':
            return
        s.sendall(b'\x05\x00')
        header = bench.exact(s, 4)
        if header[:3] != b'\x05\x01\x00':
            return
        if header[3] == 1:
            bench.exact(s, 4)
        elif header[3] == 4:
            bench.exact(s, 16)
        elif header[3] == 3:
            bench.exact(s, bench.exact(s, 1)[0])
        else:
            return
        bench.exact(s, 2)
        if getattr(self.server, 'refuse', False):
            s.sendall(b'\x05\x05\x00\x01' + b'\x00' * 6)
            return
        s.sendall(b'\x05\x00\x00\x01' + b'\x7f\x00\x00\x01' + b'\x00\x01')
        while data := s.recv(8192):
            if getattr(self.server, 'corrupt', False):
                data = bytes([data[0] ^ 1]) + data[1:]
            s.sendall(data)


class SOCKSServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


class BenchmarkTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = SOCKSServer(('127.0.0.1', 0), SOCKSHandler)
        cls.worker = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.worker.start()
        cls.proxy = bench.Address('127.0.0.1', cls.server.server_address[1])
        cls.target = bench.Address('echo.example', 9000)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.worker.join(3)

    def test_ipv4_and_ipv6_and_domain(self):
        for target in [self.target, bench.Address('127.0.0.1', 9000),
                       bench.Address('::1', 9000)]:
            with self.subTest(target=target):
                r = bench.trial(self.proxy, target, 1024 * 1024 + 13, 3, b'abc' * (bench.CHUNK // 3) + b'z' * (bench.CHUNK % 3))
                self.assertTrue(r['ok'], r['error'])
                self.assertGreater(r['payload_mbps'], 0)
                self.assertIsNotNone(r['connect_ms'])

    def test_rejected_and_corrupted_connections(self):
        self.server.refuse = True
        try:
            r = bench.trial(self.proxy, self.target, 100, 3, b'a' * bench.CHUNK)
            self.assertFalse(r['ok'])
            self.assertIn('code 5', r['error'])
        finally:
            self.server.refuse = False
        self.server.corrupt = True
        try:
            r = bench.trial(self.proxy, self.target, 100, 3, b'a' * bench.CHUNK)
            self.assertFalse(r['ok'])
            self.assertIn('echo mismatch', r['error'])
        finally:
            self.server.corrupt = False

    def test_addresses_and_percentiles(self):
        self.assertEqual(bench.address('[::1]:1080'), bench.Address('::1', 1080))
        self.assertEqual(bench.endpoint('VLESS=127.0.0.1:1081')[0], 'VLESS')
        for value in ['bad', '127.0.0.1:0', 'evil@host:500', '127.0.0.1:80/path',
                      '[::1:1080', '127.0.0.1:99999', 'host:80?ignore=yes']:
            with self.subTest(value=value), self.assertRaises(ValueError):
                bench.address(value)
        self.assertEqual(bench.percentile([10, 20, 30], .95), 29)
        self.assertIsNone(bench.percentile([], .5))
        self.assertIsNone(bench.summarize([])['success_percent'])

    def test_report_and_no_overwrite(self):
        proxy = f'127.0.0.1:{self.proxy.port}'
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / 'comparison.json'
            args = ['--proxy', f'foxtunnel={proxy}', '--proxy', f'vless={proxy}',
                    '--target', 'echo.example:9000', '--warmup', '1', '--rounds', '2',
                    '--parallel', '2', '--bytes', '131079', '--out', str(out)]
            self.assertEqual(bench.main(args), 0)
            document = json.loads(out.read_text())
            self.assertEqual(document['schema'], 1)
            self.assertEqual(len(document['samples']), 8)
            self.assertEqual(document['summary']['foxtunnel']['successful'], 4)
            self.assertEqual(document['summary']['vless']['failed'], 0)
            self.assertEqual(document['configuration']['target']['host'], 'echo.example')
            with self.assertRaises(SystemExit):
                bench.main(args)
            self.assertEqual(len(json.loads(out.read_text())['samples']), 8)


if __name__ == '__main__':
    unittest.main()

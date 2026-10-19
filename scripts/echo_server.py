#!/usr/bin/env python3
"""Controlled TCP echo target for transport comparisons (never expose publicly)."""
from __future__ import annotations

import argparse
import ipaddress
import socket
import socketserver


class EchoHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(15)
        while True:
            try:
                data = self.request.recv(32 * 1024)
            except TimeoutError:
                return
            if not data:
                return
            self.request.sendall(data)


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', default='127.0.0.1', help='numeric bind IP (default: loopback)')
    parser.add_argument('--port', type=int, default=9000)
    parser.add_argument('--allow-public', action='store_true', help='explicit acknowledgment for non-loopback bind')
    args = parser.parse_args()
    try:
        host = ipaddress.ip_address(args.host)
    except ValueError:
        parser.error('--host must be a numeric IP')
    if not host.is_loopback and not args.allow_public:
        parser.error('non-loopback bind requires --allow-public and a restrictive firewall')
    if not (1 <= args.port <= 65535):
        parser.error('--port must be 1-65535')
    class FamilyServer(EchoServer):
        address_family = socket.AF_INET6 if host.version == 6 else socket.AF_INET
    with FamilyServer((str(host), args.port), EchoHandler) as server:
        print(f'echo listening at {host}:{args.port} (no authentication; use isolated lab)', flush=True)
        server.serve_forever(poll_interval=.1)


if __name__ == '__main__':
    main()

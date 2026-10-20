#!/usr/bin/env python3
"""Controlled UDP echo target for stage-4 tests (firewall it on VDS)."""
from __future__ import annotations

import argparse
import ipaddress
import socket


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=9001)
    p.add_argument("--allow-public", action="store_true")
    a = p.parse_args(argv)
    try:
        ip = ipaddress.ip_address(a.host)
    except ValueError:
        p.error("--host must be a numeric IP")
    if not ip.is_loopback and not a.allow_public:
        p.error("non-loopback UDP echo requires --allow-public and restrictive firewall")
    if not 1 <= a.port <= 65535:
        p.error("port must be 1..65535")
    with socket.socket(socket.AF_INET6 if ip.version == 6 else socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((str(ip), a.port))
        s.settimeout(2)
        print("UDP echo active (unauthenticated; isolated lab only)", flush=True)
        try:
            while True:
                try:
                    packet, sender = s.recvfrom(1233)
                except TimeoutError:
                    continue
                if 0 < len(packet) <= 1232:
                    s.sendto(packet, sender)
        except KeyboardInterrupt:
            return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Run native FoxTunnel with explicit Linux routing, resolved DNS and nft guard.

Requires root, iproute2, nftables and (by default) systemd-resolved. The guard
persists after exit, including startup failure. Never flushes the host ruleset.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

from linux_tun_companion import TABLE, destination, dns_ip, interface, make_config

ROUTE_TABLE = '51821'
PRIORITY = 18000


def command(*args: str, check: bool = True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=10)


class Network:
    def __init__(self, endpoints, uplink, tun, dns, carrier='tcp', dns_mode='resolved'):
        # Reuse the exact endpoint validation and fail-closed policy of the lab.
        _, self.firewall = make_config(endpoints, uplink, tun, dns=dns, proto=carrier)
        self.endpoints = sorted({destination(e)[0] for e in endpoints}, key=str)
        self.uplink, self.tun, self.dns = uplink, tun, dns_ip(dns)
        if ipaddress.ip_address(self.dns) in self.endpoints:
            raise ValueError('DNS must differ from the carrier endpoint IP')
        self.dns_mode = dns_mode
        self.undo = []

    def preflight(self):
        for binary in ('ip', 'nft', *(('resolvectl',) if self.dns_mode == 'resolved' else ())):
            if not shutil.which(binary):
                raise ValueError(f'missing {binary}')
        command('ip', 'link', 'show', 'dev', self.uplink)
        if command('ip', 'link', 'show', 'dev', self.tun, check=False).returncode == 0:
            raise ValueError('TUN already exists; refusing to take over its network configuration')
        if command('nft', 'list', 'table', 'inet', TABLE, check=False).returncode == 0:
            raise ValueError(f'{TABLE} already exists; inspect/remove it explicitly before restarting')
        for family in ('-4', '-6'):
            rules = json.loads(command('ip', family, '-j', 'rule', 'show').stdout)
            # Earlier nonstandard routing could override the VPN table. Refuse
            # rather than silently route application traffic through main.
            if any(0 < int(r.get('priority', 0)) <= PRIORITY + 16 for r in rules):
                raise ValueError('conflicting policy rule before VPN priority 18016')
            routes = command('ip', family, 'route', 'show', 'table', ROUTE_TABLE, check=False)
            if routes.stdout.strip():
                raise ValueError(f'routing table {ROUTE_TABLE} is occupied')
        for ip in self.endpoints:
            route = json.loads(command('ip', '-j', 'route', 'get', str(ip)).stdout)
            if not route or route[0].get('dev') != self.uplink:
                raise ValueError(f'carrier {ip} is not reachable over {self.uplink}')
        if self.dns_mode == 'resolved':
            command('resolvectl', 'status')
            # resolvectl is ineffective with a completely independent resolver.
            target = os.path.realpath('/etc/resolv.conf')
            if target not in ('/run/systemd/resolve/stub-resolv.conf',
                              '/run/systemd/resolve/resolv.conf'):
                raise ValueError('/etc/resolv.conf must use systemd-resolved; use --dns-mode none only with separately managed DNS')

    def guard(self):
        with tempfile.TemporaryDirectory(prefix='foxtunnel-guard-') as directory:
            path = Path(directory) / 'guard.nft'
            path.write_text(self.firewall)
            path.chmod(0o600)
            command('nft', '-c', '-f', str(path))
            command('nft', '-f', str(path))
        print(f'Guard active; persists on exit. Remove explicitly: nft delete table inet {TABLE}', flush=True)

    def change(self, args, undo):
        command(*args)
        self.undo.append(undo)

    def configure(self):
        command('ip', 'link', 'set', 'dev', self.tun, 'up')
        # Addressless point-to-point defaults suffice for the userspace stack.
        # Explicit addresses also give applications a predictable source IP.
        for family, address in (('-4', '172.28.247.1/30'), ('-6', 'fdfe:dcba:9876::1/126')):
            args = ['ip', family, 'addr', 'add', address, 'dev', self.tun]
            if family == '-6':
                args.append('nodad')
            self.change(args, ['ip', family, 'addr', 'del', address, 'dev', self.tun])
            self.change(['ip', family, 'route', 'add', 'table', ROUTE_TABLE, 'default', 'dev', self.tun],
                        ['ip', family, 'route', 'del', 'table', ROUTE_TABLE, 'default', 'dev', self.tun])
            for offset, ip in enumerate(self.endpoints):
                if (ip.version == 4) != (family == '-4'):
                    continue
                pref = str(PRIORITY + offset)
                self.change(['ip', family, 'rule', 'add', 'priority', pref, 'to', str(ip), 'lookup', 'main'],
                            ['ip', family, 'rule', 'del', 'priority', pref, 'to', str(ip), 'lookup', 'main'])
            self.change(['ip', family, 'rule', 'add', 'priority', str(PRIORITY + 16), 'lookup', ROUTE_TABLE],
                        ['ip', family, 'rule', 'del', 'priority', str(PRIORITY + 16), 'lookup', ROUTE_TABLE])
        if self.dns_mode == 'resolved':
            self.undo.append(['resolvectl', 'revert', self.tun])
            command('resolvectl', 'dns', self.tun, self.dns)
            command('resolvectl', 'domain', self.tun, '~.')
            command('resolvectl', 'default-route', self.tun, 'yes')
            command('resolvectl', 'flush-caches')
        print('VPN routes active for IPv4 and IPv6; DNS mode: ' + self.dns_mode, flush=True)

    def close(self):
        failures = []
        for args in reversed(self.undo):
            try:
                result = command(*args, check=False)
                # TUN disappearance already removes its routes, addresses and DNS.
                if result.returncode and 'rule' in args:
                    failures.append(' '.join(args))
            except (OSError, subprocess.SubprocessError) as exc:
                failures.append(str(exc))
        self.undo.clear()
        if failures:
            print('Network cleanup incomplete: ' + '; '.join(failures), file=sys.stderr)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', action='append', required=True)
    parser.add_argument('--uplink', required=True)
    parser.add_argument('--tun', default='ftun0', type=interface)
    parser.add_argument('--dns', default='1.1.1.1', type=dns_ip)
    parser.add_argument('--carrier', choices=('tcp', 'udp'), default='tcp')
    parser.add_argument('--dns-mode', choices=('resolved', 'none'), default='resolved',
                        help='none requires DNS configured separately, e.g. isolated netns')
    parser.add_argument('client', nargs=argparse.REMAINDER,
                        help='-- /absolute/path/foxtunnel client ... --tun ftun0')
    args = parser.parse_args(argv)
    client_args = args.client[1:] if args.client[:1] == ['--'] else args.client
    if not client_args:
        parser.error('provide the FoxTunnel client command after --')
    if os.geteuid() != 0:
        parser.error('requires root')
    child = None
    network = None
    stopping = False
    def stop_requested(_sig, _frame):
        nonlocal stopping
        stopping = True
    try:
        network = Network(args.endpoint, args.uplink, args.tun, args.dns, args.carrier, args.dns_mode)
        network.preflight()
        for sig in (signal.SIGTERM, signal.SIGINT):
            signal.signal(sig, stop_requested)
        network.guard()
        child = subprocess.Popen(client_args)
        deadline = time.monotonic() + 20
        while not stopping and child.poll() is None:
            if command('ip', 'link', 'show', 'dev', args.tun, check=False).returncode == 0:
                network.configure()
                break
            if time.monotonic() >= deadline:
                raise ValueError('client did not create the TUN within 20 seconds')
            time.sleep(0.1)
        while not stopping and child.poll() is None:
            time.sleep(0.2)
        return child.returncode if child.returncode is not None else 0
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print(f'Native VPN failed: {exc}', file=sys.stderr)
        return 1
    finally:
        # Remove only our rules; leave guard installed on success AND failure.
        if network:
            network.close()
        if child and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(timeout=5)


if __name__ == '__main__':
    sys.exit(main())

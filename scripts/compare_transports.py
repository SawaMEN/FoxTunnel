#!/usr/bin/env python3
"""Repeatable, verified SOCKS5-over-TCP echo comparison (stdlib only).

This measures the *configured* proxy chains, not just the protocol engines.
Both proxies must be started separately; nothing here provisions remote servers.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import ipaddress
import json
import os
import platform
import socket
import statistics
import struct
import sys
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from urllib.parse import urlsplit

CHUNK = 32 * 1024


@dataclass(frozen=True)
class Address:
    host: str
    port: int


def address(value: str) -> Address:
    """Parse host:port or [IPv6]:port without DNS resolution."""
    if not value or '://' in value or '/' in value or '@' in value:
        raise ValueError('expected HOST:PORT or [IPv6]:PORT')
    try:
        url = urlsplit('//'+value)
        host, port = url.hostname, url.port
        if not host or port is None or not (1 <= port <= 65535):
            raise ValueError('missing host or port')
        # urlsplit allows query/fragment; exclude them to avoid surprises.
        if url.query or url.fragment or url.username or url.password:
            raise ValueError('invalid host')
        if ':' in host:
            ipaddress.IPv6Address(host)
        return Address(host, port)
    except (ValueError, TypeError) as exc:
        raise ValueError(f'invalid address {value!r}: {exc}') from exc


def endpoint(value: str) -> tuple[str, Address]:
    if '=' not in value:
        raise ValueError('--proxy must be NAME=HOST:PORT')
    label, addr = value.split('=', 1)
    if not label or not all(c.isalnum() or c in '-_' for c in label) or len(label) > 32:
        raise ValueError('proxy NAME must be 1-32 letters, numbers, - or _')
    return label, address(addr)


def exact(sock: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise ConnectionError(f'connection closed after {len(data)}/{count} bytes')
        data.extend(part)
    return bytes(data)


def socks5_connect(sock: socket.socket, target: Address) -> None:
    """No-auth SOCKS5 CONNECT, with domain names resolved by the proxy."""
    sock.sendall(b'\x05\x01\x00')
    if exact(sock, 2) != b'\x05\x00':
        raise ConnectionError('SOCKS5 no-auth handshake refused')
    try:
        ip = ipaddress.ip_address(target.host)
    except ValueError:
        host = target.host.encode('idna')
        if not (1 <= len(host) <= 255):
            raise ValueError('SOCKS5 target name exceeds 255 bytes')
        addr_bytes = bytes([3, len(host)]) + host
    else:
        addr_bytes = bytes([1 if ip.version == 4 else 4]) + ip.packed
    sock.sendall(b'\x05\x01\x00' + addr_bytes + struct.pack('!H', target.port))
    head = exact(sock, 4)
    if head[0] != 5 or head[2] != 0:
        raise ConnectionError('malformed SOCKS5 reply')
    if head[1] != 0:
        raise ConnectionError(f'SOCKS5 CONNECT failed with code {head[1]}')
    if head[3] == 1:
        exact(sock, 4 + 2)
    elif head[3] == 4:
        exact(sock, 16 + 2)
    elif head[3] == 3:
        exact(sock, exact(sock, 1)[0] + 2)
    else:
        raise ConnectionError('invalid SOCKS5 reply address type')


def _send(sock: socket.socket, count: int, pattern: bytes, errors: list[str]) -> None:
    try:
        while count:
            size = min(count, len(pattern))
            sock.sendall(pattern[:size])
            count -= size
    except (OSError, ValueError) as exc:
        errors.append(f'{type(exc).__name__}: {exc}')


def trial(proxy: Address, target: Address, total_bytes: int, timeout: float, pattern: bytes) -> dict:
    """Connect and validate a full-duplex, echo-verified TCP transfer."""
    started = time.perf_counter()
    result = {'ok': False, 'connect_ms': None, 'transfer_ms': None,
              'payload_mbps': None, 'error': None}
    try:
        with socket.create_connection((proxy.host, proxy.port), timeout=timeout) as conn:
            conn.settimeout(timeout)
            socks5_connect(conn, target)
            result['connect_ms'] = round((time.perf_counter() - started) * 1000, 3)
            errors: list[str] = []
            sender = threading.Thread(target=_send, args=(conn, total_bytes, pattern, errors), daemon=True)
            transfer_start = time.perf_counter()
            sender.start()
            remaining, offset = total_bytes, 0
            pattern_twice = pattern + pattern
            while remaining:
                data = conn.recv(min(remaining, len(pattern)))
                if not data:
                    raise ConnectionError(f'echo returned only {offset}/{total_bytes} bytes')
                expected = pattern_twice[offset % len(pattern):offset % len(pattern) + len(data)]
                if data != expected:
                    raise ValueError(f'echo mismatch at byte offset {offset}')
                offset += len(data)
                remaining -= len(data)
            sender.join(timeout=timeout)
            if sender.is_alive():
                raise TimeoutError('sender did not finish')
            if errors:
                raise ConnectionError(errors[0])
            elapsed = time.perf_counter() - transfer_start
            result.update(ok=True, transfer_ms=round(elapsed * 1000, 3),
                          payload_mbps=round(total_bytes * 8 / elapsed / 1e6, 3))
    except (OSError, ValueError, TimeoutError, ConnectionError) as exc:
        result['error'] = f'{type(exc).__name__}: {exc}'
    return result


def percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    sorted_values = sorted(values)
    pos = (len(sorted_values) - 1) * quantile
    lo, hi = int(pos), min(int(pos) + 1, len(values) - 1)
    return round(sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo), 3)


def summarize(rows: list[dict]) -> dict:
    ok = [row for row in rows if row['ok']]
    connect = [r['connect_ms'] for r in ok]
    speed = [r['payload_mbps'] for r in ok]
    return {'attempted': len(rows), 'successful': len(ok), 'failed': len(rows) - len(ok),
            'success_percent': round(100 * len(ok) / len(rows), 2) if rows else None,
            'connect_p50_ms': percentile(connect, .5), 'connect_p95_ms': percentile(connect, .95),
            'payload_median_mbps': round(statistics.median(speed), 3) if speed else None,
            'payload_p95_mbps': percentile(speed, .95)}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--proxy', action='append', required=True, metavar='NAME=HOST:PORT',
                        help='repeat for FoxTunnel and VLESS/Xray SOCKS5 inbounds')
    parser.add_argument('--target', required=True, metavar='HOST:PORT',
                        help='a controlled TCP echo server reachable from both exits; target DNS is remote')
    parser.add_argument('--rounds', type=int, default=10, help='measured rounds per proxy (1-1000)')
    parser.add_argument('--parallel', type=int, default=1, help='simultaneous flows per proxy (1-32)')
    parser.add_argument('--warmup', type=int, default=1, help='unmeasured warm-up rounds per proxy (0-20)')
    parser.add_argument('--bytes', type=int, default=1024 * 1024, help='echo bytes per flow (1-1GiB)')
    parser.add_argument('--timeout', type=float, default=15, help='per socket operation timeout in seconds (1-120)')
    parser.add_argument('--out', required=True, type=Path, help='JSON result path (will not overwrite)')
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        proxies = [endpoint(v) for v in args.proxy]
        if len(proxies) < 2 or len({n for n, _ in proxies}) != len(proxies):
            raise ValueError('specify at least two proxies with unique names')
        target = address(args.target)
        if not (1 <= args.rounds <= 1000 and 1 <= args.parallel <= 32 and
                0 <= args.warmup <= 20 and 1 <= args.bytes <= 1024 ** 3 and
                1 <= args.timeout <= 120):
            raise ValueError('rounds/parallel/warmup/bytes/timeout outside documented bounds')
        if args.out.exists():
            raise ValueError(f'refusing to overwrite {args.out}')
        if not args.out.parent.is_dir():
            raise ValueError('output parent directory does not exist')
    except ValueError as exc:
        parser.error(str(exc))
    # Same payload for every endpoint, but unpredictable on each invocation.
    pattern = os.urandom(CHUNK)
    warmup_errors: dict[str, int] = {n: 0 for n, _ in proxies}
    samples: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.parallel) as executor:
        for stage, count in [('warmup', args.warmup), ('measurement', args.rounds)]:
            for round_number in range(count):
                # Rotate the order, so one proxy is not always measured first.
                rotated = proxies[round_number % len(proxies):] + proxies[:round_number % len(proxies)]
                for name, proxy in rotated:
                    future_to_index = {executor.submit(trial, proxy, target, args.bytes,
                                                       args.timeout, pattern): i
                                       for i in range(args.parallel)}
                    for future in concurrent.futures.as_completed(future_to_index):
                        row = future.result()
                        if stage == 'warmup':
                            warmup_errors[name] += not row['ok']
                        else:
                            samples.append({'proxy': name, 'round': round_number + 1,
                                            'flow': future_to_index[future] + 1, **row})
    report = {'schema': 1, 'created_at_utc': dt.datetime.now(dt.timezone.utc).isoformat(),
              'host': {'platform': platform.platform(), 'python': platform.python_version()},
              'configuration': {'proxies': [{'name': name, 'socks': asdict(proxy)} for name, proxy in proxies],
                                'target': asdict(target), 'rounds': args.rounds, 'parallel': args.parallel,
                                'warmup': args.warmup, 'bytes_per_flow': args.bytes,
                                'operation_timeout_seconds': args.timeout},
              'warmup_failures': warmup_errors,
              'summary': {name: summarize([r for r in samples if r['proxy'] == name])
                          for name, _ in proxies}, 'samples': samples,
              'limitations': ('Same SOCKS echo workload, not a protocol-only microbenchmark. '
                              'Transfer timing excludes SOCKS CONNECT but includes local proxy overhead. '
                              'Does not prove DPI resistance, browser fingerprint equivalence or ISP availability.')}
    # Exclusive creation avoids overwriting existing records.
    try:
        with args.out.open('x', encoding='utf-8') as stream:
            json.dump(report, stream, ensure_ascii=False, indent=2)
            stream.write('\n')
    except OSError as exc:
        parser.exit(2, f'cannot write report: {exc}\n')
    for name, stats in report['summary'].items():
        print(f"{name}: {stats['successful']}/{stats['attempted']} passed; "
              f"p50 connect {stats['connect_p50_ms']} ms; "
              f"median echo {stats['payload_median_mbps']} Mbit/s")
    print(f'report: {args.out}')
    return 2 if any(s['successful'] == 0 for s in report['summary'].values()) else 0


if __name__ == '__main__':
    sys.exit(main())

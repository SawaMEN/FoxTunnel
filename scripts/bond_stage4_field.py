#!/usr/bin/env python3
"""Stage-4 field/lab probes for FoxTunnel SOCKS5 TCP and UDP, stdlib only.

Tests existing, independently started FoxTunnel clients. Does NOT provision
VDS, inspect TLS payloads, discover providers, run privileged netem, or
prove that --environment wan actually traversed independent networks.
No URLs, targets, credentials, raw exceptions or IPs are written to reports.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import statistics
import struct
import time

import compare_transports as tcp


def udp_packet(target: tcp.Address, payload: bytes) -> bytes:
    if not payload or len(payload) > 1200:
        raise ValueError("UDP payload must have 1..1200 bytes")
    try:
        addr = ipaddress.ip_address(target.host)
        encoded = bytes((1 if addr.version == 4 else 4,)) + addr.packed
    except ValueError:
        hostname = target.host.encode("idna")
        if not 1 <= len(hostname) <= 255:
            raise ValueError("invalid UDP hostname")
        encoded = bytes((3, len(hostname))) + hostname
    packet = b"\x00\x00\x00" + encoded + struct.pack("!H", target.port) + payload
    if len(packet) > 1232:
        raise ValueError("SOCKS UDP frame exceeds 1232-byte limit")
    return packet


def udp_payload(frame: bytes) -> bytes:
    if len(frame) < 10 or frame[:3] != b"\x00\x00\x00":
        raise ValueError("invalid SOCKS UDP response")
    kind = frame[3]
    offset = 4
    if kind == 1:
        offset += 4
    elif kind == 4:
        offset += 16
    elif kind == 3:
        if len(frame) < 5:
            raise ValueError("truncated SOCKS UDP hostname")
        offset += 1 + frame[4]
    else:
        raise ValueError("invalid SOCKS UDP address type")
    if len(frame) <= offset + 2:
        raise ValueError("truncated SOCKS UDP response")
    if int.from_bytes(frame[offset:offset + 2], "big") == 0:
        raise ValueError("zero UDP port")
    return frame[offset + 2:]


def udp_associate(proxy: tcp.Address, timeout: float):
    control = socket.create_connection((proxy.host, proxy.port), timeout=timeout)
    try:
        control.settimeout(timeout)
        control.sendall(b"\x05\x01\x00")
        if tcp.exact(control, 2) != b"\x05\x00":
            raise ConnectionError("SOCKS greeting refused")
        control.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
        head = tcp.exact(control, 4)
        if head[:3] != b"\x05\x00\x00":
            raise ConnectionError("SOCKS UDP ASSOCIATE refused")
        if head[3] == 1:
            bind = socket.inet_ntop(socket.AF_INET, tcp.exact(control, 4))
        elif head[3] == 4:
            bind = socket.inet_ntop(socket.AF_INET6, tcp.exact(control, 16))
        elif head[3] == 3:
            length = tcp.exact(control, 1)[0]
            bind = tcp.exact(control, length).decode("idna")
        else:
            raise ValueError("invalid SOCKS UDP bind address")
        port = int.from_bytes(tcp.exact(control, 2), "big")
        if not 1 <= port <= 65535:
            raise ValueError("invalid SOCKS UDP bind port")
        # Unspecified bind IP is permitted by RFC 1928; connect to the
        # local SOCKS listener instead, preserving requested IP family.
        try:
            if ipaddress.ip_address(bind).is_unspecified:
                bind = proxy.host
        except ValueError:
            pass
        return control, (bind, port)
    except BaseException:
        control.close()
        raise


def udp_flow(proxy: tcp.Address, target: tcp.Address, rounds: int, timeout: float,
             warmup: int = 0) -> list[dict]:
    results = []
    control = None
    datagram = None
    try:
        control, bind = udp_associate(proxy, timeout)
        datagram = socket.socket(socket.AF_INET6 if ":" in bind[0] else socket.AF_INET, socket.SOCK_DGRAM)
        datagram.settimeout(timeout)
        datagram.connect(bind)
        nonce = secrets.token_bytes(8)
        for idx in range(rounds + warmup):
            payload = nonce + struct.pack("!I", idx)
            frame = udp_packet(target, payload)
            started = time.perf_counter()
            ok, elapsed_ms, category = False, None, None
            try:
                datagram.send(frame)
                received = udp_payload(datagram.recv(1233))
                elapsed_ms = round((time.perf_counter() - started) * 1000, 3)
                if received != payload:
                    raise ValueError("UDP echo integrity mismatch / stale reply")
                ok = True
            except (OSError, ValueError, TimeoutError, ConnectionError) as exc:
                category = type(exc).__name__
            if idx >= warmup:
                results.append({"ok": ok, "rtt_ms": elapsed_ms if ok else None,
                                "error_category": category})
    except (OSError, ValueError, TimeoutError, ConnectionError) as exc:
        category = type(exc).__name__
        results = [{"ok": False, "rtt_ms": None, "error_category": category}
                   for _ in range(rounds)]
    finally:
        if datagram is not None:
            datagram.close()
        if control is not None:
            control.close()
    return results


def summarize(rows: list[dict], mode: str) -> dict:
    success = [r for r in rows if r["ok"]]
    result = {"attempted": len(rows), "successful": len(success),
              "failed": len(rows) - len(success),
              "success_pct": round(100 * len(success) / len(rows), 3) if rows else 0}
    if mode == "udp":
        rtt = [r["rtt_ms"] for r in success]
        result.update(rtt_p50_ms=tcp.percentile(rtt, .5),
                      rtt_p95_ms=tcp.percentile(rtt, .95),
                      rtt_p99_ms=tcp.percentile(rtt, .99),
                      loss_pct=round(100 * result["failed"] / len(rows), 3) if rows else None,
                      jitter_mean_abs_delta_ms=round(statistics.mean(
                          abs(b - a) for a, b in zip(rtt, rtt[1:])), 3) if len(rtt) > 1 else None)
    else:
        finish = [r["completion_ms"] for r in success]
        speed = [r["payload_mbps"] for r in success]
        result.update(completion_p50_ms=tcp.percentile(finish, .5),
                      completion_p95_ms=tcp.percentile(finish, .95),
                      completion_p99_ms=tcp.percentile(finish, .99),
                      median_mbps=round(statistics.median(speed), 3) if speed else None)
    return result


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--mode", choices=("tcp", "udp"), required=True)
    p.add_argument("--proxy", action="append", required=True, metavar="LABEL=HOST:PORT")
    p.add_argument("--target", action="append", required=True, metavar="HOST:PORT",
                   help="controlled TCP/UDP echo destination, may be repeated for UDP")
    p.add_argument("--scenario", required=True, help="alphanumeric experiment label")
    p.add_argument("--environment", choices=("lab", "wan"), required=True)
    p.add_argument("--confirm-independent-vds", action="store_true",
                   help="attest external network topology; not independently verified")
    p.add_argument("--rounds", type=int, default=30)
    p.add_argument("--parallel", type=int, default=2)
    p.add_argument("--warmup", type=int, default=2)
    p.add_argument("--bytes", type=int, default=32 * 1024 * 1024,
                   help="TCP only, echoed bytes per connection")
    p.add_argument("--timeout", type=float, default=3)
    p.add_argument("--out", type=Path, required=True)
    return p


def validate(a: argparse.Namespace):
    proxy = [tcp.endpoint(p) for p in a.proxy]
    targets = [tcp.address(v) for v in a.target]
    if not proxy or len({v[0] for v in proxy}) != len(proxy):
        raise ValueError("unique proxy labels are required")
    if a.mode == "tcp" and len(targets) != 1:
        raise ValueError("TCP requires exactly one controlled echo target")
    if not a.scenario or len(a.scenario) > 48 or any(c not in
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for c in a.scenario):
        raise ValueError("scenario must be an alphanumeric label (1..48 chars)")
    if not 1 <= a.rounds <= 200 or not 1 <= a.parallel <= 8 or not 0 <= a.warmup <= 10:
        raise ValueError("rounds/parallel/warmup exceed safety limits")
    if not 0.1 <= a.timeout <= 30 or not 1 <= a.bytes <= 1024**3:
        raise ValueError("timeout/bytes exceed safety limits")
    if a.mode == "udp" and a.bytes != parser().get_default("bytes"):
        raise ValueError("--bytes applies only to TCP")
    if a.environment == "wan" and not a.confirm_independent_vds:
        raise ValueError("WAN needs explicit independent-VDS confirmation")
    if a.out.exists() or not a.out.parent.is_dir():
        raise ValueError("output already exists or parent directory missing")
    return proxy, targets


def run(a: argparse.Namespace) -> dict:
    proxies, targets = validate(a)
    rows = []
    # A fresh random payload per run, identical across TCP variants.
    pattern = os.urandom(tcp.CHUNK)
    if a.mode == "udp":
        # Crucial for real latency tests: reuse ONE established SOCKS UDP
        # association and one assigned HTTPS ingress per destination flow
        # throughout all rounds. Creating a new association per datagram
        # would measure startup churn, not steady-state gaming/voice RTT.
        with concurrent.futures.ThreadPoolExecutor(max_workers=a.parallel * len(proxies)) as pool:
            jobs = {}
            for label, proxy in proxies:
                for flow in range(a.parallel):
                    future = pool.submit(udp_flow, proxy, targets[flow % len(targets)],
                                         a.rounds, a.timeout, a.warmup)
                    jobs[future] = (label, flow)
            for future in concurrent.futures.as_completed(jobs):
                label, flow = jobs[future]
                for idx, sample in enumerate(future.result()):
                    rows.append({"proxy": label, "round": idx + 1,
                                 "flow": flow + 1, **sample})
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=a.parallel) as pool:
            for label, proxy in proxies:
                for _ in range(a.warmup):
                    # Warm-up results are deliberately excluded.
                    tcp.trial(proxy, targets[0], a.bytes, a.timeout, pattern)
            for round_number in range(a.rounds):
                rotated = proxies[round_number % len(proxies):] + proxies[:round_number % len(proxies)]
                for label, proxy in rotated:
                    futures = {pool.submit(tcp.trial, proxy, targets[0], a.bytes,
                                           a.timeout, pattern): flow for flow in range(a.parallel)}
                    for future in concurrent.futures.as_completed(futures):
                        sample = future.result()
                        clean = {"ok": bool(sample["ok"]), "completion_ms": round(
                            sample["connect_ms"] + sample["transfer_ms"], 3)
                            if sample["ok"] else None,
                            "payload_mbps": sample["payload_mbps"] if sample["ok"] else None,
                            "error_category": (sample.get("error") or "").partition(":")[0] or None}
                        rows.append({"proxy": label, "round": round_number + 1,
                                     "flow": futures[future] + 1, **clean})
    rows.sort(key=lambda row: (row["proxy"], row["flow"], row["round"]))
    grouped = {name: summarize([r for r in rows if r["proxy"] == name], a.mode)
               for name, _ in proxies}
    return {"schema": 1, "kind": "foxtunnel-stage4-field", "created_at_utc":
            dt.datetime.now(dt.timezone.utc).isoformat(),
            "environment": a.environment,
            "external_topology": "user-attested-unverified" if a.environment == "wan" else "lab",
            "scenario": a.scenario, "mode": a.mode,
            "configuration": {"rounds": a.rounds, "parallel": a.parallel,
                              "bytes_per_flow": a.bytes if a.mode == "tcp" else None,
                              "timeout_s": a.timeout, "proxy_labels": [name for name, _ in proxies],
                              "distinct_target_count": len(targets)},
            "summary": grouped, "samples": rows}


def main(argv: list[str] | None = None) -> int:
    p = parser()
    a = p.parse_args(argv)
    try:
        report = run(a)
        with a.out.open("x", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
            f.write("\n")
    except (ValueError, OSError) as exc:
        p.error(str(exc))
    for label, s in report["summary"].items():
        print(f"{label}: {s['successful']}/{s['attempted']} successful; "
              f"metrics={s['rtt_p95_ms'] if a.mode == 'udp' else s['completion_p95_ms']} ms p95")
    print("environment: " + report["external_topology"])
    print("report: " + str(a.out))
    return 0 if all(s["successful"] for s in report["summary"].values()) else 2


if __name__ == "__main__":
    raise SystemExit(main())

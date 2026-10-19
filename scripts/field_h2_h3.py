#!/usr/bin/env python3
"""Stage-8 real-path H2/NSS vs H3/Neqo field probe.

Requires an independently deployed, trusted FoxTunnel server listening on
TCP and UDP at the SAME origin, plus a controlled TCP echo target reachable
from its exit. This script provisions NEITHER server and does not claim that
running on loopback proves an external network path.

Credentials are read from FOXTUNNEL_USER / FOXTUNNEL_PASSWORD by the FoxTunnel
subprocesses, never accepted as command-line flags or written to reports.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

import compare_transports as bench

ROOT = Path(__file__).resolve().parents[1]
STATUS_INTERVAL = 1.0


def server_url(value: str) -> str:
    """Allow one TLS-verified origin, never URL-embedded credentials."""
    try:
        u = urlsplit(value)
        if (u.scheme != "https" or not u.hostname or u.username is not None
                or u.password is not None or u.query or u.fragment
                or u.path not in ("", "/") or not (1 <= (u.port or 443) <= 65535)):
            raise ValueError("expected a plain https://HOST[:PORT] origin")
        return value.removesuffix("/")
    except ValueError as exc:
        raise argparse.ArgumentTypeError("invalid server URL: " + str(exc)) from exc


def listen_port(value: str) -> int:
    try:
        port = int(value)
        if not 1024 <= port <= 65535:
            raise ValueError()
        return port
    except ValueError as exc:
        raise argparse.ArgumentTypeError("SOCKS port must be 1024..65535") from exc


def expected_routes(fallback: str, expected: str) -> None:
    if expected == "h2" and fallback != "h2":
        raise ValueError("expecting HTTP/2 fallback requires --h3-fallback h2")


def latest_status(path: Path) -> dict:
    """Only parse JSON lines from the local CLI status logger."""
    snapshot = None
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        marker = "engine_status="
        if marker in line:
            try:
                doc = json.loads(line.split(marker, 1)[1])
                if doc.get("schema") == 1:
                    snapshot = doc
            except (ValueError, AttributeError):
                continue
    if snapshot is None:
        raise ValueError("missing engine_status JSON; check client startup and status interval")
    return snapshot


def wait_local(port: int, process: subprocess.Popen, seconds: float) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError("FoxTunnel client stopped before opening SOCKS (logs kept private)")
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.1)
    raise TimeoutError("local FoxTunnel SOCKS listener not ready")


def route_evidence(status: dict, route: str, minimum: int) -> dict:
    # LastRoute is informational only because concurrent requests can switch
    # independently. Selection counters and successful echo flows together
    # provide the evidence that the requested carrier was exercised.
    h2 = int(status.get("h2_selected", 0))
    h3 = int(status.get("h3_selected", 0))
    count = h2 if route == "h2" else h3
    return {
        "expected_route": route,
        "h2_selected": h2,
        "h3_selected": h3,
        "h3_probes": int(status.get("h3_probes", 0)),
        "h3_unreachable": int(status.get("h3_unreachable", 0)),
        "observed": count >= minimum,
    }


def sanitized_samples(rows: list[dict]) -> list[dict]:
    """Never export raw exception messages: they may contain endpoint IPs."""
    allowed = {"TimeoutError", "ConnectionError", "OSError", "ValueError",
               "BrokenPipeError", "ConnectionResetError"}
    out = []
    for row in rows:
        reason = (row.get("error") or "").partition(":")[0]
        out.append({
            "proxy": row.get("proxy"),
            "round": row.get("round"),
            "flow": row.get("flow"),
            "ok": bool(row.get("ok")),
            "connect_ms": row.get("connect_ms"),
            "transfer_ms": row.get("transfer_ms"),
            "payload_mbps": row.get("payload_mbps"),
            "error_category": (reason if reason in allowed else "other") if reason else None,
        })
    return out


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", type=Path, required=True, help="built Mozilla Linux amd64 FoxTunnel executable")
    p.add_argument("--server", type=server_url, required=True, help="trusted HTTPS origin, with both TCP/H2 and UDP/H3")
    p.add_argument("--ca-cert", type=Path, help="optional local CA PEM, not stored in report")
    p.add_argument("--target", required=True, help="controlled remote TCP echo HOST:PORT (on server exit)")
    p.add_argument("--h2-port", type=listen_port, default=11080)
    p.add_argument("--h3-port", type=listen_port, default=11081)
    p.add_argument("--h3-fallback", choices=("none", "h2"), default="none")
    p.add_argument("--expect-h3-route", choices=("h3", "h2"), default="h3",
                   help="for deliberate UDP outage, set h2 with --h3-fallback h2")
    p.add_argument("--rounds", type=int, default=20)
    p.add_argument("--warmup", type=int, default=2)
    p.add_argument("--parallel", type=int, default=4)
    p.add_argument("--bytes", type=int, default=4 * 1024 * 1024)
    p.add_argument("--timeout", type=float, default=20)
    p.add_argument("--budget-seconds", type=int, default=900)
    p.add_argument("--min-success-percent", type=float, default=95)
    p.add_argument("--scenario", choices=("healthy", "udp-blocked", "recovered"), default="healthy")
    p.add_argument("--out", type=Path, required=True, help="new private JSON report (exclusive create)")
    return p


def preflight(args: argparse.Namespace) -> None:
    if args.h2_port == args.h3_port:
        raise ValueError("H2 and H3 need separate loopback SOCKS ports")
    expected_routes(args.h3_fallback, args.expect_h3_route)
    if args.scenario == "udp-blocked" and args.expect_h3_route != "h2":
        raise ValueError("udp-blocked requires H2 expected route")
    if args.scenario in ("healthy", "recovered") and args.expect_h3_route != "h3":
        raise ValueError("healthy/recovered require H3 expected route")
    if (not 1 <= args.rounds <= 1000 or not 0 <= args.warmup <= 20
            or not 1 <= args.parallel <= 32 or not 1 <= args.bytes <= 1024**3
            or not 1 <= args.timeout <= 120 or not 30 <= args.budget_seconds <= 3600
            or not 0 <= args.min_success_percent <= 100):
        raise ValueError("measurement parameters outside bounded limits")
    if not args.binary.is_file():
        raise ValueError("Mozilla binary not found")
    if args.ca_cert and not args.ca_cert.is_file():
        raise ValueError("CA certificate file not found")
    if args.out.exists() or not args.out.parent.is_dir():
        raise ValueError("output path already exists or parent directory missing")
    bench.address(args.target)
    if not os.environ.get("FOXTUNNEL_USER") or not os.environ.get("FOXTUNNEL_PASSWORD"):
        raise ValueError("FOXTUNNEL_USER and FOXTUNNEL_PASSWORD must be provided in the environment")


def launch(args: argparse.Namespace, mode: str, port: int, logfile):
    cmd = [str(args.binary.resolve()), "client", "--engine", "mozilla",
           "--server", args.server, "--transport", mode,
           "--tls-backend", "nss",
           "--listen", f"127.0.0.1:{port}",
           "--engine-status-interval", "1s"]
    if args.ca_cert:
        cmd += ["--ca-cert", str(args.ca_cert.resolve())]
    if mode == "h3-post":
        cmd += ["--h3-fallback", args.h3_fallback]
    return subprocess.Popen(cmd, stdin=subprocess.DEVNULL,
                            stdout=logfile, stderr=subprocess.STDOUT,
                            close_fds=True, env=os.environ.copy())


def stop(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def measure(args: argparse.Namespace) -> tuple[dict, bool]:
    preflight(args)
    with tempfile.TemporaryDirectory(prefix="foxtunnel-field8-") as directory:
        private = Path(directory)
        h2_log, h3_log = private / "h2.log", private / "h3.log"
        result_path = private / "raw.json"
        running = []
        try:
            with h2_log.open("w", encoding="utf-8") as h2_out, h3_log.open("w", encoding="utf-8") as h3_out:
                for mode, port, dest in [
                    ("h2-post", args.h2_port, h2_out),
                    ("h3-post", args.h3_port, h3_out),
                ]:
                    process = launch(args, mode, port, dest)
                    running.append(process)
                    wait_local(port, process, 10)
                command = [
                    sys.executable, str(ROOT / "scripts" / "compare_transports.py"),
                    "--proxy", f"NSS-H2=127.0.0.1:{args.h2_port}",
                    "--proxy", f"Neqo-H3=127.0.0.1:{args.h3_port}",
                    "--target", args.target, "--rounds", str(args.rounds),
                    "--parallel", str(args.parallel), "--warmup", str(args.warmup),
                    "--bytes", str(args.bytes), "--timeout", str(args.timeout),
                    "--out", str(result_path),
                ]
                # Report and subprocess logs stay in a private temporary folder.
                subprocess.run(command, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, check=False,
                               timeout=args.budget_seconds)
                if not result_path.exists():
                    raise RuntimeError("benchmark produced no JSON output")
                # CLI status is emitted once per second; wait for a final
                # snapshot after the last stream. This is not transfer time.
                time.sleep(STATUS_INTERVAL + 0.2)
                h2_out.flush()
                h3_out.flush()
                if any(p.poll() is not None for p in running):
                    raise RuntimeError("FoxTunnel client exited unexpectedly")
                h2_status = latest_status(h2_log)
                h3_status = latest_status(h3_log)
            raw = json.loads(result_path.read_text(encoding="utf-8"))
        finally:
            for process in reversed(running):
                stop(process)

    summary = raw["summary"]
    h2_summary, h3_summary = summary["NSS-H2"], summary["Neqo-H3"]
    h2_evidence = route_evidence(h2_status, "h2", 1)
    h3_evidence = route_evidence(h3_status, args.expect_h3_route, 1)
    success = (h2_summary["success_percent"] is not None
               and h3_summary["success_percent"] is not None
               and h2_summary["success_percent"] >= args.min_success_percent
               and h3_summary["success_percent"] >= args.min_success_percent
               and h2_evidence["observed"] and h3_evidence["observed"])
    binary_hash = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    report = {
        "schema": 1,
        "kind": "foxtunnel-stage8-field-h2-h3",
        "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "passed": success,
        "scenario": args.scenario,
        "binary_sha256": binary_hash,
        "environment": {"platform": platform.platform(), "python": platform.python_version()},
        "config": {"transport_a": "nss/h2-post", "transport_b": "neqo/h3-post",
                   "h3_fallback": args.h3_fallback, "expected_h3_client_route": args.expect_h3_route,
                   "rounds": args.rounds, "warmup": args.warmup,
                   "parallel": args.parallel, "bytes_per_flow": args.bytes,
                   "timeout_seconds": args.timeout,
                   "required_success_percent": args.min_success_percent},
        "summary": summary,
        "route_evidence": {"h2_client": h2_evidence, "h3_client": h3_evidence},
        "samples": sanitized_samples(raw["samples"]),
        "limitations": [
            "No server address, target address, credentials, CA, pin, IP, or raw error is included.",
            "Connection and transfer timings cover full SOCKS/proxy chain, not only TLS/QUIC.",
            "Route counters record carrier selection before HTTP; successful echo corroborates delivery.",
            "Recovered starts fresh clients and does NOT prove live-client network change recovery.",
            "The user must verify independent physical hosts and actual network path.",
            "Does not prove Firefox fingerprint parity, DPI bypass, or operator availability.",
        ],
    }
    return report, success


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        report, success = measure(args)
        # Exclusive owner-only output; never overwrite another field run.
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
        for name, entry in report["summary"].items():
            print(f"{name}: {entry['successful']}/{entry['attempted']} verified, "
                  f"p50 CONNECT {entry['connect_p50_ms']} ms, "
                  f"median echo {entry['payload_median_mbps']} Mbit/s")
        print(f"stage 8 {'PASS' if success else 'FAIL'}; private report: {args.out}")
        return 0 if success else 2
    except (ValueError, OSError, RuntimeError, TimeoutError, KeyError,
            subprocess.SubprocessError) as exc:
        # Never print exception text: OS exception strings might contain
        # private file paths, target hosts or remote network addresses.
        print("stage 8: failed safely; inspect private local client logs if needed",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

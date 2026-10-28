#!/usr/bin/env python3
"""Stage-9 bounded real-socket NSS/H2 + Neqo/H3 soak, restart and TLS rejection.

For an isolated Linux loopback lab ONLY. Never runs with public listener,
untrusted targets or credentials on a command line. The evidence is NOT a
long-haul Internet field experiment, Rust heap leak proof or security audit.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time

import compare_transports as bench
import field_h2_h3 as field

MODES = {"NSS-H2": ("h2-post", 11080), "Neqo-H3": ("h3-post", 11081)}
SERVER_PORT = 18443
ECHO_PORT = 19000


def positive(value: str) -> int:
    number = int(value)
    if not 1 <= number <= 600:
        raise argparse.ArgumentTypeError("must be 1..600")
    return number


def rss_and_fds(pid: int) -> dict:
    """Native-inclusive Linux process RSS (Go, NSS, Neqo and Rust all counted)."""
    result = {"rss_kib": None, "fd_count": None, "threads": None}
    try:
        for row in Path(f"/proc/{pid}/status").read_text().splitlines():
            if row.startswith("VmRSS:"):
                result["rss_kib"] = int(row.split()[1])
            if row.startswith("Threads:"):
                result["threads"] = int(row.split()[1])
        result["fd_count"] = len(list(Path(f"/proc/{pid}/fd").iterdir()))
    except (OSError, ValueError):
        pass
    return result


class Memory:
    def __init__(self, processes):
        self.processes = processes
        self.first = {}
        self.peak = {}
        self.last = {}

    def sample(self):
        for name, process in self.processes.items():
            data = rss_and_fds(process.pid)
            if data["rss_kib"] is None or data["fd_count"] is None:
                raise RuntimeError("Linux process memory sample unavailable")
            self.first.setdefault(name, data)
            self.last[name] = data
            peak = self.peak.setdefault(name, dict(data))
            for k in ("rss_kib", "fd_count", "threads"):
                peak[k] = max(peak[k] or 0, data[k] or 0)

    def report(self):
        return {name: {
            "initial_rss_kib": self.first[name]["rss_kib"],
            "last_rss_kib": self.last[name]["rss_kib"],
            "peak_rss_kib": self.peak[name]["rss_kib"],
            "peak_fd_count": self.peak[name]["fd_count"],
            "peak_threads": self.peak[name]["threads"],
            "rss_growth_kib": max(0, self.last[name]["rss_kib"] - self.first[name]["rss_kib"]),
        } for name in self.processes}


def wait_tcp(host: str, port: int, seconds: float, process=None) -> None:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process is not None and process.poll() is not None:
            raise RuntimeError("lab server exited")
        try:
            with socket.create_connection((host, port), .2):
                return
        except OSError:
            time.sleep(.1)
    raise TimeoutError("lab TCP port unavailable")


def begin_server(binary: Path, cert: Path, key: Path, output):
    args = [str(binary.resolve()), "server",
            "--listen", f"127.0.0.1:{SERVER_PORT}",
            "--h3-listen", f"127.0.0.1:{SERVER_PORT}",
            "--cert", str(cert.resolve()), "--key", str(key.resolve()),
            "--allow-private"]
    proc = subprocess.Popen(args, stdin=subprocess.DEVNULL,
                            stdout=output, stderr=subprocess.STDOUT,
                            close_fds=True)
    wait_tcp("127.0.0.1", SERVER_PORT, 10, proc)
    return proc


def bench_phase(processes, parallel: int, size: int, timeout: float, duration: int) -> tuple[dict, int]:
    samples = {name: [] for name in MODES}
    memory = Memory(processes)
    deadline = time.monotonic() + duration
    completed = 0
    target = bench.Address("127.0.0.1", ECHO_PORT)
    pattern = os.urandom(32 * 1024)
    with concurrent.futures.ThreadPoolExecutor(max_workers=parallel * len(MODES)) as pool:
        while time.monotonic() < deadline:
            if any(p.poll() is not None for p in processes.values()):
                raise RuntimeError("client exited under load")
            memory.sample()
            futures = {pool.submit(
                bench.trial, bench.Address("127.0.0.1", MODES[name][1]),
                target, size, timeout, pattern
            ): name for name in MODES for _ in range(parallel)}
            for task in concurrent.futures.as_completed(futures):
                row = task.result()
                samples[futures[task]].append(row)
                completed += 1
            if completed >= 24000:
                break
    memory.sample()
    return {
        "summary": {name: bench.summarize(rows) for name, rows in samples.items()},
        "memory": memory.report(),
        "total_attempts": completed,
    }, completed


def one_flow(port: int, timeout: float = 3.0) -> dict:
    return bench.trial(
        bench.Address("127.0.0.1", port),
        bench.Address("127.0.0.1", ECHO_PORT),
        4096, timeout, b"stage9" * 6000,
    )


def wait_recovery(timeout_seconds: int) -> dict:
    deadline = time.monotonic() + timeout_seconds
    counts = dict.fromkeys(MODES, 0)
    attempts = dict.fromkeys(MODES, 0)
    started = time.monotonic()
    while time.monotonic() < deadline:
        for name, (_, port) in MODES.items():
            if counts[name] >= 2:
                continue
            attempts[name] += 1
            result = one_flow(port, min(4.0, max(1.0, deadline - time.monotonic())))
            counts[name] = counts[name] + 1 if result["ok"] else 0
        if all(n >= 2 for n in counts.values()):
            return {"passed": True, "elapsed_seconds": round(time.monotonic() - started, 3),
                    "attempts": attempts}
        time.sleep(.5)
    return {"passed": False, "elapsed_seconds": round(time.monotonic() - started, 3),
            "attempts": attempts}


def denied_identity(binary: Path, cert: Path, private: Path) -> dict:
    """Wrong verified DNS identity must fail for H2 and H3, even with H2 fallback."""
    results = {}
    for name, (mode, _) in MODES.items():
        port = 12080 if mode == "h2-post" else 12081
        log = private / (mode + "-rejection.log")
        config = argparse.Namespace(binary=binary, server=f"https://127.0.0.1:{SERVER_PORT}",
                                    ca_cert=cert, sni="definitely-wrong.invalid",
                                    h3_fallback="h2")
        with log.open("w") as output:
            process = field.launch(config, mode, port, output)
            try:
                field.wait_local(port, process, 10)
                result = one_flow(port, 4)
                time.sleep(1.2)
                output.flush()
                status = field.latest_status(log)
                # SelectH2 for an invalid H3 TLS identity would be a security
                # regression, even if the downstream HTTP request later failed.
                fallback_not_selected = (mode == "h2-post" or
                                         status.get("h2_selected", 0) == 0)
                results[name] = {
                    "rejected": not result["ok"],
                    "h2_downgrade_absent": fallback_not_selected,
                    "h3_probe_rejected": status.get("h3_probe_rejected", 0)
                    if mode == "h3-post" else None,
                }
            finally:
                field.stop(process)
    return results


def run(args) -> tuple[dict, bool]:
    binary, cert, key = (Path(x) for x in (args.binary, args.cert, args.key))
    for item in (binary, cert, key):
        if not item.is_file():
            raise ValueError("missing local lab binary or certificate")
    if not os.environ.get("FOXTUNNEL_USER") or not os.environ.get("FOXTUNNEL_PASSWORD"):
        raise ValueError("local lab credentials missing from environment")
    if args.out.exists() or not args.out.parent.is_dir():
        raise ValueError("private output already exists or parent absent")
    if not sys.platform.startswith("linux") or not Path("/proc/self/status").is_file():
        raise RuntimeError("Linux /proc is required for memory measurement")

    with tempfile.TemporaryDirectory(prefix="vetroffproxy-stage9-") as directory:
        private = Path(directory)
        processes = {}
        control = {}
        try:
            with (private / "echo.log").open("w") as echo_log, (private / "server.log").open("w") as server_log, \
                 (private / "h2.log").open("w") as h2_log, (private / "h3.log").open("w") as h3_log:
                echo = subprocess.Popen([sys.executable,
                     str(Path(__file__).resolve().parent / "echo_server.py"),
                     "--host", "127.0.0.1", "--port", str(ECHO_PORT)],
                     stdout=echo_log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
                control["echo"] = echo
                wait_tcp("127.0.0.1", ECHO_PORT, 10, echo)
                server = begin_server(binary, cert, key, server_log)
                control["server"] = server
                for name, (mode, port) in MODES.items():
                    config = argparse.Namespace(binary=binary, server=f"https://127.0.0.1:{SERVER_PORT}",
                                                ca_cert=cert, sni="localhost",
                                                h3_fallback="none")
                    process = field.launch(config, mode, port,
                                           h2_log if name == "NSS-H2" else h3_log)
                    processes[name] = process
                    field.wait_local(port, process, 10)

                soak, _ = bench_phase(processes, args.parallel, args.bytes, args.timeout, args.seconds)

                # Exercise verified TLS failures with fresh identity and no
                # downgrade; the two positive clients remain alive.
                trust = denied_identity(binary, cert, private)

                # Controlled full server restart. This is not route migration,
                # an ISP failure or a proof of stream resume.
                field.stop(server)
                control.pop("server")
                time.sleep(.3)
                outage = {name: not one_flow(port, 3)["ok"]
                          for name, (_, port) in MODES.items()}
                server = begin_server(binary, cert, key, server_log)
                control["server"] = server
                recovery = wait_recovery(args.recovery_seconds)

                h2_log.flush()
                h3_log.flush()
                time.sleep(1.2)
                h2_log.flush()
                h3_log.flush()
                route = {name: field.route_evidence(
                    field.latest_status(private / ("h2.log" if name == "NSS-H2" else "h3.log")),
                    "h2" if name == "NSS-H2" else "h3", 1)
                    for name in MODES}
                alive = all(p.poll() is None for p in processes.values())
        finally:
            for p in processes.values():
                field.stop(p)
            for p in control.values():
                field.stop(p)
    summaries = soak["summary"]
    memory = soak["memory"]
    load_pass = all(summaries[name]["success_percent"] is not None
                    and summaries[name]["success_percent"] >= args.minimum_success
                    and summaries[name]["attempted"] >= args.parallel * 2
                    for name in MODES)
    resource_pass = all(memory[name]["peak_rss_kib"] <= args.max_rss_mib * 1024
                        and memory[name]["peak_fd_count"] <= args.max_fds
                        and memory[name]["rss_growth_kib"] <= args.max_growth_mib * 1024
                        for name in MODES)
    trust_pass = all(x["rejected"] and x["h2_downgrade_absent"] for x in trust.values())
    passed = (load_pass and resource_pass and trust_pass and all(outage.values())
              and recovery["passed"] and all(r["observed"] for r in route.values()) and alive)
    report = {
        "schema": 1, "kind": "vetroffproxy-stage9-local-soak",
        "created_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "passed": passed, "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "scope": "one Linux host, IPv4 loopback server + echo; NOT independent field",
        "settings": {"duration_seconds": args.seconds, "parallel_per_transport": args.parallel,
                     "bytes_per_flow": args.bytes, "minimum_success_percent": args.minimum_success,
                     "max_rss_mib": args.max_rss_mib, "max_growth_mib": args.max_growth_mib,
                     "max_fds": args.max_fds, "recovery_timeout_seconds": args.recovery_seconds},
        "load": {"passed": load_pass, **soak},
        "resources_passed": resource_pass,
        "server_outage_detected": outage,
        "same_client_recovery": recovery,
        "invalid_tls_identity": trust,
        "route_evidence": route,
        "clients_alive_after_recovery": alive,
        "limitations": [
            "RSS includes Go, NSS, Rust/Neqo and shared libraries but cannot isolate native heaps.",
            "This is a bounded soak and maximum budget check; not proof of absence of leaks.",
            "A server restart does not model radio handover, packet loss or TSPU/DPI.",
            "Already-submitted streams are never replayed: recovered only refers to new requests.",
            "No IP, server origin, SNI, CA path, credentials or raw errors are serialized.",
        ],
    }
    return report, passed


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--binary", required=True, type=Path)
    p.add_argument("--cert", required=True, type=Path)
    p.add_argument("--key", required=True, type=Path)
    p.add_argument("--out", required=True, type=Path)
    p.add_argument("--seconds", type=positive, default=75)
    p.add_argument("--parallel", type=int, choices=range(1, 9), default=3, metavar="{1..8}")
    p.add_argument("--bytes", type=int, default=131072)
    p.add_argument("--timeout", type=float, default=8)
    p.add_argument("--recovery-seconds", type=positive, default=100)
    p.add_argument("--minimum-success", type=float, default=98)
    p.add_argument("--max-rss-mib", type=int, default=512)
    p.add_argument("--max-growth-mib", type=int, default=192)
    p.add_argument("--max-fds", type=int, default=512)
    return p


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if not (4096 <= args.bytes <= 8 * 1024 * 1024 and 1 <= args.timeout <= 30
                and 0 <= args.minimum_success <= 100
                and 64 <= args.max_rss_mib <= 4096
                and 0 <= args.max_growth_mib <= 2048
                and 32 <= args.max_fds <= 4096):
            raise ValueError("out-of-range load or resource budget")
        report, passed = run(args)
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(report, out, indent=2, sort_keys=True)
            out.write("\n")
        for mode in MODES:
            s = report["load"]["summary"][mode]
            m = report["load"]["memory"][mode]
            print(f"{mode}: {s['successful']}/{s['attempted']} verified, "
                  f"peak RSS {m['peak_rss_kib']/1024:.1f} MiB, "
                  f"peak FDs {m['peak_fd_count']}")
        print(f"stage 9 {'PASS' if passed else 'FAIL'} (private report only)")
        return 0 if passed else 2
    except (OSError, ValueError, RuntimeError, TimeoutError, KeyError,
            subprocess.SubprocessError) as exc:
        # Logs remain private; exception bodies can contain endpoint paths.
        print("stage 9 failed safely; inspect local private logs", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

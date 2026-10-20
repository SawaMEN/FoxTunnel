#!/usr/bin/env python3
"""Bounded native CLI H2/H3 loopback soak and same-client restart recovery.

Measures real processes on Linux/macOS/Windows; never binds a public address.
The report contains aggregate counters, hashes and resource budgets only.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import secrets
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

import compare_transports as bench
from linux_tun_companion import write_exclusive


def resources(pid):
    if sys.platform.startswith('linux'):
        rows = Path(f'/proc/{pid}/status').read_text().splitlines()
        rss = next(int(line.split()[1]) for line in rows if line.startswith('VmRSS:'))
        return {'rss_kib': rss, 'fd_count': len(list(Path(f'/proc/{pid}/fd').iterdir()))}
    if sys.platform == 'darwin':
        rss = int(subprocess.check_output(['ps', '-o', 'rss=', '-p', str(pid)], timeout=5))
        return {'rss_kib': rss}
    if sys.platform == 'win32':
        import ctypes as c
        from ctypes import wintypes as w
        class Counters(c.Structure):
            _fields_ = [('cb', w.DWORD), ('faults', w.DWORD)] + [(name, c.c_size_t) for name in (
                'peak', 'working', 'peak_paged', 'paged', 'peak_nonpaged', 'nonpaged', 'pagefile', 'peak_pagefile')]
        kernel, psapi = c.WinDLL('kernel32', use_last_error=True), c.WinDLL('psapi', use_last_error=True)
        kernel.OpenProcess.argtypes, kernel.OpenProcess.restype = [w.DWORD, w.BOOL, w.DWORD], w.HANDLE
        kernel.CloseHandle.argtypes, kernel.CloseHandle.restype = [w.HANDLE], w.BOOL
        kernel.GetProcessHandleCount.argtypes, kernel.GetProcessHandleCount.restype = [w.HANDLE, c.POINTER(w.DWORD)], w.BOOL
        psapi.GetProcessMemoryInfo.argtypes, psapi.GetProcessMemoryInfo.restype = [w.HANDLE, c.POINTER(Counters), w.DWORD], w.BOOL
        handle = kernel.OpenProcess(0x0410, False, pid)
        if not handle:
            raise RuntimeError('cannot sample native process')
        try:
            counters, handles = Counters(), w.DWORD()
            counters.cb = c.sizeof(counters)
            if not psapi.GetProcessMemoryInfo(handle, c.byref(counters), counters.cb) or not kernel.GetProcessHandleCount(handle, c.byref(handles)):
                raise RuntimeError('native resource sample unavailable')
            return {'rss_kib': counters.working // 1024, 'handle_count': handles.value}
        finally:
            kernel.CloseHandle(handle)
    raise ValueError('unsupported resource measurement platform')


class Echo(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        try:
            while data := self.request.recv(32768):
                self.request.sendall(data)
        except OSError:
            pass


class EchoServer(socketserver.ThreadingTCPServer):
    daemon_threads = True


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def wait_local(process, port):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise RuntimeError('laboratory process exited before readiness')
        try:
            with socket.create_connection(('127.0.0.1', port), timeout=.2):
                return
        except OSError:
            time.sleep(.05)
    raise RuntimeError('laboratory process did not become ready')


def stop(process):
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=7)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def run(args):
    binary, cert, key = (p.resolve(strict=True) for p in (args.binary, args.cert, args.key))
    env = {k: v for k, v in os.environ.items() if not k.startswith('FOXTUNNEL_')}
    env.update(FOXTUNNEL_USER='operations-lab', FOXTUNNEL_PASSWORD=secrets.token_hex(32))
    ports = {name: free_port() for name in ('server', 'h2', 'h3')}
    if len(set(ports.values())) != 3:
        raise RuntimeError('ephemeral port collision; retry')
    processes = {}
    with tempfile.TemporaryDirectory(prefix='foxtunnel-operations-') as directory, EchoServer(('127.0.0.1', 0), Echo) as echo:
        threading.Thread(target=echo.serve_forever, daemon=True).start()
        destination = bench.Address('127.0.0.1', echo.server_address[1])
        logs = []
        def launch(name, command):
            log = open(Path(directory) / (name + '.log'), 'wb')
            logs.append(log)
            p = subprocess.Popen([str(binary), *command], env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
            processes[name] = p
            return p
        def server_start():
            p = launch('server', ['server', '--listen', f"127.0.0.1:{ports['server']}", '--h3-listen', f"127.0.0.1:{ports['server']}",
                       '--cert', str(cert), '--key', str(key), '--allow-private'])
            wait_local(p, ports['server'])
        def trial(name):
            return bench.trial(bench.Address('127.0.0.1', ports[name]), destination, args.bytes, 5, b'fox-operations' * 2048)
        first, last, peak = {}, {}, {}
        def sample():
            for name, process in processes.items():
                if process.poll() is not None:
                    raise RuntimeError('laboratory process exited under load')
                data = resources(process.pid)
                first.setdefault(name, data)
                last[name] = data
                prior = peak.setdefault(name, data.copy())
                for metric, value in data.items():
                    prior[metric] = max(prior[metric], value)
        try:
            server_start()
            for name, carrier in (('h2', 'h2-post'), ('h3', 'h3-post')):
                p = launch(name, ['client', '--server', f"https://127.0.0.1:{ports['server']}", '--listen', f'127.0.0.1:{ports[name]}',
                    '--ca-cert', str(cert), '--sni', 'localhost', '--tls-backend', 'go', '--transport', carrier])
                wait_local(p, ports[name])
            counts = {name: {'attempted': 0, 'succeeded': 0} for name in ('h2', 'h3')}
            # Warm both TLS transports before taking baseline measurements.
            for name in counts:
                if not trial(name)['ok']:
                    raise RuntimeError('positive transport control failed')
            sample()
            start = time.monotonic()
            samples = 0
            # Windows loopback TIME_WAIT shares a finite ephemeral-port pool
            # between SOCKS applications and exit dials. Sustain parallel data
            # transfers without turning this soak into port-exhaustion stress.
            batch_pause = max(.25, args.parallel / 12)
            with concurrent.futures.ThreadPoolExecutor(max_workers=2 * args.parallel) as pool:
                while time.monotonic() - start < args.seconds:
                    futures = {pool.submit(trial, name): name for name in counts for _ in range(args.parallel)}
                    for task in concurrent.futures.as_completed(futures):
                        name = futures[task]
                        counts[name]['attempted'] += 1
                        counts[name]['succeeded'] += int(task.result()['ok'])
                    sample()
                    samples += 1
                    # Bound CPU/connection churn while retaining continuous,
                    # parallel payload transfers for the entire requested time.
                    time.sleep(batch_pause)
            elapsed = time.monotonic() - start
            outage = {}
            stop(processes['server'])
            for name in counts:
                outage[name] = not trial(name)['ok']
            server_start()
            recovery_start = time.monotonic()
            recovered = dict.fromkeys(counts, False)
            while not all(recovered.values()) and time.monotonic() - recovery_start < args.recovery_seconds:
                for name in counts:
                    if not recovered[name]:
                        recovered[name] = trial(name)['ok']
                time.sleep(.1)
            memory = {name: {'initial_rss_kib': first[name]['rss_kib'], 'last_rss_kib': last[name]['rss_kib'],
                      'peak': peak[name], 'growth_kib': max(0, last[name]['rss_kib'] - first[name]['rss_kib'])} for name in first}
            resource_pass = all(row['peak']['rss_kib'] <= args.max_rss_mib * 1024 and row['growth_kib'] <= args.max_growth_mib * 1024
                                and row['peak'].get('fd_count', 0) <= 1024 and row['peak'].get('handle_count', 0) <= 1024 for row in memory.values())
            load_pass = all(row['attempted'] >= 2 * args.parallel and row['succeeded'] / row['attempted'] * 100 >= 99 for row in counts.values())
            passed = load_pass and resource_pass and elapsed >= args.seconds and all(outage.values()) and all(recovered.values())
            return {'schema': 1, 'kind': 'native-cli-operations-soak', 'passed': passed, 'platform': sys.platform,
                    'created_at_utc': dt.datetime.now(dt.timezone.utc).isoformat(), 'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                    'duration_requested_seconds': args.seconds, 'elapsed_seconds': round(elapsed, 3), 'resource_samples': samples,
                    'parallel_per_carrier': args.parallel, 'batch_pause_seconds': batch_pause,
                    'max_new_flows_per_second': 2 * args.parallel / batch_pause, 'bytes_per_flow': args.bytes, 'load': counts, 'resources': memory,
                    'resources_passed': resource_pass, 'resources_scope': 'pre-restart load phase', 'outage_detected': outage, 'same_client_recovered': recovered,
                    'recovery_seconds': round(time.monotonic() - recovery_start, 3), 'recovery_budget_seconds': args.recovery_seconds,
                    'limits': ['Loopback Go H2/H3 only; no NSS/Neqo, WAN handover, TUN or production leak claim.',
                               'Working-set/RSS budget is not a proof that every native allocation is leak-free.',
                               'Recovery is for new requests only; submitted streams are never replayed.']}
        finally:
            for process in reversed(list(processes.values())):
                stop(process)
            for log in logs:
                log.close()
            echo.shutdown()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'cert', 'key', 'out'):
        parser.add_argument('--' + name, required=True, type=Path)
    parser.add_argument('--seconds', type=int, default=180)
    parser.add_argument('--recovery-seconds', type=int, default=120)
    parser.add_argument('--parallel', type=int, default=3)
    parser.add_argument('--bytes', type=int, default=131072)
    parser.add_argument('--max-rss-mib', type=int, default=512)
    parser.add_argument('--max-growth-mib', type=int, default=192)
    args = parser.parse_args(argv)
    if not (1 <= args.seconds <= 3600 and 1 <= args.recovery_seconds <= 300 and 1 <= args.parallel <= 8 and 4096 <= args.bytes <= 1048576
            and 64 <= args.max_rss_mib <= 4096 and 0 <= args.max_growth_mib <= 2048):
        parser.error('invalid bounded soak settings')
    if args.out.exists() or args.out.is_symlink() or not args.out.parent.is_dir():
        parser.error('output must be a new report in an existing directory')
    report = run(args)
    write_exclusive(args.out, json.dumps(report, sort_keys=True) + '\n', 0o600)
    print(json.dumps({'passed': report['passed'], 'elapsed_seconds': report['elapsed_seconds'], 'load': report['load'], 'resources_passed': report['resources_passed'], 'resources': report['resources'],
                      'outage_detected': report['outage_detected'], 'same_client_recovered': report['same_client_recovered'],
                      'recovery_seconds': report['recovery_seconds']}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    sys.exit(main())

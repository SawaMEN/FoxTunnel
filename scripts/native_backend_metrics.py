#!/usr/bin/env python3
"""Measure an already-built Linux test binary; no compilation in CPU/RSS data.

Each child includes the loopback client, server, echo target and setup/cleanup.
Go ns/op excludes setup; process CPU/RSS does not. No engine-only or WAN claim.
"""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess
import tempfile
import time

from private_files import write_exclusive

ROOT = Path(__file__).resolve().parents[1]
VARIANTS = {
    'go-h2': 'BenchmarkStage3GoH2',
    'nss-h2': 'BenchmarkStage3NSSH2',
    'go-h3': 'BenchmarkStage3GoH3',
    'neqo-h3': 'BenchmarkStage6NeqoH3',
}
SCENARIOS = {'small': ('64B', 64, 250), 'bulk': ('1MiB', 1 << 20, 16)}


def parse_result(log, variant, scenario):
    name = VARIANTS[variant] + '/' + SCENARIOS[scenario][0]
    pattern = (r'^' + re.escape(name) + r'(?:-\d+)?\s+([1-9]\d*)\s+'
               r'([\d.]+) ns/op\s+([\d.]+) MB/s\s+(\d+) B/op\s+(\d+) allocs/op$')
    matches = re.findall(pattern, log, re.MULTILINE)
    if len(matches) != 1 or not re.search(r'^PASS$', log, re.MULTILINE) or re.search(r'^FAIL', log, re.MULTILINE):
        raise ValueError('missing, duplicate or failed benchmark')
    iterations, nanos, speed, alloc_bytes, allocs = matches[0]
    if int(iterations) != SCENARIOS[scenario][2]:
        raise ValueError('unexpected benchmark iteration count')
    if not all(math.isfinite(float(v)) and float(v) > 0 for v in (nanos, speed)):
        raise ValueError('invalid benchmark timing')
    return dict(iterations=int(iterations), bytes_per_exchange=SCENARIOS[scenario][1],
                ns_per_exchange=float(nanos), reported_mb_per_second=float(speed),
                go_bytes_per_exchange=int(alloc_bytes), go_allocations_per_exchange=int(allocs))


def measure(binary, variant, scenario):
    fn = VARIANTS[variant]
    label, _, iterations = SCENARIOS[scenario]
    args = [str(binary), '-test.run=^$', f'-test.bench=^{fn}$/{label}$',
            f'-test.benchtime={iterations}x', '-test.benchmem', '-test.cpu=2', '-test.timeout=45s']
    with tempfile.TemporaryFile() as output, open(os.devnull, 'rb') as empty:
        actions = [(os.POSIX_SPAWN_DUP2, empty.fileno(), 0),
                   (os.POSIX_SPAWN_DUP2, output.fileno(), 1),
                   (os.POSIX_SPAWN_DUP2, output.fileno(), 2)]
        started = time.monotonic()
        pid = os.posix_spawn(str(binary), args, os.environ.copy(), file_actions=actions)
        _, status, usage = os.wait4(pid, 0)
        elapsed = time.monotonic() - started
        output.seek(0)
        data = output.read((8 << 20) + 1)
    if os.waitstatus_to_exitcode(status) != 0 or len(data) > 8 << 20:
        raise ValueError('benchmark child failed or exceeded log bound')
    result = parse_result(data.decode(), variant, scenario)
    result.update(process_user_seconds=usage.ru_utime, process_system_seconds=usage.ru_stime,
                  process_peak_rss_kib=usage.ru_maxrss, process_wall_seconds=elapsed,
                  log_sha256=hashlib.sha256(data).hexdigest())
    return result


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--binary', required=True, type=Path)
    p.add_argument('--versions', required=True, type=Path)
    p.add_argument('--out', required=True, type=Path)
    args = p.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('metrics require native Linux amd64 wait4 RSS semantics')
    binary = args.binary.resolve(strict=True)
    versions = json.loads(args.versions.read_text())
    lock = json.loads((ROOT / 'scripts/neqo.lock.json').read_text())
    if versions['neqo_version'] != lock['neqo_version'] or versions['nss_version'] != lock['nss_version']:
        raise ValueError('reported native runtime does not match lock')
    if args.out.exists() or args.out.is_symlink():
        raise ValueError('refusing to overwrite measurement')
    samples = []
    # Rotate the variant order between repetitions to reduce order bias. All
    # measurements use one runner and one binary, sequentially, without race.
    variants = list(VARIANTS)
    for repeat in range(3):
        for variant in variants[repeat:] + variants[:repeat]:
            for scenario in SCENARIOS:
                samples.append(dict(variant=variant, scenario=scenario, repeat=repeat,
                                    **measure(binary, variant, scenario)))
    medians = []
    for variant in VARIANTS:
        for scenario in SCENARIOS:
            rows = [s for s in samples if s['variant'] == variant and s['scenario'] == scenario]
            metrics = {key: statistics.median(s[key] for s in rows)
                       for key in rows[0] if key not in ('variant', 'scenario', 'repeat', 'log_sha256')}
            medians.append(dict(variant=variant, scenario=scenario, **metrics))
    report = dict(schema=1, kind='native-backend-loopback-metrics',
                  checkout_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                  worktree_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
                  binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                  versions=versions, lock_sha256=hashlib.sha256((ROOT / 'scripts/neqo.lock.json').read_bytes()).hexdigest(),
                  cpu_model=next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), 'unknown'),
                  kernel=platform.release(), samples=samples, medians=medians,
                  scope='Loopback client+proxy+echo; process CPU/RSS includes setup and native memory; Go B/op excludes native allocations. No Firefox/NaiveProxy, WAN or fingerprint equivalence claim.')
    write_exclusive(args.out, json.dumps(report, indent=2) + '\n', 0o600)
    print(json.dumps(medians, indent=2))


if __name__ == '__main__':
    main()

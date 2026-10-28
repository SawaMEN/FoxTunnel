#!/usr/bin/env python3
"""Same-runner H3 baseline and Go-side profiles of the pinned native binary."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import statistics
import subprocess
import tempfile

import native_backend_metrics as metrics
from private_files import write_exclusive

VARIANTS = ('go-h3', 'neqo-h3')
REPEATS = 7
KEYS = ('ns_per_exchange', 'go_bytes_per_exchange', 'go_allocations_per_exchange',
        'process_user_seconds', 'process_system_seconds', 'process_peak_rss_kib',
        'process_wall_seconds')


def summarize(samples):
    expected = {(v, s, r) for v in VARIANTS for s in metrics.SCENARIOS for r in range(REPEATS)}
    actual = [(s['variant'], s['scenario'], s['repeat']) for s in samples]
    if len(actual) != len(expected) or set(actual) != expected:
        raise ValueError('incomplete or duplicate paired measurements')
    results = []
    for variant in VARIANTS:
        for scenario in metrics.SCENARIOS:
            rows = [s for s in samples if s['variant'] == variant and s['scenario'] == scenario]
            summary = {}
            for key in KEYS:
                values = [r[key] for r in rows]
                if any(type(v) not in (int, float) or not math.isfinite(v) or v < 0 for v in values):
                    raise ValueError('invalid measurement')
                median = statistics.median(values)
                if key == 'ns_per_exchange' and median <= 0:
                    raise ValueError('invalid elapsed time')
                summary[key] = dict(median=median, minimum=min(values), maximum=max(values),
                                    relative_mad=statistics.median(abs(v - median) for v in values) / median if median else 0)
            results.append(dict(variant=variant, scenario=scenario, metrics=summary,
                                stable=summary['ns_per_exchange']['relative_mad'] <= .15))
    return results


def profile(binary, variant, scenario, directory):
    label = metrics.SCENARIOS[scenario][0]
    prefix = directory / (variant + '-' + scenario)
    cpu, heap = str(prefix) + '.cpu', str(prefix) + '.heap'
    command = [str(binary), '-test.run=^$',
               f'-test.bench=^{metrics.VARIANTS[variant]}$/{label}$',
               '-test.benchtime=3s', '-test.cpu=2', '-test.timeout=60s',
               '-test.cpuprofile=' + cpu, '-test.memprofile=' + heap]
    result = subprocess.run(command, capture_output=True, timeout=75, check=True)
    if b'\nPASS\n' not in result.stdout or b'\nFAIL' in result.stdout:
        raise ValueError('profile benchmark did not pass')
    output = {}
    for kind, path, sample in [('cpu', cpu, 'cpu'), ('alloc_space', heap, 'alloc_space'),
                               ('alloc_objects', heap, 'alloc_objects')]:
        text = subprocess.check_output(['go', 'tool', 'pprof', '-top', '-nodecount=20',
                                        '-sample_index=' + sample, str(binary), path],
                                       text=True, timeout=30)
        # Keep only the function table. Raw profiles, host paths and build IDs
        # remain private in the temporary directory and are not CI artifacts.
        lines = text.splitlines()
        index = next(i for i, line in enumerate(lines) if 'flat%' in line and 'cum%' in line)
        output[kind] = '\n'.join(lines[index:])
    return dict(variant=variant, scenario=scenario, top=output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('binary', 'versions', 'out', 'resource-runner'):
        parser.add_argument('--' + name, required=True, type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    resource_runner = args.resource_runner.resolve(strict=True)
    if args.out.exists() or args.out.is_symlink():
        raise ValueError('output must be new')
    versions = json.loads(args.versions.read_text())
    lock = json.loads((metrics.ROOT / 'scripts/neqo.lock.json').read_text())
    for key in ('neqo_version', 'nss_version'):
        if versions[key] != lock[key]:
            raise ValueError('native runtime differs from lock')
    if os.uname().sysname != 'Linux' or os.uname().machine != 'x86_64':
        raise ValueError('requires native Linux amd64 resource semantics')
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    # Compile before invoking this script. Warm up both engines separately.
    for variant in VARIANTS:
        for scenario in metrics.SCENARIOS:
            metrics.measure(binary, variant, scenario, resource_runner)
    samples = []
    for repeat in range(REPEATS):
        for variant in VARIANTS if repeat % 2 == 0 else VARIANTS[::-1]:
            for scenario in metrics.SCENARIOS:
                samples.append(dict(variant=variant, scenario=scenario, repeat=repeat,
                                    **metrics.measure(binary, variant, scenario, resource_runner)))
    summaries = summarize(samples)
    with tempfile.TemporaryDirectory(prefix='vetroff-h3-profile-') as temp:
        profiles = [profile(binary, v, s, Path(temp)) for v in VARIANTS for s in metrics.SCENARIOS]
    if digest != hashlib.sha256(binary.read_bytes()).hexdigest():
        raise ValueError('measured binary changed')
    report = dict(schema=1, kind='update-h3-profile', repeats=REPEATS,
                  source_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=metrics.ROOT, text=True).strip(),
                  binary_sha256=digest, versions=versions,
                  worktree_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=no'], cwd=metrics.ROOT)),
                  resource_method='exec-small-C-launcher-then-wait4',
                  resource_runner_sha256=hashlib.sha256(resource_runner.read_bytes()).hexdigest(),
                  collector_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  lock_sha256=hashlib.sha256((metrics.ROOT / 'scripts/neqo.lock.json').read_bytes()).hexdigest(),
                  cpu_model=next((line.split(':', 1)[1].strip() for line in Path('/proc/cpuinfo').read_text().splitlines() if line.startswith('model name')), 'unknown'),
                  toolchain=subprocess.check_output(['go', 'version', '-m', str(binary)], text=True),
                  samples=samples, summaries=summaries, profiles=profiles,
                  scope='Loopback client+proxy+echo, GOMAXPROCS=2; process CPU/RSS includes setup and native memory. Go allocation profiles exclude Rust/C allocations. CPU profiles attribute native calls to cgo, not Rust internals. Profile runs are separate from timing samples. No WAN or Firefox-equivalence claim.')
    write_exclusive(args.out, json.dumps(report, indent=2, allow_nan=False) + '\n', 0o600)
    print(json.dumps(dict(summaries=summaries, profiles=profiles), indent=2))


if __name__ == '__main__':
    main()

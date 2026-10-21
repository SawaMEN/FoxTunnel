#!/usr/bin/env python3
"""Paired same-host scheduler benchmark gate; no network throughput claim."""
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

from private_files import write_exclusive

CASES = {f'BenchmarkStage10Selector/{n}/{mode}'
         for n in (2, 8, 16) for mode in ('fresh', 'cold', 'cooldown')}
REPEATS = 7
# Reviewable budgets: median time +25%; no extra allocation or byte per decision.
MAX_TIME_RATIO = 1.25
MAX_RELATIVE_MAD = .15


def parse(log):
    if not re.search(r'^PASS$', log, re.M) or re.search(r'^FAIL', log, re.M):
        raise ValueError('benchmark did not pass')
    rows = {}
    benchmark_lines = [line for line in log.splitlines() if line.startswith('Benchmark')]
    pattern = (r'^(BenchmarkStage10Selector/\d+/\w+)(?:-\d+)?\s+([1-9]\d*)\s+'
               r'([\d.]+) ns/op\s+(\d+) B/op\s+(\d+) allocs/op$')
    for name, iterations, ns, size, allocs in re.findall(pattern, log, re.M):
        if name in rows or name not in CASES:
            raise ValueError('duplicate or unexpected benchmark')
        if not math.isfinite(float(ns)) or float(ns) <= 0:
            raise ValueError('invalid timing')
        rows[name] = dict(ns=float(ns), bytes=int(size), allocations=int(allocs), iterations=int(iterations))
    if len(benchmark_lines) != len(CASES) or set(rows) != CASES:
        raise ValueError('incomplete benchmark matrix')
    return rows


def compare(samples):
    if len(samples) != 2 * REPEATS:
        raise ValueError('incomplete paired repetitions')
    for variant in ('base', 'head'):
        rows = [s for s in samples if s['variant'] == variant]
        if sorted(s['repeat'] for s in rows) != list(range(REPEATS)):
            raise ValueError('duplicate or missing repetition')
        for row in rows:
            if set(row['cases']) != CASES:
                raise ValueError('incomplete sample')
            for metrics in row['cases'].values():
                for key in ('ns', 'bytes', 'allocations'):
                    value = metrics[key]
                    if type(value) not in (int, float) or not math.isfinite(value) or value < 0 or (key == 'ns' and value == 0):
                        raise ValueError('invalid sample metric')
    result = []
    for case in sorted(CASES):
        summary = {}
        for variant in ('base', 'head'):
            rows = [s['cases'][case] for s in samples if s['variant'] == variant]
            summary[variant] = {key: statistics.median(r[key] for r in rows)
                                for key in ('ns', 'bytes', 'allocations')}
            median = summary[variant]['ns']
            summary[variant]['relative_mad'] = statistics.median(abs(r['ns'] - median) for r in rows) / median
        stable = all(v['relative_mad'] <= MAX_RELATIVE_MAD for v in summary.values())
        ratio = summary['head']['ns'] / summary['base']['ns']
        passed = stable and ratio <= MAX_TIME_RATIO and all(
            summary['head'][k] <= summary['base'][k] for k in ('bytes', 'allocations'))
        result.append(dict(case=case, **summary, time_ratio=ratio, stable=stable, passed=passed))
    return result


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def measure(binary, env):
    command = [str(binary), '-test.run=^$', '-test.bench=^BenchmarkStage10Selector$',
               '-test.benchtime=250ms', '-test.benchmem', '-test.cpu=1', '-test.timeout=60s']
    result = subprocess.run(command, env=env, capture_output=True, timeout=70)
    if result.returncode or len(result.stdout) + len(result.stderr) > 1 << 20:
        raise ValueError('benchmark subprocess failed or log exceeded bound')
    log = result.stdout.decode()
    return dict(cases=parse(log), log=log, log_sha256=hashlib.sha256(result.stdout).hexdigest())


def main():
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('base', 'head', 'out'):
        p.add_argument('--' + name, type=Path, required=True)
    for name in ('base-commit', 'head-commit'):
        p.add_argument('--' + name, required=True)
    args = p.parse_args()
    if any(not re.fullmatch('[0-9a-f]{40}', v) for v in (args.base_commit, args.head_commit)):
        raise ValueError('expected full source commits')
    if args.out.exists() or args.out.is_symlink():
        raise ValueError('output must be new')
    binaries = {name: getattr(args, name).resolve(strict=True) for name in ('base', 'head')}
    env = dict(os.environ, GOMAXPROCS='1')
    # Reject inherited Go tracing/profiling/GC tuning that would bias the comparison.
    for key in ('GODEBUG', 'GOGC', 'GOMEMLIMIT', 'GOTRACEBACK'):
        env.pop(key, None)
    identities = {name: digest(path) for name, path in binaries.items()}
    toolchains = {name: subprocess.check_output(['go', 'version', '-m', str(path)], text=True, timeout=10)
                  for name, path in binaries.items()}
    for binary in binaries.values():
        measure(binary, env)  # Unrecorded warm-up of both already-built binaries.
    samples = []
    for repeat in range(REPEATS):
        for name in (('base', 'head') if repeat % 2 == 0 else ('head', 'base')):
            samples.append(dict(variant=name, repeat=repeat, **measure(binaries[name], env)))
    if identities != {name: digest(path) for name, path in binaries.items()}:
        raise ValueError('benchmark binary changed during measurement')
    comparison = compare(samples)
    report = dict(schema=1, kind='paired-scheduler-optimization', passed=all(r['passed'] for r in comparison),
                  base_commit=args.base_commit, head_commit=args.head_commit, binary_sha256=identities, binary_toolchains=toolchains,
                  benchmark_sha256=digest(Path(__file__).resolve().parents[1] / 'internal/multihop/benchmark_stage10_test.go'),
                  host=dict(system=platform.system(), machine=platform.machine(), cpu=platform.processor(),
                            logical_cpus=os.cpu_count()),
                  budget=dict(max_time_ratio=MAX_TIME_RATIO, max_relative_mad=MAX_RELATIVE_MAD,
                              extra_bytes=0, extra_allocations=0),
                  repeats=REPEATS, cpu=1, benchtime='250ms', samples=samples, comparison=comparison,
                  scope='Same-host serial scheduler microbenchmarks, not WAN throughput or native transport measurements.')
    write_exclusive(args.out, json.dumps(report, indent=2, sort_keys=True) + '\n', 0o600)
    print(json.dumps(dict(passed=report['passed'], cases=len(comparison), repeats=REPEATS)))
    if not report['passed']:
        raise SystemExit(1)


if __name__ == '__main__':
    main()

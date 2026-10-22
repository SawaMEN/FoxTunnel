#!/usr/bin/env python3
"""Alternate immutable before/after H3 binaries on one Linux amd64 runner."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import statistics
import subprocess

import native_backend_metrics as metrics
import update_h3_profile as profile
from private_files import write_exclusive


def compare(samples):
    summaries = {name: profile.summarize([s for s in samples if s['build'] == name])
                 for name in ('base', 'head')}
    if len(samples) != 4 * len(metrics.SCENARIOS) * profile.REPEATS:
        raise ValueError('invalid before/after sample count')
    comparisons = []
    for variant in profile.VARIANTS:
        for scenario in metrics.SCENARIOS:
            rows = {name: next(r for r in summaries[name] if r['variant'] == variant and r['scenario'] == scenario)
                    for name in summaries}
            ratios = {key: rows['head']['metrics'][key]['median'] / rows['base']['metrics'][key]['median']
                      if rows['base']['metrics'][key]['median'] else None for key in profile.KEYS}
            paired = []
            for repeat in range(profile.REPEATS):
                pair = {s['build']: s for s in samples if s['variant'] == variant and
                        s['scenario'] == scenario and s['repeat'] == repeat}
                paired.append(pair['head']['ns_per_exchange'] / pair['base']['ns_per_exchange'])
            stable = all(r['stable'] for r in rows.values())
            # Claim allocation reduction separately from latency. CPU/RSS
            # include process startup and are reported, never engine-only.
            allocations_reduced = ratios['go_allocations_per_exchange'] is not None and ratios['go_allocations_per_exchange'] < 1
            comparisons.append(dict(variant=variant, scenario=scenario, stable=stable,
                                    ratios=ratios, paired_time_ratio_median=statistics.median(paired),
                                    allocations_reduced=allocations_reduced,
                                    latency_regression=stable and ratios['ns_per_exchange'] > 1.15,
                                    latency_improved=stable and ratios['ns_per_exchange'] < .95))
    return dict(summaries=summaries, comparisons=comparisons)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('base', 'head', 'out', 'resource-runner'):
        parser.add_argument('--' + name, type=Path, required=True)
    for name in ('base-commit', 'head-commit'):
        parser.add_argument('--' + name, required=True)
    args = parser.parse_args()
    if not all(re.fullmatch('[0-9a-f]{40}', c) for c in (args.base_commit, args.head_commit)):
        raise ValueError('full immutable commits required')
    if args.out.exists() or args.out.is_symlink():
        raise ValueError('output must be new')
    resource_runner = args.resource_runner.resolve(strict=True)
    binaries = {name: getattr(args, name).resolve(strict=True) for name in ('base', 'head')}
    hashes = {name: hashlib.sha256(p.read_bytes()).hexdigest() for name, p in binaries.items()}
    for binary in binaries.values():
        for variant in profile.VARIANTS:
            for scenario in metrics.SCENARIOS:
                metrics.measure(binary, variant, scenario, resource_runner)
    samples = []
    for repeat in range(profile.REPEATS):
        for variant in profile.VARIANTS if repeat % 2 == 0 else profile.VARIANTS[::-1]:
            for scenario in metrics.SCENARIOS:
                for name in ('base', 'head') if repeat % 2 == 0 else ('head', 'base'):
                    samples.append(dict(build=name, variant=variant, scenario=scenario, repeat=repeat,
                                        **metrics.measure(binaries[name], variant, scenario, resource_runner)))
    if hashes != {name: hashlib.sha256(p.read_bytes()).hexdigest() for name, p in binaries.items()}:
        raise ValueError('binary changed during comparison')
    result = compare(samples)
    report = dict(schema=1, kind='update-h3-before-after', base_commit=args.base_commit,
                  head_commit=args.head_commit, binary_sha256=hashes, samples=samples, **result,
                  resource_method='exec-small-C-launcher-then-wait4',
                  resource_runner_sha256=hashlib.sha256(resource_runner.read_bytes()).hexdigest(),
                  binary_toolchains={name: subprocess.check_output(['go', 'version', '-m', str(p)], text=True)
                                     for name, p in binaries.items()},
                  scope='Same-runner loopback, GOMAXPROCS=2; Go-H3 is a control. CPU/RSS include whole client+proxy+echo processes and startup; Go allocation counts exclude Rust/C allocations. Unstable timings cannot establish a latency change.')
    write_exclusive(args.out, json.dumps(report, indent=2, allow_nan=False) + '\n', 0o600)
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()

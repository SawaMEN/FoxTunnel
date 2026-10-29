#!/usr/bin/env python3
"""Reuse a trusted native source build only when all pinned build inputs match.

A cache hit bypasses Gecko's expensive C++ compilation, never the per-release
runtime integrity checks, native tests, packaging or signed provenance checks.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import subprocess

from build_necko import ROOT, load_lock

# The source lock covers every C++ patch (including its digest). The builder
# and workflow also affect compiler flags/toolchains, so lock alone is unsafe.
BUILD_INPUTS = (
    'experiments/firefox-necko/gecko.lock.json',
    'scripts/build_necko.py',
    '.github/workflows/necko-experiment.yml',
    'scripts/necko_platform.py',
)

REQUIRED_ARTIFACTS = {
    'necko-linux-amd64-runtime', 'necko-source-provenance',
    'necko-linux-arm64-runtime', 'necko-source-provenance-arm64',
}


def matching_compiled_run(runs, expected, source_file, artifacts_for_run):
    """Return a fully uploaded native build from a successful main release."""
    for run in sorted(runs, key=lambda r: r['id'], reverse=True):
        if (run.get('status') != 'completed' or run.get('conclusion') != 'success'
                or run.get('head_branch') != 'main' or run.get('event') != 'push'):
            continue
        sha = run.get('head_sha')
        if not sha:
            continue
        # Compare bytes, not just the pinned revision: a change in patches,
        # mozconfig or workflow toolchains must force a cold build.
        if any(source_file(sha, path) != content for path, content in expected.items()):
            continue
        artifacts = artifacts_for_run(run['id'])
        names = {
            artifact['name'] for artifact in artifacts
            if not artifact.get('expired') and artifact.get('size_in_bytes', 0) > 0
        }
        if REQUIRED_ARTIFACTS <= names:
            return run['id']
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', default=os.environ.get('GITHUB_REPOSITORY'))
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if not args.repo or len(args.repo.split('/')) != 2:
        parser.error('repo must have owner/name form')

    # In addition to checking the lock contents, verify every local patch file
    # against the hashes in the lock before making the reuse decision.
    load_lock()
    expected = {path: (ROOT / path).read_bytes() for path in BUILD_INPUTS}
    response_cache = {}

    def api(path):
        result = subprocess.check_output(
            ['gh', 'api', 'repos/' + args.repo + '/' + path], text=True, timeout=60)
        return json.loads(result)

    def source_file(sha, path):
        key = (sha, path)
        if key not in response_cache:
            try:
                obj = api('contents/' + path + '?ref=' + sha)
                response_cache[key] = base64.b64decode(obj['content'])
            except (subprocess.CalledProcessError, ValueError, KeyError):
                response_cache[key] = None
        return response_cache[key]

    # Only the previous 30 completed runs are candidates. A miss falls back
    # to compilation rather than waiting or using an untrusted source branch.
    runs = api('actions/workflows/release.yml/runs?per_page=30&branch=main&status=completed')['workflow_runs']
    run_id = matching_compiled_run(
        runs, expected, source_file,
        lambda run: api(f'actions/runs/{run}/artifacts?per_page=100')['artifacts'])
    with args.output.open('a', encoding='utf-8') as out:
        out.write(f'run_id={run_id or 0}\n')
    print('Reusing completed trusted Gecko build from run ' + str(run_id)
          if run_id else 'No matching complete Gecko build; cold source build required')


if __name__ == '__main__':
    main()

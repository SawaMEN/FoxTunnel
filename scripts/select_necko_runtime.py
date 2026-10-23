#!/usr/bin/env python3
"""Select a compiled Actions artifact for this exact native source lock.

Wait for a matching source build rather than running changed native code against
an older binary. Compiled artifacts from a failed test run remain useful: all
runtime hashes/provenance and native gates are checked again by the consumer.
"""
import argparse
import base64
import json
import os
from pathlib import Path
import subprocess
import time


def matching_run(runs, expected, source_for_sha, artifacts_for_run):
    waiting = False
    for run in runs:
        if source_for_sha(run['head_sha']) != expected:
            continue
        artifacts = artifacts_for_run(run['id'])
        names = {a['name'] for a in artifacts if not a.get('expired')}
        if {'necko-linux-amd64-runtime', 'necko-source-provenance'} <= names:
            return run['id'], waiting
        if run['status'] != 'completed':
            waiting = True
    return None, waiting


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repo', default=os.environ.get('GITHUB_REPOSITORY'))
    parser.add_argument('--lock', type=Path, default=Path('experiments/firefox-necko/gecko.lock.json'))
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--wait-seconds', type=int, default=3600)
    args = parser.parse_args()
    if not args.repo or len(args.repo.split('/')) != 2:
        parser.error('repository must be owner/name')
    expected = json.loads(args.lock.read_text())
    cache = {}

    def api(path):
        return json.loads(subprocess.check_output(['gh', 'api', 'repos/' + args.repo + '/' + path],
                                                  text=True, timeout=60))

    def source(sha):
        if sha not in cache:
            try:
                content = api('contents/experiments/firefox-necko/gecko.lock.json?ref=' + sha)
                cache[sha] = json.loads(base64.b64decode(content['content']))
            except (subprocess.CalledProcessError, ValueError, KeyError):
                cache[sha] = None
        return cache[sha]

    deadline = time.monotonic() + args.wait_seconds
    while True:
        runs = api('actions/workflows/necko-experiment.yml/runs?branch=firefox&per_page=20')['workflow_runs']
        run, waiting = matching_run(runs, expected, source,
                                   lambda run_id: api(f'actions/runs/{run_id}/artifacts')['artifacts'])
        if run is not None:
            with args.output.open('a') as output:
                output.write(f'run_id={run}\n')
            print('Selected compiled runtime run', run)
            return
        if not waiting or time.monotonic() >= deadline:
            raise SystemExit('No compiled runtime matches the source lock; inspect the source build.')
        print('Waiting for compilation of the matching native source lock', flush=True)
        time.sleep(30)


if __name__ == '__main__':
    main()

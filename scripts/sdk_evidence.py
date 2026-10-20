#!/usr/bin/env python3
"""Reduce actual go-test JSON events to bounded native SDK integration evidence."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from evidence_bundle import commit, decode, require
from private_files import write_exclusive

CARRIERS = ('h2-connect', 'h2-post', 'h3-post', 'wss', 'xhttp-packet-up', 'xhttp-stream-up')
EXPECTED = {f'TestPublicHTTPClientIntegration/{c}/{route}' for c in CARRIERS
            for route in ('direct-dial', 'standard-socks5h')}
EXPECTED |= {f'TestPublicTrustAndAuthorizationBeforeApplication/{c}/{refusal}'
             for c in ('h2-connect', 'h3-post') for refusal in ('hostname', 'credentials')}
PACKAGE = 'example.com/independent-foxtunnel-consumer'
MAX_BYTES = 8 * 1024 * 1024


def summarize(data, source, platform):
    require(len(data) <= MAX_BYTES and commit(source), 'invalid test evidence input')
    require(platform in ('linux', 'darwin', 'win32'), 'unsupported native platform')
    running, passed, package_passed = set(), set(), False
    for line in data.splitlines():
        event = decode(line)
        require(isinstance(event, dict) and event.get('Package') == PACKAGE, 'unexpected test package')
        action, name = event.get('Action'), event.get('Test')
        require(action != 'fail', 'Go test failure')
        if name in EXPECTED:
            require(action != 'skip', 'required integration skipped')
            if action == 'run':
                require(name not in running, 'duplicate integration run')
                running.add(name)
            elif action == 'pass':
                require(name in running and name not in passed, 'pass without one run')
                passed.add(name)
        elif name is None and action == 'pass':
            package_passed = True
    require(package_passed and running == EXPECTED and passed == EXPECTED, 'incomplete SDK matrix')
    return {'schema': 1, 'kind': 'native-external-sdk-integration', 'checkout_commit': source,
            'native_platform': platform, 'test_event_sha256': hashlib.sha256(data).hexdigest(),
            'passed': True, 'executed_required_cases': sorted(passed), 'required_case_count': len(EXPECTED),
            'scope': 'Loopback Go TLS/quic-go via public SDK and standard net/http only; not third-party adoption.'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        require(args.input.is_file() and not args.input.is_symlink(), 'missing test event file')
        with args.input.open('rb') as stream:
            data = stream.read(MAX_BYTES + 1)
        source = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
        result = summarize(data, source, sys.platform)
        result['worktree_dirty'] = bool(subprocess.check_output(
            ['git', 'status', '--porcelain', '--untracked-files=normal'], text=True).strip())
        require(not args.out.exists() and not args.out.is_symlink() and args.out.parent.is_dir(), 'output must be new')
        write_exclusive(args.out, json.dumps(result, indent=2, sort_keys=True) + '\n', 0o600)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('SDK evidence incomplete or invalid; no passing matrix issued.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())

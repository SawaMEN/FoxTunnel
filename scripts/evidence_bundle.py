#!/usr/bin/env python3
"""Validate reviewed evidence and export an offline audit handoff, not an audit verdict."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys

import fingerprint_audit as fingerprints
from private_files import write_exclusive

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = 'docs/evidence/registry.json'
MAX_BYTES = 4 * 1024 * 1024
SUBJECTS = ('firefox', 'foxtunnel', 'naive')
PROTOCOLS = ('tls_h2', 'quic_h3')
LOCKS = ('go.mod', 'go.sum', 'integration/external/go.mod', 'integration/external/go.sum',
         'rust/neqo-bridge/Cargo.lock', 'experiments/neqo-ffi/Cargo.lock',
         'scripts/neqo.lock.json', 'scripts/mozilla-runtime.lock.json', 'scripts/wire-capture.lock.json', 'scripts/release-compat.lock.json')


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def decode(data):
    def invalid(_):
        raise ValueError('non-finite JSON number')
    return json.loads(data, object_pairs_hook=pairs, parse_constant=invalid)


def snapshot(root, name):
    require(isinstance(name, str) and name and '\\' not in name, 'invalid repository path')
    path = PurePosixPath(name)
    require(not path.is_absolute() and path.as_posix() == name
            and all(part not in ('.', '..') for part in path.parts), 'non-canonical repository path')
    target = root
    for part in path.parts:
        target = target / part
        require(not target.is_symlink(), 'symlink evidence is not allowed')
    require(target.is_file(), 'required repository file missing')
    with target.open('rb') as stream:
        data = stream.read(MAX_BYTES + 1)
    require(len(data) <= MAX_BYTES, 'repository input exceeds size limit')
    return data


def sha(data):
    return hashlib.sha256(data).hexdigest()


def integer(value, lower=0):
    return type(value) is int and value >= lower


def number(value, lower=0):
    return type(value) in (int, float) and lower <= value <= 2 ** 53 and math.isfinite(value)


def commit(value):
    return isinstance(value, str) and re.fullmatch('[0-9a-f]{40}', value) is not None


def operations(raw, source):
    require(type(raw.get('schema')) is int and raw['schema'] == 1
            and raw.get('kind') == 'native-cli-operations-workflow-log-summaries', 'invalid operations schema')
    require(raw['workflow']['head_sha'] == source and commit(source), 'operations source mismatch')
    settings = raw['settings']
    require(settings['duration_requested_seconds'] == 1800
            and settings['recovery_budget_seconds'] == 30 and settings['min_success_percent'] == 99
            and settings['max_rss_mib'] == 512 and settings['max_growth_mib'] == 192
            and settings['max_fd_or_handles'] == 1024, 'unreviewed operations budgets')
    rows = raw['results']
    require(isinstance(rows, list) and len(rows) == 3, 'incomplete native matrix')
    require({r['runner'] for r in rows} == {'ubuntu-24.04', 'macos-15', 'windows-latest'}, 'invalid native runners')
    for row in rows:
        s = row['summary']
        require(row['job_conclusion'] == 'success' and s['passed'] is True
                and s['resources_passed'] is True, 'failed native result')
        require(number(s['elapsed_seconds'], 1800) and number(s['recovery_seconds'])
                and s['recovery_seconds'] <= 30, 'duration or recovery budget not met')
        require(set(s['load']) == {'h2', 'h3'}, 'incomplete transport counts')
        for carrier in ('h2', 'h3'):
            counts = s['load'][carrier]
            require(integer(counts['attempted'], 1) and integer(counts['succeeded'])
                    and counts['succeeded'] <= counts['attempted']
                    and counts['succeeded'] / counts['attempted'] >= .99, 'load threshold not met')
            require(s['outage_detected'][carrier] is True
                    and s['same_client_recovered'][carrier] is True, 'restart not demonstrated')
        require(commit(row['build']['commit'])
                and row['build']['commit'] == raw['workflow']['checkout_commit']
                and row['build']['dirty'] is False, 'unidentified native build')
        target = {'ubuntu-24.04': ('linux', 'amd64'), 'macos-15': ('darwin', 'arm64'),
                  'windows-latest': ('windows', 'amd64')}[row['runner']]
        require((row['build']['goos'], row['build']['goarch']) == target, 'native build target mismatch')
        require(set(s['resources']) == {'server', 'h2', 'h3'}, 'missing resource samples')
        for resource in s['resources'].values():
            peak = resource['peak']
            initial, last, growth = resource['initial_rss_kib'], resource['last_rss_kib'], resource['growth_kib']
            require(integer(peak['rss_kib']) and peak['rss_kib'] <= 512 * 1024
                    and integer(initial) and integer(last) and peak['rss_kib'] >= max(initial, last)
                    and integer(growth) and growth == max(0, last - initial) and growth <= 192 * 1024,
                    'memory budget exceeded')
            counter = {'ubuntu-24.04': 'fd_count', 'windows-latest': 'handle_count'}.get(row['runner'])
            if counter:
                require(integer(peak.get(counter)) and peak[counter] <= 1024, 'descriptor budget exceeded')
    return {'source_commit': source, 'duration_seconds': 1800, 'native_runners': sorted(r['runner'] for r in rows),
            'scope': 'paced-loopback-go-h2-h3', 'thresholds_met': True}


def validate(root, manifest=MANIFEST):
    data = snapshot(root, manifest)
    require(len(data) <= 256 * 1024, 'registry too large')
    registry = decode(data)
    require(isinstance(registry, dict) and set(registry) == {'schema', 'observations', 'comparison'}, 'invalid registry fields')
    require(type(registry['schema']) is int and registry['schema'] == 1, 'unsupported registry schema')
    entries = registry['observations']
    require(isinstance(entries, list) and 1 <= len(entries) <= 32, 'invalid observation count')
    observed, summaries = {}, []
    for entry in entries:
        require(isinstance(entry, dict) and set(entry) == {'id', 'path', 'sha256', 'kind', 'subject', 'scope', 'source_commit'},
                'invalid observation fields')
        name = entry['id']
        require(isinstance(name, str) and re.fullmatch('[a-z0-9][a-z0-9-]{0,63}', name)
                and name not in observed, 'invalid or duplicate observation ID')
        require(entry['subject'] in SUBJECTS and entry['kind'] in ('tls_h2', 'quic_h3', 'native_operations'), 'unknown observation kind')
        require(isinstance(entry['path'], str) and entry['path'].startswith('docs/measurements/'), 'evidence outside measurements')
        require(isinstance(entry['sha256'], str) and re.fullmatch('[0-9a-f]{64}', entry['sha256']), 'invalid evidence hash')
        payload = snapshot(root, entry['path'])
        require(sha(payload) == entry['sha256'], 'evidence hash mismatch')
        raw = decode(payload)
        require(isinstance(raw, dict) and type(raw.get('schema')) is int and raw['schema'] == 1, 'invalid observation schema')
        require(entry['source_commit'] is None or commit(entry['source_commit']), 'invalid source commit')
        if entry['kind'] == 'native_operations':
            require(entry['scope'] == 'native-loopback' and entry['subject'] == 'foxtunnel', 'invalid operations scope')
            summary = operations(raw, entry['source_commit'])
        else:
            require(entry['scope'] in ('historical-loopback', 'controlled-loopback'), 'unsupported capture scope')
            capture_kind = 'h3_quic' if entry['kind'] == 'quic_h3' else entry['kind']
            raw = fingerprints.decode_profile(payload, capture_kind)
            summary = {'scope': entry['scope'], 'source_commit': entry['source_commit']}
        observed[name] = (entry, raw)
        summaries.append({**entry, 'validation': summary})
    selection = registry['comparison']
    expected = {s + '_' + p for s in SUBJECTS for p in PROTOCOLS}
    require(isinstance(selection, dict) and set(selection) == expected, 'incomplete comparison slots')
    captures, coverage = {}, {}
    for key, name in selection.items():
        if name is None:
            captures[key], coverage[key] = None, 'not_measured'
        else:
            require(isinstance(name, str) and name in observed, 'unknown comparison observation')
            entry, raw = observed[name]
            require(key == entry['subject'] + '_' + entry['kind'], 'comparison identity mismatch')
            captures[key], coverage[key] = raw, 'observed'
    comparisons = {subject: fingerprints.compare(captures['firefox_tls_h2'], captures[subject + '_tls_h2'],
                  captures['firefox_quic_h3'], captures[subject + '_quic_h3']) for subject in ('foxtunnel', 'naive')}
    return {'registry_sha256': sha(data), 'observations': summaries, 'coverage': coverage,
            'comparisons_to_firefox': comparisons, 'all_six_captures_present': all(v == 'observed' for v in coverage.values()),
            'integrity_checks_passed': True, 'independent_security_audit': 'not_provided',
            'limitations': ['Hashes establish integrity against this reviewed registry, not independent authenticity or recency.',
                           'Historical observations do not measure the current checkout.',
                           'Missing captures remain unmeasured; matching fields do not prove indistinguishability.',
                           'Loopback results establish neither WAN reliability nor censorship resistance.']}


def bundle(root, manifest=MANIFEST):
    evidence = validate(root, manifest)
    checked_out = subprocess.check_output(['git', '-C', str(root), 'rev-parse', 'HEAD'], text=True).strip()
    require(commit(checked_out), 'invalid checkout identity')
    dirty = bool(subprocess.check_output(['git', '-C', str(root), 'status', '--porcelain', '--untracked-files=normal'], text=True).strip())
    inventory = [{'path': name, 'sha256': sha(snapshot(root, name))} for name in LOCKS]
    return {'schema': 1, 'kind': 'foxtunnel-audit-handoff', 'checkout_commit': checked_out, 'worktree_dirty': dirty,
            'evidence': evidence, 'dependency_inputs': inventory,
            'dependency_scope': 'Reviewed lockfile digests only; not a resolved SBOM or vulnerability-scan result.',
            'review_guide': 'docs/DEVELOPMENT.md'}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', type=Path, required=True, help='new private JSON file; parent must exist')
    args = parser.parse_args(argv)
    try:
        require(not args.out.exists() and not args.out.is_symlink() and args.out.parent.is_dir(), 'output must be new')
        report = bundle(ROOT)
        write_exclusive(args.out, json.dumps(report, indent=2, sort_keys=True) + '\n', 0o600)
        print(json.dumps({'integrity_checks_passed': True, 'all_six_captures_present': report['evidence']['all_six_captures_present'],
                          'independent_security_audit': 'not_provided', 'worktree_dirty': report['worktree_dirty']}))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        print('Evidence validation failed; no audit verdict or complete comparison issued.', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())

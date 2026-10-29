#!/usr/bin/env python3
"""Compare controlled full-Firefox / Necko-helper endpoint observations.

Exact order differences remain visible. Set comparisons are additional checks,
never replacements for wire order. No similarity score or DPI claim is produced.
"""
import argparse
import hashlib
import json
import os

from fingerprint_audit import ja3_expected
from pathlib import Path


def checks(reference, candidate):
    rows = []

    def add(name, left, right):
        rows.append(dict(field=name, status='equal' if left == right else 'different',
                         reference=left, candidate=right))

    for index, (a, b) in enumerate(zip(reference, candidate)):
        prefix = f'connection_{index + 1}.'
        for key in sorted(set(a['hello']) | set(b['hello'])):
            add(prefix + 'hello.' + key, a['hello'].get(key), b['hello'].get(key))
        add(prefix + 'hello.extension_set', sorted(a['hello']['extensions']),
            sorted(b['hello']['extensions']))
        for key in ('alpn', 'resumed', 'initial_datagram_size', 'settings',
                    'quic_effective_parameters', 'requests', 'completed'):
            if key in a or key in b:
                add(prefix + key, a.get(key), b.get(key))
        for key in ('client_fin_streams', 'client_reset_codes'):
            add(prefix + key + '.unique', sorted(set(a.get(key) or [])),
                sorted(set(b.get(key) or [])))
        for key in ('hpack_blocks', 'h3_headers'):
            if key in a or key in b:
                add(prefix + key, a.get(key), b.get(key))
        # DATA chunk sizes and scheduling are observations, not normalized away.
        if 'h2_frames' in a:
            add(prefix + 'h2_frames', a['h2_frames'], b['h2_frames'])
    return rows


def read(path):
    raw = path.read_bytes()
    if len(raw) > 4 << 20:
        raise ValueError('observation exceeds bound')
    data = json.loads(raw)
    if data.get('schema') != 1 or data.get('kind') != 'necko-firefox-connect-comparison':
        raise ValueError('wrong observation schema')
    if data.get('transport') not in ('h2-connect', 'h3-connect'):
        raise ValueError('unsupported transport')
    if len(data['connections']) != 4 or {c['subject'] for c in data['connections']} != {'firefox', 'vetroff'}:
        raise ValueError('unexpected subject or connection count')
    subjects = {}
    for name in ('firefox', 'vetroff'):
        connections = [c for c in data['connections'] if c['subject'] == name]
        if len(connections) != 2:
            raise ValueError('expected two connections per subject')
        for connection in connections:
            hello = connection.get('hello')
            if not isinstance(hello, dict):
                raise ValueError('missing ClientHello')
            expected = ja3_expected(hello)
            if hello.get('ja3') != expected or hello.get('ja3_md5') != hashlib.md5(expected.encode('ascii')).hexdigest():
                raise ValueError('inconsistent ClientHello fingerprint')
            if (connection.get('truncated') or connection.get('error') or
                    not connection.get('hello') or not connection.get('settings') or
                    connection.get('requests') != 2 or connection.get('completed') != 2 or
                    connection.get('alpn') != data['transport'][:2] or
                    len(set(connection.get('client_fin_streams') or [])) != 2):
                raise ValueError('incomplete endpoint observation')
        subjects[name] = connections
    return data, subjects, hashlib.sha256(raw).hexdigest()


def report(paths, minimum=1):
    result = {'schema': 1, 'kind': 'necko-firefox-comparison-report', 'observations': []}
    runtimes, sources = None, None
    for path in sorted(paths):
        data, subjects, digest = read(path)
        if runtimes is None:
            runtimes, sources = data['runtime_sha256'], data['source_sha256']
        if runtimes != data['runtime_sha256'] or sources != data['source_sha256']:
            raise ValueError('mixed runtime or source versions')
        rows = checks(subjects['firefox'], subjects['vetroff'])
        result['observations'].append(dict(file=path.name, sha256=digest,
            transport=data['transport'], checks=rows,
            differences=[row['field'] for row in rows if row['status'] == 'different']))
    if not paths:
        raise ValueError('no observations')
    counts = {mode: sum(x['transport'] == mode for x in result['observations'])
              for mode in ('h2-connect', 'h3-connect')}
    if any(n < minimum for n in counts.values()):
        raise ValueError('not enough repetitions of both protocols')
    variability = {}
    for mode in ('h2-connect', 'h3-connect'):
        variability[mode] = {}
        for subject in ('firefox', 'vetroff'):
            phases = [[], []]
            for path in sorted(paths):
                data, subjects, _ = read(path)
                if data['transport'] == mode:
                    for phase, conn in enumerate(subjects[subject]):
                        phases[phase].append(conn['hello']['extensions'])
            variability[mode][subject] = [dict(
                distinct_orders=len({tuple(v) for v in phase}),
                distinct_sets=len({tuple(sorted(v)) for v in phase}),
            ) for phase in phases]
    result['extension_order_variability'] = variability
    result.update(runtime_sha256=runtimes, source_sha256=sources, repetitions=counts,
        both_protocols_measured=all(counts.values()),
        scope='Raw native CONNECT API in a full Firefox process versus the SOCKS helper; same patched libxul and workload.',
        limitations=[
            'Not ordinary page navigation, stock Firefox, an Internet path or a DPI test.',
            'Randomized extension order and JA3 differences are preserved alongside extension-set comparisons.',
            'H3 effective parameter values include decoder defaults; raw parameter order is not measured.',
            'H3 decoded headers are measured, QPACK instruction bytes are not.',
            'H2 resumed=false is an observation of this fixture, not proof that all TLS resumption is disabled.',
            'TLS 1.3 only, custom root and disabled socket process constrain the result.',
        ])
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observations', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--minimum-repetitions', type=int, default=3)
    args = parser.parse_args()
    if args.minimum_repetitions < 1:
        parser.error('minimum repetitions must be positive')
    result = report(list(args.observations.glob('*.json')), args.minimum_repetitions)
    fd = os.open(args.out, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(result, f, indent=2)
        f.write('\n')
    print('Repetitions:', result['repetitions'])
    for item in result['observations']:
        print(item['file'], 'differences:', ', '.join(item['differences']) or 'none in recorded fields')
    if not result['both_protocols_measured']:
        raise SystemExit('both protocols are required')


if __name__ == '__main__':
    main()

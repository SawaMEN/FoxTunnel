#!/usr/bin/env python3
"""Preserve Firefox-versus-Firefox differences as a control, without erasing them."""
import argparse
import hashlib
import json
from pathlib import Path
from compare_necko_firefox import checks


def analyze(directory):
    records = []
    identity = None
    counts = {'h2-connect': 0, 'h3-connect': 0}
    for path in sorted(directory.glob('*.json')):
        raw = path.read_bytes()
        if len(raw) > 4 << 20:
            raise ValueError('observation exceeds bound')
        d = json.loads(raw)
        if d.get('kind') != 'firefox-self-connect-comparison' or d.get('schema') != 1:
            raise ValueError('not a Firefox self comparison')
        current = (d['runtime_sha256'], d['source_sha256'])
        if identity is not None and current != identity:
            raise ValueError('mixed runtime/source identities')
        identity = current
        groups = {name: [c for c in d['connections'] if c['subject'] == name]
                  for name in ('firefox-a', 'firefox-b')}
        if len(d['connections']) != 4 or any(len(v) != 2 for v in groups.values()):
            raise ValueError('incomplete subjects')
        for c in d['connections']:
            if (c.get('truncated') or c.get('error') or c.get('requests') != 2 or
                    c.get('completed') != 2 or not c.get('hello') or not c.get('settings')):
                raise ValueError('incomplete connection')
        counts[d['transport']] += 1
        records.append(dict(file=path.name, sha256=hashlib.sha256(raw).hexdigest(),
                            transport=d['transport'], checks=checks(*groups.values())))
    if any(v < 3 for v in counts.values()):
        raise ValueError('at least three repetitions per protocol required')
    return dict(schema=1, kind='firefox-self-comparison-report',
                subjects=['firefox-a', 'firefox-b'], repetitions=counts,
                observations=records, runtime_sha256=identity[0], source_sha256=identity[1],
                scope='Full Firefox versus full Firefox; raw differences remain visible. '
                      'A control does not establish equality of distributions or DPI indistinguishability.')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observations', type=Path, required=True)
    parser.add_argument('--out', type=Path, required=True)
    args = parser.parse_args()
    args.out.write_text(json.dumps(analyze(args.observations), indent=2) + '\n')

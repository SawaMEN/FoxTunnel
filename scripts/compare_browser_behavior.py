"""Controlled GET behavior comparison. No fingerprint similarity score."""
import json
import subprocess

import fingerprint_audit

EXPECTED = {'cold': 1, 'sequential': 3, 'parallel': 8, 'cancel': 4, 'reconnect': 2}
VECTORS = ('extensions', 'cipher_suites', 'supported_groups', 'supported_versions',
           'signature_algorithms', 'key_share_groups', 'alpn')


def validate(report, protocol):
    if (report.get('schema') != 1 or report.get('kind') != 'controlled-browser-behavior'
            or report.get('protocol') != protocol or report.get('complete') is not True
            or report.get('client_failed') is not False or report.get('rotations') != 2):
        raise ValueError('incomplete behavior evidence')
    if set(report['phases']) != set(EXPECTED):
        raise ValueError('unexpected workload phases')
    for name, count in EXPECTED.items():
        row = report['phases'][name]
        if any(type(row.get(k)) is not int or row[k] < 0 for k in
               ('started', 'finished', 'canceled', 'active', 'max_active')):
            raise ValueError('invalid workload counter')
        if row['started'] != count or row['active'] or row['finished'] + row['canceled'] != count:
            raise ValueError('missing or active workload request')
        if row['canceled'] != (count if name == 'cancel' else 0):
            raise ValueError('payload or cancellation did not complete')
    connections = report['connections']
    if not 3 <= len(connections) <= 32 or [c['id'] for c in connections] != list(range(1, len(connections)+1)):
        raise ValueError('invalid connection evidence')
    for c in connections:
        if set(c['requests']) - set(EXPECTED) or any(type(n) is not int or n < 1 for n in c['requests'].values()):
            raise ValueError('invalid per-connection workload count')
        if c['requests'] and (type(c.get('session_resumed')) is not bool or c.get('alpn') != protocol):
            raise ValueError('missing server-observed TLS state')
        if protocol == 'h2' and c['requests']:
            wire = c.get('h2_wire')
            if not wire or not wire.get('hello', {}).get('extensions') or not wire.get('initial_h2_settings'):
                raise ValueError('missing TLS/H2 ordered metadata')
    for name, count in EXPECTED.items():
        if sum(c['requests'].get(name, 0) for c in connections) != count:
            raise ValueError('connection counts do not match completed workload')
    reconnect = [c for c in connections if c['requests'].get('reconnect')]
    if len(reconnect) != 2 or any(c['requests'].get('cold') for c in reconnect):
        raise ValueError('forced rotations did not create two new used connections')
    if report['phases']['parallel']['max_active'] < 2:
        raise ValueError('parallel workload was not concurrent')
    return report


def summary(report):
    connections = [c for c in report['connections'] if c['requests']]
    return dict(connections_used=len(connections), connections_accepted=len(report['connections']),
                resumed_connections=sum(c['session_resumed'] for c in connections),
                reconnect_resumed=[c['session_resumed'] for c in connections if c['requests'].get('reconnect')],
                phases=report['phases'],
                phase_connections={name: [c['id'] for c in connections if name in c['requests']]
                                   for name in EXPECTED})


def ordered_vectors(reference, candidate):
    rows = []
    for field in VECTORS:
        a, b = reference['hello'].get(field), candidate['hello'].get(field)
        rows.append(dict(field='hello.' + field, reference=a, candidate=b,
                         status='not_observed' if a is None or b is None else 'measured',
                         same_presence=None if a is None or b is None else set(a) == set(b),
                         same_order=None if a is None or b is None else a == b))
    a, b = reference['initial_h2_settings'], candidate['initial_h2_settings']
    rows.append(dict(field='initial_h2_settings', reference=a, candidate=b,
                     same_presence={r['id'] for r in a} == {r['id'] for r in b},
                     same_order=[r['id'] for r in a] == [r['id'] for r in b],
                     same_values={r['id']: r['value'] for r in a} == {r['id']: r['value'] for r in b}))
    return rows


def compare(profiles, cold_profiles):
    if set(profiles) != {(s, p) for s in ('firefox', 'foxtunnel') for p in ('h2', 'h3')}:
        raise ValueError('complete subject/protocol matrix required')
    for (subject, protocol), report in profiles.items():
        validate(report, protocol)
    cases = []
    for protocol in ('h2', 'h3'):
        ref, candidate = (profiles[(s, protocol)] for s in ('firefox', 'foxtunnel'))
        cases.append(dict(protocol=protocol, firefox=summary(ref), foxtunnel=summary(candidate)))
    # Preserve the actual order/presence of the selected TLS/H2 vectors on
    # every used H2 connection, including fresh connections after rotation.
    ordered = {subject: [dict(connection=c['id'], requests=c['requests'], resumed=c['session_resumed'],
                             hello={k: c['h2_wire']['hello'].get(k) for k in VECTORS},
                             initial_h2_settings=c['h2_wire']['initial_h2_settings'])
                         for c in profiles[(subject, 'h2')]['connections'] if c['requests']]
               for subject in ('firefox', 'foxtunnel')}
    first = {s: next(c['h2_wire'] for c in profiles[(s, 'h2')]['connections'] if c['requests'].get('cold'))
             for s in ('firefox', 'foxtunnel')}
    h3 = [fingerprint_audit.field_row(field, cold_profiles[('firefox', 'h3')], cold_profiles[('foxtunnel', 'h3')])
          for field in fingerprint_audit.H3_FIELDS]
    return dict(schema=1, kind='firefox-foxtunnel-controlled-behavior-comparison', cases=cases,
                ordered_h2_connections=ordered, first_h2_comparison=ordered_vectors(first['firefox'], first['foxtunnel']),
                cold_h3_effective_comparison=h3,
                h3_raw_presence='not_measured', h3_raw_order='not_measured',
                scope='Same local GET payloads and cancellation/forced-reconnect schedule. Firefox bootstrap page is excluded. Server-observed TLS resumption is not a client feature claim. TLS/H2 selected vector order is raw; H3 fields are selected effective decoder values including defaults, not raw presence/order. Timing, browser background traffic, full Firefox networking behavior, WAN and DPI indistinguishability are not measured.')


def capture_behavior(endpoint, firefox, cert, key, ca, work, subject, protocol, env):
    import capture_native_wire as capture
    stem = f'{subject}-{protocol}-behavior'
    out, ready = work / (stem + '.json'), work / (stem + '-ready.json')
    args = [str(endpoint), '--protocol', protocol, '--cert', str(cert), '--key', str(key),
            '--ready', str(ready), '--out', str(out)]
    if subject == 'foxtunnel':
        args += ['--sample', 'nss' if protocol == 'h2' else 'neqo']
    with (work / (stem + '.log')).open('wb') as log:
        server = subprocess.Popen(args, env=env, stdout=log, stderr=log)
        client = None
        try:
            capture.wait_file(ready, server)
            origin = json.loads(ready.read_text())['origin']
            if subject == 'firefox':
                profile = work / (stem + '-profile')
                capture.prepare_firefox_profile(profile, ca, protocol, origin)
                client = subprocess.Popen([str(firefox), '--headless', '--no-remote', '--profile', str(profile), origin],
                                          env=env, stdout=log, stderr=log)
            server.wait(timeout=45)
            if server.returncode:
                log.flush()
                if out.exists():
                    partial = json.loads(out.read_text())
                    diagnostic = {'phases': partial['phases'], 'rotations': partial['rotations'],
                                  'connections': [{k:v for k,v in c.items() if k!='h2_wire'} for c in partial['connections']]}
                    print(json.dumps({'incomplete_behavior': diagnostic}, indent=2), flush=True)
                raise ValueError(f'{subject}/{protocol}: controlled workload failed: ' +
                                 (work / (stem + '.log')).read_text(errors='replace')[-2000:])
        finally:
            if client is not None:
                capture.stop(client)
            capture.stop(server)
    raw = out.read_bytes()
    if len(raw) > 4 << 20:
        raise ValueError('behavior evidence exceeds bound')
    validate(json.loads(raw), protocol)
    return raw

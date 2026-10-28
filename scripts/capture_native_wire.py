#!/usr/bin/env python3
"""Fresh isolated Firefox/NaiveProxy/VetroffProxy loopback connection observations.

Pinned executable archives; fresh browser DB; no user profile, pcap, key log or
request headers retained. The endpoint never forwards to an external target.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import socket
import subprocess
import tarfile
import tempfile
import time
import urllib.request

import fingerprint_audit
import mozilla_runtime
from private_files import write_exclusive

ROOT = Path(__file__).resolve().parents[1]


def download(url, path, expected, bound):
    with urllib.request.urlopen(url, timeout=120) as src, path.open('xb') as dst:
        total = 0
        while block := src.read(1 << 20):
            total += len(block)
            if total > bound:
                raise ValueError('pinned download exceeds bound')
            dst.write(block)
    if mozilla_runtime.digest(path) != expected:
        raise ValueError('pinned executable archive digest mismatch')


def wait_file(path, process, seconds=25):
    deadline = time.monotonic() + seconds
    while True:
        try:
            if json.loads(path.read_text()).get('origin'):
                return
        except (OSError, ValueError):
            pass
        if process.poll() is not None:
            raise ValueError('capture endpoint exited before ready')
        if time.monotonic() >= deadline:
            raise ValueError('capture endpoint readiness timeout')
        time.sleep(0.05)


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def trigger_socks(port):
    # Only requests a CONNECT authority. The controlled endpoint responds
    # locally and never resolves or opens this deliberately unused destination.
    deadline = time.monotonic() + 5
    while True:
        try:
            conn = socket.create_connection(('127.0.0.1', port), timeout=1)
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(.05)
    with conn:
        conn.settimeout(10)
        conn.sendall(b'\x05\x01\x00')
        greeting = b''
        while len(greeting) < 2:
            part = conn.recv(2-len(greeting))
            if not part:
                raise ValueError('Naive SOCKS greeting truncated')
            greeting += part
        if greeting != b'\x05\x00':
            raise ValueError('Naive SOCKS greeting refused')
        conn.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x09')
        # TLS/H2/H3 metadata, rather than tunnel payload, is the observation.
        try:
            conn.recv(64)
        except (OSError, TimeoutError):
            pass


def prepare_firefox_profile(profile, trust, protocol, origin):
    profile.mkdir(mode=0o700)
    subprocess.run(['certutil', '-N', '--empty-password', '-d', 'sql:' + str(profile)], check=True)
    subprocess.run(['certutil', '-A', '-n', 'fixture', '-t', 'CT,,', '-i', str(trust), '-d', 'sql:' + str(profile)], check=True)
    prefs = {'browser.shell.checkDefaultBrowser': False, 'browser.startup.homepage_override.mstone': 'ignore',
             'app.update.auto': False, 'app.update.enabled': False, 'datareporting.policy.dataSubmissionEnabled': False,
             'toolkit.telemetry.enabled': False, 'network.captive-portal-service.enabled': False,
             'network.connectivity-service.enabled': False, 'network.proxy.type': 0,
             'network.dns.disableIPv6': True, 'network.http.http3.enable': protocol == 'h3',
             'network.http.http3.disable_when_third_party_roots_found': False,
             'browser.newtabpage.enabled': False, 'browser.startup.page': 0}
    if protocol == 'h3':
        port = origin.rsplit(':', 1)[1]
        prefs['network.http.http3.alt-svc-mapping-for-testing'] = f'localhost;h3=:{port}'
        prefs['network.http.http3.force-use-alt-svc-mapping-for-testing'] = True
    (profile / 'user.js').write_text(''.join(f'user_pref({json.dumps(k)}, {json.dumps(v)});\n' for k,v in prefs.items()))


def capture(endpoint, firefox, naive, cert, key, work, subject, protocol, env, ca=None):
    trust = ca or cert
    out, ready = work / f'{subject}-{protocol}.json', work / f'{subject}-{protocol}-ready.json'
    args = [str(endpoint), '--protocol', protocol, '--cert', str(cert), '--key', str(key),
            '--ready', str(ready), '--out', str(out)]
    if subject == 'vetroffproxy':
        args += ['--sample', 'nss' if protocol == 'h2' else 'neqo']
    with (work / f'{subject}-{protocol}-endpoint.log').open('wb') as log:
        server = subprocess.Popen(args, env=env, stdout=log, stderr=log)
        client = None
        try:
            wait_file(ready, server)
            origin = json.loads(ready.read_text())['origin']
            if subject == 'firefox':
                profile = work / f'firefox-{protocol}-profile'
                prepare_firefox_profile(profile, trust, protocol, origin)
                client = subprocess.Popen([str(firefox), '--headless', '--no-remote', '--profile', str(profile), origin],
                                          env=env, stdout=log, stderr=log)
            elif subject == 'naive':
                with socket.socket() as sock:
                    sock.bind(('127.0.0.1', 0))
                    port = sock.getsockname()[1]
                scheme = 'https' if protocol == 'h2' else 'quic'
                client_env = dict(env, SSL_CERT_FILE=str(trust), SSL_CERT_DIR=str(work / 'empty-roots'))
                client = subprocess.Popen([str(naive), f'--listen=socks://127.0.0.1:{port}',
                    '--proxy=' + origin.replace('https://', scheme + '://fixture:local-only@'),
                    '--host-resolver-rules=MAP localhost 127.0.0.1'], env=client_env, stdout=log, stderr=log)
                trigger_socks(port)
            server.wait(timeout=25)
            if server.returncode != 0:
                log.flush()
                diagnostic = (work / f'{subject}-{protocol}-endpoint.log').read_text(errors='replace')[-3000:]
                raise ValueError(f'{subject}/{protocol}: incomplete observation: {diagnostic}')
        finally:
            if client is not None:
                stop(client)
            stop(server)
    raw = out.read_bytes()
    fingerprint_audit.decode_profile(raw, 'tls_h2' if protocol == 'h2' else 'h3_quic')
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--endpoint', required=True, type=Path)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--behavior-endpoint', type=Path)
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() != 'x86_64':
        raise ValueError('pinned native capture currently requires Linux amd64')
    if args.out.exists():
        raise ValueError('output must be a new directory')
    lock = json.loads((ROOT / 'scripts/wire-capture.lock.json').read_text())
    mozilla = json.loads(mozilla_runtime.LOCK.read_text())
    with tempfile.TemporaryDirectory(prefix='vetroffproxy-wire-') as tmp:
        work = Path(tmp)
        env = dict(os.environ, MOZ_HEADLESS='1', MOZ_DISABLE_CONTENT_SANDBOX='1')
        archive = work / 'firefox.tar.xz'
        download(mozilla['base_url'] + mozilla['archives']['amd64']['path'], archive,
                 mozilla['archives']['amd64']['sha256'], 250 << 20)
        browser = work / 'browser'
        browser.mkdir()
        with tarfile.open(archive) as tar:
            if sum(m.size for m in tar.getmembers()) > 1 << 30:
                raise ValueError('Firefox extraction exceeds bound')
            tar.extractall(browser, filter='data')
        firefox = browser / 'firefox/firefox'
        naive_archive = work / 'naive.tar.xz'
        download(lock['naive_url'], naive_archive, lock['naive_sha256'], 16 << 20)
        naive = work / 'naive'
        with tarfile.open(naive_archive) as tar:
            member = next(m for m in tar.getmembers() if m.name.endswith('/naive'))
            if not member.isfile() or member.size > 32 << 20:
                raise ValueError('invalid Naive executable')
            naive.write_bytes(tar.extractfile(member).read())
        naive.chmod(0o700)
        versions = {'firefox': subprocess.check_output([str(firefox), '--version'], env=env, text=True).strip(),
                    'naive': subprocess.check_output([str(naive), '--version'], env=env, text=True).strip()}
        if mozilla['firefox_version'] not in versions['firefox'] or lock['naive_version'] not in versions['naive']:
            raise ValueError('executable version differs from pin')
        certdir = work / 'cert'
        certdir.mkdir(mode=0o700)
        ca, cakey = certdir / 'ca.pem', certdir / 'ca.key'
        cert, key = certdir / 'cert.pem', certdir / 'key.pem'
        # A real lab CA + signed leaf, not a Firefox certificate exception.
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
            '-days', '1', '-subj', '/CN=Isolated wire fixture CA',
            '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
            '-keyout', str(cakey), '-out', str(ca)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        csr = certdir / 'leaf.csr'
        subprocess.run(['openssl', 'req', '-new', '-newkey', 'ec', '-pkeyopt',
            'ec_paramgen_curve:P-256', '-nodes', '-subj', '/CN=localhost',
            '-keyout', str(key), '-out', str(csr)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        extensions = certdir / 'extensions'
        extensions.write_text('basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost,IP:127.0.0.1\n')
        subprocess.run(['openssl', 'x509', '-req', '-in', str(csr), '-CA', str(ca),
            '-CAkey', str(cakey), '-CAcreateserial', '-days', '1', '-extfile', str(extensions),
            '-out', str(cert)], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        cert.write_bytes(cert.read_bytes() + ca.read_bytes())
        (work / 'empty-roots').mkdir()
        observations = []
        payloads = {}
        for subject in ('firefox', 'naive', 'vetroffproxy'):
            for protocol in ('h2', 'h3'):
                raw = capture(args.endpoint.resolve(), firefox, naive, cert, key, work, subject, protocol, env, ca=ca)
                name = f'{subject}-{protocol}.json'
                payloads[name] = raw
                observations.append(dict(subject=subject, protocol=protocol, path=name,
                                         sha256=hashlib.sha256(raw).hexdigest()))
        behavior_observations = []
        if args.behavior_endpoint is not None:
            import compare_browser_behavior
            behavior_profiles = {}
            for subject in ('firefox', 'vetroffproxy'):
                for protocol in ('h2', 'h3'):
                    raw = compare_browser_behavior.capture_behavior(args.behavior_endpoint.resolve(), firefox,
                        cert, key, ca, work, subject, protocol, env)
                    name = f'{subject}-{protocol}-behavior.json'
                    payloads[name] = raw
                    behavior_profiles[(subject, protocol)] = json.loads(raw)
                    behavior_observations.append(dict(subject=subject, protocol=protocol, path=name,
                        sha256=hashlib.sha256(raw).hexdigest()))
            comparison = compare_browser_behavior.compare(behavior_profiles,
                    {(subject, protocol): json.loads(payloads[f'{subject}-{protocol}.json'])
                     for subject in ('firefox', 'vetroffproxy') for protocol in ('h2', 'h3')})
            subject = 'vetroffproxy-firefox-profile'
            raw = compare_browser_behavior.capture_behavior(args.behavior_endpoint.resolve(), firefox,
                cert, key, ca, work, subject, 'h2', env)
            name = f'{subject}-h2-behavior.json'
            payloads[name] = raw
            configured = json.loads(raw)
            compare_browser_behavior.validate(configured, 'h2')
            first = lambda report: next(c['h2_wire'] for c in report['connections'] if c['requests'].get('cold'))
            comparison['configured_h2_profile'] = dict(tls_profile='firefox-158', h2_profile='firefox-158',
                behavior=compare_browser_behavior.summary(configured),
                first_h2_comparison=compare_browser_behavior.ordered_vectors(
                    first(behavior_profiles[('firefox', 'h2')]), first(configured)))
            behavior_observations.append(dict(subject=subject, protocol='h2', path=name,
                sha256=hashlib.sha256(raw).hexdigest()))
            payloads['browser-behavior-comparison.json'] = (json.dumps(comparison, indent=2)+'\n').encode()
        manifest = dict(schema=1, kind='controlled-wire-capture-set',
                        checkout_commit=subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip(),
                        worktree_dirty=bool(subprocess.check_output(['git', 'status', '--porcelain'], cwd=ROOT)),
                        versions=versions, network_scope='IPv4 loopback with localhost SNI; DNS family and failover are not measured', firefox_fixture_overrides={'allow_h3_with_fixture_CA':True, 'force_h3_test_mapping':True, 'content_sandbox_disabled':True}, archives={'firefox':mozilla['archives']['amd64']['sha256'], 'naive':lock['naive_sha256']},
                        executable_sha256={'firefox':mozilla_runtime.digest(firefox), 'naive':mozilla_runtime.digest(naive), 'endpoint':mozilla_runtime.digest(args.endpoint)},
                        observations=observations,
                        behavior_observations=behavior_observations,
                        native_versions={'nss': mozilla['nss_version'], 'neqo': json.loads((ROOT/'scripts/neqo.lock.json').read_text())['neqo_version']},
                        lock_sha256={name: mozilla_runtime.digest(ROOT/'scripts'/name) for name in
                                     ('wire-capture.lock.json', 'mozilla-runtime.lock.json', 'neqo.lock.json')},
                        behavior_endpoint_sha256=mozilla_runtime.digest(args.behavior_endpoint) if args.behavior_endpoint else None,
                        scope='Cold verified loopback connection startup, TLS1.3/H2 or QUICv1/H3. Native GET for Firefox, CONNECT for Naive, CONNECT/POST for VetroffProxy. Initial transport metadata only; no page/tunnel workload equivalence. Effective selected QUIC parameters include defaults; raw presence/order and CIDs excluded. No production credentials/profiles/keys retained.')
        args.out.mkdir(mode=0o700)
        for name, raw in payloads.items():
            write_exclusive(args.out / name, raw.decode(), 0o600)
        write_exclusive(args.out / 'manifest.json', json.dumps(manifest, indent=2)+'\n', 0o600)
        print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()

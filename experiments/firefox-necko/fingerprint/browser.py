#!/usr/bin/env python3
"""Isolated Firefox native CONNECT reference, controlled through Marionette.

Uses a fresh temporary profile, stdin configuration and a bounded browser
lifetime. Never opens an existing profile or puts credentials on the command line.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time


def receive(sock):
    prefix = bytearray()
    while not prefix.endswith(b':'):
        part = sock.recv(1)
        if not part or len(prefix) > 12:
            raise ValueError('invalid Marionette framing')
        prefix.extend(part)
    size = int(prefix[:-1])
    if not 0 < size <= 4 << 20:
        raise ValueError('Marionette response exceeds bound')
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise EOFError('truncated Marionette response')
        data.extend(part)
    return json.loads(data)


class Marionette:
    def __init__(self, sock):
        self.sock, self.sequence = sock, 0
        if receive(sock).get('marionetteProtocol') != 3:
            raise ValueError('unsupported Marionette protocol')

    def command(self, name, params):
        self.sequence += 1
        data = json.dumps([0, self.sequence, name, params]).encode()
        self.sock.sendall(str(len(data)).encode() + b':' + data)
        response = receive(self.sock)
        if response[:2] != [1, self.sequence] or response[2] is not None:
            raise ValueError('Firefox reference command failed: ' + str(response[2]))
        return response[3]


def main():
    cfg = json.load(sys.stdin)
    runtime = Path(cfg.pop('runtime')).resolve()
    with tempfile.TemporaryDirectory(prefix='foxtunnel-browser-reference-') as tmp:
        profile = Path(tmp)
        with socket.socket() as reserve:
            reserve.bind(('127.0.0.1', 0))
            port = reserve.getsockname()[1]
        prefs = {
            'marionette.port': port,
            'network.process.enabled': False,
            'network.http.network_access_on_socket_process.enabled': False,
            'network.http.http2.websockets': True,
            'browser.shell.checkDefaultBrowser': False,
            'browser.startup.page': 0, 'browser.newtabpage.enabled': False,
            'datareporting.policy.dataSubmissionEnabled': False,
            'toolkit.telemetry.enabled': False,
            'network.captive-portal-service.enabled': False,
            'network.connectivity-service.enabled': False,
            'network.http.speculative-parallel-limit': 0,
            'network.proxy.allow_hijacking_localhost': True,
            'network.http.http3.enable': cfg['transport'] == 'h3-connect',
            'network.http.http3.disable_when_third_party_roots_found': False,
            'network.http.http3.fallback_to_h2_on_error': False,
            'network.http.http3.fallback_to_h2_on_protocol_error': False,
        }
        (profile / 'user.js').write_text(''.join(
            f'user_pref({json.dumps(k)}, {json.dumps(v)});\n' for k, v in prefs.items()))
        env = dict(os.environ, MOZ_HEADLESS='1', MOZ_DISABLE_CONTENT_SANDBOX='1',
                   MOZ_DISABLE_SOCKET_PROCESS='1', MOZ_REMOTE_ALLOW_SYSTEM_ACCESS='1',
                   LD_LIBRARY_PATH=str(runtime.parent))
        with (profile / 'browser.log').open('wb') as log:
            process = subprocess.Popen([str(runtime), '--headless', '--no-remote',
                '--profile', tmp, '--marionette', 'about:blank'], env=env, stdout=log, stderr=log)
            try:
                deadline = time.monotonic() + 20
                while True:
                    try:
                        sock = socket.create_connection(('127.0.0.1', port), timeout=1)
                        break
                    except OSError:
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise ValueError('Firefox reference startup failed')
                        time.sleep(.05)
                with sock:
                    sock.settimeout(60)
                    client = Marionette(sock)
                    session = client.command('WebDriver:NewSession', {})
                    client.command('Marionette:SetContext', {'value': 'chrome'})
                    result = client.command('WebDriver:ExecuteAsyncScript', {
                        'script': Path(__file__).with_name('browser.js').read_text(),
                        'args': [cfg], 'newSandbox': True, 'sandbox': 'system', 'scriptTimeout': 45000})
                    print(json.dumps({'browser_version': session['capabilities']['browserVersion'],
                                      'result': result['value']}))
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


if __name__ == '__main__':
    main()

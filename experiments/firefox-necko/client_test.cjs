const { test } = require('node:test');
const assert = require('node:assert/strict');
const { SocksParser, firefoxUserAgent } = require('./client.js');

test('fragmented domain request keeps application bytes and never resolves DNS', () => {
  const p = new SocksParser();
  p.push([5]); assert.equal(p.greeting(), null);
  p.push([2, 2]); assert.equal(p.greeting(), null);
  p.push([0]); assert.equal(p.greeting(), true);
  const host = [...Buffer.from('remote.invalid')];
  const request = [5, 1, 0, 3, host.length, ...host, 1, 187];
  for (const b of request.slice(0, -1)) { p.push([b]); assert.equal(p.request(), null); }
  p.push([187, 0, 255, 13]);
  const r = p.request();
  assert.equal(r.authority, 'remote.invalid:443');
  assert.deepEqual([...r.early], [0, 255, 13]);
});
test('IPv4 and IPv6 authorities are unambiguous', () => {
  for (const [wire, target] of [
    [[5,1,0,1,192,0,2,1,0,80], '192.0.2.1:80'],
    [[5,1,0,4,0x20,1,0x0d,0xb8,...Array(11).fill(0),1,1,187], '[2001:db8:0:0:0:0:0:1]:443'],
  ]) {
    const p = new SocksParser(); p.push([5,1,0]); assert.equal(p.greeting(), true);
    p.push(wire); assert.equal(p.request().authority, target);
  }
});
test('rejects UDP, reserved bytes, URI injection, empty names and zero ports', () => {
  for (const wire of [
    [5,3,0,1,127,0,0,1,0,80], [5,1,1,1,127,0,0,1,0,80],
    [5,1,0,3,0,0,80], [5,1,0,1,127,0,0,1,0,0],
    ...['a/b', 'a@b', 'a\r\nb', 'a%b', 'a:b', 'a#b'].map(h => [5,1,0,3,h.length,...Buffer.from(h),0,80]),
  ]) {
    const p = new SocksParser(); p.push([5,1,0]); p.greeting(); p.push(wire);
    assert.throws(() => p.request());
  }
});
test('authentication refusal and buffer bounds', () => {
  const p = new SocksParser(); p.push([5,1,2]); assert.equal(p.greeting(), false);
  assert.throws(() => p.push(new Uint8Array(65537)));
});

test('xpcshell UA keeps native platform and reduced Gecko version', () => {
  for (const platform of ['X11; Linux x86_64', 'Windows NT 10.0; Win64; x64', 'Macintosh; Intel Mac OS X 10.15']) {
    const prefix = `Mozilla/5.0 (${platform}; rv:160.0) Gecko/20100101`;
    assert.equal(firefoxUserAgent(prefix + ' /160.0a1'), prefix + ' Firefox/160.0');
    assert.equal(firefoxUserAgent(prefix + ' Firefox/160.0'), prefix + ' Firefox/160.0');
  }
  for (const value of ['Mozilla/5.0 /160.0a1', 'Mozilla/5.0 (rv:160.0) Gecko/20100101 Other/160.0']) {
    assert.throws(() => firefoxUserAgent(value));
  }
});

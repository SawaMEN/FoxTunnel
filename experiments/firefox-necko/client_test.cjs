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


test('private IPC requires password method and handles fragmented authentication', () => {
 const p = new SocksParser(); p.push([5, 1, 0]); assert.equal(p.greeting(2), false);
 const q = new SocksParser(); q.push([5, 1, 2]); assert.equal(q.greeting(2), true);
 const auth = [1, 9, ...Buffer.from('foxtunnel'), 3, ...Buffer.from('key')];
 for (const b of auth.slice(0,-1)) {q.push([b]);assert.equal(q.authentication(),null);}
 q.push([auth.at(-1),5,1,0,1,127,0,0,1,0,80]);
 assert.deepEqual(q.authentication(),{user:'foxtunnel',password:'key'});
 assert.equal(q.request().authority,'127.0.0.1:80');
});

test('pump reuses one bounded buffer and preserves bytes, backpressure and FIN', async () => {
  const { pumpBuffered } = require('./client.js');
  const chunks = [Buffer.alloc(32768, 0x80), Buffer.from([0, 1, 255]), Buffer.alloc(32768, 0x42)];
  const buffers = [], received = [];
  let index = 0, closed = 0, progress = 0, total = 0;
  const source = { async read(scratch) {
    assert.equal(scratch.length, 32768);
    buffers.push(scratch);
    if (index === chunks.length) return null;
    const part = chunks[index++];
    scratch.set(part);
    return scratch.subarray(0, part.length);
  }};
  const destination = {
    output: { close() { closed++; } },
    async write(part) {
      // An awaited write must finish before the shared scratch is overwritten.
      await Promise.resolve();
      received.push(Buffer.from(part));
    }
  };
  await pumpBuffered(source, destination, () => { progress++; }, n => { total += n; });
  assert.equal(new Set(buffers).size, 1);
  assert.deepEqual(Buffer.concat(received), Buffer.concat(chunks));
  assert.equal(total, Buffer.concat(chunks).length);
  assert.equal(progress, chunks.length * 2);
  assert.equal(closed, 1);
});

test('pump never sends clean FIN on write failure', async () => {
  const { pumpBuffered } = require('./client.js');
  let fin = 0;
  await assert.rejects(
    pumpBuffered({ async read(buf) { buf[0] = 9; return buf.subarray(0, 1); } },
      { output: { close() { fin++; } }, async write() { throw Error('failed write'); } },
      () => {}, () => {}),
    /failed write/
  );
  assert.equal(fin, 0);
});

test('cached output encoding handles short writes and backpressure without corruption', async () => {
  const { writeAllWithBackpressure } = require('./client.js');
  const input = Buffer.alloc(100001);
  for (let i = 0; i < input.length; i++) input[i] = i % 256;
  const accepted = [];
  let calls = 0;
  const encodings = await writeAllWithBackpressure(input, async binary => {
    calls++;
    if (calls % 7 === 0) return 0; // WOULD_BLOCK: do not lose data
    const n = Math.min(311, binary.length);
    accepted.push(binary.slice(0, n));
    return n;
  });
  assert.equal(encodings, Math.ceil(input.length / 32768));
  assert.deepEqual(Buffer.from(accepted.join(''), 'latin1'), input);
  assert.ok(calls > encodings);
});

test('invalid write count is rejected rather than silently losing data', async () => {
  const { writeAllWithBackpressure } = require('./client.js');
  await assert.rejects(writeAllWithBackpressure(Uint8Array.of(1, 2), async () => 3),
    /invalid native output write count/);
  await assert.rejects(writeAllWithBackpressure(Uint8Array.of(1), async () => -1),
    /invalid native output write count/);
  assert.equal(await writeAllWithBackpressure(Uint8Array.of(), async () => { throw Error('unexpected'); }), 0);
});

test('diagnostic session snapshot avoids allocation-heavy spreads', () => {
  const { sessionStatus } = require('./client.js');
  assert.deepEqual(sessionStatus(new Set(), 1000), { connected: 0, oldest_ms: 0 });
  const sessions = new Set([
    { remote: {}, lastProgress: 300 },
    { remote: null, lastProgress: 1100 },
    { remote: {}, lastProgress: 50 },
  ]);
  assert.deepEqual(sessionStatus(sessions, 1000), { connected: 2, oldest_ms: 950 });
  const many = new Set(Array.from({ length: 90000 }, (_, i) => ({ remote: null, lastProgress: i })));
  assert.deepEqual(sessionStatus(many, 100000), { connected: 0, oldest_ms: 100000 });
});


test('authenticated UDP-v1 IPC framing accepts only bounded complete packets', () => {
  const { udpIPCReply } = require('./client.js');
  const p = new SocksParser();
  p.push([5, 1, 2]); assert.equal(p.greeting(2), true);
  const input = [0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 0, 255];
  const frame = [5, 0xf0, 0, 0, 0, input.length, ...input];
  for (const b of frame.slice(0, -1)) {
    p.push([b]);
    assert.equal(p.request(), null);
  }
  p.push([frame.at(-1)]);
  assert.deepEqual([...p.request().udp], input);
  assert.deepEqual([...udpIPCReply(Uint8Array.from(input))],
    [5, 0, 0, input.length, ...input]);
  assert.deepEqual([...udpIPCReply(new Uint8Array())], [5, 0, 0, 0]);
  assert.deepEqual([...udpIPCReply(null, true)], [5, 1, 0, 0]);
  assert.throws(() => udpIPCReply(new Uint8Array(1233)), /invalid UDP/);
});

test('UDP IPC rejects unauthorized commands, excessive frames and trailing bytes', () => {
  for (const raw of [
    [5, 0xf0, 0, 1, 0, 8, ...Array(8).fill(0)],
    [5, 0xf0, 0, 0, 0, 7, ...Array(7).fill(0)],
    [5, 0xf0, 0, 0, 4, 209],
    [5, 0xf0, 0, 0, 0, 8, ...Array(9).fill(0)],
  ]) {
    const p = new SocksParser();
    p.push([5, 1, 2]); p.greeting(2);
    p.push(raw);
    assert.throws(() => p.request());
  }
});

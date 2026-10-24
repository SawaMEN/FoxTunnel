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
  assert.deepEqual([...udpIPCReply(null, true, 3)], [5, 3, 0, 0]);
  assert.throws(() => udpIPCReply(null, true, 255), /invalid UDP failure/);
  assert.deepEqual([...udpIPCReply(null, true, 13)], [5, 13, 0, 0]);
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


test('UDP-v2 native framer survives byte-wise fragmentation and coalescing', () => {
  const { encodeNativeUDPStreamFrame, NativeUDPFrameDecoder } = require('./client.js');
  const payload = Uint8Array.of(0, 0, 0, 1, 127, 0, 0, 1, 0, 53, 0, 255, 254, 128, 0);
  const frame = encodeNativeUDPStreamFrame(payload);
  let replies = [];
  let decoder = new NativeUDPFrameDecoder(packet => replies.push(packet));
  for (const b of frame) decoder.push(Uint8Array.of(b));
  decoder.finish();
  assert.deepEqual([...replies[0]], [...payload]);
  replies = [];
  decoder = new NativeUDPFrameDecoder(packet => replies.push(packet));
  const many = new Uint8Array(frame.length * 150);
  for (let n = 0; n < 150; n++) many.set(frame, n * frame.length);
  decoder.push(many);
  decoder.finish();
  assert.equal(replies.length, 150);
  for (const packet of replies) assert.deepEqual([...packet], [...payload]);
});
test('UDP-v2 native framer rejects malformed packets, lengths and truncated frames', () => {
  const { validateNativeUDPDatagram, encodeNativeUDPStreamFrame, NativeUDPFrameDecoder } = require('./client.js');
  for (const wire of [
    Uint8Array.of(0, 0, 1, 1, 127, 0, 0, 1, 0, 53),
    Uint8Array.of(0, 0, 0, 1, 127, 0, 0, 1, 0, 0),
    Uint8Array.of(0, 0, 0, 3, 0, 0, 53),
    new Uint8Array(1233),
  ]) {
    assert.throws(() => validateNativeUDPDatagram(wire));
    assert.throws(() => encodeNativeUDPStreamFrame(wire));
  }
  for (const frame of [Uint8Array.of(0, 0), Uint8Array.of(4, 209)])
    assert.throws(() => new NativeUDPFrameDecoder(() => {}).push(frame));
  const valid = encodeNativeUDPStreamFrame(Uint8Array.of(0, 0, 0, 1, 127, 0, 0, 1, 0, 53));
  const decoder = new NativeUDPFrameDecoder(() => {});
  decoder.push(valid.subarray(0, valid.length - 1));
  assert.throws(() => decoder.finish(), /truncated/);
  assert.throws(() => new NativeUDPFrameDecoder(() => {}).push(new Uint8Array(32769)));
});

test('UDP-v2 pump validates frames, awaits backpressure and preserves binary bytes', async () => {
  const { pumpNativeUDPFrames, encodeNativeUDPStreamFrame } = require('./client.js');
  const frame = encodeNativeUDPStreamFrame(Uint8Array.of(0,0,0,1,127,0,0,1,0,53,0,255,128));
  let reads = 0, writing = false, fin = 0;
  const received = [];
  const input = Buffer.concat([frame, frame]);
  const source = { async read(scratch) {
    assert.equal(writing, false);
    if (reads === input.length) return null;
    scratch[0] = input[reads++];
    return scratch.subarray(0,1);
  }};
  await pumpNativeUDPFrames(source, { output: {close() {fin++;}}, async write(data) {
    writing = true;
    await new Promise(resolve => setImmediate(resolve));
    received.push(Buffer.from(data)); writing = false;
  }});
  assert.deepEqual(Buffer.concat(received), input);
  assert.equal(fin, 1);
});

test('UDP-v2 pump aborts truncated and malformed streams without clean FIN', async () => {
  const { pumpNativeUDPFrames } = require('./client.js');
  for (const bytes of [Uint8Array.of(0), Uint8Array.of(0,0), Uint8Array.of(0,10,0)]) {
    let sent = false, fin = 0;
    await assert.rejects(pumpNativeUDPFrames({async read() {
      if (sent) return null; sent = true; return bytes;
    }}, {output: {close() {fin++;}}, async write() {assert.fail('invalid packet forwarded');}}));
    assert.equal(fin, 0);
  }
});

test('private UDP-v2 command is exact and rejects pipelined bytes', () => {
  for (const raw of [[5,0xf1,0,0], [5,0xf1,0,1], [5,0xf1,0,0,0]]) {
    const parser = new SocksParser(); parser.push([5,1,2]); parser.greeting(2); parser.push(raw);
    if (raw.length === 4 && raw[3] === 0) assert.deepEqual(parser.request(), {udpStream:true});
    else assert.throws(() => parser.request());
  }
});

"use strict";

// The parser is independent of XPCOM so malformed and fragmented SOCKS frames
// can also be tested with Node. All public network I/O below belongs to Necko.
class SocksParser {
  constructor() { this.bytes = []; this.greeted = false; }
  push(data) {
    if (this.bytes.length + data.length > 65536) throw new Error("SOCKS input limit");
    this.bytes.push(...data);
  }
  greeting(method = 0) {
    const b = this.bytes;
    if (b.length < 2) return null;
    if (b[0] !== 5 || b[1] === 0) throw new Error("invalid SOCKS greeting");
    if (b.length < 2 + b[1]) return null;
    const accepted = b.slice(2, 2 + b[1]).includes(method);
    b.splice(0, 2 + b[1]); this.greeted = true;
    return accepted;
  }
  authentication() {
    const b = this.bytes;
    if (b.length < 2) return null;
    if (b[0] !== 1 || !b[1]) throw new Error("invalid SOCKS authentication");
    const p = 2 + b[1];
    if (b.length < p + 1) return null;
    if (!b[p]) throw new Error("invalid SOCKS authentication");
    const end = p + 1 + b[p];
    if (b.length < end) return null;
    const user = String.fromCharCode(...b.slice(2, p));
    const password = String.fromCharCode(...b.slice(p + 1, end));
    b.splice(0, end);
    return {user, password};
  }
  request() {
    const b = this.bytes;
    if (!this.greeted) throw new Error("SOCKS greeting required");
    if (b.length < 4) return null;
    if (b[0] !== 5 || b[2] !== 0) throw new Error("invalid private SOCKS request");
    // Reserved command 0xf0 is internal, authenticated IPC, never public SOCKS.
    // It carries exactly one bounded UDP-v1 packet. The native Gecko HTTP
    // stack performs the HTTPS POST, not a Go TLS/HTTP fallback.
    if (b[1] === 0xf0) {
      if (b[3] !== 0 || b.length < 6) {
        if (b[3] !== 0) throw new Error("invalid private UDP operation");
        return null;
      }
      const n = (b[4] << 8) | b[5];
      if (n < 8 || n > 1232 || b.length > 6 + n) throw new Error("invalid private UDP packet");
      if (b.length < 6 + n) return null;
      const packet = Uint8Array.from(b.splice(6, n));
      b.splice(0, 6);
      return { udp: packet };
    }
    if (b[1] !== 1) throw new Error("only SOCKS5 CONNECT is supported");
    let size, host, offset;
    if (b[3] === 1) {
      size = 10; offset = 8;
      if (b.length < size) return null;
      host = b.slice(4, 8).join(".");
    } else if (b[3] === 4) {
      size = 22; offset = 20;
      if (b.length < size) return null;
      const groups = [];
      for (let i = 4; i < 20; i += 2) groups.push(((b[i] << 8) | b[i + 1]).toString(16));
      host = `[${groups.join(":")}]`;
    } else if (b[3] === 3) {
      if (b.length < 5) return null;
      if (b[4] === 0) throw new Error("empty SOCKS hostname");
      size = 7 + b[4]; offset = 5 + b[4];
      if (b.length < size) return null;
      host = String.fromCharCode(...b.slice(5, offset));
      // Names remain unresolved until the proxy receives CONNECT. Restrict
      // to ASCII DNS labels; prevent URI syntax from changing the destination.
      if (!/^[A-Za-z0-9_.-]+$/.test(host)) throw new Error("invalid SOCKS hostname");
    } else { throw new Error("unsupported SOCKS address"); }
    const port = (b[offset] << 8) | b[offset + 1];
    if (!port) throw new Error("invalid SOCKS port");
    b.splice(0, size);
    return { authority: `${host}:${port}`, early: Uint8Array.from(b.splice(0)) };
  }
}

// xpcshell has no Firefox application name, although its HTTP implementation
// and platform token come from the same libxul. Use the UA's own Gecko version
// (which already applies Mozilla's version reduction), not appinfo.version's
// prerelease suffix. Keep native OS/architecture tokens intact.
function firefoxUserAgent(nativeUA) {
  const version = nativeUA.match(/\brv:(\d+\.\d+)\)/);
  if (!version || !/ (?:\/[^\s]+|Firefox\/[^\s]+)$/.test(nativeUA)) {
    throw new Error("unsupported native Firefox user agent");
  }
  return nativeUA.replace(/ (?:\/[^\s]+|Firefox\/[^\s]+)$/, ` Firefox/${version[1]}`);
}

function socksReply(code) { return Uint8Array.from([5, code, 0, 1, 0, 0, 0, 0, 0, 0]); }

// Fixed-width reply to authenticated private UDP IPC: status and bounded
// payload. A status 0 with an empty payload means the exit timed out (HTTP 204).
function udpIPCReply(data, failed = false, reason = 1) {
  // Only internal fixed status categories cross IPC, not server URLs,
  // certificate details, errors or response payloads.
  if (failed) {
    if (!Number.isInteger(reason) || reason < 1 || reason > 15) throw new Error("invalid UDP failure reason");
    return Uint8Array.of(5, reason, 0, 0);
  }
  if (!(data instanceof Uint8Array) || data.length > 1232) throw new Error("invalid UDP reply");
  return Uint8Array.from([5, 0, data.length >> 8, data.length & 255, ...data]);
}

// One scratch buffer per active direction, not one ArrayBuffer allocation for
// every 32 KiB of payload. A read's slice must be fully written before the next
// read overwrites it. The buffer is released when the pump exits, even on error.
async function pumpBuffered(source, destination, onProgress, onBytes) {
  const scratch = new Uint8Array(32768);
  for (;;) {
    const data = await source.read(scratch);
    if (data === null) { destination.output.close(); return; }
    onProgress();
    await destination.write(data);
    onProgress();
    onBytes(data.length);
  }
}

// Encode at most 32 KiB once, even when the native output stream performs
// partial writes or temporarily reports WOULD_BLOCK. Binary strings are used
// only at the nsIOutputStream boundary; they are not UTF-8 text.
async function writeAllWithBackpressure(data, attemptWrite) {
  let encodings = 0;
  for (let offset = 0; offset < data.length;) {
    const encoded = String.fromCharCode(...data.subarray(offset, offset + 32768));
    encodings++;
    let written = 0;
    while (written < encoded.length) {
      const remaining = written ? encoded.substring(written) : encoded;
      const n = await attemptWrite(remaining);
      if (!Number.isInteger(n) || n < 0 || n > remaining.length) {
        throw new Error("invalid native output write count");
      }
      // Zero means a real WOULD_BLOCK, never a successful zero-byte write.
      written += n;
    }
    offset += encoded.length;
  }
  return encodings;
}

// The metrics snapshot intentionally avoids temporary arrays, Array.map and
// Math.max(...manyValues). Diagnostic sampling should not create O(N) garbage.
function sessionStatus(sessions, now) {
  let connected = 0, oldest = 0;
  for (const session of sessions) {
    if (session.remote) connected++;
    oldest = Math.max(oldest, Math.max(0, now - session.lastProgress));
  }
  return { connected, oldest_ms: oldest };
}

if (typeof module !== "undefined") module.exports = {
  SocksParser, socksReply, firefoxUserAgent, pumpBuffered,
  writeAllWithBackpressure, sessionStatus, udpIPCReply,
};

if (typeof Components !== "undefined") {
  const { classes: Cc, interfaces: Ci, results: Cr } = Components;
  const { NetUtil } = ChromeUtils.importESModule("resource://gre/modules/NetUtil.sys.mjs");
  const { setTimeout, clearTimeout, setInterval, clearInterval } = ChromeUtils.importESModule("resource://gre/modules/Timer.sys.mjs");
  const thread = Services.tm.mainThread;
  const localFile = path => {
    const f = Cc["@mozilla.org/file/local;1"].createInstance(Ci.nsIFile);
    f.initWithPath(path); return f;
  };
  const root = Services.env.get("FOXTUNNEL_FIREFOX_ROOT");
  if (!root) throw new Error("private Firefox runtime directory required");
  const profile = localFile(root + "/profile");
  Services.dirsvc.registerProvider({
    getFile(key, persistent) {
      if (["ProfD", "ProfLD", "ProfDS", "ProfLDS", "TmpD"].includes(key)) { persistent.value = true; return profile.clone(); }
      return null;
    }, QueryInterface: ChromeUtils.generateQI(["nsIDirectoryServiceProvider"]),
  });
  Services.obs.notifyObservers(null, "profile-do-change", "foxtunnel");
  const input = Cc["@mozilla.org/network/file-input-stream;1"].createInstance(Ci.nsIFileInputStream);
  input.init(localFile(root + "/config.json"), -1, 0, 0);
  const cfg = JSON.parse(NetUtil.readInputStreamToString(input, input.available(), { charset: "UTF-8" }));
  input.close();

  // Connect-only socket handoff is not implemented by Gecko's socket process.
  // Keep native HTTP/TLS in the dedicated helper, not in the main Go process.
  Services.prefs.setBoolPref("network.process.enabled", false);
  Services.prefs.setBoolPref("network.http.network_access_on_socket_process.enabled", false);
  // A CONNECT handoff occupies a destination pool slot for its full lifetime.
  // Match Necko's uint8 per-host cap to this helper's bounded session limit.
  Services.prefs.setIntPref("network.http.max-persistent-connections-per-server",
    Math.min(cfg.max_connections, 255));
  Services.prefs.setBoolPref("network.http.http2.enabled", true);
  Services.prefs.setBoolPref("network.http.http2.websockets", true);
  Services.prefs.setBoolPref("network.http.http3.enable", cfg.transport === "h3-connect");
  if (cfg.transport === "h3-connect") {
    // An explicit H3 tunnel must fail rather than race/retry HTTP/2. Give
    // our bounded setup timer priority over Gecko's TCP backup timer too.
    Services.prefs.setBoolPref("network.http.http3.fallback_to_h2_on_error", false);
    Services.prefs.setBoolPref("network.http.http3.fallback_to_h2_on_protocol_error", false);
    Services.prefs.setIntPref("network.http.http3.backup_timer_delay", cfg.connect_timeout_ms + 1000);
  }
  Services.prefs.setBoolPref("network.proxy.allow_hijacking_localhost", true);
  Services.prefs.setIntPref("network.http.speculative-parallel-limit", 0);
  Services.prefs.setBoolPref("network.captive-portal-service.enabled", false);
  Services.prefs.setBoolPref("network.connectivity-service.enabled", false);
  Services.prefs.setBoolPref("toolkit.telemetry.enabled", false);

  if (cfg.ca_pem) {
    const certdb = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
    const certs = [...cfg.ca_pem.matchAll(/-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----/g)];
    if (!certs.length) throw new Error("invalid additional CA file");
    for (const cert of certs) certdb.addCertFromBase64(cert[1].replace(/\s/g, ""), "CT,,");
    // Firefox normally falls back from H3 when a non-builtin root is used.
    // An explicitly configured CA must work with the explicitly selected H3
    // transport too; certificate chain/hostname verification remains in NSS.
    if (cfg.transport === "h3-connect") {
      Services.prefs.setBoolPref("network.http.http3.disable_when_third_party_roots_found", false);
    }
  }

  const httpProtocol = Cc["@mozilla.org/network/protocol;1?name=http"].getService(Ci.nsIHttpProtocolHandler);
  Services.prefs.setStringPref("general.useragent.override", firefoxUserAgent(httpProtocol.userAgent));

  const pps = Cc["@mozilla.org/network/protocol-proxy-service;1"].getService(Ci.nsIProtocolProxyService);
  // A fixed proxy with no DIRECT/failover entry. Credentials are attached to
  // that proxy, not to a destination URI or an inner application request.
  const proxyFlags = Ci.nsIProxyInfo.ALWAYS_TUNNEL_VIA_PROXY | Ci.nsIProxyInfo.TRANSPARENT_PROXY_RESOLVES_HOST;
  const proxy = cfg.transport === "h3-connect"
    ? pps.newMASQUEProxyInfo(cfg.proxy_host, cfg.proxy_port,
        "/.well-known/masque/udp/{target_host}/{target_port}/", cfg.authorization, "foxtunnel-firefox", proxyFlags, 0, null)
    : pps.newProxyInfo("https", cfg.proxy_host, cfg.proxy_port, cfg.authorization, "foxtunnel-firefox", proxyFlags, 0, null);
  const filter = {
    applyFilter(uri, previous, callback) {
      // Internal UDP-v1 POST requests address the authenticated HTTPS proxy
      // origin directly. They must never CONNECT recursively through itself,
      // nor inherit a system proxy. The only such URL is constructed below.
      if (uri.scheme === "https" && uri.host === cfg.proxy_host &&
          (uri.port === -1 ? 443 : uri.port) === cfg.proxy_port &&
          uri.pathQueryRef === "/.well-known/foxtunnel-udp-v1") {
        callback.onProxyFilterResult(null); return;
      }
      callback.onProxyFilterResult(proxy);
    },
    QueryInterface: ChromeUtils.generateQI(["nsIProtocolProxyFilter"]),
  };
  pps.registerFilter(filter, 0);

  class AsyncIO {
    constructor(input, output) {
      this.input = input;
      this.output = output;
      // An nsIBinaryInputStream wrapper owns the same underlying async stream
      // throughout the session. Reuse it instead of allocating an XPCOM wrapper
      // for every callback on the payload hot path.
      this.binary = Cc["@mozilla.org/binaryinputstream;1"].createInstance(Ci.nsIBinaryInputStream);
      this.binary.setInputStream(input);
    }
    read(scratch = null) {
      return new Promise((resolve, reject) => {
        const callback = {
          onInputStreamReady: stream => {
            try {
              const n = Math.min(stream.available(), scratch ? scratch.byteLength : 32768);
              if (!n) { resolve(null); return; }
              // During an established pump, reuse its own bounded ArrayBuffer.
              // No second read starts before the previous write completes.
              const bytes = scratch || new Uint8Array(n);
              const count = this.binary.readArrayBuffer(n, bytes.buffer);
              if (!count) { resolve(null); return; }
              resolve(bytes.subarray(0, count));
            } catch (e) {
              if (e.result === Cr.NS_BASE_STREAM_WOULD_BLOCK) stream.asyncWait(callback, 0, 0, thread);
              else if (e.result === Cr.NS_BASE_STREAM_CLOSED) resolve(null);
              else reject(e);
            }
          }, QueryInterface: ChromeUtils.generateQI(["nsIInputStreamCallback"]),
        };
        this.input.asyncWait(callback, 0, 0, thread);
      });
    }
    async write(data) {
      // Await each partial write before advancing the source buffer. Avoid
      // recreating a 32 KiB binary string on each native short write.
      return writeAllWithBackpressure(data, text => new Promise((resolve, reject) => {
        this.output.asyncWait({
          onOutputStreamReady: stream => {
            try {
              const n = stream.write(text, text.length);
              if (n <= 0) throw Cr.NS_BASE_STREAM_CLOSED;
              resolve(n);
            } catch (e) {
              if (e.result === Cr.NS_BASE_STREAM_WOULD_BLOCK) resolve(0);
              else reject(e);
            }
          }, QueryInterface: ChromeUtils.generateQI(["nsIOutputStreamCallback"]),
        }, 0, 0, thread);
      }));
    }
    close() { try { this.input.close(); } catch {} try { this.output.close(); } catch {} }
  }

  const sessions = new Set();
  // Native copier completion is not exposed by the handoff API. Retain a
  // bounded number of clean sessions until their drain budget expires. Never
  // infer completion from IsAlive(): H3 currently always returns true there.
  const draining = new Set();
  const counters = { accepted: 0, completed: 0, rejected: 0, idle_expired: 0,
    drain_expired: 0, upload_bytes: 0, download_bytes: 0, gc_collections: 0, gc_ms: 0 };
  let retiredSinceCollection = 0;
  let lastCollection = Math.floor(ChromeUtils.now());
  const sweep = setInterval(() => {
    const now = Math.floor(ChromeUtils.now());
    for (const session of sessions) {
      if (session.remote && now - session.lastProgress >= cfg.idle_timeout_ms) {
        counters.idle_expired++; session.close();
      }
    }
    for (const session of draining) {
      if (now >= session.drainDeadline) { counters.drain_expired++; session.close(); }
    }
    // Bound reclamation of native wrappers and callback cycles in the
    // embedded shell without relying on browser idle GC/CC scheduling.
    // Collect retired work at a bounded cadence; keep live objects rooted
    // and leave HTTP/TLS
    // caches alone (no global memory-pressure notification).
    if (retiredSinceCollection >= 64 && now - lastCollection >= 5000) {
      const start = ChromeUtils.now();
      Cu.forceGC(); Cu.forceCC(); Cu.forceGC();
      counters.gc_collections++;
      counters.gc_ms += Math.ceil(ChromeUtils.now() - start);
      retiredSinceCollection = 0;
      lastCollection = Math.floor(ChromeUtils.now());
    }
  }, Math.max(50, Math.min(1000, cfg.idle_timeout_ms / 2, cfg.drain_timeout_ms / 2)));
  const stats = cfg.stats_interval_ms ? setInterval(() => {
    print(JSON.stringify({ type: "stats", ...sessionStatus(sessions, Math.floor(ChromeUtils.now())),
      idle_limit: cfg.idle_timeout_ms, active: sessions.size, draining: draining.size, ...counters }));
  }, cfg.stats_interval_ms) : null;
  // Standalone proxy handoff cannot reliably initialize several cold CONNECT
  // channels at once (both H2 and H3). Queue setup only; established streams retain
  // independent, concurrent pumps on the native multiplexed connection.
  // The session limit and each session's setup timer also bound this queue.
  let setupTail = Promise.resolve();
  function openTunnel(authority, session) {
    const pending = setupTail.then(() => {
      if (session.closed) throw new Error("Firefox setup cancelled");
      return connect(authority, session);
    });
    setupTail = pending.then(() => {}, () => {});
    return pending;
  }
  function connect(authority, session) {
    return new Promise((resolve, reject) => {
      session.cancelConnect = () => reject(new Error("Firefox setup cancelled"));
      const channel = NetUtil.newChannel({
        uri: `http://${authority}/`, loadUsingSystemPrincipal: true,
        securityFlags: Ci.nsILoadInfo.SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL |
          Ci.nsILoadInfo.SEC_DONT_FOLLOW_REDIRECTS | Ci.nsILoadInfo.SEC_COOKIES_OMIT,
      }).QueryInterface(Ci.nsIHttpChannel);
      const internal = channel.QueryInterface(Ci.nsIHttpChannelInternal);
      internal.blockAuthPrompt = true;
      let handedOff = false;
      session.channel = channel;
      internal.HTTPUpgrade("webrtc", {
        onTransportAvailable(transport, incoming, outgoing) {
          try {
          if (session.closed) { transport.close(Cr.NS_BINDING_ABORTED); return; }
          // Fail closed if Gecko negotiated HTTP/1 or fell back from H3. No
          // application bytes have been sent and no request is replayed here.
          const expected = cfg.transport === "h3-connect" ? "h3" : "h2";
          const actual = channel.protocolVersion;
          if (actual !== expected) {
            transport.close(Cr.NS_BINDING_ABORTED);
            reject(new Error("unexpected proxy protocol")); return;
          }
          handedOff = true;
          session.cancelConnect = null;
          session.remoteTransport = transport;
          const io = new AsyncIO(incoming, outgoing);
          session.remote = io;
          resolve(io);
          } catch { reject(new Error("Firefox native handoff failed")); }
        },
        onUpgradeFailed() { reject(new Error("Firefox CONNECT failed")); },
        QueryInterface: ChromeUtils.generateQI(["nsIHttpUpgradeListener"]),
      });
      internal.setConnectOnly(false);
      channel.asyncOpen({
        onStartRequest() {},
        onDataAvailable() { channel.cancel(Cr.NS_BINDING_ABORTED); reject(new Error("unexpected CONNECT body")); },
        onStopRequest(request, status) {
          if (!Components.isSuccessCode(status) && !handedOff) reject(new Error("Firefox CONNECT failed"));
        },
        QueryInterface: ChromeUtils.generateQI(["nsIStreamListener", "nsIRequestObserver"]),
      });
    });
  }

  // Single-datagram HTTPS relay through Gecko's own nsIHttpChannel. No
  // application UDP datagram is sent over Go TLS, a Go RoundTripper or H3
  // MASQUE. This first native stage supports H2 only; stream-v2 and H3 are
  // rejected until their distinct wire contracts have native adapters.
  function udpFailure(reason) {
    const err = new Error("native UDP transport failure");
    err.reason = reason;
    return err;
  }
  function exchangeUDPThroughNecko(packet, session) {
    if (!cfg.socks_token || cfg.transport !== "h2-connect" || packet.length < 8 || packet.length > 1232) {
      return Promise.reject(new Error("unsupported native UDP operation"));
    }
    return new Promise((resolve, reject) => {
      session.udpSetupPhase = 8; // fixed numeric diagnostics only; no URLs/secrets
      const host = cfg.proxy_host.includes(":") ? `[${cfg.proxy_host}]` : cfg.proxy_host;
      const target = `https://${host}:${cfg.proxy_port}/.well-known/foxtunnel-udp-v1`;
      const channel = NetUtil.newChannel({
        uri: target, loadUsingSystemPrincipal: true,
        securityFlags: Ci.nsILoadInfo.SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL |
          Ci.nsILoadInfo.SEC_DONT_FOLLOW_REDIRECTS | Ci.nsILoadInfo.SEC_COOKIES_OMIT,
      }).QueryInterface(Ci.nsIHttpChannel);
      session.channel = channel;
      session.udpSetupPhase = 9;
      const internal = channel.QueryInterface(Ci.nsIHttpChannelInternal);
      internal.blockAuthPrompt = true;
      session.udpSetupPhase = 10;
      channel.loadFlags |= Ci.nsIRequest.LOAD_BYPASS_CACHE | Ci.nsIRequest.INHIBIT_CACHING;
      session.udpSetupPhase = 11;
      const upload = Cc["@mozilla.org/io/string-input-stream;1"].createInstance(Ci.nsIStringInputStream);
      const binary = String.fromCharCode(...packet);
      session.udpSetupPhase = 12;
      upload.setData(binary, binary.length);
      session.udpSetupPhase = 13;
      channel.QueryInterface(Ci.nsIUploadChannel2)
        .explicitSetUploadStream(upload, "application/octet-stream", packet.length, "POST");
      session.udpSetupPhase = 14;
      channel.setRequestHeader("Proxy-Authorization", cfg.authorization, false);
      let finished = false;
      const received = [];
      const complete = (err, data) => {
        if (finished) return;
        finished = true;
        if (err) reject(err); else resolve(data);
      };
      const timeout = setTimeout(() => {
        channel.cancel(Cr.NS_BINDING_ABORTED);
        complete(udpFailure(7));
      }, cfg.connect_timeout_ms);
      const close = (error, bytes) => { clearTimeout(timeout); complete(error, bytes); };
      session.udpSetupPhase = 15;
      channel.asyncOpen({
        onStartRequest(request) {
          // Require native H2, a fixed endpoint and a no-redirect status.
          try {
            if (channel.protocolVersion !== "h2") {
              channel.cancel(Cr.NS_BINDING_ABORTED);
              close(udpFailure(4)); return;
            }
            if (channel.responseStatus !== 200 && channel.responseStatus !== 204) {
              channel.cancel(Cr.NS_BINDING_ABORTED);
              close(udpFailure(3));
            }
          } catch {
            channel.cancel(Cr.NS_BINDING_ABORTED);
            close(udpFailure(2));
          }
        },
        onDataAvailable(request, input, offset, count) {
          try {
            if (finished || count > 1232 - received.length) {
              throw new Error("oversized UDP HTTPS response");
            }
            const stream = Cc["@mozilla.org/binaryinputstream;1"].createInstance(Ci.nsIBinaryInputStream);
            stream.setInputStream(input);
            const bytes = new Uint8Array(count);
            if (stream.readArrayBuffer(count, bytes.buffer) !== count) throw new Error("truncated UDP HTTPS response");
            received.push(...bytes);
          } catch {
            channel.cancel(Cr.NS_BINDING_ABORTED);
            close(udpFailure(6));
          }
        },
        onStopRequest(request, status) {
          if (finished) return;
          if (!Components.isSuccessCode(status)) {
            close(udpFailure(5)); return;
          }
          if (channel.protocolVersion !== "h2") {
            close(udpFailure(4)); return;
          }
          if (channel.responseStatus === 204 && received.length === 0) {
            close(null, Uint8Array.of()); return;
          }
          if (channel.responseStatus !== 200 || received.length < 8) {
            close(udpFailure(6)); return;
          }
          close(null, Uint8Array.from(received));
        },
        QueryInterface: ChromeUtils.generateQI(["nsIStreamListener", "nsIRequestObserver"]),
      });
      session.udpSetupPhase = 0;
    });
  }

  async function pump(source, destination, session, direction) {
    return pumpBuffered(source, destination,
      () => { session.lastProgress = Math.floor(ChromeUtils.now()); },
      count => { counters[direction] += count; });
  }
  async function serve(transport) {
    if (sessions.size >= cfg.max_connections || sessions.size + draining.size >= cfg.max_retained_connections) {
      counters.rejected++; transport.close(Cr.NS_BINDING_ABORTED); return;
    }
    counters.accepted++;
    // Closing an ordinary Gecko socket output does not send FIN while input
    // remains open. Enable the pinned plain-TCP fix on the local SOCKS socket.
    // The guard keeps older research runtimes usable for blocker diagnostics.
    if (typeof Ci.nsISocketTransport.ENABLE_TCP_HALF_CLOSE === "number") {
      transport.connectionFlags |= Ci.nsISocketTransport.ENABLE_TCP_HALF_CLOSE;
    }
    const local = new AsyncIO(
      transport.openInputStream(0, 0, 0).QueryInterface(Ci.nsIAsyncInputStream),
      transport.openOutputStream(0, 0, 0).QueryInterface(Ci.nsIAsyncOutputStream));
    const session = { local, closed: false, established: false, lastProgress: Math.floor(ChromeUtils.now()), channel: null, remote: null };
    session.close = (graceful = false) => {
      if (session.closed) return;
      // Both pumps close their destination writer on clean EOF. Native
      // copiers still own queued bytes and transports until those bytes drain.
      // Aborting here would discard the tail under network backpressure.
      if (graceful) {
        session.drainDeadline = Math.floor(ChromeUtils.now()) + cfg.drain_timeout_ms;
        draining.add(session); counters.completed++; return;
      }
      session.closed = true;
      sessions.delete(session); draining.delete(session);
      if (session.cancelConnect) { session.cancelConnect(); session.cancelConnect = null; }
      if (session.channel) session.channel.cancel(Cr.NS_BINDING_ABORTED);
      local.close();
      if (session.remote) session.remote.close();
      if (session.remoteTransport) session.remoteTransport.close(Cr.NS_BINDING_ABORTED);
      transport.close(Cr.NS_BINDING_ABORTED);
      // Retired sessions must not retain native channels/streams through the
      // session -> close closure -> serve scope after their drain deadline.
      session.channel = session.remote = session.remoteTransport = session.local = null;
      session.close = () => {};
      retiredSinceCollection++;
    };
    sessions.add(session);
    const timer = setTimeout(session.close, cfg.connect_timeout_ms);
    let established = false;
    let completed = false;
    try {
      const parser = new SocksParser();
      let greeting = null;
      while (greeting === null) {
        const chunk = await local.read(); if (chunk === null) return;
        parser.push(chunk); greeting = parser.greeting(cfg.socks_token ? 2 : 0);
      }
      await local.write(Uint8Array.from([5, greeting ? (cfg.socks_token ? 2 : 0) : 255]));
      if (!greeting) return;
      if (cfg.socks_token) {
        let auth = parser.authentication();
        while (auth === null) {
          const chunk = await local.read(); if (chunk === null) return;
          parser.push(chunk); auth = parser.authentication();
        }
        if (auth.user !== "foxtunnel" || auth.password !== cfg.socks_token) {
          await local.write(Uint8Array.from([1, 1])); return;
        }
        await local.write(Uint8Array.from([1, 0]));
      }
      let request = parser.request();
      while (request === null) {
        const chunk = await local.read(); if (chunk === null) return;
        parser.push(chunk); request = parser.request();
      }
      if (request.udp) {
        // Fail closed for an unauthenticated/public SOCKS socket and for
        // transports without a native H2 request bridge.
        established = true;
        try {
          const answer = await exchangeUDPThroughNecko(request.udp, session);
          if (!session.closed) await local.write(udpIPCReply(answer));
        } catch (error) {
          if (!session.closed) {
            const reason = Number.isInteger(error?.reason) ? error.reason : (session.udpSetupPhase || 2);
            try { await local.write(udpIPCReply(null, true, reason)); } catch {}
          }
        }
        return;
      }
      const remote = await openTunnel(request.authority, session);
      clearTimeout(timer);
      await local.write(socksReply(0)); established = true; session.established = true; session.lastProgress = Math.floor(ChromeUtils.now());
      if (request.early.length) {
        await remote.write(request.early);
        session.lastProgress = Math.floor(ChromeUtils.now());
        counters.upload_bytes += request.early.length;
      }
      // A failed pump aborts both directions. A clean EOF half-closes only
      // that direction; the other can deliver the remaining response bytes.
      await Promise.all([pump(local, remote, session, "upload_bytes"), pump(remote, local, session, "download_bytes")]);
      completed = true;
    } catch {
      if (!established && !session.closed) {
        try { await local.write(socksReply(1)); } catch {}
      }
      // Do not serialize exception text: Gecko errors may contain targets.
    } finally { clearTimeout(timer); session.close(completed); sessions.delete(session); }
  }

  const server = Cc["@mozilla.org/network/server-socket;1"].createInstance(Ci.nsIServerSocket);
  server.init(cfg.listen_port === 0 ? -1 : cfg.listen_port, true, 128);
  let stopped = false;
  server.asyncListen({
    onSocketAccepted(socket, transport) { void serve(transport); },
    onStopListening() { stopped = true; },
    QueryInterface: ChromeUtils.generateQI(["nsIServerSocketListener"]),
  });
  print(JSON.stringify({ type: "ready", engine: "firefox-necko", transport: cfg.transport,
    listen: `127.0.0.1:${server.port}`, pid: Services.appinfo.processID, process_tag: root.split("/").pop(), version: Services.appinfo.platformVersion }));
  // Standalone xpcshell has no browser event loop. All callbacks above run on
  // this thread; native socket work remains on Gecko's networking threads.
  Services.tm.spinEventLoopUntil("FoxTunnel Firefox networking", () => stopped);
  for (const session of sessions) session.close();
  for (const session of draining) session.close();
  clearInterval(sweep); if (stats !== null) clearInterval(stats);
  pps.unregisterFilter(filter);
}

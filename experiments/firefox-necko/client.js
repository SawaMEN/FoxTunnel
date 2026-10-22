"use strict";

// The parser is independent of XPCOM so malformed and fragmented SOCKS frames
// can also be tested with Node. All public network I/O below belongs to Necko.
class SocksParser {
  constructor() { this.bytes = []; this.greeted = false; }
  push(data) {
    if (this.bytes.length + data.length > 65536) throw new Error("SOCKS input limit");
    this.bytes.push(...data);
  }
  greeting() {
    const b = this.bytes;
    if (b.length < 2) return null;
    if (b[0] !== 5 || b[1] === 0) throw new Error("invalid SOCKS greeting");
    if (b.length < 2 + b[1]) return null;
    const accepted = b.slice(2, 2 + b[1]).includes(0);
    b.splice(0, 2 + b[1]); this.greeted = true;
    return accepted;
  }
  request() {
    const b = this.bytes;
    if (!this.greeted) throw new Error("SOCKS greeting required");
    if (b.length < 4) return null;
    if (b[0] !== 5 || b[1] !== 1 || b[2] !== 0) throw new Error("only SOCKS5 CONNECT is supported");
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

function socksReply(code) { return Uint8Array.from([5, code, 0, 1, 0, 0, 0, 0, 0, 0]); }

if (typeof module !== "undefined") module.exports = { SocksParser, socksReply };

if (typeof Components !== "undefined") {
  const { classes: Cc, interfaces: Ci, results: Cr } = Components;
  const { NetUtil } = ChromeUtils.importESModule("resource://gre/modules/NetUtil.sys.mjs");
  const { setTimeout, clearTimeout } = ChromeUtils.importESModule("resource://gre/modules/Timer.sys.mjs");
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

  const pps = Cc["@mozilla.org/network/protocol-proxy-service;1"].getService(Ci.nsIProtocolProxyService);
  // A fixed proxy with no DIRECT/failover entry. Credentials are attached to
  // that proxy, not to a destination URI or an inner application request.
  const proxyFlags = Ci.nsIProxyInfo.ALWAYS_TUNNEL_VIA_PROXY | Ci.nsIProxyInfo.TRANSPARENT_PROXY_RESOLVES_HOST;
  const proxy = cfg.transport === "h3-connect"
    ? pps.newMASQUEProxyInfo(cfg.proxy_host, cfg.proxy_port,
        "/.well-known/masque/udp/{target_host}/{target_port}/", cfg.authorization, "foxtunnel-firefox", proxyFlags, 0, null)
    : pps.newProxyInfo("https", cfg.proxy_host, cfg.proxy_port, cfg.authorization, "foxtunnel-firefox", proxyFlags, 0, null);
  const filter = {
    applyFilter(uri, previous, callback) { callback.onProxyFilterResult(proxy); },
    QueryInterface: ChromeUtils.generateQI(["nsIProtocolProxyFilter"]),
  };
  pps.registerFilter(filter, 0);

  class AsyncIO {
    constructor(input, output) { this.input = input; this.output = output; }
    read() {
      return new Promise((resolve, reject) => {
        const callback = {
          onInputStreamReady: stream => {
            try {
              const n = Math.min(stream.available(), 32768);
              if (!n) { resolve(null); return; }
              const binary = Cc["@mozilla.org/binaryinputstream;1"].createInstance(Ci.nsIBinaryInputStream);
              binary.setInputStream(stream);
              resolve(Uint8Array.from(binary.readByteArray(n)));
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
      // One pending chunk per direction; backpressure reaches the SOCKS peer.
      let offset = 0;
      while (offset < data.length) {
        await new Promise((resolve, reject) => {
          this.output.asyncWait({
            onOutputStreamReady: stream => {
              try {
                const text = String.fromCharCode(...data.subarray(offset, offset + 32768));
                const n = stream.write(text, text.length);
                if (n <= 0) throw Cr.NS_BASE_STREAM_CLOSED;
                offset += n; resolve();
              } catch (e) {
                if (e.result === Cr.NS_BASE_STREAM_WOULD_BLOCK) resolve();
                else reject(e);
              }
            }, QueryInterface: ChromeUtils.generateQI(["nsIOutputStreamCallback"]),
          }, 0, 0, thread);
        });
      }
    }
    close() { try { this.input.close(); } catch {} try { this.output.close(); } catch {} }
  }

  const sessions = new Set();
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

  async function pump(source, destination) {
    for (;;) {
      const data = await source.read();
      if (data === null) { destination.output.close(); return; }
      await destination.write(data);
    }
  }
  async function serve(transport) {
    if (sessions.size >= cfg.max_connections) { transport.close(Cr.NS_BINDING_ABORTED); return; }
    // Closing an ordinary Gecko socket output does not send FIN while input
    // remains open. Enable the pinned plain-TCP fix on the local SOCKS socket.
    // The guard keeps older research runtimes usable for blocker diagnostics.
    if (typeof Ci.nsISocketTransport.ENABLE_TCP_HALF_CLOSE === "number") {
      transport.connectionFlags |= Ci.nsISocketTransport.ENABLE_TCP_HALF_CLOSE;
    }
    const local = new AsyncIO(
      transport.openInputStream(0, 0, 0).QueryInterface(Ci.nsIAsyncInputStream),
      transport.openOutputStream(0, 0, 0).QueryInterface(Ci.nsIAsyncOutputStream));
    const session = { local, closed: false, channel: null, remote: null };
    session.close = () => {
      if (session.closed) return;
      session.closed = true;
      if (session.cancelConnect) { session.cancelConnect(); session.cancelConnect = null; }
      if (session.channel) session.channel.cancel(Cr.NS_BINDING_ABORTED);
      local.close();
      if (session.remote) session.remote.close();
      if (session.remoteTransport) session.remoteTransport.close(Cr.NS_BINDING_ABORTED);
      transport.close(Cr.NS_BINDING_ABORTED);
    };
    sessions.add(session);
    const timer = setTimeout(session.close, cfg.connect_timeout_ms);
    let established = false;
    try {
      const parser = new SocksParser();
      let greeting = null;
      while (greeting === null) {
        const chunk = await local.read(); if (chunk === null) return;
        parser.push(chunk); greeting = parser.greeting();
      }
      await local.write(Uint8Array.from([5, greeting ? 0 : 255]));
      if (!greeting) return;
      let request = parser.request();
      while (request === null) {
        const chunk = await local.read(); if (chunk === null) return;
        parser.push(chunk); request = parser.request();
      }
      const remote = await openTunnel(request.authority, session);
      clearTimeout(timer);
      await local.write(socksReply(0)); established = true;
      if (request.early.length) await remote.write(request.early);
      // A failed pump aborts both directions. A clean EOF half-closes only
      // that direction; the other can deliver the remaining response bytes.
      await Promise.all([pump(local, remote), pump(remote, local)]);
    } catch {
      if (!established && !session.closed) {
        try { await local.write(socksReply(1)); } catch {}
      }
      // Do not serialize exception text: Gecko errors may contain targets.
    } finally { clearTimeout(timer); session.close(); sessions.delete(session); }
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
    listen: `127.0.0.1:${server.port}`, version: Services.appinfo.platformVersion }));
  // Standalone xpcshell has no browser event loop. All callbacks above run on
  // this thread; native socket work remains on Gecko's networking threads.
  Services.tm.spinEventLoopUntil("FoxTunnel Firefox networking", () => stopped);
  for (const session of sessions) session.close();
  pps.unregisterFilter(filter);
}

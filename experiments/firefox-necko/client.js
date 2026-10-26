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
    if (b[1] === 0xf2) {
      if (b[3] !== 0) throw new Error("invalid private HTTP operation");
      if (b.length < 6) return null;
      const length = (b[4] << 8) | b[5];
      if (length < 2 || length > 16384) throw new Error("HTTP metadata limit");
      if (b.length < 6 + length) return null;
      const metadata = JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(Uint8Array.from(b.slice(6, 6 + length))));
      validateHTTPMetadata(metadata);
      b.splice(0, 6 + length);
      return {http: metadata, early: Uint8Array.from(b.splice(0))};
    }
    if (b[1] === 0xf1) {
      if (b[3] !== 0 || b.length !== 4) throw new Error("invalid private UDP stream operation");
      b.splice(0, 4);
      return { udpStream: true };
    }
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

// Metadata never contains an origin or credentials. Every public request is
// constrained to the helper's configured HTTPS origin and authorization.
function validateHTTPMetadata(meta) {
  if (!meta || !["GET", "POST", "HEAD", "CONNECT"].includes(meta.method) ||
      typeof meta.origin !== "string" || !/^https:\/\/([A-Za-z0-9_.-]+|\[[0-9A-Fa-f:]+\])(:[0-9]{1,5})?$/.test(meta.origin) ||
      typeof meta.path !== "string" || !meta.path.startsWith("/") ||
      meta.path.startsWith("//") || /[\\#\x00-\x20\x7f-\uffff]/.test(meta.path) ||
      typeof meta.body !== "boolean" || (meta.body && meta.method !== "POST" && meta.method !== "CONNECT") ||
      typeof meta.host !== "string" || /[^A-Za-z0-9_.:\[\]-]/.test(meta.host) ||
      !Array.isArray(meta.headers) || meta.headers.length > 64)
    throw new Error("invalid native HTTP metadata");
  if (meta.length === undefined) meta.length = -1;
  if (!Number.isInteger(meta.length) || meta.length < -1 || meta.length > 1048576 || (!meta.body && meta.length > 0))
    throw new Error("invalid native HTTP upload length");
  for (const h of meta.headers) {
    if (!Array.isArray(h) || h.length !== 2 || typeof h[0] !== "string" ||
        typeof h[1] !== "string" || !/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(h[0]) ||
        /[\x00-\x08\x0a-\x1f\x7f-\uffff]/.test(h[1]) ||
        /^(connection|transfer-encoding|upgrade|host|cookie|authorization|proxy-connection|te|trailer)$/i.test(h[0]))
      throw new Error("invalid native HTTP header");
  }
}
function httpChunkHeader(length) {
  const data = new Uint8Array(4); new DataView(data.buffer).setUint32(0, length); return data;
}
// Pull one bounded IPC frame at a time. EOF without the explicit terminator is
// always an error, including EOF exactly between frame boundaries.
async function pumpHTTPUpload(source, destination, early = new Uint8Array(), progress = () => {}) {
  let buffered = early;
  const readExact = async count => {
    const result = new Uint8Array(count); let offset = 0;
    while (offset < count) {
      if (!buffered.length) {buffered = await source.read(); if (buffered === null) throw new Error("truncated HTTP upload");}
      const take = Math.min(count - offset, buffered.length);
      result.set(buffered.subarray(0, take), offset); offset += take; buffered = buffered.subarray(take);
    }
    return result;
  };
  for (;;) {
    const header = await readExact(4), length = new DataView(header.buffer).getUint32(0);
    if (!length) {if (buffered.length) throw new Error("HTTP bytes after terminator"); destination.output.close(); return;}
    if (length > 32768) throw new Error("HTTP upload chunk limit");
    const chunk = await readExact(length); await destination.write(chunk); progress(length);
  }
}
async function collectHTTPUpload(source, early, length) {
  if (!Number.isInteger(length) || length < 0 || length > 1048576) throw new Error("fixed HTTP upload limit");
  const body = new Uint8Array(length);let offset = 0;
  await pumpHTTPUpload(source, {output:{close(){}}, async write(chunk){
    if (chunk.length > length-offset) throw new Error("fixed HTTP upload overflow");
    body.set(chunk,offset);offset += chunk.length;
  }}, early);
  if (offset!==length) throw new Error("fixed HTTP upload truncated");
  return body;
}
async function pumpHTTPDownload(source, destination, progress = () => {}) {
  const scratch = new Uint8Array(32768);
  for (;;) {
    const chunk = await source.read(scratch);
    if (chunk === null) {await destination.write(httpChunkHeader(source.failed ? 0xffffffff : 0)); return;}
    await destination.write(httpChunkHeader(chunk.length)); await destination.write(chunk); progress(chunk.length);
  }
}

// FoxTunnel UDP stream-v2 uses BE16-sized, complete RFC1928 UDP packets.
// Keep this codec independent of XPCOM for deterministic fuzz and fragment
// testing. The native streaming adapter below uses bounded async pipes.
const MAX_NATIVE_UDP_DATAGRAM = 1232;
function validateNativeUDPDatagram(data) {
  if (!(data instanceof Uint8Array) || data.length < 8 ||
      data.length > MAX_NATIVE_UDP_DATAGRAM || data[0] !== 0 ||
      data[1] !== 0 || data[2] !== 0) throw new Error("invalid native UDP datagram");
  let end;
  switch (data[3]) {
    case 1: end = 8; break;
    case 4: end = 20; break;
    case 3: {
      if (data.length < 7 || !data[4]) throw new Error("invalid native UDP hostname");
      end = 5 + data[4];
      if (data.length < end + 2) throw new Error("truncated native UDP hostname");
      for (let i = 5; i < end; i++) {
        const byte = data[i];
        if (byte === 0 || byte === 32 || (byte >= 9 && byte <= 13) ||
            byte === 47 || byte === 92 || byte === 64 || byte === 63 || byte === 35)
          throw new Error("invalid native UDP hostname");
      }
      break;
    }
    default: throw new Error("unknown native UDP address type");
  }
  if (data.length < end + 2 || (data[end] === 0 && data[end + 1] === 0))
    throw new Error("invalid native UDP destination port");
  return true;
}
function encodeNativeUDPStreamFrame(packet) {
  validateNativeUDPDatagram(packet);
  const frame = new Uint8Array(packet.length + 2);
  frame[0] = packet.length >>> 8;
  frame[1] = packet.length & 255;
  frame.set(packet, 2);
  return frame;
}
class NativeUDPFrameDecoder {
  constructor(onPacket) {
    if (typeof onPacket !== "function") throw new TypeError("onPacket required");
    this.onPacket = onPacket;
    this.buffer = new Uint8Array(MAX_NATIVE_UDP_DATAGRAM);
    this.length = -1;
    this.offset = 0;
    this.header = -1;
  }
  push(chunk) {
    if (!(chunk instanceof Uint8Array) || chunk.length > 32768)
      throw new Error("invalid native UDP stream chunk");
    for (let i = 0; i < chunk.length;) {
      if (this.length < 0) {
        if (this.header < 0) { this.header = chunk[i++]; continue; }
        this.length = (this.header << 8) | chunk[i++];
        this.header = -1;
        if (this.length < 8 || this.length > MAX_NATIVE_UDP_DATAGRAM)
          throw new Error("invalid native UDP stream frame length");
        this.offset = 0;
      }
      const count = Math.min(this.length - this.offset, chunk.length - i);
      this.buffer.set(chunk.subarray(i, i + count), this.offset);
      this.offset += count;
      i += count;
      if (this.offset === this.length) {
        const packet = Uint8Array.from(this.buffer.subarray(0, this.length));
        this.offset = 0;
        this.length = -1;
        validateNativeUDPDatagram(packet);
        // The callback is synchronous: no unbounded event queue can build up.
        this.onPacket(packet);
      }
    }
  }
  finish() {
    if (this.header >= 0 || this.length >= 0)
      throw new Error("truncated native UDP stream frame");
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

// Validate each complete datagram before forwarding it. Read no further input
// while a downstream write is pending; at most one 32 KiB chunk and one partial
// packet are retained. A partial final frame aborts the stream rather than FIN.
async function pumpNativeUDPFrames(source, destination, onProgress = () => {}) {
  const scratch = new Uint8Array(32768);
  let packets = [];
  const decoder = new NativeUDPFrameDecoder(packet => packets.push(packet));
  for (;;) {
    const chunk = await source.read(scratch);
    if (chunk === null) {
      decoder.finish();
      destination.output.close();
      return;
    }
    decoder.push(chunk);
    for (const packet of packets) {
      await destination.write(encodeNativeUDPStreamFrame(packet));
      onProgress(packet.length);
    }
    packets = [];
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

// The pinned native runtime reports this status but does not expose its name
// in Components.results. Its value is fixed by xpcom/base/ErrorList.py.
function nativeHTTPFailureReason(status, results) {
  const uncleanShutdown = results.NS_ERROR_NET_UNCLEAN_SHUTDOWN ?? 0x804b0065;
  return [results.NS_ERROR_CONNECTION_REFUSED, results.NS_ERROR_NET_TIMEOUT,
    results.NS_ERROR_NET_RESET, results.NS_ERROR_OFFLINE, results.NS_ERROR_UNKNOWN_HOST,
    uncleanShutdown].includes(status) ? 2 : 1;
}

// Inputs are canonical native URI hosts. A primary policy never follows a
// request to another host or port, including discovered/fallback nodes.
function nativeRoutePolicy(cfg, host, port) {
  if (cfg.node_policies && Object.keys(cfg.node_policies).length) {
    const authority = host.includes(":") ? `[${host.toLowerCase()}]:${port}` : `${host.toLowerCase()}:${port}`;
    if (!Object.hasOwn(cfg.node_policies, authority)) throw new Error("HTTPS route has no configured identity policy");
    const policy = cfg.node_policies[authority];
    return {serverName:policy.sni || "", pin:policy.pin_sha256, tlsProfile:cfg.tls_client_profile === "firefox-158" ? "firefox-158" : ""};
  }
  const primary = host.toLowerCase() === cfg.proxy_host.toLowerCase() && port === cfg.proxy_port;
  return {serverName: primary ? (cfg.server_name || "") : "",
    pin: primary ? (cfg.pin_sha256 || "") : "",
    tlsProfile: cfg.tls_client_profile === "firefox-158" ? "firefox-158" : ""};
}

if (typeof module !== "undefined") module.exports = {
  SocksParser, socksReply, firefoxUserAgent, pumpBuffered, nativeHTTPFailureReason, nativeRoutePolicy,
  validateHTTPMetadata, httpChunkHeader, pumpHTTPUpload, pumpHTTPDownload, collectHTTPUpload,
  writeAllWithBackpressure, sessionStatus, udpIPCReply,
  validateNativeUDPDatagram, encodeNativeUDPStreamFrame, NativeUDPFrameDecoder, pumpNativeUDPFrames,
};

if (typeof Components !== "undefined") {
  const { classes: Cc, interfaces: Ci, results: Cr } = Components;
  const { NetUtil } = ChromeUtils.importESModule("resource://gre/modules/NetUtil.sys.mjs");
  const { setTimeout, clearTimeout, setInterval, clearInterval } = ChromeUtils.importESModule("resource://gre/modules/Timer.sys.mjs");
  Components.utils.importGlobalProperties(["TextEncoder", "TextDecoder"]);
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

  const primaryURIHost = cfg.proxy_host.includes(":") ? `[${cfg.proxy_host}]` : cfg.proxy_host;
  cfg.proxy_host = Services.io.newURI(`https://${primaryURIHost}:${cfg.proxy_port}`).host;
  const nativeCertDB = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
  function registerEndpoint(host, port) {
    // Identity belongs only to the primary origin, never an alternate node.
    const {serverName: sni, pin, tlsProfile} = nativeRoutePolicy(cfg, host, port);
    if (sni || pin || tlsProfile) {
      if (typeof nativeCertDB.registerFoxTunnelPolicy !== "function") throw new Error("native identity API required");
      nativeCertDB.registerFoxTunnelPolicy(host, port, sni, pin, tlsProfile);
    }
  }
  registerEndpoint(cfg.proxy_host, cfg.proxy_port);
  if (cfg.server_name || cfg.pin_sha256 || (cfg.node_policies && Object.keys(cfg.node_policies).length) || cfg.tls_client_profile === "firefox-158") {
    Services.prefs.setBoolPref("network.http.http2.coalesce-hostnames", false);
    // No credentials may enter QUIC early data before the pin is checked.
    Services.prefs.setBoolPref("network.http.http3.enable_0rtt", false);
    Services.prefs.setBoolPref("security.tls.enable_0rtt_data", false);
  }
  if (cfg.tls_client_profile === "firefox-158") {
    Services.prefs.setIntPref("security.tls.version.min", 4);
    Services.prefs.setIntPref("security.tls.version.max", 4);
  }
  if (cfg.http2_receive_profile === "firefox-158") {
    Services.prefs.setIntPref("network.http.http2.push-allowance", 131072);
    Services.prefs.setIntPref("network.http.http2.pull-allowance", 12582912);
    Services.prefs.setIntPref("network.http.http2.default-hpack-buffer", 65536);
  }

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
  const channelProxies = new WeakMap();
  const filter = {
    applyFilter(channel, previous, callback) {
      if (channelProxies.has(channel)) {callback.onProxyFilterResult(channelProxies.get(channel)); return;}
      const uri = channel.URI;
      // Authenticated native HTTP IPC addresses its verified origin directly.
      // CONNECT handoff uses an HTTP URI and a per-channel proxy override.
      // Never inherit a system proxy or recursively tunnel a carrier POST.
      if (uri.scheme === "https" && cfg.socks_token) {
        callback.onProxyFilterResult(null); return;
      }
      callback.onProxyFilterResult(proxy);
    },
    QueryInterface: ChromeUtils.generateQI(["nsIProtocolProxyChannelFilter"]),
  };
  pps.registerChannelFilter(filter, 0);

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
  let bytesAtCollection = 0;
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
    // Persistent HTTP/Bond channels allocate temporary wrappers and buffers
    // without retiring sessions. Collect by traffic as well as retired work,
    // at the same bounded cadence. Live objects and HTTP/TLS caches stay rooted;
    // do not send a global memory-pressure notification.
    const transferred = counters.upload_bytes + counters.download_bytes;
    const idleGarbage = sessions.size === 0 && draining.size === 0 &&
      (retiredSinceCollection > 0 || transferred > bytesAtCollection);
    if ((idleGarbage || retiredSinceCollection >= 64 || transferred - bytesAtCollection >= 16 * 1024 * 1024) &&
        now - lastCollection >= 5000) {
      const start = ChromeUtils.now();
      Cu.forceGC(); Cu.forceCC(); Cu.forceGC();
      counters.gc_collections++;
      counters.gc_ms += Math.ceil(ChromeUtils.now() - start);
      retiredSinceCollection = 0;
      bytesAtCollection = transferred;
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
  function openTunnel(authority, session, origin = null) {
    const pending = setupTail.then(() => {
      if (session.closed) throw new Error("Firefox setup cancelled");
      return connect(authority, session, origin);
    });
    setupTail = pending.then(() => {}, () => {});
    return pending;
  }
  function nativeHTTPFailure(status) {
    const error = new Error("native HTTP setup failed");
    // A multiplexed connection can disappear before response headers without
    // GOAWAY. Gecko reports a distinct network status for that case; keep TLS
    // and protocol errors terminal while sequence-based carriers recover.
    error.nativeHTTPReason = nativeHTTPFailureReason(status, Cr);
    return error;
  }
  function connect(authority, session, origin) {
    return new Promise((resolve, reject) => {
      session.cancelConnect = () => reject(new Error("Firefox setup cancelled"));
      const channel = NetUtil.newChannel({
        uri: `http://${authority}/`, loadUsingSystemPrincipal: true,
        securityFlags: Ci.nsILoadInfo.SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL |
          Ci.nsILoadInfo.SEC_DONT_FOLLOW_REDIRECTS | Ci.nsILoadInfo.SEC_COOKIES_OMIT,
      }).QueryInterface(Ci.nsIHttpChannel);
      if (origin) {
        const endpoint = Services.io.newURI(origin);
        registerEndpoint(endpoint.host, endpoint.port === -1 ? 443 : endpoint.port);
        const port = endpoint.port === -1 ? 443 : endpoint.port;
        const selectedProxy = cfg.transport === "h3-connect"
          ? pps.newMASQUEProxyInfo(endpoint.host, port, "/.well-known/masque/udp/{target_host}/{target_port}/", cfg.authorization, "foxtunnel-firefox", proxyFlags, 0, null)
          : pps.newProxyInfo("https", endpoint.host, port, cfg.authorization, "foxtunnel-firefox", proxyFlags, 0, null);
        channelProxies.set(channel, selectedProxy);
      }
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
        onUpgradeFailed(status) { reject(nativeHTTPFailure(status)); },
        QueryInterface: ChromeUtils.generateQI(["nsIHttpUpgradeListener"]),
      });
      internal.setConnectOnly(false);
      channel.asyncOpen({
        onStartRequest() {},
        onDataAvailable() { channel.cancel(Cr.NS_BINDING_ABORTED); reject(new Error("unexpected CONNECT body")); },
        onStopRequest(request, status) {
          if (!Components.isSuccessCode(status) && !handedOff) reject(nativeHTTPFailure(status));
        },
        QueryInterface: ChromeUtils.generateQI(["nsIStreamListener", "nsIRequestObserver"]),
      });
    });
  }

  // Single-datagram HTTPS relay through Gecko's own nsIHttpChannel. No
  // application UDP datagram is sent over Go TLS, a Go RoundTripper or H3
  // MASQUE. H3 requires the pinned native HTTP3-only API and never races TCP.
  function udpFailure(reason) {
    const err = new Error("native UDP transport failure");
    err.reason = reason;
    return err;
  }
  function exchangeUDPThroughNecko(packet, session) {
    if (!cfg.socks_token || !["h2-connect", "h3-connect"].includes(cfg.transport) || packet.length < 8 || packet.length > 1232) {
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
      if (cfg.transport === "h3-connect") {internal.allowHttp3 = true; internal.forceHTTP3();}
      else {internal.allowHttp3 = false;}
      session.udpSetupPhase = 10;
      channel.loadFlags |= Ci.nsIRequest.LOAD_BYPASS_CACHE | Ci.nsIRequest.INHIBIT_CACHING;
      session.udpSetupPhase = 11;
      // The pinned Gecko revision removed nsIStringInputStream.setData().
      // Use the scriptable ArrayBuffer stream so arbitrary 0x00 / 0xff UDP
      // bytes are uploaded exactly, with no UTF-8 conversion or URI encoding.
      const upload = Cc["@mozilla.org/io/arraybuffer-input-stream;1"]
        .createInstance(Ci.nsIArrayBufferInputStream);
      const binary = Uint8Array.from(packet);
      session.udpSetupPhase = 12;
      upload.setData(binary.buffer, binary.byteOffset, binary.byteLength);
      session.udpSetupPhase = 13;
      // Finite carrier bodies must also opt into the native non-replayable
      // path. Preserve their exact length on the wire from this owned buffer.
      internal.enableStreamingUpload();
      channel.QueryInterface(Ci.nsIUploadChannel2)
        .explicitSetUploadStream(upload, "application/octet-stream", packet.length, "POST");
      channel.setRequestHeader("Content-Length", String(packet.length), false);
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
          // Require the selected native protocol, a fixed endpoint and no redirects.
          try {
            if (channel.protocolVersion !== (cfg.transport === "h3-connect" ? "h3" : "h2")) {
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
          if (channel.protocolVersion !== (cfg.transport === "h3-connect" ? "h3" : "h2")) {
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

  // Experimental UDP-v2 bridge. Production configuration remains gated until
  // the pinned runtime passes native full-duplex and long-session validation.
  function openUDPStreamThroughNecko(session) {
    if (!cfg.socks_token || !["h2-connect", "h3-connect"].includes(cfg.transport))
      return Promise.reject(new Error("unsupported native UDP stream"));
    return new Promise((resolve, reject) => {
      const host = cfg.proxy_host.includes(":") ? `[${cfg.proxy_host}]` : cfg.proxy_host;
      const channel = NetUtil.newChannel({
        uri: `https://${host}:${cfg.proxy_port}/.well-known/foxtunnel-udp-stream-v2`,
        loadUsingSystemPrincipal: true,
        securityFlags: Ci.nsILoadInfo.SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL |
          Ci.nsILoadInfo.SEC_DONT_FOLLOW_REDIRECTS | Ci.nsILoadInfo.SEC_COOKIES_OMIT,
      }).QueryInterface(Ci.nsIHttpChannel);
      session.channel = channel;
      channel.contentType = "application/octet-stream";
      const internal = channel.QueryInterface(Ci.nsIHttpChannelInternal);
      internal.blockAuthPrompt = true;
      if (cfg.transport === "h3-connect") {internal.allowHttp3 = true; internal.forceHTTP3();}
      else {internal.allowHttp3 = false;}
      internal.deliverResponseHeadersEarly = true;
      channel.loadFlags |= Ci.nsIRequest.LOAD_BYPASS_CACHE | Ci.nsIRequest.INHIBIT_CACHING;
      const makePipe = () => {
        const pipe = Cc["@mozilla.org/pipe;1"].createInstance(Ci.nsIPipe);
        pipe.init(true, true, 32768, 2);
        return pipe;
      };
      const upload = makePipe(), download = makePipe();
      const remote = new AsyncIO(download.inputStream.QueryInterface(Ci.nsIAsyncInputStream),
        upload.outputStream.QueryInterface(Ci.nsIAsyncOutputStream));
      const sink = new AsyncIO(upload.inputStream.QueryInterface(Ci.nsIAsyncInputStream),
        download.outputStream.QueryInterface(Ci.nsIAsyncOutputStream));
      // Own both ends even if channel setup, TLS or authentication fails.
      const closeRemote = remote.close.bind(remote);
      remote.close = () => { closeRemote(); sink.close(); };
      session.remote = remote;
      // -1 alone requests length discovery and buffers the pipe until EOF.
      // The pinned API opts into Gecko's Fetch streaming path before attaching
      // the pipe. Older runtimes must fail, never silently buffer or use Go.
      channel.QueryInterface(Ci.nsIHttpChannelInternal).enableStreamingUpload();
      channel.QueryInterface(Ci.nsIUploadChannel2).explicitSetUploadStream(
        upload.inputStream, "application/octet-stream", -1, "POST");
      channel.setRequestHeader("Proxy-Authorization", cfg.authorization, false);
      let started = false, pending = Promise.resolve();
      channel.asyncOpen({
        onStartRequest() {
          try {
            if (channel.protocolVersion !== (cfg.transport === "h3-connect" ? "h3" : "h2") || channel.responseStatus !== 200)
              throw new Error("native UDP stream rejected");
            started = true;
            resolve(remote);
          } catch {
            reject(new Error("native UDP stream rejected")); session.close();
          }
        },
        onDataAvailable(request, input, offset, count) {
          try {
            if (!started || count > 1048576) throw new Error("invalid native UDP response chunk");
            const binary = Cc["@mozilla.org/binaryinputstream;1"].createInstance(Ci.nsIBinaryInputStream);
            binary.setInputStream(input);
            const bytes = new Uint8Array(count);
            if (binary.readArrayBuffer(count, bytes.buffer) !== count)
              throw new Error("truncated native UDP response chunk");
            // Suspend before yielding to the event loop. Gecko cannot queue a
            // second callback while the bounded download pipe is blocked.
            channel.suspend();
            pending = sink.write(bytes).then(() => {
              if (!session.closed) channel.resume();
            }).catch(() => session.close());
          } catch { session.close(); }
        },
        onStopRequest(request, status) {
          if (!started) reject(new Error("native UDP stream setup failed"));
          if (!Components.isSuccessCode(status)) { session.close(); return; }
          void pending.then(() => { try { sink.output.close(); } catch {} });
        },
        QueryInterface: ChromeUtils.generateQI(["nsIStreamListener", "nsIRequestObserver"]),
      });
    });
  }

  function openHTTPThroughNecko(session, metadata, fixedBody) {
    if (!cfg.socks_token) return Promise.reject(new Error("native HTTP requires private IPC"));
    if (metadata.method === "CONNECT") {
      if (!metadata.host || !metadata.body || metadata.headers.some(([name]) => !/^proxy-authorization$/i.test(name)))
        return Promise.reject(new Error("native CONNECT request policy unsupported"));
      return openTunnel(metadata.host, session, metadata.origin).then(remote => ({remote, encoded: new TextEncoder().encode(JSON.stringify({status: 200, proto: cfg.transport === "h3-connect" ? 3 : 2, headers: []}))}));
    }
    return new Promise((resolve, reject) => {
      const endpoint = Services.io.newURI(metadata.origin);
      registerEndpoint(endpoint.host, endpoint.port === -1 ? 443 : endpoint.port);
      const channel = NetUtil.newChannel({
        uri: `${metadata.origin}${metadata.path}`, loadUsingSystemPrincipal: true,
        securityFlags: Ci.nsILoadInfo.SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL |
          Ci.nsILoadInfo.SEC_DONT_FOLLOW_REDIRECTS | Ci.nsILoadInfo.SEC_COOKIES_OMIT,
      }).QueryInterface(Ci.nsIHttpChannel);
      session.channel = channel;
      const internal = channel.QueryInterface(Ci.nsIHttpChannelInternal);
      // Binary carrier setup must not wait for MIME sniffing to accumulate a
      // response body when the peer flushes headers before reading upload.
      channel.contentType = "application/octet-stream";
      internal.blockAuthPrompt = true;
      if (cfg.transport === "h3-connect") {internal.allowHttp3 = true; internal.forceHTTP3();}
      else {internal.allowHttp3 = false;}
      internal.deliverResponseHeadersEarly = true;
      channel.loadFlags |= Ci.nsIRequest.LOAD_BYPASS_CACHE | Ci.nsIRequest.INHIBIT_CACHING;
      channel.QueryInterface(Ci.nsIEncodedChannel).applyConversion = false;
      channel.setRequestHeader("Accept-Encoding", "identity", false);
      const makePipe = () => {const p = Cc["@mozilla.org/pipe;1"].createInstance(Ci.nsIPipe); p.init(true, true, 32768, 2); return p;};
      const upload = makePipe(), download = makePipe();
      const remote = new AsyncIO(download.inputStream.QueryInterface(Ci.nsIAsyncInputStream), upload.outputStream.QueryInterface(Ci.nsIAsyncOutputStream));
      const sink = new AsyncIO(upload.inputStream.QueryInterface(Ci.nsIAsyncInputStream), download.outputStream.QueryInterface(Ci.nsIAsyncOutputStream));
      const close = remote.close.bind(remote); remote.close = () => {close(); sink.close();};
      session.remote = remote;
      if (fixedBody !== null) {
        const stream = Cc["@mozilla.org/io/arraybuffer-input-stream;1"].createInstance(Ci.nsIArrayBufferInputStream);
        stream.setData(fixedBody.buffer, fixedBody.byteOffset, fixedBody.byteLength);
        // Gecko's streaming-body guard prevents replay after any request
        // bytes were consumed, even when the owned finite stream is cloneable.
        internal.enableStreamingUpload();
        channel.QueryInterface(Ci.nsIUploadChannel2).explicitSetUploadStream(stream, "application/octet-stream", fixedBody.length, metadata.method);
        channel.setRequestHeader("Content-Length", String(fixedBody.length), false);
        upload.outputStream.close();
      } else if (metadata.body) {
        internal.enableStreamingUpload();
        channel.QueryInterface(Ci.nsIUploadChannel2).explicitSetUploadStream(upload.inputStream, "application/octet-stream", -1, metadata.method);
      } else {channel.requestMethod = metadata.method; upload.outputStream.close();}
      const requestHeaders = new Set();
      for (const [name, value] of metadata.headers) {
        if (/^(proxy-authorization|content-length)$/i.test(name)) continue;
        const key = name.toLowerCase();
        // The first explicit value replaces Gecko's default (notably the
        // upload Content-Type). Only subsequent values are merged.
        channel.setRequestHeader(name, value, requestHeaders.has(key));
        requestHeaders.add(key);
      }
      if (metadata.host) channel.setRequestHeader("Host", metadata.host, false);
      channel.setRequestHeader("Proxy-Authorization", cfg.authorization, false);
      let started = false, pending = Promise.resolve();
      channel.asyncOpen({
        onStartRequest() {
          if (!Components.isSuccessCode(channel.status)) {reject(nativeHTTPFailure(channel.status)); return;}
          try {
            const expected = cfg.transport === "h3-connect" ? "h3" : "h2";
            if (channel.protocolVersion !== expected) throw new Error("unexpected native HTTP protocol");
            const headers = [];
            channel.visitResponseHeaders({visitHeader(name, value) {if (headers.length >= 128) throw new Error("HTTP header limit"); headers.push([name, value]);}});
            const encoded = new TextEncoder().encode(JSON.stringify({status: channel.responseStatus, proto: cfg.transport === "h3-connect" ? 3 : 2, headers}));
            if (encoded.length > 16384) throw new Error("HTTP response metadata limit");
            started = true; resolve({remote, encoded});
          } catch {reject(nativeHTTPFailure(Cr.NS_ERROR_FAILURE)); channel.cancel(Cr.NS_BINDING_ABORTED);}
        },
        onDataAvailable(request, input, offset, count) {
          try {
            // Native delivery may coalesce several 32-KiB segments in one
            // callback. Consume it synchronously as Gecko requires, then
            // suspend while the bounded pipe drains. IPC reads remain 32 KiB.
            if (!started || count > 1048576) throw new Error("native HTTP chunk limit");
            const binary = Cc["@mozilla.org/binaryinputstream;1"].createInstance(Ci.nsIBinaryInputStream); binary.setInputStream(input);
            const bytes = new Uint8Array(count);
            if (binary.readArrayBuffer(count, bytes.buffer) !== count) throw new Error("truncated HTTP response");
            channel.suspend(); pending = sink.write(bytes).then(() => {if (!session.closed) channel.resume();}).catch(() => session.close());
          } catch {session.close();}
        },
        onStopRequest(request, status) {
          if (!started) {reject(nativeHTTPFailure(status)); return;}
          remote.failed = !Components.isSuccessCode(status);
          void pending.then(() => {try {sink.output.close();} catch {}});
        },
        QueryInterface: ChromeUtils.generateQI(["nsIStreamListener", "nsIRequestObserver"]),
      });
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
    let privateHTTP = false;
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
      if (request.http) {
        privateHTTP = true;
        // Start pumping upload immediately, before waiting for response headers.
        // openHTTPThroughNecko synchronously owns session.remote's bounded pipe.
        const fixedBody = request.http.method !== "CONNECT" && request.http.body && request.http.length >= 0
          ? await collectHTTPUpload(local, request.early, request.http.length) : null;
        if (fixedBody !== null) request.early = new Uint8Array();
        const opening = openHTTPThroughNecko(session, request.http, fixedBody);
        let upload = fixedBody !== null ? Promise.resolve() : null;
        if (request.http.body && fixedBody === null && session.remote) {
          upload = pumpHTTPUpload(local, session.remote, request.early, count => {session.lastProgress = Math.floor(ChromeUtils.now()); counters.upload_bytes += count;});
          upload.catch(() => session.close());
        } else if (!request.http.body && request.early.length) throw new Error("unexpected HTTP upload");
        const {remote, encoded} = await opening;
        if (request.http.body && fixedBody === null && upload === null) {
          upload = pumpHTTPUpload(local, remote, request.early, count => {session.lastProgress = Math.floor(ChromeUtils.now()); counters.upload_bytes += count;});
        }
        clearTimeout(timer);
        await local.write(Uint8Array.of(5, 0, encoded.length >>> 8, encoded.length & 255)); await local.write(encoded);
        established = true; session.established = true;
        await Promise.all([upload, pumpHTTPDownload(remote, local, count => {session.lastProgress = Math.floor(ChromeUtils.now()); counters.download_bytes += count;})]);
        local.output.close();
        // The peer closes its IPC socket when the response body is released.
        // Wait for that acknowledgement before retiring native channel owners.
        if (await local.read() !== null) throw new Error("bytes after HTTP upload");
        return;
      }
      if (request.udpStream) {
        const remote = await openUDPStreamThroughNecko(session);
        clearTimeout(timer);
        await local.write(Uint8Array.of(5, 0, 0, 0));
        established = true; session.established = true;
        const progress = direction => count => {
          session.lastProgress = Math.floor(ChromeUtils.now());
          counters[direction] += count;
        };
        await Promise.all([
          pumpNativeUDPFrames(local, remote, progress("upload_bytes")),
          pumpNativeUDPFrames(remote, local, progress("download_bytes")),
        ]);
        return;
      }
      if (request.udp) {
        // Fail closed for an unauthenticated/public SOCKS socket and for
        // transports without a native H2 request bridge.
        established = true;
        let replied = false;
        try {
          const answer = await exchangeUDPThroughNecko(request.udp, session);
          if (!session.closed) { await local.write(udpIPCReply(answer)); replied = true; }
        } catch (error) {
          if (!session.closed) {
            const reason = Number.isInteger(error?.reason) ? error.reason : (session.udpSetupPhase || 2);
            try { await local.write(udpIPCReply(null, true, reason)); replied = true; } catch {}
          }
        }
        if (replied && !session.closed) {
          // write() transfers bytes to the native socket buffer. An immediate
          // transport abort can still discard them. FIN and the peer's close
          // acknowledge delivery of this one-response IPC operation.
          local.output.close();
          if (await local.read() !== null) throw new Error("bytes after UDP operation");
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
    } catch (error) {
      if (!established && !session.closed) {
        try {
          await local.write(privateHTTP ? Uint8Array.of(5, error?.nativeHTTPReason === 2 ? 2 : 1, 0, 0) : socksReply(1));
          if (privateHTTP) {
            local.output.close();
            // Flush the fixed failure category before retiring the socket.
            // Otherwise a certificate denial could look like retryable EOF.
            while (await local.read() !== null) {}
          }
        } catch {}
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
  pps.unregisterChannelFilter(filter);
}

// Full Firefox native CONNECT reference, independent of the SOCKS adapter.
// This invokes Firefox's raw transport API, not ordinary page navigation.
const cfg = arguments[0], done = arguments[arguments.length - 1];
const { classes: Cc, interfaces: Ci, results: Cr } = Components;
const { NetUtil } = ChromeUtils.importESModule("resource://gre/modules/NetUtil.sys.mjs");
const { setTimeout } = ChromeUtils.importESModule("resource://gre/modules/Timer.sys.mjs");
const results = [];
(async () => {
  const db = Cc["@mozilla.org/security/x509certdb;1"].getService(Ci.nsIX509CertDB);
  for (const cert of cfg.ca_pem.matchAll(/-----BEGIN CERTIFICATE-----([A-Za-z0-9+/=\s]+)-----END CERTIFICATE-----/g)) {
    db.addCertFromBase64(cert[1].replace(/\s/g, ""), "CT,,");
  }
  const pps = Cc["@mozilla.org/network/protocol-proxy-service;1"].getService(Ci.nsIProtocolProxyService);
  const flags = Ci.nsIProxyInfo.ALWAYS_TUNNEL_VIA_PROXY | Ci.nsIProxyInfo.TRANSPARENT_PROXY_RESOLVES_HOST;
  const proxy = cfg.transport === "h3-connect"
    ? pps.newMASQUEProxyInfo(cfg.proxy_host, cfg.proxy_port,
        "/.well-known/masque/udp/{target_host}/{target_port}/", cfg.authorization, "foxtunnel-reference", flags, 0, null)
    : pps.newProxyInfo("https", cfg.proxy_host, cfg.proxy_port, cfg.authorization, "foxtunnel-reference", flags, 0, null);
  const filter = {applyFilter(uri, previous, callback) {callback.onProxyFilterResult(proxy);},
    QueryInterface: ChromeUtils.generateQI(["nsIProtocolProxyFilter"])};
  pps.registerFilter(filter, 0);
  try {
    for (let i = 0; i < cfg.rounds; ++i) {
      if (i === 2) await new Promise(resolve => setTimeout(resolve, 700));
      results.push(await new Promise((resolve, reject) => {
        const channel = NetUtil.newChannel({uri: cfg.target, loadUsingSystemPrincipal: true,
          securityFlags: Ci.nsILoadInfo.SEC_ALLOW_CROSS_ORIGIN_SEC_CONTEXT_IS_NULL |
            Ci.nsILoadInfo.SEC_DONT_FOLLOW_REDIRECTS | Ci.nsILoadInfo.SEC_COOKIES_OMIT}).QueryInterface(Ci.nsIHttpChannel);
        const internal = channel.QueryInterface(Ci.nsIHttpChannelInternal);
        internal.blockAuthPrompt = true;
        let handedOff = false;
        internal.HTTPUpgrade("webrtc", {
          onTransportAvailable(transport, incoming, outgoing) {
            handedOff = true;
            const input = incoming.QueryInterface(Ci.nsIAsyncInputStream);
            const output = outgoing.QueryInterface(Ci.nsIAsyncOutputStream);
            const payload = atob(cfg.payload);
            let sent = 0, received = "";
            const finish = () => {input.close(); resolve({bytes: received.length,
              body_ok: received === payload, protocol: channel.protocolVersion});};
            const read = {
              onInputStreamReady(stream) {
                try {
                  const count = Math.min(stream.available(), 32768);
                  if (!count) {finish(); return;}
                  received += NetUtil.readInputStreamToString(stream, count);
                  if (received.length > payload.length) throw new Error("reference overflow");
                  stream.asyncWait(read, 0, 0, Services.tm.mainThread);
                } catch (error) {
                  if (error.result === Cr.NS_BASE_STREAM_CLOSED) finish();
                  else if (error.result === Cr.NS_BASE_STREAM_WOULD_BLOCK) stream.asyncWait(read, 0, 0, Services.tm.mainThread);
                  else reject(error);
                }
              }, QueryInterface: ChromeUtils.generateQI(["nsIInputStreamCallback"]),
            };
            const write = {
              onOutputStreamReady(stream) {
                try {
                  const count = Math.min(32768, payload.length - sent);
                  sent += stream.write(payload.slice(sent, sent + count), count);
                  if (sent === payload.length) stream.close();
                  else stream.asyncWait(write, 0, 0, Services.tm.mainThread);
                } catch (error) {
                  if (error.result === Cr.NS_BASE_STREAM_WOULD_BLOCK) stream.asyncWait(write, 0, 0, Services.tm.mainThread);
                  else reject(error);
                }
              }, QueryInterface: ChromeUtils.generateQI(["nsIOutputStreamCallback"]),
            };
            input.asyncWait(read, 0, 0, Services.tm.mainThread);
            output.asyncWait(write, 0, 0, Services.tm.mainThread);
          },
          onUpgradeFailed() {reject(new Error("reference CONNECT failed"));},
          QueryInterface: ChromeUtils.generateQI(["nsIHttpUpgradeListener"]),
        });
        internal.setConnectOnly(false);
        channel.asyncOpen({onStartRequest() {}, onDataAvailable() {reject(new Error("unexpected channel data"));},
          onStopRequest(req, status) {if (!handedOff && !Components.isSuccessCode(status)) reject(new Error("reference request failed"));},
          QueryInterface: ChromeUtils.generateQI(["nsIStreamListener", "nsIRequestObserver"])});
      }));
      await new Promise(resolve => setTimeout(resolve, 100));
    }
    done({ok: true, requests: results});
  } finally {pps.unregisterFilter(filter);}
})().catch(() => done({ok: false, requests: results, error: "Firefox reference workload failed"}));

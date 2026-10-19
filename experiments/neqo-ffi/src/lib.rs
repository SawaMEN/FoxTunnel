//! Experimental Neqo UDP state-machine interface for an external socket driver.
//!
//! Creates authentic Neqo QUIC datagrams, accepts packets from one pinned UDP
//! peer, and exports retransmission callbacks. TLS authentication is deliberately
//! FAIL-CLOSED: every certificate request is rejected until trust+SPKI pinning
//! is implemented. No HTTP/3 request/credentials API exists. Never ship this
//! bridge in release binaries or treat it as an operational tunnel.

#![forbid(unsafe_op_in_unsafe_fn)]

use std::{
    cell::RefCell,
    ffi::{CStr, c_char},
    net::SocketAddr,
    ptr,
    rc::Rc,
    time::Instant,
};

use neqo_common::{Datagram, Tos, event::Provider as _};
use neqo_http3::{Http3Client, Http3ClientEvent, Http3Parameters, Output};
use neqo_transport::{ConnectionIdGenerator, RandomConnectionIdGenerator};
use nss::AuthenticationStatus;

/// 1: datagram written; 0: no datagram available; -1: invalid
/// arguments/state; -2: output buffer is too small (packet is retained).
const INVALID: i32 = -1;
const TOO_SMALL: i32 = -2;
const STOPPED: i32 = -3;
const DATAGRAM: i32 = 1;
const TIMER: i32 = 2;
const MAX_DATAGRAM_BYTES: usize = 65_527;

/// Opaque, single-thread-owned Neqo client; callers must not share it
/// between threads or use it after ft_neqo_free.
pub struct NeqoProbe {
    client: Http3Client,
    pending: Option<Vec<u8>>,
    local: SocketAddr,
    remote: SocketAddr,
    auth_rejected: bool,
    stopped: bool,
}

impl NeqoProbe {
    // Never allow implicit 'AuthenticationStatus::Ok'. An application that has
    // not verified trust roots and SPKI pins MUST NOT authenticate the peer.
    fn reject_unverified_peer(&mut self) {
        while let Some(event) = self.client.next_event() {
            match event {
                Http3ClientEvent::AuthenticationNeeded => {
                    self.auth_rejected = true;
                    let now = Instant::now();
                    self.client.authenticated(AuthenticationStatus::CertUntrusted, now);
                    self.client.close(now, 0x100, "certificate validation unavailable");
                }
                Http3ClientEvent::EchFallbackAuthenticationNeeded { .. } => {
                    self.auth_rejected = true;
                    self.client.close(Instant::now(), 0x100, "ECH certificate validation unavailable");
                }
                _ => {}
            }
        }
    }
}

fn validate_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && host.is_ascii()
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}

/// ABI version for callers that validate the exact bridge contract.
#[unsafe(no_mangle)]
pub extern "C" fn ft_neqo_abi_version() -> u32 {
    2
}

/// Create an isolated Neqo HTTP/3 client, without opening sockets.
///
/// # Safety
///
/// host, local_addr and remote_addr must be non-null, NUL-terminated,
/// readable C strings; the caller retains their memory only for this call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ft_neqo_new(
    host: *const c_char,
    local_addr: *const c_char,
    remote_addr: *const c_char,
) -> *mut NeqoProbe {
    if host.is_null() || local_addr.is_null() || remote_addr.is_null() {
        return ptr::null_mut();
    }

    let parse = |p: *const c_char| {
        // SAFETY: The C ABI requires a valid NUL-terminated input string.
        unsafe { CStr::from_ptr(p) }.to_str().ok()
    };
    let Some(host) = parse(host) else { return ptr::null_mut() };
    if !validate_hostname(host) {
        return ptr::null_mut();
    }
    let (Some(local), Some(remote)) = (parse(local_addr), parse(remote_addr)) else {
        return ptr::null_mut();
    };
    let (Ok(local), Ok(remote)) = (local.parse::<SocketAddr>(), remote.parse::<SocketAddr>()) else {
        return ptr::null_mut();
    };
    if local.is_ipv4() != remote.is_ipv4() || remote.port() == 0 {
        return ptr::null_mut();
    }
    if nss::init().is_err() {
        return ptr::null_mut();
    }

    let ids: Rc<RefCell<dyn ConnectionIdGenerator>> =
        Rc::new(RefCell::new(RandomConnectionIdGenerator::new(8)));
    let Ok(client) = Http3Client::new(
        host,
        ids,
        local,
        remote,
        Http3Parameters::default(),
        Instant::now(),
    ) else {
        return ptr::null_mut();
    };
    Box::into_raw(Box::new(NeqoProbe {
        client, pending: None, local, remote, auth_rejected: false, stopped: false,
    }))
}

/// Retrieve a UDP payload or the next QUIC retransmission deadline.
///
/// Return: 1 = payload copied; 2 = callback after timeout_ms; 0 = quiescent;
/// -1 = invalid pointer/argument; -2 = insufficient output capacity (packet
/// remains queued); -3 = caller stopped the probe.
/// On return 2, call again AFTER the delay or immediately after receiving a
/// UDP datagram. Callback deadlines are relative (milliseconds, minimum 1).
///
/// # Safety
///
/// The opaque probe must be live and exclusively used by the caller thread.
/// out_len and timeout_ms must be distinct writable pointers; out must address
/// capacity writable bytes when capacity > 0. None may overlap probe memory.
/// A stopped handle may only be inspected or freed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ft_neqo_next(
    probe: *mut NeqoProbe,
    out: *mut u8,
    capacity: usize,
    out_len: *mut usize,
    timeout_ms: *mut u32,
) -> i32 {
    if probe.is_null() || out_len.is_null() || timeout_ms.is_null()
        || (capacity > 0 && out.is_null()) || capacity > MAX_DATAGRAM_BYTES
    {
        return INVALID;
    }
    // SAFETY: Caller guarantees these pointers are distinct and writable.
    let p = unsafe { &mut *probe };
    unsafe { *out_len = 0; *timeout_ms = 0; }
    if p.stopped { return STOPPED; }
    p.reject_unverified_peer();

    if p.pending.is_none() {
        match p.client.process_output(Instant::now()) {
            Output::Datagram(datagram) => p.pending = Some(datagram.to_vec()),
            Output::Callback(duration) => {
                p.reject_unverified_peer();
                let ms = duration.as_millis().clamp(1, 60_000);
                // SAFETY: Caller provides a writable timeout_ms.
                unsafe { *timeout_ms = ms as u32 };
                return TIMER;
            }
            Output::None => {
                p.reject_unverified_peer();
                return 0;
            }
        }
    }
    p.reject_unverified_peer();
    let packet = p.pending.as_ref().expect("queued Neqo packet");
    // SAFETY: Caller provides writable out_len.
    unsafe { *out_len = packet.len() };
    if capacity < packet.len() { return TOO_SMALL; }
    // SAFETY: output storage is valid and large enough; bytes do not overlap.
    unsafe { ptr::copy_nonoverlapping(packet.as_ptr(), out, packet.len()) };
    p.pending = None;
    DATAGRAM
}

/// Supply a UDP datagram received from the socket's connected peer.
///
/// 'source_addr' is a numeric address equal to remote_addr passed into
/// ft_neqo_new. Callers must verify the address using recvfrom(), or use a
/// connected UDP socket. Source spoofing and connection migration are not
/// supported. Non-matching sources are rejected before Neqo sees the data.
/// Certificates are NEVER approved: AuthenticationNeeded is failed closed.
///
/// # Safety
///
/// probe must be live, single-thread-owned; source_addr must be a readable,
/// NUL-terminated C string; bytes must be valid for length bytes and
/// non-overlapping with probe storage.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ft_neqo_feed(
    probe: *mut NeqoProbe,
    source_addr: *const c_char,
    bytes: *const u8,
    length: usize,
) -> i32 {
    if probe.is_null() || source_addr.is_null() || bytes.is_null()
        || length == 0 || length > MAX_DATAGRAM_BYTES
    {
        return INVALID;
    }
    // SAFETY: Caller guarantees a readable NUL-terminated address.
    let Ok(src) = (unsafe { CStr::from_ptr(source_addr) }).to_str() else { return INVALID; };
    let Ok(src) = src.parse::<SocketAddr>() else { return INVALID; };
    // SAFETY: caller owns probe exclusively.
    let p = unsafe { &mut *probe };
    if p.stopped { return STOPPED; }
    if src != p.remote { return INVALID; }
    // SAFETY: caller guarantees a readable datagram of length bytes.
    let packet = unsafe { std::slice::from_raw_parts(bytes, length) }.to_vec();
    let datagram = Datagram::new(p.remote, p.local, Tos::default(), packet);
    p.client.process_input(datagram, Instant::now());
    p.reject_unverified_peer();
    DATAGRAM
}

/// Return 1 if certificate authentication was rejected, otherwise 0.
/// There is intentionally no "authenticated" result in this ABI.
///
/// # Safety
/// probe must be a live, single-thread-owned opaque handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ft_neqo_auth_rejected(probe: *mut NeqoProbe) -> i32 {
    if probe.is_null() { return INVALID; }
    // SAFETY: opaque probe is live and caller-owned.
    let p = unsafe { &mut *probe };
    p.reject_unverified_peer();
    i32::from(p.auth_rejected)
}

/// Stop processing immediately (do not initiate new connections or requests).
/// Idempotent. The caller must still free the handle.
///
/// # Safety
/// probe must be a live, single-thread-owned opaque handle.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ft_neqo_stop(probe: *mut NeqoProbe) -> i32 {
    if probe.is_null() { return INVALID; }
    // SAFETY: opaque probe is live and caller-owned.
    let p = unsafe { &mut *probe };
    if !p.stopped {
        p.stopped = true;
        p.pending = None;
        p.client.close(Instant::now(), 0x100, "probe stopped");
    }
    0
}

/// ABI v1 compatibility: return the next datagram, ignoring timer hints.
/// New code should use ft_neqo_next and schedule its returned timeout.
///
/// # Safety
/// Same pointer ownership / buffer rules as ft_neqo_next.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ft_neqo_initial(
    probe: *mut NeqoProbe,
    out: *mut u8,
    capacity: usize,
    out_len: *mut usize,
) -> i32 {
    let mut delay = 0u32;
    // SAFETY: FFI caller upholds ft_neqo_next's pointer preconditions;
    // delay is local and distinct from all caller-supplied pointers.
    match unsafe { ft_neqo_next(probe, out, capacity, out_len, &mut delay) } {
        TIMER => 0,
        code => code,
    }
}

/// Destroy the single-thread-owned client.
///
/// # Safety
///
/// probe must be NULL or a pointer returned by ft_neqo_new that has not
/// already been freed. Do not call concurrently with other bridge methods.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ft_neqo_free(probe: *mut NeqoProbe) {
    if !probe.is_null() {
        // SAFETY: Caller transfers back the sole ownership.
        drop(unsafe { Box::from_raw(probe) });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn make_probe(host: &str) -> *mut NeqoProbe {
        let host = CString::new(host).expect("test hostname");
        let local = c"127.0.0.1:23456";
        let remote = c"127.0.0.1:443";
        // SAFETY: Valid, alive, NUL-terminated C strings.
        unsafe { ft_neqo_new(host.as_ptr(), local.as_ptr(), remote.as_ptr()) }
    }

    #[test]
    fn rejects_unsafe_hostnames_and_null_args() {
        assert_eq!(ft_neqo_abi_version(), 2);
        for host in ["", "-bad.example", "bad..example", "site/example", "a".repeat(255).as_str()] {
            let p = make_probe(host);
            assert!(p.is_null(), "accepted invalid SNI: {host}");
        }
        // SAFETY: Invalid null pointers are checked before dereferencing.
        assert!(unsafe { ft_neqo_new(ptr::null(), ptr::null(), ptr::null()) }.is_null());
    }

    #[test]
    fn udp_callbacks_invalid_sources_and_stop() {
        let p = make_probe("example.org");
        assert!(!p.is_null());
        let mut len = 0usize;
        let mut delay = 0u32;
        let mut buf = vec![0u8; 1600];
        // SAFETY: Live owned probe and correct buffers.
        unsafe {
            assert_eq!(ft_neqo_next(p, buf.as_mut_ptr(), buf.len(), &mut len, &mut delay), 1);
            assert!(len >= 1200);
            assert_eq!(ft_neqo_auth_rejected(p), 0);
            assert_eq!(ft_neqo_feed(p, c"127.0.0.2:443".as_ptr(), b"hello".as_ptr(), 5), INVALID);
            assert_eq!(ft_neqo_feed(p, c"127.0.0.1:443".as_ptr(), ptr::null(), 0), INVALID);
            assert_eq!(ft_neqo_feed(p, c"127.0.0.1:443".as_ptr(), b"bad".as_ptr(), 3), DATAGRAM);
            assert_eq!(ft_neqo_auth_rejected(p), 0);
            // A malformed UDP packet must not authorize peer authentication.
            let step = ft_neqo_next(p, buf.as_mut_ptr(), buf.len(), &mut len, &mut delay);
            assert!(matches!(step, 0 | 1 | TIMER));
            assert_eq!(ft_neqo_stop(p), 0);
            assert_eq!(ft_neqo_stop(p), 0);
            assert_eq!(ft_neqo_next(p, buf.as_mut_ptr(), buf.len(), &mut len, &mut delay), STOPPED);
            assert_eq!(ft_neqo_feed(p, c"127.0.0.1:443".as_ptr(), b"bad".as_ptr(), 3), STOPPED);
            ft_neqo_free(p);
        }
    }

    #[test]
    fn exports_a_real_neqo_quic_initial_packet() {
        let p = make_probe("example.org");
        assert!(!p.is_null(), "NSS/Neqo failed to create HTTP/3 client");
        let mut needed = 0usize;
        // SAFETY: Valid, uniquely owned probe, valid length pointer.
        let ret = unsafe { ft_neqo_initial(p, ptr::null_mut(), 0, &mut needed) };
        assert_eq!(ret, TOO_SMALL);
        assert!(needed >= 1200, "QUIC Initial must be padded to >=1200 bytes");
        let mut packet = vec![0u8; needed];
        // SAFETY: Packet buffer is writable for its length.
        let ret = unsafe { ft_neqo_initial(p, packet.as_mut_ptr(), packet.len(), &mut needed) };
        assert_eq!(ret, 1);
        assert_eq!(needed, packet.len());
        assert_eq!(packet[0] & 0xC0, 0xC0, "not a QUIC long-header packet");
        assert_eq!(&packet[1..5], &[0, 0, 0, 1], "unexpected QUIC version");
        // SAFETY: Probe has not been freed and is used by one thread.
        unsafe { ft_neqo_free(p) };
    }
}

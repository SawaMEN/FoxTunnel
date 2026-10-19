//! Experimental first step of the Neqo-to-Go boundary.
//!
//! This bridge deliberately implements *only* creation of a client and
//! generation of the first QUIC packet. It never consumes server packets,
//! authenticates certificates or sends proxy credentials. It is NOT a
//! usable HTTP/3 transport, and should never be linked into release builds.

#![forbid(unsafe_op_in_unsafe_fn)]

use std::{
    cell::RefCell,
    ffi::{CStr, c_char},
    net::SocketAddr,
    ptr,
    rc::Rc,
    slice,
    time::Instant,
};

use neqo_http3::{Http3Client, Http3Parameters, Output};
use neqo_transport::{ConnectionIdGenerator, RandomConnectionIdGenerator};

/// 1: datagram written; 0: no datagram available; -1: invalid
/// arguments/state; -2: output buffer is too small (packet is retained).
const INVALID: i32 = -1;
const TOO_SMALL: i32 = -2;

/// Opaque, single-thread-owned Neqo client; callers must not share it
/// between threads or use it after ft_neqo_free.
pub struct NeqoProbe {
    client: Http3Client,
    pending: Option<Vec<u8>>,
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
    1
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
    Box::into_raw(Box::new(NeqoProbe { client, pending: None }))
}

/// Emit the first Neqo-generated datagram. The bridge does not process
/// incoming packets; consequently, this cannot establish a connection.
/// On TOO_SMALL, out_len receives the required size and the datagram is
/// retained until successfully copied.
///
/// # Safety
///
/// probe must be a valid, live pointer returned by ft_neqo_new and exclusively
/// owned by this thread. out_len must be writable. When capacity is nonzero,
/// out must be writable for that many bytes. Do not overlap output arguments.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ft_neqo_initial(
    probe: *mut NeqoProbe,
    out: *mut u8,
    capacity: usize,
    out_len: *mut usize,
) -> i32 {
    if probe.is_null() || out_len.is_null() || (capacity != 0 && out.is_null()) {
        return INVALID;
    }
    // SAFETY: Caller guarantees the opaque pointer and out_len are valid.
    let probe = unsafe { &mut *probe };
    // SAFETY: out_len points to writable memory.
    unsafe { *out_len = 0 };

    if probe.pending.is_none() {
        match probe.client.process_output(Instant::now()) {
            Output::Datagram(packet) => probe.pending = Some(packet.to_vec()),
            Output::Callback(_) | Output::None => return 0,
        }
    }
    let packet = probe.pending.as_ref().expect("pending datagram");
    // SAFETY: out_len points to writable memory.
    unsafe { *out_len = packet.len() };
    if capacity < packet.len() {
        return TOO_SMALL;
    }
    // SAFETY: Caller supplies a writable output buffer with sufficient size.
    unsafe { slice::from_raw_parts_mut(out, capacity)[..packet.len()].copy_from_slice(packet) };
    probe.pending = None;
    1
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
        assert_eq!(ft_neqo_abi_version(), 1);
        for host in ["", "-bad.example", "bad..example", "site/example", "a".repeat(255).as_str()] {
            let p = make_probe(host);
            assert!(p.is_null(), "accepted invalid SNI: {host}");
        }
        // SAFETY: Invalid null pointers are checked before dereferencing.
        assert!(unsafe { ft_neqo_new(ptr::null(), ptr::null(), ptr::null()) }.is_null());
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

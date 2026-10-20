//! Minimal synchronous ABI 1. The Go actor pins an OS thread and owns UDP,
//! deadlines, trust verification, bounded queues and the lifetime of this engine.
use neqo_common::{Datagram, Header, event::Provider};
use neqo_http3::{Http3Client, Http3ClientEvent, Http3Parameters, Http3State, Priority};
use neqo_transport::{
    ConnectionParameters, Output, RandomConnectionIdGenerator, StreamDataLimit, StreamId,
    StreamType,
};
use nss::AuthenticationStatus;
use std::{
    cell::RefCell,
    ffi::{CStr, c_char},
    net::SocketAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    rc::Rc,
    slice, str,
    time::{Duration, Instant},
};

const MAX_META: usize = 1 << 20;
const MAX_HEADERS: usize = 64 << 10;
unsafe extern "C" {
    fn NSS_GetVersion() -> *const c_char;
}
struct Event {
    kind: u32,
    stream: u64,
    arg: u64,
    data: Vec<u8>,
}
pub struct Engine {
    client: Http3Client,
    local: SocketAddr,
    remote: SocketAddr,
    pending: Option<Event>,
    verified: bool,
    connected: bool,
}
fn guarded(f: impl FnOnce() -> Result<i32, ()>) -> i32 {
    catch_unwind(AssertUnwindSafe(f))
        .ok()
        .and_then(Result::ok)
        .unwrap_or(-1)
}
unsafe fn bytes<'a>(p: *const u8, n: usize, max: usize) -> Result<&'a [u8], ()> {
    if n > max || (n > 0 && p.is_null()) {
        return Err(());
    };
    if n == 0 {
        Ok(&[])
    } else {
        Ok(unsafe { slice::from_raw_parts(p, n) })
    }
}
unsafe fn engine<'a>(p: *mut Engine) -> Result<&'a mut Engine, ()> {
    unsafe { p.as_mut() }.ok_or(())
}
struct Fields<'a>(&'a [u8]);
impl<'a> Fields<'a> {
    fn take(&mut self) -> Result<&'a [u8], ()> {
        if self.0.len() < 4 {
            return Err(());
        };
        let n = u32::from_be_bytes(self.0[..4].try_into().map_err(|_| ())?) as usize;
        self.0 = &self.0[4..];
        if n > self.0.len() {
            return Err(());
        };
        let (v, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(v)
    }
    fn text(&mut self) -> Result<&'a str, ()> {
        str::from_utf8(self.take()?).map_err(|_| ())
    }
}
fn put(out: &mut Vec<u8>, data: &[u8]) -> Result<(), ()> {
    if data.len() > MAX_META || out.len() + 4 + data.len() > MAX_META {
        return Err(());
    };
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}
#[unsafe(no_mangle)]
pub extern "C" fn ftn_abi() -> u32 {
    1
}
#[unsafe(no_mangle)]
pub extern "C" fn ftn_init() -> i32 {
    guarded(|| {
        let version = unsafe { NSS_GetVersion() };
        if version.is_null() || unsafe { CStr::from_ptr(version) }.to_bytes() != b"3.130" {
            return Err(());
        };
        nss::init().map_err(|_| ())?;
        Ok(0)
    })
}
/// # Safety
/// The caller owns all valid buffers and uses a live engine exclusively on its
/// creating OS thread. Buffers may not alias mutable engine state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftn_new(p: *const u8, n: usize) -> *mut Engine {
    catch_unwind(AssertUnwindSafe(|| -> Result<*mut Engine, ()> {
        let mut f = Fields(unsafe { bytes(p, n, 4096)? });
        let name = f.text()?.to_owned();
        let local = f.text()?.parse().map_err(|_| ())?;
        let remote = f.text()?.parse().map_err(|_| ())?;
        if !f.0.is_empty() || name.is_empty() {
            return Err(());
        }
        let params = ConnectionParameters::default()
            .disable_migration(true)
            .datagram_size(0)
            .idle_timeout(Duration::from_secs(90))
            .max_data(1 << 20)
            .max_streams(StreamType::BiDi, 0)
            .max_streams(StreamType::UniDi, 8)
            .max_stream_data(StreamDataLimit::BiDiLocal, 128 << 10);
        let client = Http3Client::new(
            name,
            Rc::new(RefCell::new(RandomConnectionIdGenerator::new(12))),
            local,
            remote,
            Http3Parameters::default()
                .http3_datagram(false)
                .connection_parameters(params)
                .max_table_size_decoder(4096)
                .max_table_size_encoder(4096)
                .max_blocked_streams(16),
            Instant::now(),
        )
        .map_err(|_| ())?;
        Ok(Box::into_raw(Box::new(Engine {
            client,
            local,
            remote,
            pending: None,
            verified: false,
            connected: false,
        })))
    }))
    .ok()
    .and_then(Result::ok)
    .unwrap_or(std::ptr::null_mut())
}
/// # Safety
/// The caller owns all valid buffers and uses a live engine exclusively on its
/// creating OS thread. Buffers may not alias mutable engine state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftn_free(p: *mut Engine) {
    if !p.is_null() {
        let _ = catch_unwind(AssertUnwindSafe(|| drop(unsafe { Box::from_raw(p) })));
    }
}
/// # Safety
/// The caller owns all valid buffers and uses a live engine exclusively on its
/// creating OS thread. Buffers may not alias mutable engine state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftn_input(p: *mut Engine, b: *const u8, n: usize) -> i32 {
    guarded(|| {
        let e = unsafe { engine(p)? };
        let data = unsafe { bytes(b, n, 65535)? };
        if data.is_empty() {
            return Err(());
        };
        e.client.process_input(
            Datagram::new(e.remote, e.local, Default::default(), data.to_vec()),
            Instant::now(),
        );
        Ok(0)
    })
}
/// # Safety
/// The caller owns all valid buffers and uses a live engine exclusively on its
/// creating OS thread. Buffers may not alias mutable engine state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftn_output(p: *mut Engine, b: *mut u8, cap: usize, wait: *mut u64) -> i32 {
    guarded(|| {
        let e = unsafe { engine(p)? };
        if b.is_null() || cap < 65535 || wait.is_null() {
            return Err(());
        };
        unsafe { *wait = 1_000_000_000 };
        match e.client.process_output(Instant::now()) {
            Output::Datagram(d) => {
                if d.destination() != e.remote || d.len() > cap {
                    return Err(());
                };
                unsafe { std::ptr::copy_nonoverlapping(d.as_ptr(), b, d.len()) };
                Ok(d.len() as i32)
            }
            Output::Callback(d) => {
                unsafe { *wait = d.as_nanos().clamp(1, 1_000_000_000) as u64 };
                Ok(0)
            }
            Output::None => Ok(0),
        }
    })
}
/// # Safety
/// The caller owns all valid buffers and uses a live engine exclusively on its
/// creating OS thread. Buffers may not alias mutable engine state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftn_event(
    p: *mut Engine,
    kind: *mut u32,
    stream: *mut u64,
    arg: *mut u64,
    b: *mut u8,
    cap: usize,
) -> i32 {
    guarded(|| {
        let e = unsafe { engine(p)? };
        if kind.is_null() || stream.is_null() || arg.is_null() || b.is_null() {
            return Err(());
        }
        while e.pending.is_none() {
            let Some(event) = e.client.next_event() else {
                unsafe { *kind = 0 };
                return Ok(0);
            };
            let mut out = Event {
                kind: 0,
                stream: 0,
                arg: 0,
                data: Vec::new(),
            };
            match event {
                Http3ClientEvent::AuthenticationNeeded => {
                    out.kind = 1;
                    let certs = e.client.peer_certificate().ok_or(())?;
                    let mut count = 0;
                    for der in &certs {
                        count += 1;
                        if count > 16 {
                            return Err(());
                        };
                        put(&mut out.data, der)?;
                    }
                    if count == 0 {
                        return Err(());
                    }
                }
                Http3ClientEvent::StateChange(Http3State::Connected) => {
                    let info = e.client.tls_info().ok_or(())?;
                    if !e.verified
                        || info.version() != 0x0304
                        || info.alpn() != Some("h3")
                        || info.resumed()
                        || info.early_data_accepted()
                    {
                        return Err(());
                    };
                    e.connected = true;
                    out.arg = u64::from(info.cipher_suite());
                    out.kind = 2
                }
                Http3ClientEvent::StateChange(Http3State::Closing(_) | Http3State::Closed(_)) => {
                    out.kind = 7
                }
                Http3ClientEvent::HeaderReady {
                    stream_id,
                    headers,
                    fin,
                    interim,
                } => {
                    out.kind = 3;
                    out.stream = stream_id.as_u64();
                    out.arg = u64::from(fin) | (u64::from(interim) << 1);
                    for h in headers {
                        put(&mut out.data, h.name().as_bytes())?;
                        put(&mut out.data, h.value())?;
                    }
                    if out.data.len() > MAX_HEADERS {
                        return Err(());
                    }
                }
                Http3ClientEvent::DataReadable { stream_id } => {
                    out.kind = 4;
                    out.stream = stream_id.as_u64()
                }
                Http3ClientEvent::DataWritable { stream_id } => {
                    out.kind = 5;
                    out.stream = stream_id.as_u64()
                }
                Http3ClientEvent::Reset { stream_id, .. }
                | Http3ClientEvent::StopSending { stream_id, .. } => {
                    out.kind = 6;
                    out.stream = stream_id.as_u64()
                }
                Http3ClientEvent::GoawayReceived => out.kind = 8,
                Http3ClientEvent::EchFallbackAuthenticationNeeded { .. }
                | Http3ClientEvent::ZeroRttRejected => return Err(()),
                _ => continue,
            };
            e.pending = Some(out)
        }
        let out = e.pending.as_ref().ok_or(())?;
        if out.data.len() > cap {
            return Ok(-2);
        };
        unsafe {
            *kind = out.kind;
            *stream = out.stream;
            *arg = out.arg;
            std::ptr::copy_nonoverlapping(out.data.as_ptr(), b, out.data.len())
        };
        let n = out.data.len();
        e.pending = None;
        Ok(n as i32)
    })
}
/// # Safety
/// The caller owns all valid buffers and uses a live engine exclusively on its
/// creating OS thread. Buffers may not alias mutable engine state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftn_auth(p: *mut Engine) -> i32 {
    guarded(|| {
        let e = unsafe { engine(p)? };
        if e.verified {
            return Err(());
        };
        e.verified = true;
        e.client
            .authenticated(AuthenticationStatus::Ok, Instant::now());
        Ok(0)
    })
}
/// # Safety
/// The caller owns all valid buffers and uses a live engine exclusively on its
/// creating OS thread. Buffers may not alias mutable engine state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftn_fetch(p: *mut Engine, b: *const u8, n: usize, id: *mut u64) -> i32 {
    guarded(|| {
        let e = unsafe { engine(p)? };
        if !e.verified || !e.connected || id.is_null() {
            return Err(());
        };
        let mut f = Fields(unsafe { bytes(b, n, MAX_HEADERS)? });
        let method = f.text()?;
        let scheme = f.text()?;
        let authority = f.text()?;
        let path = f.text()?;
        let mut headers = Vec::new();
        while !f.0.is_empty() {
            let name = f.text()?;
            let val = f.text()?;
            if headers.len() >= 128 {
                return Err(());
            };
            headers.push(Header::new(name, val));
        }
        let stream = e
            .client
            .fetch(
                Instant::now(),
                method,
                (scheme, authority, path),
                &headers,
                Priority::default(),
            )
            .map_err(|_| ())?;
        unsafe { *id = stream.as_u64() };
        Ok(0)
    })
}
/// # Safety
/// The caller owns all valid buffers and uses a live engine exclusively on its
/// creating OS thread. Buffers may not alias mutable engine state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftn_send(p: *mut Engine, id: u64, b: *const u8, n: usize) -> i32 {
    guarded(|| {
        let e = unsafe { engine(p)? };
        let data = unsafe { bytes(b, n, 32 << 10)? };
        Ok(e.client
            .send_data(StreamId::new(id), data, Instant::now())
            .map_err(|_| ())? as i32)
    })
}
/// # Safety
/// The caller owns all valid buffers and uses a live engine exclusively on its
/// creating OS thread. Buffers may not alias mutable engine state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftn_fin(p: *mut Engine, id: u64) -> i32 {
    guarded(|| {
        unsafe { engine(p)? }
            .client
            .stream_close_send(StreamId::new(id), Instant::now())
            .map_err(|_| ())?;
        Ok(0)
    })
}
/// # Safety
/// The caller owns all valid buffers and uses a live engine exclusively on its
/// creating OS thread. Buffers may not alias mutable engine state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftn_read(
    p: *mut Engine,
    id: u64,
    b: *mut u8,
    cap: usize,
    fin: *mut u32,
) -> i32 {
    guarded(|| {
        let e = unsafe { engine(p)? };
        if b.is_null() || fin.is_null() || cap > 32 << 10 {
            return Err(());
        };
        let out = unsafe { slice::from_raw_parts_mut(b, cap) };
        let (n, end) = e
            .client
            .read_data(Instant::now(), StreamId::new(id), out)
            .map_err(|_| ())?;
        unsafe { *fin = u32::from(end) };
        Ok(n as i32)
    })
}
/// # Safety
/// The caller owns all valid buffers and uses a live engine exclusively on its
/// creating OS thread. Buffers may not alias mutable engine state.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftn_reset(p: *mut Engine, id: u64) -> i32 {
    guarded(|| {
        let e = unsafe { engine(p)? };
        let _ = e.client.stream_reset_send(StreamId::new(id), 0x10c);
        let _ = e.client.stream_stop_sending(StreamId::new(id), 0x10c);
        Ok(0)
    })
}

/// # Safety
/// The engine is live and used exclusively on its creating OS thread.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ftn_shutdown(p: *mut Engine) -> i32 {
    guarded(|| {
        unsafe { engine(p)? }
            .client
            .close(Instant::now(), 0, "closed");
        Ok(0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_fields() {
        assert!(Fields(&[0, 0, 0, 4, 1]).take().is_err());
        let mut f = Fields(&[0, 0, 0, 1, 42]);
        assert_eq!(f.take(), Ok(&[42][..]));
        assert!(f.0.is_empty());
        assert!(Fields(&[0, 0, 0, 1, 255]).text().is_err());
    }
    #[test]
    fn panic_does_not_cross_abi() {
        assert_eq!(guarded(|| panic!("contained")), -1);
    }
    #[test]
    fn metadata_bound() {
        let mut data = vec![0; MAX_META];
        assert!(put(&mut data, b"a").is_err());
    }
    #[test]
    fn null_and_oversized_buffers_are_rejected() {
        unsafe {
            assert_eq!(bytes(std::ptr::null(), 0, 1), Ok(&[][..]));
            assert!(bytes(std::ptr::null(), 1, 1).is_err());
            assert!(bytes(std::ptr::null(), 2, 1).is_err());
            assert!(ftn_new(std::ptr::null(), 1).is_null());
            assert_eq!(ftn_input(std::ptr::null_mut(), std::ptr::null(), 1), -1);
            assert_eq!(ftn_auth(std::ptr::null_mut()), -1);
            assert_eq!(ftn_shutdown(std::ptr::null_mut()), -1);
            ftn_free(std::ptr::null_mut());
        }
    }
}

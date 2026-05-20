use std::net::{IpAddr, SocketAddr};

pub fn reverse_ptr_name(addr: IpAddr) -> Option<String> {
    let socket = SocketAddr::new(addr, 0);
    let mut host = [0_i8; 1025];
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match socket {
        SocketAddr::V4(v4) => {
            let sin: &mut libc::sockaddr_in =
                unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in) };
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = v4.port().to_be();
            sin.sin_addr = libc::in_addr {
                s_addr: u32::from(*v4.ip()).to_be(),
            };
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t
        }
        SocketAddr::V6(v6) => {
            let sin6: &mut libc::sockaddr_in6 =
                unsafe { &mut *(&mut storage as *mut _ as *mut libc::sockaddr_in6) };
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = v6.port().to_be();
            sin6.sin6_addr = libc::in6_addr {
                s6_addr: v6.ip().octets(),
            };
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t
        }
    };
    let rc = unsafe {
        libc::getnameinfo(
            &storage as *const _ as *const libc::sockaddr,
            len,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NAMEREQD,
        )
    };
    if rc != 0 {
        return None;
    }
    let cstr = unsafe { std::ffi::CStr::from_ptr(host.as_ptr()) };
    let name = cstr.to_str().ok()?.trim_end_matches('.');
    if name.is_empty() || name.parse::<IpAddr>().is_ok() {
        return None;
    }
    Some(name.to_string())
}

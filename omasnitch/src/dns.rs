use std::{
    ffi::CStr,
    net::IpAddr,
};

pub fn reverse_hostname(address: &str) -> Option<String> {
    let ip: IpAddr = address.parse().ok()?;
    let mut hostname = [0 as libc::c_char; libc::NI_MAXHOST as usize];

    let result = match ip {
        IpAddr::V4(ipv4) => {
            let socket = libc::sockaddr_in {
                sin_family: libc::AF_INET as libc::sa_family_t,
                sin_port: 0,
                sin_addr: libc::in_addr {
                    s_addr: u32::from_ne_bytes(ipv4.octets()),
                },
                sin_zero: [0; 8],
            };

            unsafe {
                libc::getnameinfo(
                    &socket as *const _ as *const libc::sockaddr,
                    std::mem::size_of_val(&socket) as libc::socklen_t,
                    hostname.as_mut_ptr(),
                    hostname.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
        IpAddr::V6(ipv6) => {
            let socket = libc::sockaddr_in6 {
                sin6_family: libc::AF_INET6 as libc::sa_family_t,
                sin6_port: 0,
                sin6_flowinfo: 0,
                sin6_addr: libc::in6_addr {
                    s6_addr: ipv6.octets(),
                },
                sin6_scope_id: 0,
            };

            unsafe {
                libc::getnameinfo(
                    &socket as *const _ as *const libc::sockaddr,
                    std::mem::size_of_val(&socket) as libc::socklen_t,
                    hostname.as_mut_ptr(),
                    hostname.len() as libc::socklen_t,
                    std::ptr::null_mut(),
                    0,
                    libc::NI_NAMEREQD,
                )
            }
        }
    };

    if result != 0 {
        return None;
    }

    let value = unsafe { CStr::from_ptr(hostname.as_ptr()) }
        .to_str()
        .ok()?
        .trim_end_matches('.')
        .to_string();

    if value.is_empty() || value == address {
        None
    } else {
        Some(value)
    }
}

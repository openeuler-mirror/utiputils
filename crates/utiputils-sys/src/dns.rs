use std::ffi::CStr;

/// Safe wrapper for `libc::getnameinfo`.
///
/// - Returns `Err(eai_code)` if `getnameinfo` fails (note: this is not `errno`).
/// - On success returns the resolved host name.
pub fn getnameinfo_host(
    sockaddr: *const libc::sockaddr,
    socklen: libc::socklen_t,
    flags: libc::c_int,
) -> Result<String, i32> {
    let mut host_buf = [0 as libc::c_char; 1024];
    let mut service_buf = [0 as libc::c_char; 1024];

    let ret = unsafe {
        libc::getnameinfo(
            sockaddr,
            socklen,
            host_buf.as_mut_ptr(),
            host_buf.len() as libc::socklen_t,
            service_buf.as_mut_ptr(),
            service_buf.len() as libc::socklen_t,
            flags,
        )
    };

    if ret != 0 {
        return Err(ret);
    }

    let host = unsafe { CStr::from_ptr(host_buf.as_ptr()) }
        .to_string_lossy()
        .into_owned();

    Ok(host)
}

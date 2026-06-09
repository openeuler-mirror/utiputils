use std::io;
use std::os::fd::RawFd;

pub fn setsockopt_int(
    fd: RawFd,
    level: libc::c_int,
    optname: libc::c_int,
    optval: libc::c_int,
) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of_val(&optval) as libc::socklen_t,
        )
    };

    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

pub fn setsockopt_bytes(
    fd: RawFd,
    level: libc::c_int,
    optname: libc::c_int,
    optval: &[u8],
) -> io::Result<()> {
    let ret = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            optval.as_ptr() as *const libc::c_void,
            optval.len() as libc::socklen_t,
        )
    };

    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

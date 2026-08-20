//! The wire format FUSE libraries and `fusermount3` use to hand over the
//! `/dev/fuse` descriptor: one byte of payload carrying an `SCM_RIGHTS`
//! control message on a unix socket.
//!
//! The daemon speaks both halves. It gives `fusermount3` a socket of its
//! own, takes the descriptor itself, and passes it on to the application
//! only once the resulting mount has been checked — so a mount that landed
//! somewhere it should not have is never served by anyone.

use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::time::Duration;

fn last_error<T>() -> io::Result<T> {
    Err(io::Error::last_os_error())
}

/// A connected pair of unix stream sockets.
pub fn socketpair() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    // No CLOEXEC on purpose: one end is handed to fusermount3 across exec.
    let rc = unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, fds.as_mut_ptr()) };
    if rc == -1 {
        return last_error();
    }
    unsafe { Ok((OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))) }
}

/// A pipe, used only to tell a waiting thread to stop: closing the write
/// end makes the read end readable, which is the whole signal.
pub fn stop_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    if rc == -1 {
        return last_error();
    }
    unsafe { Ok((OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1]))) }
}

/// One `read`, reported as it happened: `Ok(0)` means the far end is gone.
pub fn read_byte(fd: BorrowedFd<'_>, buf: &mut [u8; 1]) -> io::Result<usize> {
    let n = unsafe { libc::read(fd.as_raw_fd(), buf.as_mut_ptr().cast(), 1) };
    if n < 0 {
        return last_error();
    }
    Ok(n as usize)
}

/// Bound how long a receive may block, so a helper that never answers
/// cannot wedge the daemon.
pub fn set_receive_timeout(sock: BorrowedFd<'_>, timeout: Duration) -> io::Result<()> {
    let tv = libc::timeval {
        tv_sec: timeout.as_secs() as libc::time_t,
        tv_usec: timeout.subsec_micros() as libc::suseconds_t,
    };
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            std::ptr::addr_of!(tv).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc == -1 {
        return last_error();
    }
    Ok(())
}

/// Receive one descriptor. Returns `Ok(None)` on a clean end of stream,
/// which is what a helper that failed before sending anything leaves behind.
pub fn recv_fd(sock: BorrowedFd<'_>) -> io::Result<Option<OwnedFd>> {
    unsafe {
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: 1,
        };
        let mut control = [0u8; 64];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = control.len() as _;

        let n = libc::recvmsg(sock.as_raw_fd(), &mut msg, 0);
        if n == -1 {
            return last_error();
        }
        if n == 0 {
            return Ok(None);
        }
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        if cmsg.is_null()
            || (*cmsg).cmsg_level != libc::SOL_SOCKET
            || (*cmsg).cmsg_type != libc::SCM_RIGHTS
        {
            return Ok(None);
        }
        let mut fd: RawFd = -1;
        std::ptr::copy_nonoverlapping(libc::CMSG_DATA(cmsg).cast::<RawFd>(), &mut fd, 1);
        if fd < 0 {
            return Ok(None);
        }
        Ok(Some(OwnedFd::from_raw_fd(fd)))
    }
}

/// Send one descriptor, in the shape `fusermount3` uses: a single zero byte
/// carrying the control message.
pub fn send_fd(sock: BorrowedFd<'_>, fd: BorrowedFd<'_>) -> io::Result<()> {
    unsafe {
        let byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_ptr() as *mut _,
            iov_len: 1,
        };
        let mut control = [0u8; 64];
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _;

        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        let raw = fd.as_raw_fd();
        std::ptr::copy_nonoverlapping(&raw, libc::CMSG_DATA(cmsg).cast::<RawFd>(), 1);

        loop {
            let n = libc::sendmsg(sock.as_raw_fd(), &msg, 0);
            if n == 1 {
                return Ok(());
            }
            if n == -1 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err);
            }
            return Err(io::Error::other("short write passing the fuse descriptor"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek, Write};
    use std::os::fd::AsFd;

    #[test]
    fn a_descriptor_survives_the_round_trip() {
        let (a, b) = socketpair().unwrap();

        let mut file = tempfile();
        write!(file, "payload").unwrap();

        send_fd(a.as_fd(), file.as_fd()).unwrap();
        let received = recv_fd(b.as_fd()).unwrap().expect("a descriptor");

        // The received descriptor must name the same open file.
        let mut copy = std::fs::File::from(received);
        copy.rewind().unwrap();
        let mut content = String::new();
        copy.read_to_string(&mut content).unwrap();
        assert_eq!(content, "payload");
    }

    #[test]
    fn end_of_stream_is_not_an_error() {
        let (a, b) = socketpair().unwrap();
        drop(a);
        assert!(recv_fd(b.as_fd()).unwrap().is_none());
    }

    #[test]
    fn a_receive_can_time_out() {
        let (_a, b) = socketpair().unwrap();
        set_receive_timeout(b.as_fd(), Duration::from_millis(50)).unwrap();
        let err = recv_fd(b.as_fd()).unwrap_err();
        assert!(
            matches!(
                err.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "unexpected error: {err:?}"
        );
    }

    fn tempfile() -> std::fs::File {
        let path = std::env::temp_dir().join(format!(
            "fb-fdpass-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let file = std::fs::File::options()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        std::fs::remove_file(&path).unwrap();
        file
    }
}

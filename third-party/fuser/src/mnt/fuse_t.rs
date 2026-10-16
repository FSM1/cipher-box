//! CipherBox patch: end the FUSE-T server a mount started.
//!
//! FUSE-T forks one `go-nfsv4` server per mount and holds two sockets to it:
//! the FUSE channel, and a monitor socket. An unmount, from inside the app or
//! outside it, does not end the server. The server ends when its monitor socket
//! reaches end-of-file, and it then force-unmounts the mount point by path.
//! Thus only a drop that may unmount the path may end it.
//!
//! `fuse_mount_compat25` keeps the monitor socket inside the library. The mount
//! asks `fuse_kern_mount` for it instead: the library hands it to a callback
//! when the server reports the mount status.

#[cfg(fuser_fuse_t)]
use std::os::fd::{FromRawFd, RawFd};
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use log::warn;

/// How long a drop waits for the server to exit. A server that exits after a
/// drop returned could force-unmount the next mount at the same path.
const EXIT_WITHIN: Duration = Duration::from_secs(5);

const EXIT_POLL: Duration = Duration::from_millis(10);

/// The monitor socket of one mount, as the library and the drop see it.
#[derive(Debug)]
enum State {
    /// The library has not reported the mount status yet.
    Awaited,
    /// The server is running, and this socket is its monitor.
    Held { monitor: OwnedFd, server: libc::pid_t },
    /// The mount dropped. A monitor that arrives now stays open: the drop no
    /// longer vouches for what the path carries.
    Ended,
}

/// The server of one mount. Shared with the library's mount-status thread.
#[derive(Debug, Clone)]
pub(crate) struct Server(Arc<Mutex<State>>);

impl Server {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(State::Awaited)))
    }

    fn state(&self) -> MutexGuard<'_, State> {
        // A poisoned lock still holds a valid state, and the callback that
        // reads it must not unwind into the library.
        self.0.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The library reported the mount status over `monitor`, whose peer is
    /// `server`.
    pub(crate) fn deliver(&self, monitor: OwnedFd, server: libc::pid_t) {
        let mut state = self.state();
        if matches!(*state, State::Awaited) {
            *state = State::Held { monitor, server };
        } else {
            // A close here would end a server, and that unmounts by path.
            let _ = monitor.into_raw_fd();
        }
    }

    /// Ends the server, if the library has reported it.
    pub(crate) fn end(&self) {
        let ended = std::mem::replace(&mut *self.state(), State::Ended);
        if let State::Held { monitor, server } = ended {
            end(monitor, server);
        }
    }

    /// The context `fuse_kern_mount` hands back to [`delivered`]. The callback
    /// takes this reference back. A mount whose status never arrives keeps it.
    #[cfg(fuser_fuse_t)]
    pub(crate) fn context(&self) -> *mut libc::c_void {
        Arc::into_raw(self.0.clone()) as *mut libc::c_void
    }
}

/// The `fuse_kern_mount` status callback, on the library's mount-status thread.
///
/// # Safety
///
/// `context` comes from [`Server::context`], and the library calls this once.
#[cfg(fuser_fuse_t)]
pub(crate) unsafe extern "C" fn delivered(
    context: *mut libc::c_void,
    _status: libc::c_int,
    monitor: libc::c_int,
) {
    let server = Server(unsafe { Arc::from_raw(context as *const Mutex<State>) });
    if monitor <= 0 {
        return;
    }
    // Left open when the server is unknown: a close would end a live mount.
    let Some(pid) = peer_of(monitor) else {
        warn!("the FUSE-T server of this mount has no process id");
        return;
    };
    // The library makes no use of the monitor socket after this callback.
    server.deliver(unsafe { OwnedFd::from_raw_fd(monitor) }, pid);
}

/// The process at the other end of `socket`: the last one to use it, which is
/// the server once it has sent the mount status.
#[cfg(fuser_fuse_t)]
fn peer_of(socket: RawFd) -> Option<libc::pid_t> {
    let mut pid: libc::pid_t = 0;
    let mut len = std::mem::size_of::<libc::pid_t>() as libc::socklen_t;
    let read = unsafe {
        libc::getsockopt(
            socket,
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::pid_t).cast(),
            &mut len,
        )
    };
    (read == 0 && pid > 0 && pid != std::process::id() as libc::pid_t).then_some(pid)
}

/// Closes the monitor socket, then reaps the server once it exits.
///
/// A shutdown, not only a close: a process forked after the mount holds a copy
/// of the socket, and a close of this copy alone sends no end-of-file.
fn end(monitor: OwnedFd, server: libc::pid_t) {
    unsafe { libc::shutdown(monitor.as_raw_fd(), libc::SHUT_RDWR) };
    drop(monitor);
    let deadline = Instant::now() + EXIT_WITHIN;
    loop {
        let mut status = 0;
        match unsafe { libc::waitpid(server, &mut status, libc::WNOHANG) } {
            0 if Instant::now() < deadline => std::thread::sleep(EXIT_POLL),
            0 => {
                warn!("the FUSE-T server {server} did not exit within {EXIT_WITHIN:?}");
                return;
            }
            // Reaped, or not a child this process can reap.
            _ => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::FromRawFd;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};

    /// A stand-in server: a child that reads its monitor socket until
    /// end-of-file, then exits. The tests reap it by its process id.
    fn spawn_server() -> (OwnedFd, Child) {
        let (ours, theirs) = UnixStream::pair().expect("a socket pair");
        let theirs = OwnedFd::from(theirs);
        let fd = theirs.as_raw_fd();
        let mut command = Command::new("/bin/cat");
        command.stdout(Stdio::null());
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(fd, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().expect("the stand-in server starts");
        drop(theirs);
        (OwnedFd::from(ours), child)
    }

    fn pid_of(child: &Child) -> libc::pid_t {
        child.id() as libc::pid_t
    }

    /// Whether `pid` ends within a second once its monitor closes.
    fn stops(pid: libc::pid_t) -> bool {
        let mut status = 0;
        (0..100).any(|_| {
            std::thread::sleep(Duration::from_millis(10));
            unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) != 0 }
        })
    }

    /// Whether `pid` is still a child of this process, after a non-blocking
    /// reap. An ended and reaped server is not.
    fn running(pid: libc::pid_t) -> bool {
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) == 0 }
    }

    #[test]
    fn a_drop_ends_the_server_it_was_given() {
        let (monitor, child) = spawn_server();
        let pid = pid_of(&child);
        let server = Server::new();
        server.deliver(monitor, pid);
        assert!(running(pid), "the server runs while the mount does");

        server.end();
        assert!(!running(pid), "the drop left the server running");
    }

    /// The server unmounts by path as it exits, and a drop that came first no
    /// longer vouches for what that path carries.
    #[test]
    fn a_status_after_the_drop_leaves_the_server_alone() {
        let server = Server::new();
        server.end();

        let (monitor, child) = spawn_server();
        let pid = pid_of(&child);
        let raw = monitor.as_raw_fd();
        server.deliver(monitor, pid);
        assert!(running(pid), "the late status ended the server");

        drop(unsafe { OwnedFd::from_raw_fd(raw) });
        assert!(stops(pid), "the stand-in server did not stop");
    }

    /// A process forked after the mount holds a copy of the monitor socket. The
    /// server still ends.
    #[test]
    fn a_copy_of_the_monitor_does_not_keep_the_server() {
        let (monitor, child) = spawn_server();
        let pid = pid_of(&child);
        let copy = monitor.try_clone().expect("a second descriptor");
        let server = Server::new();
        server.deliver(monitor, pid);

        server.end();
        assert!(!running(pid), "the copy kept the server running");
        drop(copy);
    }

    #[test]
    fn a_mount_with_no_status_has_nothing_to_end() {
        let server = Server::new();
        server.end();
        server.end();
    }
}

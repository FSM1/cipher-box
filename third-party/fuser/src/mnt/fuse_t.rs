//! CipherBox patch: end the FUSE-T server a mount started.
//!
//! FUSE-T forks one `go-nfsv4` server per mount and holds two sockets to it:
//! the FUSE channel, and a monitor socket. An unmount, from inside the app or
//! outside it, does not end the server. The server ends when its monitor socket
//! reaches end-of-file, and it then force-unmounts the mount point by path.
//! Thus a drop ends it only where the mount table lists no mount at the path,
//! and a server the drop ends keeps its path until it exits: no new mount
//! lands there first. A server the drop keeps runs until the app exits.
//!
//! `fuse_mount_compat25` keeps the monitor socket inside the library. The mount
//! asks `fuse_kern_mount` for it instead: the library hands it to a callback
//! when the server reports the mount status.

use std::ffi::{CStr, CString};
use std::io;
#[cfg(fuser_fuse_t)]
use std::os::fd::{FromRawFd, RawFd};
use std::os::fd::{AsRawFd, IntoRawFd, OwnedFd};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use log::warn;

/// How long a new mount waits for the server of an earlier mount at its path
/// to exit before it refuses.
pub(crate) const EXIT_WITHIN: Duration = Duration::from_secs(5);

/// The mount points whose last server has not exited yet, one entry per
/// server.
static EXITING: Mutex<Vec<CString>> = Mutex::new(Vec::new());
static EXITED: Condvar = Condvar::new();

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    // A poisoned lock still holds a valid value, and the callback that reads
    // one must not unwind into the library.
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The monitor socket of one mount, as the library and the drop see it.
#[derive(Debug)]
enum State {
    /// The library has not reported the mount status yet.
    Awaited,
    /// The server is running, and this socket is its monitor.
    Held { monitor: OwnedFd, server: libc::pid_t },
    /// The mount dropped. Every monitor from here stays open, because a close
    /// ends a server, and the drop no longer vouches for what the path carries.
    Ended,
}

/// The server of one mount. Shared with the library's mount-status thread.
#[derive(Debug)]
pub(crate) struct Server(Arc<Mutex<State>>);

impl Server {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Mutex::new(State::Awaited)))
    }

    /// The library reported the mount status over `monitor`, whose peer is
    /// `server`.
    pub(crate) fn deliver(&self, monitor: OwnedFd, server: libc::pid_t) {
        let mut state = locked(&self.0);
        if matches!(*state, State::Awaited) {
            *state = State::Held { monitor, server };
        } else {
            let _ = monitor.into_raw_fd();
        }
    }

    /// The mount at `at` dropped. Ends its server only when `mounted_there`
    /// proves no mount is left there: a successful unmount can still leave a
    /// mount that the vault mount covered.
    pub(crate) fn release(
        &self,
        at: &CStr,
        mounted_there: impl FnOnce(&CStr) -> io::Result<bool>,
    ) {
        let ended = std::mem::replace(&mut *locked(&self.0), State::Ended);
        let State::Held { monitor, server } = ended else {
            return;
        };
        if matches!(mounted_there(at), Ok(false)) {
            shut_down_and_reap(monitor, server, at);
        } else {
            let _ = monitor.into_raw_fd();
            warn!("the FUSE-T server {server} stays: its mount point may carry another mount");
        }
    }

    /// The context `fuse_kern_mount` hands back to [`delivered`]. The callback
    /// takes this reference back. A mount whose status never arrives keeps it.
    #[cfg(fuser_fuse_t)]
    pub(crate) fn context(&self) -> *mut libc::c_void {
        Arc::into_raw(self.0.clone()) as *mut libc::c_void
    }
}

/// Waits until no server of an earlier mount at `at` is still exiting, or
/// refuses once `within` runs out. The refusal is worth a retry.
pub(crate) fn await_exits(at: &CStr, within: Duration) -> io::Result<()> {
    let deadline = Instant::now() + within;
    let mut exiting = locked(&EXITING);
    while exiting.iter().any(|path| path.as_c_str() == at) {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::ResourceBusy,
                "the FUSE-T server of the last mount at this mount point has not exited yet",
            ));
        }
        exiting = EXITED
            .wait_timeout(exiting, left)
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .0;
    }
    Ok(())
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

/// Whether the mount table lists a mount at `at`, which is spelled the way the
/// table spells it. Read with `MNT_NOWAIT`: a read through a mount whose
/// server is this process could wait on itself.
#[cfg(any(fuser_fuse_t, all(test, target_os = "macos")))]
pub(crate) fn mounted_at(at: &CStr) -> io::Result<bool> {
    let listed = unsafe { libc::getfsstat(std::ptr::null_mut(), 0, libc::MNT_NOWAIT) };
    if listed < 0 {
        return Err(io::Error::last_os_error());
    }
    // Room for mounts that land between the two reads.
    let mut table: Vec<libc::statfs> = (0..listed as usize + 8)
        .map(|_| unsafe { std::mem::zeroed() })
        .collect();
    let bytes = (table.len() * std::mem::size_of::<libc::statfs>()) as libc::c_int;
    let read = unsafe { libc::getfsstat(table.as_mut_ptr(), bytes, libc::MNT_NOWAIT) };
    if read < 0 {
        return Err(io::Error::last_os_error());
    }
    lists(&table, read as usize, at)
}

/// Whether the first `read` entries of `table` list a mount at `at`. A full
/// table may have been cut short, so it answers nothing.
#[cfg(any(fuser_fuse_t, all(test, target_os = "macos")))]
fn lists(table: &[libc::statfs], read: usize, at: &CStr) -> io::Result<bool> {
    if read >= table.len() {
        return Err(io::Error::other("the mount table filled its buffer"));
    }
    Ok(table[..read]
        .iter()
        .any(|mounted| unsafe { CStr::from_ptr(mounted.f_mntonname.as_ptr()) } == at))
}

/// Closes the monitor socket, and reaps the server off the caller's thread.
/// Until then the path is in [`EXITING`].
///
/// A shutdown, not only a close: a process forked after the mount holds a copy
/// of the socket, and a close of this copy alone sends no end-of-file.
fn shut_down_and_reap(monitor: OwnedFd, server: libc::pid_t, at: &CStr) {
    locked(&EXITING).push(at.to_owned());
    unsafe { libc::shutdown(monitor.as_raw_fd(), libc::SHUT_RDWR) };
    drop(monitor);
    let reaping = at.to_owned();
    let started = std::thread::Builder::new()
        .name("fuse-t-reaper".to_owned())
        .spawn(move || reap(server, &reaping));
    if started.is_err() {
        reap(server, at);
    }
}

/// Waits for `server` to exit, then frees its path in [`EXITING`].
fn reap(server: libc::pid_t, at: &CStr) {
    let mut status = 0;
    // Returns once the server exits, or at once for a pid that is not a child
    // this process can reap.
    while unsafe { libc::waitpid(server, &mut status, 0) } < 0
        && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
    {}
    let mut exiting = locked(&EXITING);
    if let Some(entry) = exiting.iter().position(|path| path.as_c_str() == at) {
        exiting.swap_remove(entry);
    }
    EXITED.notify_all();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::{FromRawFd, RawFd};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};

    /// A stand-in server: `program` with the monitor socket as its standard
    /// input. `/bin/cat` exits at end-of-file, `/bin/sleep` does not. The
    /// tests reap it by its process id.
    fn spawn_server(program: &str, args: &[&str]) -> (OwnedFd, Child) {
        let (ours, theirs) = UnixStream::pair().expect("a socket pair");
        let theirs = OwnedFd::from(theirs);
        let fd = theirs.as_raw_fd();
        let mut command = Command::new(program);
        command.args(args).stdout(Stdio::null());
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

    /// A mount point of its own per test: the tests share [`EXITING`].
    fn path(name: &str) -> CString {
        CString::new(format!("/fuse-t-test/{name}")).expect("no NUL")
    }

    /// Whether `pid` is still a child of this process, after a non-blocking
    /// reap. An ended and reaped server is not.
    fn running(pid: libc::pid_t) -> bool {
        let mut status = 0;
        unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) == 0 }
    }

    /// Whether `done` holds within a second.
    fn within_a_second(mut done: impl FnMut() -> bool) -> bool {
        (0..100).any(|_| {
            std::thread::sleep(Duration::from_millis(10));
            done()
        })
    }

    fn nothing_mounted(_: &CStr) -> io::Result<bool> {
        Ok(false)
    }

    /// A server, delivered to a fresh [`Server`], whose monitor this test
    /// closes itself.
    fn held_server() -> (Server, libc::pid_t, RawFd) {
        let (monitor, child) = spawn_server("/bin/cat", &[]);
        let pid = pid_of(&child);
        let raw = monitor.as_raw_fd();
        let server = Server::new();
        server.deliver(monitor, pid);
        (server, pid, raw)
    }

    /// Closes the monitor a kept server still holds, and waits for it to stop.
    fn stop_kept(pid: libc::pid_t, raw: RawFd) {
        drop(unsafe { OwnedFd::from_raw_fd(raw) });
        assert!(
            within_a_second(|| !running(pid)),
            "the stand-in server did not stop"
        );
    }

    /// The path still carries a mount after the drop: one that took it after
    /// the vault left, or one the vault mount covered, which a successful
    /// unmount uncovers. The server must not force-unmount it.
    #[test]
    fn a_mount_left_at_the_path_keeps_the_server() {
        let at = path("foreign");
        let (server, pid, raw) = held_server();

        server.release(&at, |_| Ok(true));
        assert!(running(pid), "the server ended over another mount");
        stop_kept(pid, raw);
    }

    #[test]
    fn an_unread_mount_table_keeps_the_server() {
        let at = path("unread");
        let (server, pid, raw) = held_server();

        server.release(&at, |_| Err(io::Error::other("unread")));
        assert!(running(pid), "an unread table ended the server");
        stop_kept(pid, raw);
    }

    #[test]
    fn an_empty_mount_point_ends_the_server() {
        let at = path("empty");
        let (monitor, child) = spawn_server("/bin/cat", &[]);
        let pid = pid_of(&child);
        let server = Server::new();
        server.deliver(monitor, pid);

        assert!(running(pid), "the server runs while the mount does");

        server.release(&at, nothing_mounted);
        await_exits(&at, EXIT_WITHIN).expect("the server exits");
        assert!(!running(pid), "the server outlived an empty mount point");
    }

    #[test]
    fn a_status_after_the_drop_leaves_the_server_alone() {
        let at = path("late");
        let server = Server::new();
        server.release(&at, nothing_mounted);

        let (monitor, child) = spawn_server("/bin/cat", &[]);
        let pid = pid_of(&child);
        let raw = monitor.as_raw_fd();
        server.deliver(monitor, pid);
        assert!(running(pid), "the late status ended the server");
        stop_kept(pid, raw);
    }

    /// A process forked after the mount holds a copy of the monitor socket.
    #[test]
    fn a_copy_of_the_monitor_does_not_keep_the_server() {
        let at = path("copy");
        let (monitor, child) = spawn_server("/bin/cat", &[]);
        let pid = pid_of(&child);
        let copy = monitor.try_clone().expect("a second descriptor");
        let server = Server::new();
        server.deliver(monitor, pid);

        server.release(&at, nothing_mounted);
        await_exits(&at, EXIT_WITHIN).expect("the server exits");
        assert!(!running(pid), "the copy kept the server running");
        drop(copy);
    }

    /// A server that outlives the wait still owns its path: a new mount there
    /// is refused until it exits, and then goes ahead.
    #[test]
    fn a_mount_waits_for_the_last_server_at_its_path() {
        let at = path("slow");
        let (monitor, child) = spawn_server("/bin/sleep", &["30"]);
        let pid = pid_of(&child);
        let server = Server::new();
        server.deliver(monitor, pid);

        server.release(&at, nothing_mounted);
        let refused = await_exits(&at, Duration::from_millis(50)).expect_err("a live server");
        assert_eq!(refused.kind(), io::ErrorKind::ResourceBusy);
        await_exits(&path("elsewhere"), Duration::ZERO).expect("another path is free");

        unsafe { libc::kill(pid, libc::SIGKILL) };
        await_exits(&at, EXIT_WITHIN).expect("the path is free once the server exits");
    }

    #[test]
    fn a_mount_with_no_status_has_nothing_to_end() {
        let at = path("no-status");
        let server = Server::new();
        server.release(&at, nothing_mounted);
        server.release(&at, nothing_mounted);
        await_exits(&at, Duration::ZERO).expect("nothing exits");
    }

    /// The session thread reads the channel, whose other end the server holds,
    /// so the thread ends when the server does.
    #[test]
    fn the_session_thread_ends_with_its_server() {
        struct Nothing;
        impl crate::Filesystem for Nothing {}

        let (ours, theirs) = UnixStream::pair().expect("a socket pair");
        let session =
            crate::Session::from_fd(Nothing, OwnedFd::from(ours), crate::SessionACL::Owner)
                .spawn()
                .expect("the session thread starts");
        drop(theirs);
        assert!(
            within_a_second(|| session.guard.is_finished()),
            "the session thread outlived its server"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_mount_table_lists_the_root_and_not_a_plain_directory() {
        let dir = tempfile::tempdir().expect("a temp dir");
        let plain = std::fs::canonicalize(dir.path()).expect("a real path");
        let plain = CString::new(plain.as_os_str().as_encoded_bytes()).expect("no NUL");
        assert!(mounted_at(c"/").expect("the table reads"));
        assert!(!mounted_at(&plain).expect("the table reads"));
    }

    #[cfg(target_os = "macos")]
    fn entry(on: &str) -> libc::statfs {
        let mut entry: libc::statfs = unsafe { std::mem::zeroed() };
        for (to, from) in entry.f_mntonname.iter_mut().zip(on.bytes()) {
            *to = from as libc::c_char;
        }
        entry
    }

    /// `getfsstat` stops at the buffer it was given, so a buffer it filled
    /// may have left the path's mount out.
    #[cfg(target_os = "macos")]
    #[test]
    fn a_full_mount_table_answers_nothing() {
        let table = [entry("/"), entry("/Volumes/other")];
        assert!(lists(&table, 2, c"/Volumes/vault").is_err());
        assert!(!lists(&[entry("/"), entry("")], 1, c"/Volumes/vault").expect("room left"));
        assert!(lists(&[entry("/Volumes/vault"), entry("")], 1, c"/Volumes/vault").expect("room left"));
    }

    /// The monitor's peer is the server once the server has used the socket,
    /// as it does when it reports the mount status.
    #[cfg(fuser_fuse_t)]
    #[test]
    fn the_status_callback_hands_over_the_server_and_its_monitor() {
        let at = path("delivered");
        let (monitor, child) = spawn_server("/bin/sh", &["-c", "echo up >&0; exec cat"]);
        let pid = pid_of(&child);
        let mut ready = [0u8; 3];
        let read = unsafe { libc::read(monitor.as_raw_fd(), ready.as_mut_ptr().cast(), 3) };
        assert_eq!(read, 3, "the stand-in server reported");
        assert_eq!(peer_of(monitor.as_raw_fd()), Some(pid));

        let server = Server::new();
        unsafe { delivered(server.context(), 0, monitor.into_raw_fd()) };
        server.release(&at, nothing_mounted);
        await_exits(&at, EXIT_WITHIN).expect("the server exits");
        assert!(!running(pid), "the delivered server outlived the drop");
    }
}

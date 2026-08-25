use std::{
    fs::File,
    io,
    os::{
        fd::{AsFd, BorrowedFd},
        unix::prelude::AsRawFd,
    },
    sync::Arc,
};

use libc::{c_int, c_void, size_t};

#[cfg(feature = "abi-7-40")]
use crate::passthrough::BackingId;
use crate::reply::ReplySender;

/// A raw communication channel to the FUSE kernel driver
#[derive(Debug)]
pub struct Channel(Arc<File>);

impl AsFd for Channel {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.0.as_fd()
    }
}

impl Channel {
    /// Create a new communication channel to the kernel driver by mounting the
    /// given path. The kernel driver will delegate filesystem operations of
    /// the given path to the channel.
    pub(crate) fn new(device: Arc<File>) -> Self {
        Self(device)
    }

    /// Receives data up to the capacity of the given buffer (can block).
    ///
    /// Platform behavior:
    /// - **Linux** (`/dev/fuse`): the kernel delivers one complete FUSE message
    ///   per `read()`. `MSG_PEEK` is not an option here — the device is not a
    ///   socket, and `recv` on it answers `ENOTSOCK`.
    /// - **macOS** (FUSE-T): the channel is a Unix domain socket, which
    ///   fragments messages above ~256KB. CipherBox patch: peek the header for
    ///   the message length, then loop-read exactly that many bytes.
    pub fn receive(&self, buffer: &mut [u8]) -> io::Result<usize> {
        // `cfg!` rather than `#[cfg]`: both strategies compile on every unix
        // target, so the framed one carries its regression test wherever the
        // suite runs (blueprint/testing.md, `FUSE Op Core`).
        if cfg!(target_os = "linux") {
            receive_atomic(self.0.as_fd(), buffer)
        } else {
            receive_framed(self.0.as_fd(), buffer)
        }
    }

    /// Returns a sender object for this channel. The sender object can be
    /// used to send to the channel. Multiple sender objects can be used
    /// and they can safely be sent to other threads.
    pub fn sender(&self) -> ChannelSender {
        // Since write/writev syscalls are threadsafe, we can simply create
        // a sender by using the same file and use it in other threads.
        ChannelSender(self.0.clone())
    }
}

/// The `fuse_in_header` every message starts with. A framed read refuses a
/// length that could not even hold it.
const FUSE_IN_HEADER_BYTES: usize = std::mem::size_of::<crate::ll::fuse_abi::fuse_in_header>();

/// One `read()` per message, the way `/dev/fuse` delivers them.
fn receive_atomic(fd: BorrowedFd<'_>, buffer: &mut [u8]) -> io::Result<usize> {
    let rc = unsafe {
        libc::read(
            fd.as_raw_fd(),
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as size_t,
        )
    };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(rc as usize)
}

/// One message reassembled from however many fragments the socket hands over.
///
/// The first four bytes of `fuse_in_header` are the total message length, and
/// `MSG_PEEK` reads them without consuming them, so the length is known before
/// a single byte is taken.
fn receive_framed(fd: BorrowedFd<'_>, buffer: &mut [u8]) -> io::Result<usize> {
    let fd = fd.as_raw_fd();

    let mut header = [0u8; 4];
    loop {
        // MSG_WAITALL parks until the whole length field is there; without it a
        // peer that has sent one byte would spin this loop on a full core.
        let rc = unsafe {
            libc::recv(
                fd,
                header.as_mut_ptr() as *mut c_void,
                header.len() as size_t,
                libc::MSG_PEEK | libc::MSG_WAITALL,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if rc == 0 {
            return Ok(0); // EOF
        }
        if rc as usize >= header.len() {
            break;
        }
    }

    // A length that cannot even cover the header, or that overruns the buffer,
    // is refused rather than turned into a short read the decoder would have to
    // recognize as a truncated request.
    let expected = u32::from_ne_bytes(header) as usize;
    if !(FUSE_IN_HEADER_BYTES..=buffer.len()).contains(&expected) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "FUSE message length {} is outside {}..={}",
                expected,
                FUSE_IN_HEADER_BYTES,
                buffer.len()
            ),
        ));
    }

    let mut total = 0usize;
    while total < expected {
        let rc = unsafe {
            libc::read(
                fd,
                buffer.as_mut_ptr().add(total) as *mut c_void,
                (expected - total) as size_t,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        if rc == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("FUSE message ended after {total} of {expected} bytes"),
            ));
        }
        total += rc as usize;
    }

    Ok(total)
}

#[derive(Clone, Debug)]
pub struct ChannelSender(Arc<File>);

impl ReplySender for ChannelSender {
    fn send(&self, bufs: &[io::IoSlice<'_>]) -> io::Result<()> {
        let rc = unsafe {
            libc::writev(
                self.0.as_raw_fd(),
                bufs.as_ptr() as *const libc::iovec,
                bufs.len() as c_int,
            )
        };
        if rc < 0 {
            return Err(io::Error::last_os_error());
        }
        // Release-active, not a debug_assert: a short writev on the FUSE-T
        // socket delivers a truncated reply, and reporting success for it
        // desynchronizes the session against the kernel's own accounting.
        let written = rc as usize;
        let expected: usize = bufs.iter().map(|b| b.len()).sum();
        if written != expected {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                format!("short FUSE reply: {written} of {expected} bytes"),
            ));
        }
        Ok(())
    }

    #[cfg(feature = "abi-7-40")]
    fn open_backing(&self, fd: BorrowedFd<'_>) -> std::io::Result<BackingId> {
        BackingId::create(&self.0, fd)
    }
}

/// The CipherBox socket-read patch's regression suite. FUSE-T hands FUSE
/// messages over a Unix socket, which splits anything large across several
/// reads; stock fuser took one `read()` as one message and truncated them.
#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;

    use super::*;

    /// A FUSE message: the four-byte total length, then the body that makes it
    /// up to that length.
    fn message(len: usize) -> Vec<u8> {
        assert!(len >= FUSE_IN_HEADER_BYTES);
        let mut out = (len as u32).to_ne_bytes().to_vec();
        out.extend((4..len).map(|i| (i % 251) as u8));
        out
    }

    #[test]
    fn a_message_split_across_reads_is_reassembled_whole() {
        let (kernel, us) = UnixStream::pair().expect("socketpair");
        let sent = message(64 * 1024);
        let (head, tail) = sent.split_at(1024);
        let (head, tail) = (head.to_vec(), tail.to_vec());

        let writer = std::thread::spawn(move || {
            let mut kernel = kernel;
            kernel.write_all(&head).expect("head");
            // The reader is now parked on the rest of the message. Stock fuser
            // takes the head alone and calls it a whole request; the patched
            // read knows from the header how much is still coming.
            std::thread::sleep(std::time::Duration::from_millis(100));
            kernel.write_all(&tail).expect("tail");
        });

        let mut buffer = vec![0u8; sent.len() + 4096];
        let taken = receive_framed(us.as_fd(), &mut buffer).expect("receive");
        writer.join().expect("writer");

        assert_eq!(taken, sent.len(), "a fragmented message arrives whole");
        assert_eq!(&buffer[..taken], &sent[..]);
    }

    /// The length field itself can arrive split. Peeking it must park, not spin
    /// and not decide on the bytes it has.
    #[test]
    fn a_header_split_across_reads_is_waited_out() {
        let (kernel, us) = UnixStream::pair().expect("socketpair");
        let sent = message(128);
        let (head, tail) = sent.split_at(2);
        let (head, tail) = (head.to_vec(), tail.to_vec());

        let writer = std::thread::spawn(move || {
            let mut kernel = kernel;
            kernel.write_all(&head).expect("head");
            std::thread::sleep(std::time::Duration::from_millis(100));
            kernel.write_all(&tail).expect("tail");
        });

        let mut buffer = vec![0u8; 4096];
        let taken = receive_framed(us.as_fd(), &mut buffer).expect("receive");
        writer.join().expect("writer");
        assert_eq!(&buffer[..taken], &sent[..]);
    }

    /// Back-to-back messages: taking more than one message's bytes would leave
    /// the next request's header mid-stream and desynchronize the session.
    #[test]
    fn a_read_stops_at_the_end_of_one_message() {
        let (kernel, us) = UnixStream::pair().expect("socketpair");
        let first = message(64);
        let second = message(96);
        let mut kernel = kernel;
        kernel.write_all(&first).expect("first");
        kernel.write_all(&second).expect("second");

        let mut buffer = vec![0u8; 8192];
        let taken = receive_framed(us.as_fd(), &mut buffer).expect("first receive");
        assert_eq!(&buffer[..taken], &first[..]);

        let taken = receive_framed(us.as_fd(), &mut buffer).expect("second receive");
        assert_eq!(&buffer[..taken], &second[..]);
    }

    /// A length outside the admissible range is refused rather than turned into
    /// a short read the decoder has to recognize as truncated.
    #[test]
    fn a_length_the_buffer_cannot_hold_is_refused() {
        let (kernel, us) = UnixStream::pair().expect("socketpair");
        let mut kernel = kernel;
        kernel.write_all(&message(4096)).expect("write");

        let mut buffer = vec![0u8; 64];
        let refusal = receive_framed(us.as_fd(), &mut buffer).expect_err("refused");
        assert_eq!(refusal.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_length_too_small_for_a_header_is_refused() {
        let (kernel, us) = UnixStream::pair().expect("socketpair");
        let mut kernel = kernel;
        let mut claim = vec![0u8; 64];
        claim[..4].copy_from_slice(&8u32.to_ne_bytes());
        kernel.write_all(&claim).expect("write");

        let mut buffer = vec![0u8; 8192];
        let refusal = receive_framed(us.as_fd(), &mut buffer).expect_err("refused");
        assert_eq!(refusal.kind(), io::ErrorKind::InvalidData);
    }

    /// A peer that dies mid-message must not present the fragment it managed to
    /// send as a complete request.
    #[test]
    fn a_message_cut_short_by_a_dead_peer_is_not_a_message() {
        let (kernel, us) = UnixStream::pair().expect("socketpair");
        let sent = message(4096);
        let mut kernel = kernel;
        kernel.write_all(&sent[..512]).expect("prefix");
        drop(kernel);

        let mut buffer = vec![0u8; 8192];
        let refusal = receive_framed(us.as_fd(), &mut buffer).expect_err("refused");
        assert_eq!(refusal.kind(), io::ErrorKind::UnexpectedEof);
    }

    /// A closed peer ends the session loop; it must not read as a message.
    #[test]
    fn a_closed_peer_reads_as_end_of_stream() {
        let (kernel, us) = UnixStream::pair().expect("socketpair");
        drop(kernel);

        let mut buffer = vec![0u8; 64];
        assert_eq!(receive_framed(us.as_fd(), &mut buffer).expect("eof"), 0);
    }

    /// A reply the socket only partly took is an error, not a success — and the
    /// check has to hold in a release build, where a `debug_assert` is gone
    /// (AGENTS.md rule 8).
    #[test]
    fn a_reply_the_socket_only_partly_took_is_refused() {
        let (kernel, us) = UnixStream::pair().expect("socketpair");
        let small: c_int = 4096;
        let set = unsafe {
            libc::setsockopt(
                us.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                std::ptr::addr_of!(small).cast(),
                std::mem::size_of::<c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(set, 0, "the send buffer must shrink for this to be short");
        us.set_nonblocking(true).expect("nonblocking");

        let payload = vec![0x5au8; 4 << 20];
        let sender = ChannelSender(Arc::new(File::from(OwnedFd::from(us))));
        let refusal = sender
            .send(&[io::IoSlice::new(&payload)])
            .expect_err("a short reply is refused");
        assert_eq!(refusal.kind(), io::ErrorKind::WriteZero);
        drop(kernel);
    }
}

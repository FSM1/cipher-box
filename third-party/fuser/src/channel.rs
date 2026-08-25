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
        let rc = unsafe {
            libc::recv(
                fd,
                header.as_mut_ptr() as *mut c_void,
                header.len() as size_t,
                libc::MSG_PEEK,
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
        // A partial header: the rest of it is still in flight.
    }

    let expected = u32::from_ne_bytes(header) as usize;
    if expected > buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "FUSE message ({} bytes) exceeds receive buffer ({} bytes)",
                expected,
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
            break; // EOF
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
            Err(io::Error::last_os_error())
        } else {
            debug_assert_eq!(bufs.iter().map(|b| b.len()).sum::<usize>(), rc as usize);
            Ok(())
        }
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
    use std::os::unix::net::UnixStream;

    use super::*;

    /// A FUSE message: the four-byte total length, then the body that makes it
    /// up to that length.
    fn message(len: usize) -> Vec<u8> {
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

    /// The peek must not consume: a header read out of the stream would leave
    /// the body headerless.
    #[test]
    fn peeking_the_header_leaves_it_in_the_stream() {
        let (kernel, us) = UnixStream::pair().expect("socketpair");
        let sent = message(32);
        let mut kernel = kernel;
        kernel.write_all(&sent).expect("write");

        let mut peeked = [0u8; 4];
        let rc = unsafe {
            libc::recv(
                us.as_raw_fd(),
                peeked.as_mut_ptr() as *mut c_void,
                peeked.len() as size_t,
                libc::MSG_PEEK,
            )
        };
        assert_eq!(rc, 4);

        let mut buffer = vec![0u8; 8192];
        let taken = receive_framed(us.as_fd(), &mut buffer).expect("receive");
        assert_eq!(&buffer[..taken], &sent[..], "the peek consumed nothing");
    }

    /// A message the buffer cannot hold is refused rather than truncated into
    /// a half-decoded request.
    #[test]
    fn a_message_wider_than_the_buffer_is_refused() {
        let (kernel, us) = UnixStream::pair().expect("socketpair");
        let mut kernel = kernel;
        kernel.write_all(&message(4096)).expect("write");

        let mut buffer = vec![0u8; 64];
        let refusal = receive_framed(us.as_fd(), &mut buffer).expect_err("refused");
        assert_eq!(refusal.kind(), io::ErrorKind::InvalidData);
    }

    /// A closed peer ends the session loop; it must not read as a message.
    #[test]
    fn a_closed_peer_reads_as_end_of_stream() {
        let (kernel, us) = UnixStream::pair().expect("socketpair");
        drop(kernel);

        let mut buffer = vec![0u8; 64];
        assert_eq!(receive_framed(us.as_fd(), &mut buffer).expect("eof"), 0);
    }
}

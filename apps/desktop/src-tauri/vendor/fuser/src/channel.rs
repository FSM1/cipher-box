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
    /// - **Linux** (`/dev/fuse`): The kernel delivers complete FUSE messages
    ///   atomically via a single `read()` call. Simple and efficient.
    /// - **macOS** (FUSE-T): Communication happens over a Unix domain socket
    ///   where large messages (>256KB) may arrive in fragments. We peek at
    ///   the header to learn the expected length, then loop-read until the
    ///   full message is received.
    pub fn receive(&self, buffer: &mut [u8]) -> io::Result<usize> {
        let fd = self.0.as_raw_fd();

        // Linux /dev/fuse: each read() returns exactly one complete FUSE
        // message atomically. A single read() call is all we need.
        #[cfg(target_os = "linux")]
        {
            let rc = unsafe {
                libc::read(fd, buffer.as_mut_ptr() as *mut c_void, buffer.len() as size_t)
            };
            if rc < 0 {
                return Err(io::Error::last_os_error());
            }
            return Ok(rc as usize);
        }

        // macOS FUSE-T: the channel is a Unix domain socket where large
        // messages may arrive in fragments. We:
        //   1. Peek at the header to learn the expected message length
        //   2. Read exactly that many bytes (looping if fragmented)
        #[cfg(not(target_os = "linux"))]
        {
            // Step 1: Peek at the FUSE header to get the message length.
            // The first 4 bytes of fuse_in_header is the total message length (u32).
            // Loop until we've peeked all 4 bytes (MSG_PEEK doesn't consume data).
            let mut header_buf = [0u8; 4];
            loop {
                let rc = unsafe {
                    libc::recv(
                        fd,
                        header_buf.as_mut_ptr() as *mut c_void,
                        4 as size_t,
                        libc::MSG_PEEK,
                    )
                };
                if rc < 0 {
                    return Err(io::Error::last_os_error());
                }
                if rc == 0 {
                    return Ok(0); // EOF
                }
                if rc as usize >= 4 {
                    break;
                }
                // Less than 4 bytes available — data still arriving, retry.
            }

            let expected = u32::from_ne_bytes(header_buf) as usize;
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
            let to_read = expected;

            // Step 2: Read exactly `to_read` bytes (the complete FUSE message).
            let mut total = 0usize;
            while total < to_read {
                let rc = unsafe {
                    libc::read(
                        fd,
                        buffer.as_mut_ptr().add(total) as *mut c_void,
                        (to_read - total) as size_t,
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

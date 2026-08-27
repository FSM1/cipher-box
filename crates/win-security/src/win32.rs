use std::ffi::c_void;
use std::io;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
use windows_sys::Win32::Security::{
    GetLengthSid, GetTokenInformation, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// A process token, closed when it goes out of scope.
struct Token(HANDLE);

impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: `self.0` came from a successful `OpenProcessToken` and is
        // closed exactly once, here.
        unsafe { CloseHandle(self.0) };
    }
}

impl Token {
    /// The current process's token, opened for query.
    fn open() -> io::Result<Self> {
        let mut token: HANDLE = ptr::null_mut();
        // SAFETY: `GetCurrentProcess` returns a pseudo-handle that needs no
        // closing, and `token` is a live out-parameter for the duration.
        let opened = unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) };
        if opened == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(token))
    }

    /// `TokenUser` as raw bytes, sized by the query the call itself answers.
    fn user_information(&self) -> io::Result<Vec<u8>> {
        let mut needed = 0u32;
        // SAFETY: the null buffer with a zero length is the documented way to
        // ask for the size; it writes only `needed` and fails with
        // `ERROR_INSUFFICIENT_BUFFER`, which is why the return is ignored.
        unsafe { GetTokenInformation(self.0, TokenUser, ptr::null_mut(), 0, &mut needed) };
        if needed == 0 {
            return Err(io::Error::last_os_error());
        }
        let mut buffer = vec![0u8; needed as usize];
        // SAFETY: `buffer` is `needed` bytes long, which is what the sizing
        // call above asked for and what `needed` still says.
        let read = unsafe {
            GetTokenInformation(
                self.0,
                TokenUser,
                buffer.as_mut_ptr().cast::<c_void>(),
                needed,
                &mut needed,
            )
        };
        if read == 0 {
            return Err(io::Error::last_os_error());
        }
        buffer.truncate(needed as usize);
        Ok(buffer)
    }
}

/// The SID of the user this process is running as, in the self-relative layout
/// a security descriptor embeds.
///
/// This is the identity a vault mount belongs to: the projection stores no
/// ownership of its own, so the account that made the mount is the only one its
/// access check can name.
pub fn current_user_sid() -> io::Result<Vec<u8>> {
    let token = Token::open()?;
    let information = token.user_information()?;
    if information.len() < size_of::<TOKEN_USER>() {
        return Err(io::Error::other("the process token carried no user"));
    }
    // SAFETY: `GetTokenInformation(TokenUser, ..)` fills the buffer with a
    // `TOKEN_USER` followed by the SID it points at, and the length check above
    // covers the struct itself.
    let user = unsafe { &*information.as_ptr().cast::<TOKEN_USER>() };
    let sid = user.User.Sid;
    if sid.is_null() {
        return Err(io::Error::other("the process token carried no user SID"));
    }
    // SAFETY: `sid` points into `information`, which outlives this borrow, and
    // `GetLengthSid` reports how much of it the SID occupies.
    let length = unsafe { GetLengthSid(sid) } as usize;
    if length == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `sid` is a valid SID of `length` bytes, inside `information`.
    Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length) }.to_vec())
}

/// Copy `descriptor` into the out-buffer WinFsp supplied, reporting the size
/// the descriptor needs whether or not it fit.
///
/// Reporting the true size on a short buffer is the protocol, not a failure:
/// WinFsp reallocates and asks again.
pub fn write_descriptor(out: Option<&mut [c_void]>, descriptor: &[u8]) -> u64 {
    if let Some(out) = out
        && out.len() >= descriptor.len()
    {
        // SAFETY: `out` is a caller-owned buffer of at least `descriptor.len()`
        // bytes, and the two cannot overlap — one is WinFsp's transaction
        // buffer, the other this process's own `Vec`.
        unsafe {
            ptr::copy_nonoverlapping(
                descriptor.as_ptr(),
                out.as_mut_ptr().cast::<u8>(),
                descriptor.len(),
            );
        }
    }
    descriptor.len() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The mounting user's SID is what the vault's access check names, so a
    /// mount that could not read it would have nothing to enforce.
    #[test]
    fn the_process_token_yields_a_well_formed_sid() {
        let sid = current_user_sid().expect("the process has a user");
        assert_eq!(sid[0], 1, "SID_REVISION");
        let subauthorities = usize::from(sid[1]);
        assert!(subauthorities > 0, "a user SID has subauthorities");
        assert_eq!(
            sid.len(),
            8 + 4 * subauthorities,
            "the length matches the subauthority count"
        );
    }

    #[test]
    fn a_descriptor_reports_its_size_and_copies_only_when_it_fits() {
        let descriptor = [1u8, 2, 3, 4];

        assert_eq!(
            write_descriptor(None, &descriptor),
            4,
            "size without a copy"
        );

        let mut short = [0u8; 2];
        let short_out: &mut [c_void] =
            // SAFETY: reinterpreting an owned byte buffer as the opaque element
            // type WinFsp's signature uses; same length, same alignment.
            unsafe { std::slice::from_raw_parts_mut(short.as_mut_ptr().cast(), short.len()) };
        assert_eq!(write_descriptor(Some(short_out), &descriptor), 4);
        assert_eq!(short, [0, 0], "a short buffer is never partly written");

        let mut room = [0u8; 6];
        let room_out: &mut [c_void] =
            // SAFETY: as above.
            unsafe { std::slice::from_raw_parts_mut(room.as_mut_ptr().cast(), room.len()) };
        assert_eq!(write_descriptor(Some(room_out), &descriptor), 4);
        assert_eq!(room, [1, 2, 3, 4, 0, 0]);
    }
}

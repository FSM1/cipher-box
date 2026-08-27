//! The vault volume's security descriptor: owner-only, assembled as bytes.
//!
//! Windows is the one platform where the mount's access control is the
//! filesystem's own job. The unix backends get it from the kernel — a mount
//! made without `allow_other` is unreachable by anyone else — but WinFsp asks
//! the filesystem for a descriptor and grants the caller whatever it asked for
//! when the filesystem reports none. Bypass-traverse-checking is granted to
//! Everyone by default, so a second local account can open a full path under
//! another user's profile without ever passing a check on the directories above
//! it: the descriptor served here is the only thing standing between them and
//! the vault's plaintext.
//!
//! A self-relative `SECURITY_DESCRIPTOR` is a fixed binary layout, so it is
//! built and tested in safe Rust; only the mounting user's SID and the copy
//! into WinFsp's out-buffer cross into `cipherbox-win-security`.

use std::io;

/// `SECURITY_DESCRIPTOR_REVISION`.
const SD_REVISION: u8 = 1;
/// `SE_DACL_PRESENT | SE_SELF_RELATIVE`.
const SD_CONTROL: u16 = 0x0004 | 0x8000;
/// The fixed header of a self-relative descriptor: revision, `Sbz1`, control,
/// then the four offsets.
const SD_HEADER_BYTES: usize = 20;

/// `ACL_REVISION`.
const ACL_REVISION: u8 = 2;
/// The fixed header of an `ACL`: revision, `Sbz1`, size, count, `Sbz2`.
const ACL_HEADER_BYTES: usize = 8;

/// `ACCESS_ALLOWED_ACE_TYPE`.
const ACE_TYPE_ALLOWED: u8 = 0;
/// `OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE` — the vault is a tree, and an
/// entry created under it inherits the same two grants.
const ACE_FLAGS_INHERIT: u8 = 0x01 | 0x02;
/// The fixed part of an `ACCESS_ALLOWED_ACE`, before the SID.
const ACE_HEADER_BYTES: usize = 8;

/// `FILE_ALL_ACCESS`.
const FILE_ALL_ACCESS: u32 = 0x001F_01FF;

/// `S-1-5-18`, the local SYSTEM account, in the self-relative SID layout.
///
/// Granted because a service that cannot open the volume cannot flush or unmount
/// it; SYSTEM can read any user's files on this machine regardless, so it is not
/// a widening.
const SYSTEM_SID: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];

/// The descriptor every node on the volume reports.
///
/// One descriptor for the whole vault, not one per node: the projection stores
/// no per-node ownership, and the mount belongs to exactly one account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerOnlyDescriptor(Vec<u8>);

impl OwnerOnlyDescriptor {
    /// The descriptor for the account this process is running as.
    pub fn for_this_user() -> io::Result<Self> {
        Ok(Self::over(&cipherbox_win_security::current_user_sid()?))
    }

    /// The descriptor granting `owner` and SYSTEM, and naming nobody else.
    ///
    /// Absence is the denial: an account with no ACE matching it is granted
    /// nothing, so no explicit deny entry is needed — and none is wanted, since
    /// a deny ACE would also bind the owner if they were ever in the denied
    /// group.
    fn over(owner: &[u8]) -> Self {
        let dacl = dacl(owner);
        let offset_owner = SD_HEADER_BYTES;
        let offset_group = offset_owner + owner.len();
        let offset_dacl = offset_group + SYSTEM_SID.len();

        let mut out = Vec::with_capacity(offset_dacl + dacl.len());
        out.push(SD_REVISION);
        out.push(0);
        out.extend_from_slice(&SD_CONTROL.to_le_bytes());
        out.extend_from_slice(&(offset_owner as u32).to_le_bytes());
        out.extend_from_slice(&(offset_group as u32).to_le_bytes());
        // No SACL: auditing is the machine's policy, not a vault's to state.
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(offset_dacl as u32).to_le_bytes());
        out.extend_from_slice(owner);
        // The primary group is SYSTEM rather than the owner's: it grants
        // nothing on its own — only the DACL does — and the vault has no group
        // of its own to name.
        out.extend_from_slice(&SYSTEM_SID);
        out.extend_from_slice(&dacl);
        Self(out)
    }

    /// The descriptor's bytes, in the self-relative layout WinFsp expects.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// How large the descriptor is — what `get_security_by_name` reports
    /// whether or not the caller's buffer could hold it.
    pub fn len(&self) -> u64 {
        self.0.len() as u64
    }
}

/// A DACL granting full access to `owner` and to SYSTEM, and to nothing else.
fn dacl(owner: &[u8]) -> Vec<u8> {
    let entries = [owner, SYSTEM_SID.as_slice()];
    let size = ACL_HEADER_BYTES
        + entries
            .iter()
            .map(|sid| ACE_HEADER_BYTES + sid.len())
            .sum::<usize>();

    let mut out = Vec::with_capacity(size);
    out.push(ACL_REVISION);
    out.push(0);
    out.extend_from_slice(&(size as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    for sid in entries {
        out.push(ACE_TYPE_ALLOWED);
        out.push(ACE_FLAGS_INHERIT);
        out.extend_from_slice(&((ACE_HEADER_BYTES + sid.len()) as u16).to_le_bytes());
        out.extend_from_slice(&FILE_ALL_ACCESS.to_le_bytes());
        out.extend_from_slice(sid);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A plausible user SID: `S-1-5-21-1-2-3-1001`.
    fn user_sid() -> Vec<u8> {
        let mut sid = vec![1, 5, 0, 0, 0, 0, 0, 5];
        for subauthority in [21u32, 1, 2, 3, 1001] {
            sid.extend_from_slice(&subauthority.to_le_bytes());
        }
        sid
    }

    fn read_u32(bytes: &[u8], at: usize) -> usize {
        u32::from_le_bytes(bytes[at..at + 4].try_into().expect("four bytes")) as usize
    }

    fn read_u16(bytes: &[u8], at: usize) -> usize {
        u16::from_le_bytes(bytes[at..at + 2].try_into().expect("two bytes")) as usize
    }

    /// WinFsp reads this with the Windows security APIs, so the header has to
    /// be exactly what a self-relative descriptor's is — a malformed one is
    /// read as no descriptor at all, which is the grant-everything case this
    /// exists to close.
    #[test]
    fn the_descriptor_is_self_relative_with_a_dacl() {
        let owner = user_sid();
        let sd = OwnerOnlyDescriptor::over(&owner);
        let bytes = sd.as_bytes();

        assert_eq!(bytes[0], SD_REVISION);
        assert_eq!(read_u16(bytes, 2), usize::from(SD_CONTROL));
        assert_eq!(
            read_u16(bytes, 2) & 0x8000,
            0x8000,
            "SE_SELF_RELATIVE, or WinFsp reads pointers where offsets are"
        );
        assert_eq!(read_u16(bytes, 2) & 0x0004, 0x0004, "SE_DACL_PRESENT");
        assert_eq!(read_u32(bytes, 12), 0, "no SACL");
        assert_eq!(sd.len(), bytes.len() as u64);

        let offset_owner = read_u32(bytes, 4);
        assert_eq!(&bytes[offset_owner..offset_owner + owner.len()], &owner[..]);
    }

    /// Every offset has to land inside the descriptor and on a DWORD boundary,
    /// or the security APIs walk off the end of it.
    #[test]
    fn every_offset_is_in_bounds_and_aligned() {
        let sd = OwnerOnlyDescriptor::over(&user_sid());
        let bytes = sd.as_bytes();
        for at in [4usize, 8, 16] {
            let offset = read_u32(bytes, at);
            assert!(
                offset >= SD_HEADER_BYTES,
                "offset {offset} overlaps the header"
            );
            assert!(offset < bytes.len(), "offset {offset} is past the end");
            assert_eq!(offset % 4, 0, "offset {offset} is not DWORD-aligned");
        }
    }

    /// The whole point: the account that made the mount, and SYSTEM, and no
    /// third party. A second local user matching no ACE is granted nothing.
    #[test]
    fn the_dacl_names_the_owner_and_system_and_nobody_else() {
        let owner = user_sid();
        let sd = OwnerOnlyDescriptor::over(&owner);
        let bytes = sd.as_bytes();
        let dacl = &bytes[read_u32(bytes, 16)..];

        assert_eq!(dacl[0], ACL_REVISION);
        assert_eq!(read_u16(dacl, 2), dacl.len(), "the ACL spans to the end");
        assert_eq!(read_u16(dacl, 4), 2, "two entries, and only two");

        let mut at = ACL_HEADER_BYTES;
        for expected in [owner.as_slice(), SYSTEM_SID.as_slice()] {
            assert_eq!(dacl[at], ACE_TYPE_ALLOWED);
            assert_eq!(
                dacl[at + 1],
                ACE_FLAGS_INHERIT,
                "a child inherits the grant"
            );
            let ace = read_u16(dacl, at + 2);
            assert_eq!(ace, ACE_HEADER_BYTES + expected.len());
            assert_eq!(
                u32::from_le_bytes(dacl[at + 4..at + 8].try_into().expect("a mask")),
                FILE_ALL_ACCESS
            );
            assert_eq!(&dacl[at + ACE_HEADER_BYTES..at + ace], expected);
            at += ace;
        }
        assert_eq!(at, dacl.len(), "nothing follows the two grants");
    }

    /// A zero-length descriptor is exactly the state WinFsp reads as "this
    /// filesystem has no security", which grants every caller what it asked
    /// for. Reporting a length is the enforcement.
    #[test]
    fn the_descriptor_is_never_empty() {
        let sd = OwnerOnlyDescriptor::over(&user_sid());
        assert!(sd.len() > SD_HEADER_BYTES as u64);
    }
}

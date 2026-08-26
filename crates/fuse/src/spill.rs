//! Per-handle sealed spill files: where a kernel write lands before release
//! turns it into one `updateContent` op (blueprint/desktop.md "Reads, writes,
//! and the never-block law").
//!
//! The sealing key is minted per handle from injected entropy, lives only in
//! this process's memory, and dies with the handle — a crash leaves ciphertext
//! whose key is gone. Nonces are a per-file counter: the key is fresh per
//! handle, so a counter is unique under it by construction and needs no further
//! entropy.

use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use cipherbox_core::suite::aead::{self, KEY_LEN, NONCE_LEN, TAG_LEN};
use cipherbox_engine::Entropy;
use cipherbox_engine::entropy::{EntropyError, fresh_bytes, fresh_seed};
use zeroize::Zeroizing;

use crate::error::VfsError;
use crate::lease::{self, Lease};

/// The engine data dir's child holding every area's directory. Fixed, because
/// the account directory is shared and this is the part of it the mount owns.
const SPILL_DIR: &str = "spill";

/// The most areas one account's spill root holds at once. Reaching it means
/// live instances are holding every slot.
const MAX_AREAS: usize = 32;

/// AAD domain for a spill block. The block index rides in the AAD, so a slot
/// moved to another offset in the same file no longer opens.
const SPILL_AAD_DOMAIN: &[u8] = b"cipherbox/spill/v1";

/// The engine data dir's spill area: where every handle's sealed spill file is
/// minted, and the one place the per-handle keys come from.
///
/// Each area owns a directory of its own under the account's `spill/`, claimed
/// for as long as it lives ([`crate::lease`]). Nothing stops a second instance
/// from signing into the same account, and an area that swept the shared
/// directory would delete that instance's live spill files mid-write.
pub struct SpillArea {
    dir: PathBuf,
    /// Held for the life of the area: what tells a sibling instance this
    /// directory is not debris to reclaim.
    _lease: Lease,
    entropy: Box<dyn Entropy>,
}

/// Where slot `slot`'s directory and the lock claiming it live.
fn slot_paths(root: &Path, slot: usize) -> (PathBuf, PathBuf) {
    (
        root.join(format!("area.{slot}")),
        root.join(format!("area.{slot}.lock")),
    )
}

impl SpillArea {
    /// The spill area a real mount runs on: a fixed child of the engine's
    /// `data_dir`, under the OS CSPRNG.
    ///
    /// Entropy is not a seam here, and deliberately so. A spill block's nonce
    /// is a counter under the per-file key, unique only because that key is
    /// fresh random — a seeded or replayed source repeats a key and with it
    /// every nonce under it, which is an XChaCha20 keystream reuse, not a
    /// weakened one. A host mount has no reason to choose, so it is given none.
    ///
    /// The last path component is this constructor's, not the caller's:
    /// opening an area deletes every file in the directory it claims.
    pub fn production(data_dir: &Path) -> io::Result<Self> {
        Self::open(data_dir.join(SPILL_DIR), Box::new(OsEntropy))
    }

    /// Open a spill area under `root` with an injected source, for the vfs
    /// suite (`test-kit`). Never reachable from a production build — see
    /// [`production`](Self::production) for why substituting the source is a
    /// keystream reuse rather than a weakening.
    #[cfg(any(test, feature = "test-kit"))]
    pub fn seeded(root: PathBuf, entropy: Box<dyn Entropy>) -> io::Result<Self> {
        Self::open(root, entropy)
    }

    /// Take the first slot under `root` no live area holds, and reclaim what
    /// instances that are no longer running left in the others.
    fn open(root: PathBuf, entropy: Box<dyn Entropy>) -> io::Result<Self> {
        fs::create_dir_all(&root)?;
        restrict_dir(&root)?;

        for slot in 0..MAX_AREAS {
            let (dir, lock) = slot_paths(&root, slot);
            let Some(lease) = lease::claim(&lock)? else {
                continue;
            };
            // The lease is the proof this slot is ours, so whatever a previous
            // run left in it is ciphertext whose key died with that run. A
            // sweep that did not go leaves that debris in the directory the
            // area is about to open over, so only its absence is tolerated.
            match fs::remove_dir_all(&dir) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            fs::create_dir_all(&dir)?;
            restrict_dir(&dir)?;
            reclaim(&root, slot);
            return Ok(Self {
                dir,
                _lease: lease,
                entropy,
            });
        }
        Err(io::Error::other(
            "every spill area under this account is already claimed",
        ))
    }

    /// Mint a spill file under a fresh per-handle key, framed in `block_bytes`
    /// plaintext blocks.
    pub(crate) fn create(&mut self, block_bytes: u64) -> Result<SpillFile, VfsError> {
        // A zero-wide block would divide by zero on every framing decision and
        // let `put` accept an empty plaintext as a whole block.
        if block_bytes == 0 {
            return Err(VfsError::Internal {
                message: "a spill needs a non-zero block size".to_owned(),
            });
        }
        let key = fresh_seed(self.entropy.as_mut()).map_err(spill_entropy)?;
        // Named from entropy, not a counter: two areas over one dir would mint
        // the same counter and each would then unlink the other's live spill.
        let suffix: [u8; 8] =
            fresh_bytes(self.entropy.as_mut(), "spill name suffix").map_err(spill_entropy)?;
        let path = self.dir.join(format!("spill.{}", hex(&suffix)));
        let file = open_private(&path).map_err(spill_io)?;
        Ok(SpillFile {
            path,
            file: Some(file),
            key,
            block_bytes,
            blocks: BTreeSet::new(),
            next_nonce: 0,
        })
    }
}

/// Delete every slot but `mine` that no live area claims. Best-effort by
/// design: a directory that will not go is disk left behind, while refusing
/// the area over it would cost the session its whole projection.
fn reclaim(root: &Path, mine: usize) {
    for slot in (0..MAX_AREAS).filter(|slot| *slot != mine) {
        let (dir, lock) = slot_paths(root, slot);
        // Held across the delete, so a sibling that starts meanwhile takes a
        // free slot rather than the one being swept.
        if matches!(lease::claim(&lock), Ok(Some(_dead))) {
            let _ = fs::remove_dir_all(&dir);
        }
    }
}

/// The target's CSPRNG. Fail-closed: a draw that cannot be served is an error,
/// never substituted bytes.
struct OsEntropy;

impl Entropy for OsEntropy {
    fn fill(&mut self, dest: &mut [u8]) -> Result<(), EntropyError> {
        getrandom::fill(dest).map_err(|error| EntropyError::new(error.to_string()))
    }
}

/// A draw the engine's fail-closed helpers refused.
fn spill_entropy(error: EntropyError) -> VfsError {
    VfsError::Internal {
        message: error.message().to_owned(),
    }
}

/// One handle's spill: a slot per plaintext block, each sealed on its own.
pub(crate) struct SpillFile {
    path: PathBuf,
    /// Taken on drop so the handle is closed before the path is unlinked —
    /// Windows refuses to delete a file it is still holding open.
    file: Option<File>,
    key: Zeroizing<[u8; KEY_LEN]>,
    block_bytes: u64,
    /// The block indices this spill claims. A slot outside the set is
    /// uninitialized, never zero bytes: the caller falls back to the base
    /// version for it.
    blocks: BTreeSet<u64>,
    next_nonce: u64,
}

impl SpillFile {
    /// The plaintext of block `index`, `None` when the spill never took it.
    /// Always a whole block wide.
    pub(crate) fn block(&mut self, index: u64) -> Result<Option<Zeroizing<Vec<u8>>>, VfsError> {
        if !self.blocks.contains(&index) {
            return Ok(None);
        }
        let mut sealed = vec![0u8; self.slot_bytes()];
        let at = self.slot_offset(index)?;
        let file = self.file()?;
        file.seek(SeekFrom::Start(at)).map_err(spill_io)?;
        file.read_exact(&mut sealed).map_err(spill_io)?;
        let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
        let nonce: &[u8; NONCE_LEN] = nonce.try_into().expect("split_at NONCE_LEN");
        let plaintext = aead::decrypt(&self.key, nonce, &block_aad(index), ciphertext).ok_or(
            VfsError::Internal {
                message: "a spill block did not open".to_owned(),
            },
        )?;
        Ok(Some(Zeroizing::new(plaintext)))
    }

    /// Seal a whole block of plaintext into slot `index`, replacing whatever
    /// the slot held.
    pub(crate) fn put(&mut self, index: u64, plaintext: &[u8]) -> Result<(), VfsError> {
        if plaintext.len() as u64 != self.block_bytes {
            return Err(VfsError::Internal {
                message: "a spill block must be sealed whole".to_owned(),
            });
        }
        let at = self.slot_offset(index)?;
        let nonce = self.next_nonce()?;
        let mut slot = Vec::with_capacity(self.slot_bytes());
        slot.extend_from_slice(&nonce);
        slot.extend(aead::encrypt(
            &self.key,
            &nonce,
            &block_aad(index),
            plaintext,
        ));
        // Claimed before the bytes land: a write that dies half-way leaves a
        // slot the AEAD rejects, so the commit fails closed rather than quietly
        // substituting the base version for a block the caller wrote.
        self.blocks.insert(index);
        let file = self.file()?;
        file.seek(SeekFrom::Start(at)).map_err(spill_io)?;
        file.write_all(&slot).map_err(spill_io)?;
        Ok(())
    }

    /// Forget everything at or past `len`: whole blocks are dropped, and the
    /// tail of the block `len` falls inside is zeroed, so a later write past
    /// `len` reads holes as zeros rather than as the bytes truncate removed.
    pub(crate) fn truncate(&mut self, len: u64) -> Result<(), VfsError> {
        let block_bytes = self.block_bytes;
        self.blocks
            .retain(|index| index.saturating_mul(block_bytes) < len);
        let within = (len % block_bytes) as usize;
        if within == 0 {
            return Ok(());
        }
        let last = len / block_bytes;
        if let Some(mut block) = self.block(last)? {
            block[within..].fill(0);
            self.put(last, &block)?;
        }
        Ok(())
    }

    /// The open handle, or the fail-closed verdict for a spill already torn
    /// down.
    fn file(&mut self) -> Result<&mut File, VfsError> {
        self.file.as_mut().ok_or(VfsError::Internal {
            message: "the spill file is closed".to_owned(),
        })
    }

    fn slot_bytes(&self) -> usize {
        NONCE_LEN + self.block_bytes as usize + TAG_LEN
    }

    /// Where slot `index` starts. Fails closed past the addressable file: a
    /// wrapped offset would alias one block onto another's slot.
    fn slot_offset(&self, index: u64) -> Result<u64, VfsError> {
        index
            .checked_mul(self.slot_bytes() as u64)
            .ok_or_else(|| VfsError::Internal {
                message: "spill offset is not addressable".to_owned(),
            })
    }

    /// The next nonce for this file's key. Fails closed rather than wrapping:
    /// a repeated nonce under one XChaCha20-Poly1305 key breaks both
    /// confidentiality and integrity.
    fn next_nonce(&mut self) -> Result<[u8; NONCE_LEN], VfsError> {
        let counter = self.next_nonce;
        self.next_nonce = self
            .next_nonce
            .checked_add(1)
            .ok_or_else(|| VfsError::Internal {
                message: "spill nonce space exhausted".to_owned(),
            })?;
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..8].copy_from_slice(&counter.to_le_bytes());
        Ok(nonce)
    }
}

impl Drop for SpillFile {
    /// The spill dies with the handle. The ciphertext is not overwritten: the
    /// key was memory-only and goes with it. The handle is closed first —
    /// Windows refuses to unlink a file it is still holding open.
    fn drop(&mut self) {
        drop(self.file.take());
        let _ = fs::remove_file(&self.path);
    }
}

/// Lowercase hex, for a filename component drawn from entropy.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// The AAD binding one spill block to its slot.
fn block_aad(index: u64) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SPILL_AAD_DOMAIN.len() + 8);
    aad.extend_from_slice(SPILL_AAD_DOMAIN);
    aad.extend_from_slice(&index.to_le_bytes());
    aad
}

/// Spill I/O never carries a path or a byte of content into the message.
fn spill_io(error: io::Error) -> VfsError {
    VfsError::Internal {
        message: format!("spill file: {}", error.kind()),
    }
}

#[cfg(unix)]
fn open_private(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Off unix the file inherits the parent's ACL. Confidentiality rests on the
/// seal, not the mode: every block is ciphertext under a per-handle key that
/// only ever exists in memory.
#[cfg(not(unix))]
fn open_private(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(path)
}

/// Owner-only: the one rule every directory CipherBox makes for itself carries,
/// whether it holds sealed spill blocks or is a mount point about to hold
/// plaintext.
#[cfg(unix)]
pub(crate) fn restrict_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

/// Off unix the directory keeps the permissions it was created with; the spill
/// area holds nothing but sealed blocks, for the reason given on
/// `open_private`.
#[cfg(not(unix))]
pub(crate) fn restrict_dir(_dir: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use cipherbox_engine::testkit::{SeededEntropy, SilentEntropy};

    use super::*;

    /// The plaintext a spill holds at `index`, as a plain vector.
    fn held(spill: &mut SpillFile, index: u64) -> Option<Vec<u8>> {
        spill
            .block(index)
            .expect("the block opens")
            .map(|b| b.to_vec())
    }

    fn area(dir: &Path) -> SpillArea {
        SpillArea::seeded(dir.to_path_buf(), Box::new(SeededEntropy::new(7))).expect("spill area")
    }

    /// How many spill files an area's directory holds.
    fn spilled(area: &SpillArea) -> usize {
        fs::read_dir(&area.dir).unwrap().count()
    }

    /// A seam reporting success having written nothing would seal every spill
    /// under one known key and give every spill file one name, so two spills in
    /// one area would unlink each other.
    #[test]
    fn a_silent_seam_mints_no_spill() {
        let dir = tempfile::tempdir().unwrap();
        let mut area = SpillArea::seeded(dir.path().to_path_buf(), Box::new(SilentEntropy))
            .expect("spill area");
        assert!(
            matches!(area.create(8), Err(VfsError::Internal { message }) if message.contains("all-zero")),
            "the refusal is the entropy guard, not any internal error"
        );
        assert_eq!(spilled(&area), 0, "no spill file is left behind");
    }

    /// Two instances sign into one account and each opens an area over its
    /// `spill/`; neither may sweep the other's live files.
    #[test]
    fn a_live_areas_spill_survives_another_areas_open() {
        let root = tempfile::tempdir().unwrap();
        let mut first = area(root.path());
        let live = first.create(8).unwrap();
        assert_eq!(spilled(&first), 1);

        let second = area(root.path());
        assert_ne!(second.dir, first.dir, "each area claims its own slot");
        assert!(
            live.path.exists(),
            "an open spill file survives a sibling area opening"
        );
        assert_eq!(spilled(&second), 0, "and is not the sibling's to see");
    }

    /// A killed instance leaves its directory behind with nothing holding it;
    /// the next area reclaims it rather than leaking it forever.
    #[test]
    fn a_dead_areas_directory_is_reclaimed() {
        let root = tempfile::tempdir().unwrap();
        // What a killed process leaves: a slot's directory and its unopenable
        // ciphertext, with nothing holding the claim.
        let live = area(root.path());
        let (abandoned, _) = slot_paths(root.path(), MAX_AREAS - 1);
        fs::create_dir_all(&abandoned).unwrap();
        fs::write(
            abandoned.join("spill.0011"),
            b"ciphertext whose key is gone",
        )
        .unwrap();

        let _next = area(root.path());
        assert!(!abandoned.exists(), "a dead area's directory is reclaimed");
        assert!(live.dir.is_dir(), "and a live one's is not");
    }

    #[test]
    fn a_block_round_trips_through_its_slot() {
        let dir = tempfile::tempdir().unwrap();
        let mut spill = area(dir.path()).create(8).unwrap();
        assert_eq!(held(&mut spill, 0), None, "an unwritten slot is absent");
        spill.put(3, b"abcdefgh").unwrap();
        assert_eq!(held(&mut spill, 3), Some(b"abcdefgh".to_vec()));
        assert_eq!(held(&mut spill, 2), None, "slots are independent");
    }

    #[test]
    fn a_rewritten_block_never_repeats_a_nonce() {
        let dir = tempfile::tempdir().unwrap();
        let mut spill = area(dir.path()).create(8).unwrap();
        spill.put(0, b"aaaaaaaa").unwrap();
        let first = fs::read(&spill.path).unwrap();
        spill.put(0, b"aaaaaaaa").unwrap();
        let second = fs::read(&spill.path).unwrap();
        assert_ne!(
            first[..NONCE_LEN],
            second[..NONCE_LEN],
            "the same plaintext resealed must use a fresh nonce"
        );
    }

    #[test]
    fn plaintext_never_reaches_the_slot_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let mut spill = area(dir.path()).create(16).unwrap();
        spill.put(0, b"secret-plaintext").unwrap();
        let bytes = fs::read(&spill.path).unwrap();
        assert!(
            !bytes
                .windows(b"secret-plaintext".len())
                .any(|window| window == b"secret-plaintext"),
            "a spill file must hold ciphertext only"
        );
    }

    #[test]
    fn a_slot_moved_to_another_index_does_not_open() {
        let dir = tempfile::tempdir().unwrap();
        let mut spill = area(dir.path()).create(8).unwrap();
        spill.put(0, b"abcdefgh").unwrap();
        let slot = fs::read(&spill.path).unwrap();
        // Transplant slot 0's bytes into slot 1 and claim the spill holds it.
        let at = spill.slot_offset(1).unwrap();
        let file = spill.file().unwrap();
        file.seek(SeekFrom::Start(at)).unwrap();
        file.write_all(&slot).unwrap();
        spill.blocks.insert(1);
        assert!(
            matches!(spill.block(1), Err(VfsError::Internal { .. })),
            "the block index is bound by the AAD"
        );
    }

    #[test]
    fn two_files_from_one_area_get_different_keys() {
        let dir = tempfile::tempdir().unwrap();
        let mut area = area(dir.path());
        let mut first = area.create(8).unwrap();
        let mut second = area.create(8).unwrap();
        first.put(0, b"abcdefgh").unwrap();
        second.put(0, b"abcdefgh").unwrap();
        assert_ne!(*first.key, *second.key);
        assert_ne!(
            fs::read(&first.path).unwrap(),
            fs::read(&second.path).unwrap(),
            "one plaintext under two per-handle keys must not seal alike"
        );
    }

    #[test]
    fn truncation_drops_whole_blocks_and_zeroes_the_partial_tail() {
        let dir = tempfile::tempdir().unwrap();
        let mut spill = area(dir.path()).create(8).unwrap();
        spill.put(0, b"abcdefgh").unwrap();
        spill.put(1, b"ijklmnop").unwrap();
        spill.truncate(11).unwrap();
        assert_eq!(held(&mut spill, 0), Some(b"abcdefgh".to_vec()));
        assert_eq!(
            held(&mut spill, 1),
            Some(b"ijk\0\0\0\0\0".to_vec()),
            "bytes past the new length must not survive as content"
        );

        spill.truncate(8).unwrap();
        assert_eq!(
            held(&mut spill, 1),
            None,
            "a block wholly past the new length is dropped"
        );
    }

    #[test]
    fn dropping_a_spill_removes_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let mut spill = area(dir.path()).create(8).unwrap();
        spill.put(0, b"abcdefgh").unwrap();
        let path = spill.path.clone();
        assert!(path.exists());
        drop(spill);
        assert!(!path.exists(), "a released handle leaves no spill behind");
    }

    #[test]
    fn opening_the_area_sweeps_a_previous_runs_debris() {
        let root = tempfile::tempdir().unwrap();
        let (dir, _) = slot_paths(root.path(), 0);
        fs::create_dir_all(&dir).unwrap();
        let debris = dir.join("spill.0011");
        fs::write(&debris, b"unopenable ciphertext").unwrap();

        let taken = area(root.path());
        assert_eq!(taken.dir, dir, "the first free slot is the one taken");
        assert!(!debris.exists());
    }

    #[test]
    fn a_zero_block_size_spill_is_refused_at_creation() {
        let dir = tempfile::tempdir().unwrap();
        assert!(matches!(
            area(dir.path()).create(0),
            Err(VfsError::Internal { .. })
        ));
    }

    #[test]
    fn an_unaddressable_slot_is_refused_rather_than_wrapped() {
        let dir = tempfile::tempdir().unwrap();
        let mut spill = area(dir.path()).create(8).unwrap();
        assert!(matches!(
            spill.put(u64::MAX, &[0u8; 8]),
            Err(VfsError::Internal { .. })
        ));
    }

    #[test]
    fn a_partial_block_is_refused_rather_than_padded() {
        let dir = tempfile::tempdir().unwrap();
        let mut spill = area(dir.path()).create(8).unwrap();
        assert!(matches!(
            spill.put(0, b"short"),
            Err(VfsError::Internal { .. })
        ));
    }

    /// The production area is the one a mount links, so it has to be exercised
    /// somewhere: a stub or a mis-wired source shows up here as a repeated key.
    #[test]
    fn the_production_area_mints_a_fresh_key_per_spill() {
        let data_dir = tempfile::tempdir().expect("data dir");
        let mut area = SpillArea::production(data_dir.path()).expect("production area");
        let first = area.create(8).expect("first spill");
        let second = area.create(8).expect("second spill");

        assert_ne!(
            first.key, second.key,
            "a repeated key repeats every counter nonce under it"
        );
        assert!(first.key.iter().any(|byte| *byte != 0));
        assert!(
            data_dir.path().join(SPILL_DIR).is_dir(),
            "the area owns its own directory, so opening it deletes nothing else"
        );
    }
}

---
created: 2026-06-15
title: Add unit test coverage for fuse journal_helpers, read_ops, and write_ops
area: fuse
files:
  - crates/fuse/src/journal_helpers.rs
  - crates/fuse/src/read_ops.rs
  - crates/fuse/src/write_ops.rs
---

## Problem

Three FUSE source files currently have ~0% direct unit-test patch coverage:

- `crates/fuse/src/journal_helpers.rs` — `build_upload_journal_entry`,
  `build_mkdir_journal_entry`, and the free helpers `wrap_key_to_hex`,
  `generate_entry_id`, `current_unix_ms`.
- `crates/fuse/src/read_ops.rs` — `handle_init/destroy/lookup/getattr/open/read/`
  `release/flush/access/getxattr/listxattr`.
- `crates/fuse/src/write_ops.rs` — `handle_setattr/write/create/unlink/mkdir/rmdir/rename`.

The two are NOT equally testable, and that gates the approach:

### journal_helpers.rs — unit-testable now (no blocker)

The builders are pure and synchronous (no network I/O): encrypt → ECIES-wrap →
resolve-parent-IPNS-from-inodes → build `JournalEntry`. They need a constructed
`CipherBoxFS` plus, for the upload path, an `OpenFileHandle` backed by a temp file
(`OpenFileHandle::new_write(ino, temp_dir, Some(content))`). No existing test builds a
`CipherBoxFS`, so a shared `make_test_fs()` helper is the main lift (struct has ~30
fields incl. a `tokio::runtime::Handle`, mpsc channels, `ApiClient::new("http://127.0.0.1:1")`,
`WriteQueue::new(dir, 5)`, `PublishCoordinator::new()`). The root inode must have its
`ipns_private_key`/`ipns_name` set (via `get_mut(ROOT_INO)`) for `build_folder_metadata`
to succeed. Assertions are pure: ciphertext decrypts to plaintext, journal op references
ciphertext (base64) not plaintext, wrapped keys ECIES-unwrap back to originals, TEE-wrap
present/absent toggled by `tee_public_key`, `is_first_publish` passthrough, empty-folder
metadata `{version:"v2",children:[]}` round-trips, `status == Pending`, `retries == 0`.

### read_ops.rs / write_ops.rs — blocked on a fuser limitation

Every handler consumes a concrete `fuser::Reply*` value (`ReplyEntry`, `ReplyAttr`, …).
The only constructor is `Reply::new(unique, sender)` where `sender: impl ReplySender`.
In our vendored fuser (`apps/desktop/src-tauri/vendor/fuser`, wired via the workspace
`[patch.crates-io] fuser = { path = ... }`), `mod reply;` is private and the crate root
re-exports only the `Reply` trait + concrete reply types — **`ReplySender` is not
exported** (`lib_impl.rs:28`). A separate crate (`cipherbox-fuse`) therefore cannot
implement a capturing sender, so the reply objects cannot be constructed in a test.
Additionally, `handle_read`/`handle_open` do blocking network polls (up to 3s) and
background prefetch, so several paths aren't pure even if a sender existed.

The reply wire format, for reference if/when this is unblocked: out-header is
`len:u32 LE | error:i32 LE | unique:u64 LE`; `error == 0` is success, `-errno` on error
(see fuser `reply.rs` `AssertSender` tests).

## Solution

Decision (2026-06-15): defer. Capture options for later:

- **journal_helpers.rs (do first, standalone):** add `make_test_fs()` + builder tests.
  No dependency on the reply blocker. This is the clean, high-value win.
- **read_ops/write_ops — Option A (recommended if pursued):** add one line to the
  vendored fuser (`pub use reply::ReplySender;`), write a channel-backed capture sender in
  cipherbox-fuse test support, and unit-test the metadata-only handlers (getattr, access,
  lookup incl. "."/"..", setattr truncate, create, unlink, rmdir, rename, flush, xattr,
  mkdir happy-path). Leave the network read/open paths to E2E. Lowest-touch real coverage.
- **Option B:** refactor each handler into a pure `-> Result<Resolved, errno>` core + a
  thin reply shim; unit-test the cores. Largest change; rewrites both files.
- **Option C:** cover via a real mounted FUSE mount (headless desktop FUSE UAT recipe) —
  integration coverage, not unit patch-coverage.

Source: follow-up from PR #491 review; testability investigation 2026-06-15.

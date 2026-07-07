---
status: awaiting_human_verify
trigger: "list_folder_owned fails: parent READ plane has SealedChildRef for uuid_from_ino(7) but WRITE plane has no paired WriteChildRef (D-07 read/write pairing failed). FUSE write path publishes a parent whose two planes disagree about the child set. [CONTINUED] Cross-client 'Decryption failed' in the node/v3 desktop path (CI desktop-e2e run 28871971401, all 3 platforms) persisted after the D-07 fix, incl. single-session Step 3."
created: 2026-07-07T00:00:00Z
updated: 2026-07-07T12:00:00Z
---

## Current Focus

active_investigation: "Decryption failed" (distinct from the resolved D-07 pairing error)

reasoning_checkpoint_iv:
  hypothesis: "The mount publishes NodeContent.file_iv as HEX (journal_helpers.rs:216 iv_hex = hex::encode(iv); content_ops.rs:214 file_iv: iv_hex.to_string()), and its own reader decodes it as HEX (content_ops.rs:148/155 hex::decode). But the SHIPPED TS/web read chain treats NodeContent.file_iv as BASE64 (file/index.ts createFileMetadata stores bytesToBase64(fileIv); downloadFileContent does base64ToBytes(fileIv); web hooks all say 'fileIv is base64, v3 contract'). The TS verifier decodes the mount's 24-char hex IV as base64 -> wrong IV bytes -> AES-GCM tag mismatch -> 'Decryption failed' at the CONTENT decrypt layer (layer c). Single-session Step 3 fails here because layers (a) unsealChildReadKey and (b) resolveFileMetadata succeed (id/read_key consistent same-session) and only content decrypt uses the IV."
  confirming_evidence:
    - "journal_helpers.rs:205-216 generate_iv() (12B GCM) then iv_hex = hex::encode(iv); comment lines 68-70 explicitly 'NodeContent.file_iv is HEX'."
    - "content_ops.rs:214 publish_file_node sets file_iv: iv_hex.to_string() (hex); lines 148/155 fetch_and_decrypt_content_async does hex::decode(&content.file_iv)."
    - "packages/sdk-core/src/file/index.ts:269 createFileMetadata fileIv: bytesToBase64(params.fileIv); :415 downloadFileContent iv = base64ToBytes(params.fileIv)."
    - "apps/web hooks (useFileVersions.ts:184, useStreamingPreview.ts:176, VersionHistory.tsx:58) all base64ToBytes(metadata.fileIv) — the reference web contract is base64."
    - "KAT node-codec.json uses fileIv '000102030405060708090a0b' which is coincidentally valid as BOTH hex and base64 (chars 0-9a-b) and is treated as an opaque string by the codec — so the KAT never pins the hex-vs-base64 semantic. This is the 'runtime value divergence the KAT doesn't pin'."
    - "docs/METADATA_SCHEMAS.md:253/283 says fileIv is 'hex (24 hex chars)' — STALE relative to shipped TS runtime (base64). The Rust mount followed the stale doc."
  falsification_test: "Reproduce round-trip; add per-layer try/catch to verify-filepointer.mts. If (a) and (b) pass and only downloadFileContent (c) throws 'Decryption failed', hypothesis confirmed. After making the mount publish+read file_iv as base64, Step 3 goes green."
  fix_rationale: "Align the mount's NodeContent.file_iv wire encoding with the TS/web reference (base64) at the two crypto boundaries in content_ops.rs: publish (line 214) emits base64(raw iv), read (148/155) base64-decodes. inode.iv stays hex (display-only, never used for crypto — decrypt always reads content.file_iv from the freshly-unsealed node). Windows + macOS both route through content_ops.rs so one change fixes both."
  blind_spots: "Must confirm layers (a)/(b) actually pass (no second bug) via reproduction. Must confirm inode.iv is truly never fed into a decrypt. resolve_file_descriptors (content_ops.rs:103) will return base64 into inode.iv — verify no consumer hex-decodes inode.iv."

reasoning_checkpoint:
  hypothesis: "The child node identity (published.id / WriteChildRef.child_id / seal AAD) is derived from the client-LOCAL inode number via uuid_from_ino(ino). When a child is materialized from a remote listing (apply_owned_children, inode.rs:456) it is assigned a FRESH local ino via allocate_ino(). A subsequent parent re-publish (build_folder_metadata, fs.rs:213) seals the WriteChildRef with child_id = uuid_from_ino(fresh_local_ino), which does NOT equal the child file node's real published.id = uuid_from_ino(original_creator_ino). list_folder_owned's D-07 pairing (find w.child_id == published.id) then fails."
  confirming_evidence:
    - "fs.rs:213 build_folder_metadata: child_id = uuid_from_ino(child_ino) — recomputed from the LOCAL ino for BOTH planes; and fs.rs:235 the folder's own id = uuid_from_ino(folder_ino)."
    - "inode.rs:456 apply_owned_children: ino = existing_ino.unwrap_or_else(|| self.allocate_ino()) — a re-materialized child (fresh mount / cross-client / move) gets a NEW local ino, decoupled from the ino encoded in its published.id."
    - "SDK emit.rs:172/239 mints node ids via generate_uuid_v4() (stable, portable) — that is the intended identity; uuid_from_ino(local_ino) is a client-local substitute that is not stable across clients/remounts."
    - "listing.rs:448 resolve_owned_child pairs by published.id (read from the fetched child node, correct) but the parent's write plane was sealed with the wrong local-ino-derived child_id."
    - "Failing e2e groups are Cross-client sync + Move (both operate on trees re-materialized with different local inos); passing groups (create/API round-trip/recycle bin) are single-session with stable inos."
  falsification_test: "If build_folder_metadata used a STORED stable node_id (== child's published.id) instead of uuid_from_ino(local_ino), a parent published after re-materialization would carry a WriteChildRef whose child_id equals the child's published.id, and list_folder_owned would pair successfully. Regression test: materialize a child whose stored node_id differs from uuid_from_ino(local_ino), publish the parent, run list_folder_owned/resolve_owned_child, assert Ok (fails before fix, passes after)."
  fix_rationale: "Stop deriving node identity from the local ino at publish time. Persist the node's real id (node_id) on InodeData: uuid_from_ino(ino) at creation (zero behavior change for same-session nodes), published.id on materialization. Use node_id in build_folder_metadata + journal + per-file publish. Same-session nodes (all currently-passing paths) are unaffected because node_id == uuid_from_ino(ino) for them; only re-materialized nodes change (from buggy fresh-ino id to correct remote id)."
  blind_spots: "delete.rs / grant_scope.rs / windows write_ops also build WriteChildRefs keyed by uuid_from_ino(child_ino) — must switch to node_id for full consistency (delete of a materialized file). winfsp is CI-only locally. Root's node_id must stay uuid_from_ino(ROOT_INO) to preserve root read behavior."

test: implement stored node_id; add regression test in crates/fuse reproducing a materialized child (node_id != uuid_from_ino(local_ino)) -> build_folder_metadata -> list_folder_owned pairs OK.
next_action: read remaining InodeData construction + publish sites (mkdir.rs, file_data.rs, grant_scope.rs, delete.rs, windows), then implement node_id field.

## Symptoms

expected: Every SealedChildRef the parent publishes has a paired WriteChildRef with child_id == child node's published.id (uuid_from_ino).
actual: list_folder_owned fails with "no WriteChildRef paired with child node id 00000000-0000-4007-8007-000000000007 (D-07 read/write pairing failed)" on every metadata refresh for minutes.
errors: cipherbox_fuse::events: Metadata refresh failed for k51...: list_folder_owned: node codec/crypto error: Invalid node format: no WriteChildRef paired with child node id 00000000-0000-4007-8007-000000000007 (D-07 read/write pairing failed)
reproduction: live desktop-e2e; write a file via FUSE mount -> parent re-publish -> subsequent list_folder_owned fails. uuid_from_ino(7) = file created via mount.
started: node/v3 FUSE write path (phase 69).

## Eliminated

## Evidence

- timestamp: init
  checked: crates/sdk/src/listing.rs resolve_owned_child (:448)
  found: D-07 pairing is `parent_write_children.iter().find(|w| w.child_id == published.id)`. published.id = child's own node id (uuid_from_ino). Fails closed if no match.
  implication: The FUSE write path must publish the parent WRITE body (write_children) containing a WriteChildRef with child_id == uuid_from_ino(child_ino). Somewhere it publishes the read ref without the write ref.

- timestamp: iv-investigation
  checked: mount publish (crates/fuse content_ops.rs:214 publish_file_node, journal_helpers.rs:288) vs TS reference read (packages/sdk-core file/index.ts downloadFileContent, createFileMetadata) + apps/web hooks.
  found: >
    Mount stores NodeContent.file_iv as HEX (iv_hex = hex::encode(iv); 12B GCM IV
    -> 24 hex chars) and its own reader hex::decodes it (content_ops.rs:148/155).
    The shipped TS/web read chain treats NodeContent.fileIv as BASE64
    (downloadFileContent -> base64ToBytes(fileIv); createFileMetadata ->
    bytesToBase64(fileIv); every web hook says 'fileIv is base64, v3 contract').
  implication: >
    HEX-vs-BASE64 divergence in the file_iv WIRE encoding. The KATs never pin it:
    node-codec.json treats file_iv as an opaque string and its sample value
    '000102030405060708090a0b' is coincidentally valid as BOTH hex and base64.
    This is the runtime value divergence the task predicted.

- timestamp: iv-reproduction
  checked: two standalone reproductions using the SHIPPED @cipherbox/crypto + @cipherbox/core (in .planning/tmp, since removed).
  found: >
    (1) decryptAesGcm(ct, key, base64ToBytes(hexIv)) -> 'Decryption failed' (hex IV
    read as base64 -> 18 wrong bytes); base64ToBytes(b64Iv) -> 12B -> decrypts to
    'API-visible content' (the exact Step 3 content + exact error string).
    (2) Faithful node round-trip via core sealNode/unsealNode (byte-twin of Rust
    seal_published_node, KAT-pinned): BROKEN(hex) -> layer (b) unsealNode OK, layer
    (c) content decrypt 'Decryption failed'; FIXED(base64) -> layer (b) OK, layer
    (c) OK -> 'API-visible content'.
  implication: >
    FAILING LAYER = (c) content AES-GCM decrypt. Layers (a) unsealChildReadKey
    (role 0x02) and (b) unsealNode read-body (role 0x01) PASS — both are pinned
    byte-identical Rust<->TS by tests/vectors/crypto/node-aad.json seal_vectors, so
    the seal chain was never the problem. Single-session Step 3 fails at (c) only.

## Resolution

root_cause: |
  FUSE node identity (published.id / WriteChildRef.child_id / seal AAD) was derived
  from the client-LOCAL inode number via uuid_from_ino(ino) at PUBLISH time
  (fs.rs build_folder_metadata:213/235, read_ops flush:825, journal_helpers:300,
  delete.rs:128/330, grant_scope:318). But a child materialized from a remote
  listing is assigned a FRESH local ino by apply_owned_children (inode.rs:456), which
  differs from the ino its creator used. So a parent re-published after cross-client
  sync / move / remount sealed the child's WriteChildRef with child_id =
  uuid_from_ino(fresh_local_ino), which no longer equals the child file node's real
  published.id = uuid_from_ino(creator_ino). list_folder_owned's D-07 pairing
  (listing.rs:448, find w.child_id == published.id) then failed for minutes on every
  refresh. The SDK's own emit.rs mints stable generate_uuid_v4() ids — uuid_from_ino
  was a client-local substitute that is not portable across clients/remounts.
fix: |
  Persist the node's stable id on the inode and use it (never uuid_from_ino(local_ino))
  in all publish/pairing paths:
  - SDK: added ResolvedOwnedChild.node_id (= published.id) so the mount can recover
    a materialized child's real id (listing.rs).
  - FUSE: added InodeData.node_id. Set uuid_from_ino(ino) at creation (zero behavior
    change for same-session nodes) and the remote published.id on materialization
    (apply_owned_children). Root keeps uuid_from_ino(ROOT_INO).
  - Publish paths now key by the stored node_id: build_folder_metadata (child_id AND
    the folder's own id), the per-file publish (read_ops flush), the upload journal
    (journal_helpers), the recycle-bin refs (delete.rs), and the grant scope-exit
    (grant_scope.rs). mkdir keeps uuid_from_ino (always a fresh folder).
  Minimal + correct: same-session nodes are unaffected (node_id == uuid_from_ino(ino));
  only re-materialized nodes change from the buggy fresh-ino id to their real id. The
  list_folder_owned pairing invariant (security property) is untouched.
verification: |
  - Added regression test crates/fuse/src/fs.rs::d07_write_plane_pairing_tests::
    build_folder_metadata_pairs_a_materialized_child_by_its_real_node_id — drives the
    REAL build_folder_metadata for a materialized child (node_id != uuid_from_ino(ino))
    then runs cipherbox_sdk::list_folder_owned against the published parent.
    FAILS BEFORE fix with the exact live error ("no WriteChildRef paired with child
    node id 00000000-0000-4007-8007-000000000007 (D-07 read/write pairing failed)"),
    PASSES AFTER.
  - cargo test -p cipherbox-fuse: 96 passed / 0 failed (95 prior + 1 new).
  - cargo test -p cipherbox-sdk: 132 passed / 0 failed.
  - cargo check --workspace (default): Finished, no errors, no new warnings.
  - --features winfsp RED locally: fails in third-party winfsp-sys build script
    (windows_registry::LOCAL_MACHINE) — a macOS platform-dep limitation, CI-only,
    unrelated to this change (our fuse code never compiled). node_id was added to the
    two windows InodeData literals for consistency when windows is ported.
  - Terminal-owner zeroization preserved (SDK still returns raw keys, caller-owned;
    node_id is a non-secret String). D-07 (write=childId / read=ipnsName) preserved
    and hardened. No new Cargo dependency.
  - PENDING: orchestrator rebuilds the FUSE-T binary and re-runs the live desktop-e2e
    (Cross-client sync + Move) to confirm end-to-end.
files_changed:
  - crates/sdk/src/listing.rs
  - crates/fuse/src/inode.rs
  - crates/fuse/src/fs.rs
  - crates/fuse/src/read_ops.rs
  - crates/fuse/src/journal_helpers.rs
  - crates/fuse/src/write_ops/implementation/file_data.rs
  - crates/fuse/src/write_ops/implementation/mkdir.rs
  - crates/fuse/src/write_ops/implementation/delete.rs
  - crates/fuse/src/write_ops/grant_scope.rs
  - crates/fuse/src/platform/windows/write_ops.rs

## Resolution (second bug — cross-client "Decryption failed")

root_cause: |
  The FUSE mount published the file content IV (NodeContent.file_iv) as HEX
  (journal_helpers.rs:216 iv_hex = hex::encode(iv); content_ops.rs:214
  publish_file_node file_iv: iv_hex; journal_helpers.rs:288 journaled placeholder
  file_iv: iv_hex — the last re-sealed verbatim by replay.rs:1099). Its own reader
  hex::decoded it (content_ops.rs:148/155), so the mount was internally consistent
  and local FUSE reads (served from cache) passed. But the SHIPPED TS/web read
  chain — the reference — treats NodeContent.fileIv as BASE64: sdk-core
  downloadFileContent does base64ToBytes(fileIv); createFileMetadata stores
  bytesToBase64(fileIv); every apps/web hook decodes base64. A cross-client TS
  reader decoded the mount's 24-char hex IV as base64 -> 18 wrong IV bytes -> the
  file content AES-GCM auth tag failed -> "Decryption failed" at the CONTENT
  decrypt layer (layer c). This bit EVERY cross-language content read, including
  single-session Step 3 (the D-07 re-materialization fix does not touch it).
  The KATs never caught it: node-codec.json treats file_iv as an opaque string
  whose sample value is coincidentally valid as both hex and base64, and node-aad
  seal_vectors only pin the role 0x01/0x02 node seals (layers a/b), which pass.
  Root of the divergence: docs/METADATA_SCHEMAS.md said fileIv was hex (stale vs
  the shipped TS runtime), and the Rust mount followed the doc.
fix: |
  Align the mount's NodeContent.file_iv WIRE encoding with the TS/web reference
  (base64) at the crypto boundaries (mount internal `iv_hex` naming/threading and
  the display-only inode.iv field are unchanged — decrypt never uses inode.iv):
  - content_ops.rs publish_file_node: file_iv = base64(hex_decode(iv_hex)).
  - content_ops.rs fetch_and_decrypt_content_async: base64-decode content.file_iv
    (both GCM and CTR branches) instead of hex::decode. (This ALSO fixes the mount
    reading web-uploaded files, which was latently broken.)
  - journal_helpers.rs journaled placeholder NodeContent: file_iv = base64 (so the
    replay path, which re-seals from it, publishes base64 too — no replay.rs edit).
  - Doc/comment fixes: journal_helpers.rs iv_hex field doc; content_ops.rs
    resolve_file_descriptors doc; docs/METADATA_SCHEMAS.md NodeContent.fileIv +
    VersionEntry.fileIv "hex" -> "base64".
  Both platforms fixed by the content_ops.rs change (macOS + Windows route through
  it). No migration concern: node/v3 FUSE is unreleased (phase 69), no legacy hex
  files in the wild.
verification: |
  - cargo check -p cipherbox-fuse --features fuse: Finished, clean (only pre-existing
    vendor warnings).
  - Standalone shipped-crypto repro: hex IV read as base64 -> "Decryption failed"
    (exact prod error); base64 IV -> decrypts to "API-visible content" (exact Step 3
    content).
  - Faithful cross-language node round-trip (core sealNode == Rust seal_published_node
    per KAT, + shipped decryptAesGcm): BROKEN(hex) layer(b) OK / layer(c) "Decryption
    failed"; FIXED(base64) layer(b) OK / layer(c) OK -> "API-visible content". Confirms
    failing layer = (c) content decrypt; layers (a)/(b) pass.
  - PENDING: authoritative end-to-end is CI desktop-e2e (warm stack, dispatch-gated) —
    re-run tests/desktop-e2e (test-round-trip.sh Step 3 + Cross-Client Sync + Move).
    Local headless FUSE-T mount was NOT run: documented cold-Kubo/FUSE-T flakiness
    risks a false signal, and the bug is deterministic (all 3 CI platforms identical).
files_changed_2:
  - crates/fuse/src/content_ops.rs
  - crates/fuse/src/journal_helpers.rs
  - docs/METADATA_SCHEMAS.md

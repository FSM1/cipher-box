# Read Key-Chaining Design — Amendments

Amendments to `2026-06-26-sharing-read-keychaining-design.md`, produced from grilling sessions with the maintainer on 2026-06-26 (session 1: schema / flows / rotation / write-revocation; session 2: resolve / republish / TEE — see the dedicated block near the end). These supersede the cited sections of the design doc where they conflict. Treat this file as the authoritative delta until the base design doc is rewritten to absorb it.

Cross-references: [`docs/adr/0001-write-revocation-full-ed25519-rotation.md`](../../docs/adr/0001-write-revocation-full-ed25519-rotation.md), [`docs/adr/0002-read-revocation-protects-future-content-only.md`](../../docs/adr/0002-read-revocation-protects-future-content-only.md), and the root [`CONTEXT.md`](../../CONTEXT.md) glossary.

## Decisions ratified

1. **Greenfield.** No production instance; staging was wiped. No data migration, no dual-codec, no `version`-discriminator bridge. `node/v3` is the only codec; delete the v1/v2 read paths and the `share_keys` entity outright.
2. **Delete/move/rename rotate only on scope exit.** A node with no covering grant is a pure relink — zero rotations. The §3.6 "delete = rotate" framing is wrong.
3. **Revocation is lazy + honest** (ADR 0002). Revoke protects future writes + navigation + filenames; already-distributed content and prior versions are presumed leaked.
4. **Scope computation is client-side**; FUSE gains grant-root awareness; the relay supplies the grant-root set; web rotates online and rotates only the items that left scope; reconcile-then-rotate, defer if the tree can't be reconciled.
5. **Republisher signs the canonical `latestCid`, never its own snapshot** (security-critical). The resolve someguy-vs-DB precedence is a confirmed read-revocation bypass vector.
6. **Write-revocation = approach (c)** full Ed25519 rotation (ADR 0001); it is the most expensive operation in the system.
7. **Invites folded in** as an ephemeral-wrapped single `readKey` + claim-time re-wrap-to-self; delete the `encryptedChildKeys` fan-out.
8. **`generation` is not forward-protected by the CAS gate**; safety needs same-parent serialization + the M1 client check + a server-side generation gate.
9. **AAD does not enforce topology**; its `generation` is sourced from the parent mirror / grant `rootGeneration`.
10. **Content keeps `encryptionMode`** (GCM/CTR) per node and per version.
11. **Bin is in scope** and gets simpler under content self-seal.
12. **Terminology pinned** (`readKey`/`writeKey`, the three counters, `shares` + descriptor refs, `ipns_records`).
13. **Drop `folder_ipns.public_key`**; recover the Ed25519 pubkey from the k51 name.

## §1 / §6 — Scope is greenfield (migration removed)

There is no production instance and staging was wiped, so the design's silent live-data-cutover assumption is void. Remove any migration framing. Build `node/v3` as the sole codec; delete v1/v2 read paths and the `share_keys` entity rather than bridging them. The vault-key recovery blob is re-designed (not migrated) to carry **two** keys — `ECIES(rootReadKey)` + `ECIES(rootWriteKey)` — since the root Node has both a read and a write key. Terminology can be renamed cleanly in code from day one (no transitional coexistence).

## §3.6 / §3.8 — Delete rule rewrite (scope-exit only)

Replace "delete collapses to rotate" with the per-grant predicate, stated as a tested invariant:

> Rotate iff the node leaves the reachable scope of at least one active grant; "reachable" means reachable by a grantee, not the owner. A node with no covering grant is a pure relink (zero rotations).

"No covering grant ⇒ 0 rotation" must be a hard test. Taken literally, the old wording would rotate on every private delete — an O(subtree) storm over the unshared 99% of a vault. For the shared case, compose the shipped `revoke-for-items` row-revoke (#563) **with** rotation, preserving its ordering invariant (never a window where the item is gone but its key is not yet rotated).

## §3.5 / §4 — Scope computation and the FUSE blind spot

The scope predicate ("is node X reachable from any active grant root?") is **inherently client-side** — the relay cannot answer it, because parent-to-child links live in the sealed read-body and only a key-holder can walk ancestry. Amendments:

- The relay supplies the active grant-root set (`shares` keyed by `rootIpnsName` — plaintext it already holds). The client walks the mutated node's ancestor chain against that set.
- Web computes coverage from `folderTree` **reconciled to the current `sequenceNumber` first** (per the existing reconcile-before-publish discipline). A wrong "don't rotate" is a silent missed revoke, so when the tree cannot be reconciled the mutation **defers** rather than skips rotation.
- **FUSE must gain a grant-root concept** in its `delete`/`rename`/`move` paths (new work; add to the blast radius). It already holds the mounted tree, so ancestry is cheap — compute exact per-grant scope rather than the design's conservative "rotate on any ancestor-set change." This disposes of open Q3 (no over-rotation on benign within-scope moves).

## §4.1 / §4.8 — Revocation semantics (lazy content rekey)

See ADR 0002. Reword §4.8: "eager rotation" means eager cut of navigation + future writes, **not** eager content protection. A file rotated on revoke gets a fresh `fileKey` only on its next content write (`contentRekeyPending`); a cold file that is never rewritten keeps its old `fileKey` valid, and the still-pinned CID remains decryptable by anyone who held the key. Every revoke flow must carry the caveat that already-distributed content and all prior versions stay readable. Optionally offer per-file "re-encrypt now" and O(versions) "purge history".

## §4.6 — Convergence claim corrections

§4.6's "every op is a forward-only function on generation + sequence" is **false**: the CAS gate enforces forward-only **sequence** only; `generation` lives in the body/envelope and is not gated. A stale-key holder can republish a cached pre-rotation body (re-sealed under the old `readKey`) at a forward sequence, regressing `generation` and silently undoing the cut. HIGH-4's re-merge covers dropped children, not this. Corrected invariant and controls:

- **Same-parent serialization.** Add/rename/move on a node take the same `PublishCoordinator.get_lock(name)` the rotation holds, so a stale-key add cannot interleave with that node's rotation locally.
- **M1 client check** (below) is the fail-closed backstop for the cross-client / colluding-relay case.
- **Server-side generation gate (ratified, defence-in-depth).** Because `generation` is plaintext on the published envelope, extend the publish gate to enforce forward-only generation per node, mirroring the sequence anti-rollback and its wild-jump / wedge-poison handling (`ipns.service.ts:313`).

Restate the invariant as: forward-only **sequence** (CAS-enforced) + forward-only **generation** (same-parent serialization + M1 client check + server-side gate), not by the CAS alone.

## §4.3 — M1 generation monotonicity is net-new durable client state

Confirmed against code: **no resolve path enforces a per-node `generation` check today.** `resolve_sequence_strict` (`crates/fuse/src/publish.rs:140`) tracks only `sequence`, in-memory, lost on restart; `VerifiedResolve` exposes `{cid, sequence_number}` and never decodes node metadata; web `resolveIpnsRecord` performs the same sequence-only checks. So §4.3's M1 defence is **new work**, not an extension:

- Persist `{nodeId → highestGeneration}` durably (IndexedDB / sqlite, beside the sequence cache), seeded from the grant's `rootGeneration` (owner-vouched floor).
- Thread it into `resolve_ipns_verified` (Rust) and `resolveIpnsRecord` (web); fail closed on generation regression. On a first-ever resolve with no high-water mark, cross-check the envelope generation against the parent's `SealedChildRef.generation` mirror.
- Document the irreducible residual: a colluding relay can serve a victim a self-consistent OLD whole-subtree snapshot if it never lets them see any newer node (no signed generation closes this).

## §4.6 — Republisher / resolve interaction (security-critical)

The 6-hour TEE republisher is **not** orthogonal to rotation. It signs from its own `ipns_republish_schedule.latestCid` snapshot (`republish.service.ts:101,136`), which is refreshed on publish only when `encryptedIpnsPrivateKey` is supplied (`ipns.service.ts:349-358`). A read-key rotation does not rotate the Ed25519 key, so the snapshot stays at the pre-rotation CID; the next republish re-signs the **stale (revoked-readable) CID at a forward sequence**, and `syncFolderIpnsSequence` (`republish.service.ts:379-385`) writes it into `folder_ipns.signedRecord` without updating `latestCid`.

Confirmed reachable: the relay's `resolveRecord` (`ipns.service.ts:456`) queries both someguy and the DB; when the inconsistent DB row trips the codec guard (`ipns-record.codec.ts:73`, `signedRecord`-CID ≠ `latestCid`) it returns null and the service falls through to serve the someguy network record verbatim (`ipns.service.ts:506-540`). Every downstream verifier accepts it because the old record is internally self-consistent. **This is an exploitable read-revocation bypass.**

Fix (ratified): the republisher sources its CID from the canonical `folder_ipns.latestCid` at sign time (never its own snapshot), and `schedule.latestCid` is refreshed on every publish (decouple from the `encryptedIpnsPrivateKey` guard). Add a section to the design covering the rotation × republisher × resolve interaction (currently under-specified), and reconsider the someguy-vs-DB precedence in `resolveRecord` given recent churn.

## §5 — Write-revocation ratified as (c)

See ADR 0001. Re-cost §5.3 honestly: (c) is **not** "a subset of the read-rotation machinery" — it is strictly heavier. Read-revoke keeps k51 names stable and descends; write-revoke under (c) mints a new keypair and k51 name per node, cascades parent re-points **upward** to the share root, re-enrolls/unenrolls the TEE per node, and re-points all co-grants + owner devices. The explainer's `(c)` framing and flow 08 are now correct; relabel nothing as "preview". Also fix the §5.4-vs-§8 inconsistency: full (a) uniquely serializes the sequence race (atomic sign + assign); the §8 "no candidate solves the race, don't factor it in" line wrongly erases (a)'s only real edge.

## §2.2 / §2.6 — Write-body shape (resolved)

Approach (c) is ratified, so the write-body is the structured recursive write chain the explainer shows: each node's write-body holds its Ed25519 signing material, and each parent write-body seals the child's `writeKey` (the explainer's `writeKeySealed: AES-GCM(child.writeKey, parent.writeKey)`). Reserve AAD `role = 0x04 child-writekey` for this. `SealedChildRef` stays read-only (one sealed field, `readKeySealed`); the write link lives in the parent write-body, not in `SealedChildRef`.

## §2.5 / §2.6 — AAD semantics and byte encoding

- **Transplant claim reworded.** The AAD does not bind `parentId`, and a legitimate move re-seals byte-identical AAD under a new parent — so the AAD does **not** enforce topology. State it as: the AAD prevents stale-generation replay and cross-node-id confusion; topology is enforced by parent-`readKey` possession.
- **Generation source.** The reader's expected AAD `generation` comes from the parent's `SealedChildRef.generation` mirror (integrity-anchored via the signed CID chain), or, for a share-root, from the grant's `rootGeneration`. The node's own envelope plaintext `generation` is used only for the M1 high-water check and dirty-edge detection — never as unseal key-material input. This makes a stale-child serve fail closed.
- **Byte encoding frozen** (blocks the KAT, so freeze first): `kind` = `folder 0x01 / file 0x02 / root 0x03`; `nodeId` = the raw 16 RFC-4122 bytes (`uuid.as_bytes()`, canonical field order), not a hash; `generation` = 4-byte big-endian; `role` = `{0x01 body, 0x02 child-readkey, 0x03 content, 0x04 child-writekey}`. Pin all of it as the first vector in `crates/crypto/tests/cross_language.rs`, asserted by `packages/crypto` too.

## §2.3 / §2.9 — Content schema

Carry `encryptionMode` (`'GCM' | 'CTR'`) in `content` **and** in each `VersionEntry` — CTR powers large-file range reads (`aes_ctr::decrypt_aes_ctr_range`); do not normalise to GCM-only. The `fileKeyEncrypted → content.fileKey` change is a **semantic type change** (ECIES hex string → raw 32-byte key inside the sealed body), applied to both content and every `VersionEntry`; document it as a type change in `METADATA_SCHEMAS.md`, not a rename.

## New section — Invites (link/email sharing)

Invites are shipped (`share_invites` table, `share-invite.service.ts`) and in-scope per `CLAUDE.md`, but the design omits them. Under `node/v3`:

- An invite wraps the **single share-root `readKey`** to an ephemeral public key; the ephemeral private key travels in the URL fragment (never reaches the server — zero-knowledge holds). Delete the `encryptedChildKeys[]` fan-out (JSONB column) — the read chain obsoletes it.
- On claim, the claimer unwraps `readKey` with the URL-fragment ephemeral private key, **re-wraps it to their own public key**, and the server stores a standard `shares` grant. A multi-claim invite mints one standard grant per claimer of the same `readKey`. Revoke = rotate the `readKey` (cuts the link and all claimers at once).
- Accepted exposure: a v3 invite link carries the subtree-root `readKey`; anyone with the link reads the granted subtree — identical in spirit to today's link semantics.

## New section — Bin (recoverable delete)

The bin is shipped (`packages/core/src/bin/*`, `sdk/src/bin/*`, `spawn_bin_entry_publish`) and absent from the design. Under `node/v3`:

- A `BinEntry` becomes a `SealedChildRef`-shaped link sealed under the bin's own `readKey`. **Restore = pure re-link** (re-seal the node's `readKey` under the destination parent), identical to a move. `originalFolderKeyEncrypted` and the re-encrypt-on-restore path become dead code — delete them.
- Private delete → unlink + `BinEntry`, no rotation. Shared delete → rotate the departing subtree + revoke the grant rows (composing #563) + `BinEntry`. Permanent delete → unpin CIDs + drop grant rows.
- Add `bin/*` to the blast radius.

## §3.1 — Cost table: add Copy

Content self-seal means a copy cannot alias the source CID — it must decrypt and re-encrypt under a fresh `fileKey`, yielding a new CID. Add a row:

> Copy | decrypt + re-encrypt under a fresh `fileKey` → new CID | no re-grant | no rotation | new node's own | O(content); new CID pins under the copier's quota

## Terminology (see CONTEXT.md)

- Adopt `readKey` / `writeKey` (not `nodeKey`). Add them and `generation` to the `CLAUDE.md` terminology table, with a Counters sub-table distinguishing `sequenceNumber` / `keyEpoch` / `generation`. Fully retire `folderKey` / `fileKey` / `rootFolderKey` from code (greenfield).
- Grant row: keep table `shares`; use `readDescriptorRef` / `writeDescriptorRef`; retire `readKeyEcies` and the explainer's `ShareGrant` name.
- Rename table `folder_ipns` → `ipns_records` (entity `IpnsRecord`, `ipnsRecordRepository`) — it holds the IPNS records for files, root, bin, and the vault-key blob too, not just folders. Free under greenfield.
- Drop `folder_ipns.public_key`: it is the raw 32-byte Ed25519 IPNS pubkey (`ipns.service.ts:72-79` validates length 32 and `deriveIpnsName(pubkey) === ipnsName`), not the user's secp256k1 `publicKey` (the owner is tracked by `userId`). It is derivable from the k51 name via `publicKeyFromIpnsName`, so drop the nullable column and always recover from the name — removing the null-row footgun behind two Phase-60 regressions.

## §6.1 — Blast-radius additions

- FUSE grant-root awareness in `delete` / `rename` / `move`.
- `bin/*` (core, sdk, FUSE `spawn_bin_entry_publish`).
- M1 durable client state (high-water generation map) on both clients.
- Republisher canonical-CID fix + `schedule.latestCid` refresh on every publish.
- `resolveRecord` someguy-vs-DB precedence review.
- `folder_ipns` → `ipns_records` rename (entity, repository, all references).

## §6.3 — Test additions

- Republisher re-signs a stale CID mid-rotation → assert the revoked CID is never re-signed and never served.
- Stale-key add during rotation (generation regression) → assert it is rejected / re-converged.
- M1 generation monotonicity → fail closed on a generation downgrade across resolves.
- CTR content + a CTR version both decrypt under the v3 content schema.
- Invite claim re-wraps the share-root `readKey` to the claimer; revoke (rotate) cuts the link and all claimers.
- Bin restore is a pure re-link (no re-encrypt); shared delete rotates + revokes.

## Citation corrections (verified against code)

- The per-child ECIES unwrap the read chain replaces is at `crates/fuse/src/inode.rs:434,452` (also `:658,716`, `replay.rs:365`) — **not** `metadata.rs:428-453`, which is `spawn_bin_entry_publish`.
- `spawn_file_meta_reencrypt` is defined at `metadata.rs:655`; callers are `write_ops/implementation/rename.rs:248` **and** `platform/windows/write_ops.rs:1182` (the WinFsp twin the design omits — killing it must touch both and round-trip the Windows CI gate).
- The republisher lives at `apps/api/src/republish/republish.service.ts`, not under `ipns/`.

## Session 2 (resolve / republish / TEE) — ratified 2026-06-26

A second grilling session covered the resolve path, the republish path, whether the republish must increment the IPNS sequence, where the TEE sources the data it signs, and a six-lens adversarial failure/vulnerability sweep. These **refine and in places supersede the §4.6 republisher amendment above** — the canonical-CID fix is now achieved structurally by decisions 16–17 rather than by patching the snapshot refresh. All claims below were verified against current code (two structured-verification workflows).

### Decisions ratified (continued)

14. **`generation` (M1) is the anti-rollback _authority_; resolve-source is a latency/availability layer beneath it.** The IPFS network is permissionless — its only anti-rollback is "higher sequence wins; equal sequence, later EOL wins" (verified against boxo/go-ipns `compare`), so it cannot be the integrity authority. DB-canonical near-term: the relay writes the DB synchronously _before_ the fire-and-forget someguy push (`ipns.service.ts:106-144`), so the DB leads the DHT by ~10-30s — the "network is fresher" latency intuition is **inverted** in the relay-mediated topology. "Network strictly ahead of DB" is an **alarm**, not a normal branch. The maintainer's network-as-source-of-truth ideal is reachable for _confidentiality_ once M1 ships (generation rejects any cross-generation rollback regardless of source); the residual barrier is _within-generation_ consistency, which makes fully-decentralized resolve a post-M1 / v2 move.
15. **Sequence advances iff the CID changes; republish _never_ increments.** A republish re-signs the _same_ sequence with a fresh EOL — IPNS record selection's equal-sequence→later-EOL tiebreak lets the refreshed record win without consuming a sequence. The relay publish path already does this on the idempotent branch (`ipns.service.ts:306-317`, "D-09"); the **TEE 6-hour republisher still does `+ 1n`** (`apps/tee-worker/src/routes/republish.ts:79`) and must be unified to the no-increment path. Incrementing on republish is not just unnecessary but harmful — it races client writes for sequence numbers and widens the replay window. This invariant _alone_ closes the §4.6 republisher-stale-CID rollback (a re-signed stale CID stays at its old sequence and is dominated by any genuine forward client publish). Increment policy moves out of the enclave into the relay.
16. **Collapse the dual-source record state.** `ipns_republish_schedule` duplicates `latestCid` / `sequenceNumber` / `encryptedIpnsKey` / `keyEpoch` (`republish-schedule.entity.ts:39-60`) and the TEE signs _that_ snapshot (`republish.service.ts:101-102`), which goes stale on a normal content write (refreshed only on key-enrollment). Make the canonical `ipns_records` row the **sole** source of the TEE's signing inputs; reduce the schedule to scheduling metadata (`next_republish_at`, `consecutive_failures`, `status`) — or fold those columns into `ipns_records` and drop the table. This structurally kills both the stale-CID rollback _and_ a latent availability bug: today the republisher keeps the _old_ CID's network record fresh while the canonical new CID's record expires ~48h after the client's one-time publish (masked only by DB-canonical resolve).
17. **The TEE is a record-_lease-renewer_, not a signer of supplied scalars.** Clients self-sign every content change with their client-held Ed25519 key (`packages/core/src/ipns/create-record.ts`; the relay only verifies, `ipns.service.ts:100`), so the TEE never needs to originate a CID. New enclave contract: the relay sends the **marshaled existing `signedRecord`**; the TEE parses it, **verifies its signature**, and re-emits a record with the same value (CID) and same sequence, only a later EOL — so it **cannot originate or repoint a CID**. "Verify against what the network resolves" was rejected as the mechanism: it is circular (the relay controls the enclave's network view), inverts the ratified source-of-truth (the network is the lagging untrusted replica), and fights the propagation window. Worst residual: a malicious relay replays an _old_ lower-seq validly-signed record for renewal — dominated by sequence and caught by M1.
18. **Complete the resolve anti-rollback (the seq-floor companion to M1).** `generation` only bumps on rotation, so _within-generation_ version rollback — serving an old, genuinely-signed, lower-seq record in the same generation — passes every current check. Add: (a) a **durable per-node `{nodeId → highestSeq}` high-water** on the client (the sequence analog of the M1 generation map), rejecting `seq < high-water` regardless of resolve source; (b) **bind a version floor** (current seq, or a hash of the head Node) into the `SealedChildRef` at (re)share, so first-contact and cold/reset devices inherit an owner-vouched floor from the parent chain (the `SealedChildRef` mirrors generation but not version today); (c) the relay must **never silently fall through to an ungated network record** — when the canonical DB row is unparseable (`parseCachedRecord` null: missing `signedRecord`, or `signedRecord`-CID ≠ `latestCid`; notably shared-folder rows with null `signedRecord`/`public_key`), **fail closed** or apply a `seq ≥ storedSeq` floor from the DB `sequenceNumber` column. This closes the §4.3-M1 colluding-relay-drops-publish residual — the durable client floor is the signed-signal-independent defense.
19. **Atomic publish CAS.** `publishRecord` is a non-atomic `findOne → gate → save` with no row lock / `@VersionColumn` / conditional UPDATE, so two concurrent forward writers both at `dbSeq = N` both pass the gate and the second `save` clobbers the first — a `200`'d write silently lost (generation cannot help; same generation). Decision 16's single canonical row makes it the sole serialization point and decision 17's lease-renewal hits the idempotent branch on it, _widening_ the race. Fix: a single compare-and-set — `UPDATE … SET … WHERE ipnsName = :n AND sequenceNumber = :expected`, 0 rows affected ⇒ 409 — with the idempotent/renewal write guarded identically (`WHERE sequenceNumber = :loaded`) so an EOL-only renewal can never regress `latestCid`/`sequenceNumber` from a stale in-memory row.
20. **Three enclave bindings beyond decision 17.** The relay still feeds the enclave the epoch scalars, the wrapped key, and the claimed name. Harden: (a) the TEE **derives `currentEpoch`/`previousEpoch` from its own clock + epoch schedule** (never the relay's scalars), with re-wrap targets restricted to an enclave-enumerated set — else a malicious relay coerces re-wrapping every IPNS key under an attacker-chosen epoch pubkey for later offline forgery; (b) **name↔key binding** — before emitting, assert `publicKeyFromIpnsName(ipnsName) == pubkey(decryptedKey) == record.pubkey` (closes batch cross-contamination / key-confusion / cross-name forgery); (c) **migration durability** — because a malicious relay can drop the returned `upgradedEncryptedKey` and brick a name at epoch retirement, make the **client** the recovery path (periodic re-enroll / re-wrap from its held key), or have the TEE refuse to renew a key older than `currentEpoch − 1`.
21. **Tombstone the rotated-out IPNS name (tombstone-and-keep).** Approach-(c) write-rotation changes the k51 name and re-points parents, but `unenrollIpns` deletes only the schedule row (`republish.service.ts:257`) — the old `ipns_records` row persists and the publish gate has zero revocation awareness, so a revoked writer's cached key can publish to the old name **forever** and resolve still serves it to stale links. On rotation, **tombstone** the old row (keep it, do not hard-delete): the publish gate rejects all writes to a tombstoned name, resolve returns a tombstone / `410` (never stale content), and the name is TEE-unenrolled. Tombstone-and-keep so stale links/bookmarks get an explicit "moved/revoked" signal rather than silent stale content.

### §4.6 supersession note

The Session-1 §4.6 fix ("republisher sources canonical `folder_ipns.latestCid`; refresh `schedule.latestCid` on every publish; reconsider the someguy-vs-DB precedence") is **subsumed**: decision 16 removes the schedule's `latestCid` entirely (nothing to refresh), decision 17 makes the TEE re-sign the existing record rather than take a CID scalar, and decisions 14 + 18 resolve the precedence (DB-canonical + fail-closed fall-through). Keep §4.6's _diagnosis_; replace its _fix_ with decisions 14–18.

### Accepted residuals (resolve / republish / TEE)

- **Compromised enclave / leaked epoch key = total loss** — every wrapped IPNS key is unwrappable offline and every vault repointable. Decision 17 bounds the _honest_ enclave's worst case to lower-seq replay; it does **not** contain a malicious enclave. This rests entirely on Phala remote-attestation (enforced on every epoch-key provisioning) + epoch-rotation cadence (bounds the exposure window). State it as the explicit systemic residual.
- **Equal-sequence EOL selection** is a freshness/availability nuisance only: under decisions 15 + 17 same-sequence records must share a CID, so the relay's choice of which equal-seq record a client sees cannot fork content. Escalate only if equal-seq distinct-CID records can ever be minted.
- **Already-distributed ciphertext stays readable** (ADR 0002) — unchanged.

### §6.1 — Blast-radius additions (session 2)

- TEE enclave contract rewrite (lease-renewer: receive marshaled record, verify signature, extend EOL; internal epoch derivation; name↔key binding) — `apps/tee-worker`, `packages/core/src/ipns`.
- Collapse `ipns_republish_schedule` duplicated columns into `ipns_records` (or reduce the table to scheduling metadata); rework `republish.service.ts` to source canonical inputs.
- Atomic conditional-UPDATE publish CAS in `publishRecord` + the idempotent/renewal branch.
- Durable per-node `highestSeq` high-water on both clients, beside the M1 generation map.
- `SealedChildRef` version floor (read-body schema + share-mint path).
- Tombstone state on `ipns_records` + publish-gate rejection + resolve tombstone/410 + TEE unenroll.
- Client-side re-enroll / re-wrap recovery path for epoch-key migration.

### §6.3 — Test additions (session 2)

- Within-generation rollback: relay serves an old lower-seq same-generation signed record → client rejects via the seq high-water.
- First-contact / cold-device rollback: fresh client with no local high-water → the `SealedChildRef` version floor rejects a below-floor seq.
- `parseCachedRecord`-null fall-through: an unparseable canonical DB row → resolve fails closed (or applies the seq floor), never serving an ungated network record.
- Concurrent forward publishes (two devices at the same `dbSeq`) → exactly one 409, zero lost updates.
- Lease-renewal racing a forward publish → the renewal never regresses `latestCid`/`sequenceNumber`.
- TEE name↔key binding: a swapped wrapped key / wrong-name slot → the enclave refuses to emit.
- TEE epoch self-derivation: an attacker-supplied `currentEpoch` is ignored; re-wrap only targets an enclave-valid epoch.
- Tombstoned name: writes rejected; resolve returns the tombstone, not stale content.

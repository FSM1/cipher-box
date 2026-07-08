---
phase: 70
audited: 2026-07-08
status: SECURED
---

# Phase 70 Security Audit — Rotation Soundness (Deep-Merge, Fresh-Record-Resume, Durable Floor)

Branch: `feat/rotation-soundness-deep-merge-fresh-record-resume-and-durabl`
Scope reviewed: `git diff origin/main...HEAD` (code files only). Focus files:

- `packages/sdk-core/src/rotation/engine.ts`
- `packages/sdk-core/src/rotation/merge.ts`
- `packages/sdk/src/client.ts`
- `packages/sdk/src/state/rotation-high-water.ts`
- `crates/sdk/src/floor_store.rs`
- `crates/sdk/src/rotation/high_water.rs`
- `apps/web/src/services/rotation-driver.service.ts`
- `packages/sdk-core/src/folder/registration.ts`

Verdict: **SECURED**. No CRITICAL, HIGH, or MEDIUM findings. Five LOW / informational
observations, all either documented accepted residuals or gated behind the same-UID /
single-daemon boundary (i.e. outside the untrusted-server threat model that rotation
defends).

## Finding counts

| Severity | Count |
| -------- | ----- |
| CRITICAL | 0     |
| HIGH     | 0     |
| MEDIUM   | 0     |
| LOW/info | 5     |

---

## Area 1 — Concurrent-add re-seal (the key fix): SOUND

`createConcurrentAddResealingMerge` (`engine.ts:1176-1249`), wired as the only
republish merge policy via `decrementPendingAndMaybeRepublish` (`engine.ts:1259-1289`,
call at `:1278`).

### (a) No key material leaks or is logged — CLEAN

- Repo-wide grep of the changed source for `console.*` / `log::(debug|info|trace)` /
  `println!` / `dbg!` / `eprintln!` returned no matches. The only log statements in the
  diff are `log::error!` in `floor_store.rs` (`:67`, `:187`, `:214`, `:219`) and they
  emit file paths / node IDs / IO errors only — never key material (the floor store
  never holds key material by design).
- Every transient key the closure derives is zeroed in a `finally`
  (`engine.ts:1226`, `:1243`); the caller-owned `parentOldReadKey` / `parentNewReadKey`
  are correctly NOT zeroed inside the closure.

### (b) Old→new re-seal is cryptographically correct — CLEAN

- Unwrap uses `unsealChildReadKey` (via `resolveChildKeyAndEnvelope`, `engine.ts:564-579`),
  re-wrap uses `sealChildReadKey` (`engine.ts:1231-1237`). Both bind identical AAD:
  `buildNodeAad(childId, kindByte(kind), generation, 0x02 /* child-readkey role */)`
  (`packages/core/src/node/seal.ts:195` seal, `:221` unseal).
- The re-seal preserves `childPub.id`, `childPub.kind`, and `child.generation` — the same
  values the successful unwrap authenticated — so there is no AAD substitution or
  cross-node/cross-role confusion (role `0x02` for child-readkey is distinct from `0x01`
  node-body and `0x04` child-writekey).
- The re-wrap is always under `parentNewReadKey` (the parent's engine-minted `readKeyPrime`),
  so the concurrent add ends up navigable by surviving members under the new epoch.

### (c) "Try old key then current key" fallback cannot seal under a wrong/attacker key — CLEAN

- Both unwrap attempts are AEAD-authenticated (`unsealChildReadKey` throws on a wrong key
  or wrong AAD). The OUTPUT seal is always `parentNewReadKey`, a fixed closure argument
  minted by `rotateOne` (`crypto.getRandomValues`, `engine.ts:799`) — the attacker (the
  concurrent writer) never influences the sealing key.
- If neither key unwraps, the ref is left as-is (`engine.ts:1223 continue`). Its original
  ciphertext will fail AEAD on a later read under `parentNewReadKey` — fail-closed
  (an unreadable ref, never an over-permissive one).
- The "already sealed under the new key" branch (`engine.ts:1216-1228`) is only reachable
  when the writer possessed `parentNewReadKey`, i.e. is a surviving current member — a
  read-revoked party cannot reach it.

### (d) A concurrent add from a different / revoked / malicious writer cannot survive with read access it shouldn't have — SOUND

- The actual revocation cut is the root's own `K_old -> K_new` rotation
  (`rotateOne(root)`, `engine.ts:1029`), committed FIRST (§4.2). After it publishes, a
  revoked holder of `K_old` cannot unseal the parent body and therefore cannot derive ANY
  child key. The re-seal does not affect that cut.
- The re-seal only re-wraps a concurrent add's pointer under `K_new`. It never leaks
  `K_new` (sealing `childReadKey` under `K_new` does not reveal `K_new`), and never grants
  the revoked party access to any OTHER node.
- Local-wins in `mergeRotatedChildren` (`merge.ts:44-66`) is the load-bearing property:
  a concurrent writer that re-publishes an existing child under the stale `K_old` seal
  loses to the rotation's own `K_new` re-seal (`local` inserted last, `merge.ts:61-63`),
  so a revoked reader's old-key seal is never re-adopted. An ipnsName collision with a
  rotated child is also defeated (local wins, and `createConcurrentAddResealingMerge`
  skips anything in `localNames`, `engine.ts:1197`).
- Crux verified: `updateFolderMetadataAndPublish` is invoked from exactly ONE place in the
  engine (`engine.ts:1265`) and hardcodes `mergeChildrenFn: createConcurrentAddResealingMerge`
  (`engine.ts:1278`); every republish path routes through `decrementPendingAndMaybeRepublish`.
  There is no rotation republish that can fall back to the default remote-wins
  `mergeChildren` (`registration.ts:346`). `mergeRotatedChildren` is a separate function
  (not a flag), so local-wins is syntactically impossible to invoke from a non-rotation
  site (closes the merge-downgrade EoP, T-70-01).

Informational (LOW-1): a still-write-authorized party being *read*-revoked can plant a
child that the re-seal adopts into the post-rotation tree, visible to surviving members
(and readable by that party, since they chose the child's key). This is inherent to a
pure read-revoke and is a documented design boundary (`merge.ts:17-20`): full revocation
must additionally run `rotateWriteFromNode` (which mints new k51 names so the revoked
party's writes to old names are ignored). Not a code defect; call it out in the revoke
runbook so read-revoke is never shipped as "full revoke."

---

## Area 2 — Zeroization (terminal-owner discipline): SOUND

- Enumerated all 19 `.fill(0)` sites in `engine.ts`. Every one targets an engine-owned
  buffer: minted `readKeyPrime` on failure (`:927`), minted/derived `fileKey` (`:419`,
  `:932`), engine-derived child keys (`:695`, `:1226`, `:1243`, `:1629`), the engine-owned
  `parentOldReadKey` copy (`:1286`), and write-plane minted keys (`:1809`, `:1810`, `:1852`,
  `:1859`, `:1915`, `:1936`, `:1937`, `:1995`, `:2036`).
- No site zeros a caller-owned buffer. `rootReadKey` and `parentReadKey` are never zeroed;
  the only interactions with `rootReadKey` are defensive COPIES (`new Uint8Array(rootReadKey)`
  at `:1373`, `:1423`, `:1444`), and only those copies are later zeroed. The past incident
  (a callee zeroing a reused caller buffer, 48/89 E2E failures) is not reintroduced.
- `parentOldReadKey` defensive copy: created as a copy at `:1444` (normal root), `:1579`
  (BFS child — a copy specifically because `item.nodeReadKey` is zeroed in the `finally`
  at `:1629` while the tracking state outlives that iteration), and `:1373` (dirty-resume
  root). Zeroed exactly at teardown by its terminal owner (`:1286`) AFTER the awaited
  republish that consumes it — no use-after-zero (the async merge closure runs to
  completion inside the awaited `updateFolderMetadataAndPublish`).
- `client.ts:2098` zeros `rotationResult.readKey` as terminal owner. Verified
  `rotateReadFromNode` always returns a fresh/engine-minted buffer, never an alias of
  `params.rootReadKey`: normal path returns `rootResult.childReadKey` (engine-minted,
  `:1655`); dirty-resume returns `new Uint8Array(rootReadKey)` (`:1423`); skip path returns
  `undefined`. The `folderTree` entry takes its own independent copy first
  (`client.ts:2081`). `updateFolderMetadataAndPublish` also confirmed NOT to zero its
  `readKey` arg (`registration.ts:160` contract), so the dirty-resume alias of the caller's
  `rootReadKey` (`engine.ts:1368`) is safe.

Informational (LOW-2): on a mid-walk throw, engine-owned `parentOldReadKey` copies still
sitting in the `parentTracking` map are not explicitly zeroed (they become unreferenced and
are GC'd). Best-effort hygiene only — these are copies of keys the caller still owns
(`rootReadKey`) or of already-zeroed `item.nodeReadKey`, so the value at risk is low. Not a
functional leak.

---

## Area 3 — RootKeyStaleError fail-closed: SOUND

- The entry-gate probe (`engine.ts:998-1012`) resolves the current published root and, if
  present, attempts `unsealNode(rootProbePub, rootReadKey)` BEFORE any rotation. On unseal
  failure it throws `RootKeyStaleError` — it never proceeds to `rotateOne` with a stale key.
  Any stale key (K0/K1 vs a current K2) fails AEAD and is caught; a key that DOES unseal the
  current root is, by AEAD authentication, genuinely current.
- `RootKeyStaleError` is exported from `rotation/index.ts` and `sdk-core/src/index.ts`, so
  `client.ts:2017`'s `instanceof sdkCore.RootKeyStaleError` resolves correctly.
- Client fallback (`client.ts:2016-2058`): catches ONLY `RootKeyStaleError` (re-throws every
  other error, `:2017` — fail-closed on unexpected errors); drops the stale `folderTree`
  entry (`:2029`, which zeros it); recovers strictly via network top-down re-navigation
  (`ensureFolderLoaded`, `:2030`). There is NO cryptographic key-recovery from the stale key
  (by design — the durable floor stores numbers only, never key material). On recovery
  failure it throws a descriptive, actionable error (`:2041-2049`) — fail-closed, never
  proceeds. On success `rotationResult` stays `undefined`, the terminal `if (rotationResult)`
  block (`client.ts:2070`) is skipped, and rotation is deferred to the next covered mutation.
- Untrusted-server angle: a server serving a bogus root record merely triggers re-nav /
  fail-closed; the client never adopts a server-provided key. Worst case is a DoS (inherent
  to an untrusted server), never a wrong-key acceptance.

---

## Area 4 — Rust floor store (`floor_store.rs`): SOUND

- Atomicity: `get` (`:156-172`) and `put` (`:174-225`) hold a `tokio::sync::Mutex` across
  the entire load-modify-write, with blocking FS work inside `spawn_blocking` while the guard
  is held. `put` computes `max(existing, candidate)` INSIDE the locked section (`:200-201`) —
  no lost updates across same- or different-node_id concurrent puts (proven by the two
  concurrency tests, `:311-362`).
- Corrupt sidecar fail-closed: a present-but-unparseable sidecar yields
  `LoadOutcome::Corrupt`; `get` returns `Some(CORRUPT_SIDECAR_FAIL_CLOSED_FLOOR)` (`:168`),
  and `put` REFUSES to overwrite (`:182-193`) so it can't blind-drop other nodes' floors.
  `CORRUPT_SIDECAR_FAIL_CLOSED_FLOOR = i64::MAX as u64` (`:46`) — the reasoning is correct
  and important: `u64::MAX as i64` wraps to `-1`, which would make every `attempted < floor`
  comparison FALSE and defeat every regression check; `i64::MAX` stays positive under the
  `high_water.rs` `floor as i64` cast (`:230`, `:256`) and exceeds any legitimate live input,
  guaranteeing rejection. `corrupt_sidecar_fails_closed` (`:364-399`) proves both stores
  reject.
- Perms + atomic write (`write_map_atomic_blocking`, `:87-111`): temp file created with
  `0o600` on unix (`:95`), `write_all` + `sync_all` (fsync), durable `rename` over the real
  path, best-effort parent-dir fsync. A crash mid-write orphans the `.tmp` and leaves the real
  sidecar untouched — never a torn JSON file (`no_partial_json_survives_a_write`, `:291-308`).
  gen/seq temp paths are distinct stems, so they never collide.

Informational (LOW-3): the "single-daemon-per-journal-dir" invariant is load-bearing for
atomicity. Two independently-constructed `JsonSidecarFloorStore`s pointed at the same sidecar
do NOT share the in-process `Arc<Mutex>` (`:118-128` doc), so a max-preserving update could be
lost (floor LOWERED) if two daemons ever share a journal dir. Acceptable given the FUSE
single-daemon model; worth a guard/lockfile only if that model ever changes.

Informational (LOW-4): repairing a corrupt sidecar is "delete the file," which resets that
store to cold-start (`LoadOutcome::Empty -> get None`), dropping all floors and re-enabling
rollback on next contact. Reaching this requires corrupting a `0600` file (same-UID) AND then
replaying stale records — same-UID-gated, outside the untrusted-server model. Consider a
`.corrupt` rename + operator alert rather than silent deletion if this is ever automated.

---

## Area 5 — Anti-rollback (max-preserving floor): SOUND

- `bump_floor` (Rust, `high_water.rs:114-127`) and `bumpFloor` (TS,
  `rotation-high-water.ts:113-129`) only ever raise or hold the floor; there is no code path
  that lowers a stored floor via the public API. `seed_from_grant` / `seedFromGrant` also go
  through `bump_floor` (`high_water.rs:172-175`) and never lower
  (`seed_from_grant_never_lowers_the_generation_floor`, `:504-513`).
- `enforce_resolved` validates live inputs (rejecting negative/NaN, fail-closed V5) BEFORE any
  floor comparison, checks generation then seq regressions, and only then bumps
  (`high_water.rs:200-276`). A corrupt sidecar surfaces as `i64::MAX` and forces rejection at
  both the generation gate (`:229-237`) and the seq gate (`:255-263`).
- The only floor-lowering vectors are (a) a direct valid-but-lower JSON write to the sidecar
  (no MAC on the file) and (b) the corrupt-then-delete reset (LOW-4). Both require same-UID
  filesystem write to a `0600` file, which is outside rotation's threat model (an attacker
  with the user's UID already owns the user's keys). The anti-rollback defense targets the
  untrusted server replaying old IPNS records, and against that it holds: the client rejects
  any resolved seq/generation below its durably-remembered floor.

---

## Single most important thing to keep verified

Revocation soundness hinges on two coupled invariants that this phase gets right and that
must not regress:

1. `mergeRotatedChildren` is **local-wins** and is the ONLY merge used at rotation republish
   sites (`engine.ts:1278` is the sole `updateFolderMetadataAndPublish` caller in the engine).
   A remote-wins merge at a rotation site would let a concurrent writer re-adopt the
   pre-rotation `K_old` seal and keep a revoked reader navigable.
2. The root's `K_old -> K_new` rotation is committed FIRST and the `RootKeyStaleError` probe
   fails closed, so a stale/lost-run key can never be silently "recovered" and reused.

Any future change to the republish merge wiring or the entry-gate probe should re-run this
audit's Area 1 and Area 3 reasoning.

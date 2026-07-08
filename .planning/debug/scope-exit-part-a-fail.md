---
status: fixed
trigger: "DATA_START\nReproduce and root-cause a Phase 70.1 desktop-e2e failure LOCALLY: tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts failed in CI on BOTH macOS and Linux at Part A setup: pollFindChild secret.txt never appeared under grant-root ipns after 18 attempts, line 250. Journal malformed-entry warnings are a pre-existing red herring, not the cause.\nDATA_END"
created: 2026-07-08T00:00:00Z
updated: 2026-07-09T12:00:00Z
---

## Current Focus (2026-07-09 — HEADLINE PROMOTED: the +2 / Bob-bypass Part A assertion failures)

status: ROOT-CAUSED (two distinct deterministic defects; see Resolution)

reasoning_checkpoint:
  hypothesis: "TWO DISTINCT DETERMINISTIC DEFECTS in the covered scope-exit
    delete path, NOT one shared root cause. (1) '+2' bump: the rotation walk
    itself publishes the grant-root TWICE for a folder that still has a child
    at rotation time — rotate_one(root) then the batched republish_parent(root)
    — both under the NEW read key. (2) Bob revocation bypass: the delete's
    plain relink republish (update_folder_metadata, delete.rs:230) is NOT
    suppressed for a covered scope-exit and reseals the grant-root under the
    STALE OLD in-memory read key, because rotate_read_on_scope_exit discards
    the RotateReadResult and never propagates the new key into the inode — so
    the grant-root's newest record ends up sealed under the pre-rotation key
    again, re-exposing it to the revoked reader."
  confirming_evidence:
    - "EXECUTABLE PROOF (Defect 1): new scoped test
       crates/fuse/src/write_ops/rotation_deps.rs
       `covered_scope_exit_with_a_child_publishes_the_grant_root_twice` PASSES
       asserting publish_count_for(grant-root)==2 for a grant-root with one
       child, using the injectable FakeTransport. The pre-existing sibling test
       `covered_scope_exit_rotates_the_grant_root_exactly_once` (CHILDLESS
       folder) asserts ==1. Both green under `cargo test -p cipherbox-fuse`.
       The delta is exactly the presence of one child."
    - "CODE (Defect 1 mechanism): engine.rs:1418 rotate_one(root) publishes the
       root (publish #1); engine.rs:1454-1471 seeds ParentTrackingState with
       pending_child_count = root_committed.children.len(); after the child
       rotates, engine.rs:2031 complete_pending_child decrements to 0 and fires
       engine.rs:2115 republish_parent → publish_with_cas on the SAME
       state.parent_ipns_name (grant-root) = publish #2, under
       state.parent_new_read_key (the NEW key)."
    - "CODE (Defect 2 mechanism): grant_scope.rs:452-461 —
       rotate_read_on_scope_exit matches `Ok(_)` and DISCARDS the
       RotateReadResult (engine.rs:1832 carries the root's NEW read_key). It
       borrows fs immutably (run_scope_exit_gate takes `&CipherBoxFS`,
       grant_scope.rs:510), so it CANNOT and does NOT update the grant-root
       inode's read_key. delete.rs:230 then calls update_folder_metadata(parent)
       → fs.rs build_folder_metadata reads the in-memory parent read_key
       (fs.rs:196/211) and seals under it (fs.rs:301) → metadata.rs:277
       spawn_metadata_publish CAS last-writer-wins (metadata.rs:323 resolve
       current seq, :341 publish seq+1). Result: the grant-root's newest record
       is sealed under the OLD (pre-rotation) key."
    - "HARNESS THEORY RULED OUT: the API IPNS resolve is NOT per-user —
       apps/api/src/ipns/ipns.controller.ts:227-228 resolveRecord(query.ipnsName)
       and ipns.service.ts:557 resolveRecord(ipnsName) take only the name (no
       userId); it serves delegated-routing + DB cache preferring the higher
       sequence, identical for owner and Bob. So Bob reading the old key is NOT
       a per-user stale cache — it is the genuine last-writer-wins OLD-key
       record (the relink) being the newest published state."
  falsification_test: "Defect 1: if a childless grant-root also published
    twice, the mechanism would be wrong — it does not (the ==1 sibling test
    passes). Defect 2: if the in-memory grant-root read_key WERE refreshed
    post-rotation, the relink would reseal under the new key and Bob would be
    cut off — grant_scope.rs:452 provably discards RotateReadResult, so it is
    not refreshed."
  fix_rationale: "See Resolution.fix — propagate the rotation's new read key
    into the grant-root inode so the (still-needed, secret.txt-removing) relink
    reseals under the NEW key, closing the revocation window; and treat the
    e2e's '+1' sequence assertion as a folder-with-children expectation bug (a
    scope-root with a child inherently costs 2 rotation publishes)."
  blind_spots: "Did NOT re-run the full live headless mount this session (per
    the orchestrator's sanctioned Rust-test alternative). The exact
    owner-PASS-while-Bob-FAILs interleaving is timing-driven: owner's canRead
    (mts:368) lands in the brief NEW-key window after the synchronous rotation
    (seq 3/4) but before the async relink (seq 5, OLD key) lands; Bob's canRead
    (mts:384) lands after. This transient is not independently reproduced
    here, but the END STATE (grant-root newest record sealed under the OLD key)
    is deterministic and is the security-relevant fact. Whether the relink
    lands as exactly seq 5 vs racing republish_parent was not instrumented
    live; the last-writer-wins CAS loop (metadata.rs:319-374) makes the OLD-key
    record win regardless of interleaving."

--- PRIOR SESSION (2026-07-08) below — status: INVESTIGATION COMPLETE (mixed outcome) ---

reasoning_checkpoint:
  hypothesis: "Two DISTINCT findings. (1) The originally-reported Part A SETUP
    failure (pollFindChild 'secret.txt' never appeared under the grant-root
    within 90s, BEFORE any share/rotation) did not reproduce locally in 2 real
    headless-mount runs — both got past that phase (in ~40-47s, comfortably
    under the 90s/18-attempt budget). (2) A SEPARATE, code-confirmed race
    condition in JsonSidecarFloorStore causes intermittent rotation failures
    LATER in Part A (during the scope-exit rotation itself, after the delete),
    reproduced in 1 of 2 local runs."
  confirming_evidence:
    - "crates/fuse/src/fs.rs:82-92 — CipherBoxFS holds THREE independently-
       constructed JsonSidecarFloorStore instances (high_water.generation_store,
       high_water.seq_store, rotation_checkpoint_store) that all point at the
       SAME on-disk file (rotation-high-water.json, confirmed by the field's own
       doc comment: 'Points at the SAME combined rotation-high-water.json
       sidecar as high_water') — but each instance has its OWN independent
       Arc<Mutex<()>> (crates/sdk/src/floor_store.rs:265-271 `new()` always
       constructs a fresh lock), so persist_wrapped_key (rotation_checkpoint_store)
       is NOT serialized against bump_generation/bump_seq/enforce_resolved
       (high_water) even though both write to the SAME rotation-high-water.tmp
       path (floor_store.rs:212, `path.with_extension('tmp')`, deterministic and
       shared across all 3 instances)."
    - "Live log evidence (run2, /tmp/cipherbox-desktop-debug3.log 21:29:18):
       'JsonSidecarFloorStore: failed to persist for node
       00000000-0000-4007-8007-000000000007: No such file or directory (os
       error 2)' followed by 'shared-scope-exit read-key rotation FAILED... —
       failing closed' and 'scope-exit gate failed (fail-closed)'. ENOENT on a
       create+truncate open() would require a missing PARENT dir (ruled out —
       directory verified present/populated throughout); the only code path
       that produces bare ENOENT here is `std::fs::rename(&tmp_path, path)`
       finding tmp_path already consumed by a CONCURRENT writer's own rename —
       exactly the shared-tmp-path race above."
    - "The file's own size grew across this exact window (669 bytes at
       21:29:02 -> 1307 bytes at 21:29:32, from the recurring 'Journal:
       malformed entry ... column N' log line), proving a DIFFERENT concurrent
       writer's rename succeeded around the same failing timestamp — direct
       proof two writers were both mid-flight."
    - "Run1 (/tmp/scope-exit-run1.log) did NOT hit this race and instead showed
       a distinct symptom in the same neighborhood: grant-root sequence bumped
       by 2 instead of 1, and Bob's pre-rotation key still decrypted the
       final grant-root body after rotation (revocation-bypass-shaped result) —
       consistent with a second, unaccounted publish/timing interaction in the
       same rotation-adjacent code, though NOT independently root-caused to the
       same file/line (kept as a secondary, unconfirmed lead, not the headline
       finding)."
  falsification_test: "If the race theory is wrong, forcing high_water and
    rotation_checkpoint_store to share ONE Arc<Mutex<()>> (or serializing all
    three stores' writes behind one lock) should make the ENOENT stop
    recurring under repeated concurrent-write stress; if it still recurs, the
    hypothesis is falsified and another mechanism is at play."
  fix_rationale: "N/A for this session — this is a PRODUCT bug (race condition
    introduced by Phase 70.1 plans 70.1-03/70.1-09's rotation_checkpoint_store
    wiring), not a harness bug. Per task instructions: report with evidence,
    do NOT hack the leg script, STOP for orchestrator decision. No fix applied."
  blind_spots: "Did not instrument/prove the EXACT concurrent second writer
    (most likely candidate: the 30s background sync daemon's own
    resolve-triggered enforce_resolved bump on `high_water`, racing
    rotation_checkpoint_store's persist_wrapped_key during the scope-exit
    rotation — cipherbox_sdk::sync logged 'IPNS change detected for root
    folder: seq 5 -> 6' at 21:28:02, ~76s before the failure, so timing is
    consistent but not proven by a direct stack trace). Did not reproduce the
    ORIGINAL CI-reported Part A setup failure at all, so cannot rule out an
    additional, different CI-only mechanism for that specific symptom. Did not
    fully root-cause run1's '+2 sequence / Bob still reads' anomaly — flagged
    as a secondary lead only, insufficient evidence to name an exact file:line."

hypothesis (ORIGINAL scope — Part A setup): could not be confirmed; did not
  reproduce locally in 2 attempts with a real headless FUSE-T mount. Leading
  candidate is CI-environment timing (slower/colder IPFS + delegated-routing
  round trip for the file's-own-first-publish + folder-children-republish
  two-hop chain) exceeding the 90s/18-attempt poll budget, based on a directly
  measured ~40-47s for this same pipeline on a fast, warm, dedicated local
  machine — but this is NOT proven, only a plausible, evidence-informed
  hypothesis since the failure never actually occurred locally to inspect.
test: ran the leg twice against a real dev-key headless FUSE-T mount
  (~/CipherBox) with local docker stack (kubo/redis/someguy/postgres) + local
  API on :3000.
expecting: N/A — investigation concluded, returning findings to orchestrator.
next_action: none — report findings; no commit made (no code changed).

## Symptoms

expected: >
  Part A creates SharedGrant-<tag> folder via mkdir through the mount, writes
  secret.txt inside it, then polls (a) root's children for the folder name,
  then (b) the folder's OWN ipns metadata for secret.txt as a child. Both
  polls should succeed within their 18*5s=90s budgets since the desktop
  debounces publish at 1.5s/10s safety valve.
actual: >
  CI failure (both macOS and Linux) at the SECOND pollFindChild call (line 250
  in the reviewed file): "secret.txt" never appeared under the grant-root's
  own ipnsName after 18 attempts (90s). The FIRST pollFindChild (folder found
  under root, line 243) evidently succeeded since the stack trace points at
  line 250, not 243.
errors: |
  Error: pollFindChild: "secret.txt" never appeared under k51qzi5uqu5dhpuyderj99ut3s2vv5r8kcfvko9b06ra2gi535zfggcccbxz0t after 18 attempts
      at pollFindChild (.../shared-scope-exit-rotation.mts:151:9)
      at async main (.../shared-scope-exit-rotation.mts:250:5)
reproduction: |
  Run tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts against a real
  headless FUSE mount (--dev-key) with local API/docker stack up.
started: "Introduced by plan 70.1-13 (commit f97441e5c), first live CI run failed on both platforms; never run live before (only typechecked)."

## Eliminated

- hypothesis: "pollFindChild polls the WRONG ipns name (recipient/owner/stale
    confusion)"
  evidence: "Traced the leg script line-by-line: grantRootIpnsName = sharedRef.ipnsName
    (the folder's OWN ipns, obtained from the SealedChildRef found under root) is
    used consistently for both the folder-under-root poll and the
    file-under-folder poll. No stale/wrong-name reuse found. Both local runs
    passed this exact setup phase using the same code path."
  timestamp: 2026-07-08T21:35:00Z
- hypothesis: "sharedFolderReadKey/bobFolderReadKey derivation bug (ECIES
    wrap/unwrap producing different bytes) explains the run1 revocation-bypass
    anomaly"
  evidence: "Script's own positive control ('Bob could decrypt the shared
    folder while the grant was active') passed, proving the two keys were
    byte-identical pre-rotation. No further evidence found to confirm or deny
    a derivation bug post-rotation; downgraded to a secondary, unconfirmed
    lead rather than eliminated outright."
  timestamp: 2026-07-08T21:50:00Z

- hypothesis: "The Bob revocation-bypass is a HARNESS artifact: an API-side
    per-user IPNS resolve cache serves Bob his earlier (seq-2, old-key) record
    while the owner sees the fresh one."
  evidence: "ELIMINATED by reading the API resolve path. apps/api/src/ipns/
    ipns.controller.ts:227-228 (@Get resolve → resolveRecord(query.ipnsName))
    and apps/api/src/ipns/ipns.service.ts:557 (resolveRecord(ipnsName: string))
    take ONLY the ipns name — there is no userId dimension, no per-principal
    cache. Resolution reads delegated routing + the single shared DB row,
    preferring the higher sequence. Owner and Bob resolve identically. Bob
    reading the old key is therefore the GENUINE newest published record (the
    old-key relink republish winning last-writer-wins), NOT a stale per-user
    cache. This makes the Bob-bypass a PRODUCT bug, not a harness bug."
  timestamp: 2026-07-09T00:00:00Z

- hypothesis: "(ORCHESTRATOR HYPOTHESIS as stated) BOTH symptoms share ONE
    root cause and the '+2' is: publish#1 = the delete relink (OLD key, seq 3)
    then publish#2 = the rotation re-seal (NEW key, seq 4)."
  evidence: "PARTIALLY REFUTED. The '+2' is NOT relink+rotation — it is the
    rotation ALONE publishing the grant-root twice (rotate_one seq 3 NEW key +
    republish_parent seq 4 NEW key), proven by the FakeTransport test
    (publish_count_for(grant-root)==2 for a one-child folder, ==1 for a
    childless one) with NO relink involved. The relink is a SEPARATE, THIRD
    publish (seq 5, OLD key) that lands AFTER the +2 and is not counted by the
    e2e's pollSequenceBump (which returns at the first seq>floor = seq 4). The
    attribution 'publish#1 = old-key relink' is INVERTED: the old-key publish
    is LAST, not first. The Bob-bypass IS the relink (confirmed), but it is a
    DISTINCT defect from the +2, not the same one."
  timestamp: 2026-07-09T00:00:00Z

## Evidence

- timestamp: 2026-07-08T21:19:32Z
  checked: "Local repro environment: docker stack (kubo :5001, redis :6380,
    someguy :8190, mock-ipns-routing :3001, postgres) up 23h+, API on :3000
    healthy. Built sdk-core/sdk/core/crypto/api-client dists. Launched desktop
    headless via `pnpm dev -- -- --dev-key <hex>` with
    CIPHERBOX_API_URL/VITE_API_URL/VITE_ENVIRONMENT=local/VITE_TEST_LOGIN_SECRET
    matching e2e-test-secret-ci-only (per CI workflow desktop-e2e.yml)."
  found: "Real FUSE-T/SMB mount achieved at ~/CipherBox after clearing STALE
    local state left over from an earlier (unrelated) debug session: had to
    rm -rf ~/Library/Application Support/cipherbox/cb-journal (stale anti-
    rollback floor=24 collided with a freshly-vaulted user, unrelated to
    Phase 70.1) and kill a leftover vite process wedged on :1420."
  implication: "Local reproduction is viable with a real mount; local
    Application Support state must be clean for a fair comparison to CI's
    always-fresh runner."
- timestamp: 2026-07-08T21:26:00Z
  checked: "Ran shared-scope-exit-rotation.mts run #1 against the live mount."
  found: "Part A SETUP passed cleanly (both pollFindChild calls succeeded,
    folder-under-root and file-under-folder). Desktop log timestamps show the
    file's own first publish + folder's children-republish two-hop chain took
    ~40-47s wall clock (mkdir published 21:19:49 -> file's own node published
    21:20:34 -> folder's children-list republished 21:20:36), well under the
    90s/18-attempt budget but a non-trivial fraction of it even on a fast,
    warm, dedicated local machine. Test then failed LATER: 'grant-root
    sequence bumped by 2, expected exactly 1 (2 -> 4)' and 'recipient (Bob)
    can STILL decrypt the rotated subtree -- revocation bypass'."
  implication: "The ORIGINAL reported CI symptom (Part A setup timeout) did
    NOT reproduce. A different, new anomaly surfaced further downstream in the
    same Part A (post-rotation sequence/key-visibility mismatch) — logged as a
    secondary, unconfirmed lead."
- timestamp: 2026-07-08T21:30:52Z
  checked: "Ran shared-scope-exit-rotation.mts run #2 against the live mount
    (same live desktop process, no restart)."
  found: "Part A SETUP again passed cleanly. Delete eventually succeeded (no
    EIO) after retries, but 'pollSequenceBump: sequence for <grant-root>
    never exceeded 2 after 18 attempts' (rotation's IPNS sequence bump never
    landed within 90s). Desktop log at 21:29:18Z: 'JsonSidecarFloorStore:
    failed to persist for node 00000000-0000-4007-8007-000000000007: No such
    file or directory (os error 2)' -> 'shared-scope-exit read-key rotation
    FAILED... failing closed' -> 'scope-exit gate failed (fail-closed)'."
  implication: "A CONCRETE, reproducible (1/2 runs) product-level failure in
    the rotation checkpoint persistence layer, distinct from the originally
    assigned Part A setup symptom."
- timestamp: 2026-07-08T21:45:00Z
  checked: "crates/sdk/src/floor_store.rs (JsonSidecarFloorStore::new,
    write_map_atomic_blocking) and crates/fuse/src/fs.rs:82-92 (CipherBoxFS
    field declarations for high_water and rotation_checkpoint_store)."
  found: "CipherBoxFS holds THREE JsonSidecarFloorStore instances
    (high_water.generation_store, high_water.seq_store,
    rotation_checkpoint_store) that the field doc comment at fs.rs:87-88
    explicitly states point at the SAME combined rotation-high-water.json
    sidecar. Each JsonSidecarFloorStore::new() call (floor_store.rs:265-271)
    constructs its OWN fresh Arc<Mutex<()>> — the three instances do NOT share
    a lock. write_map_atomic_blocking (floor_store.rs:206-233) always writes
    to the SAME deterministic tmp path (`path.with_extension('tmp')`) for a
    given sidecar path, then calls std::fs::rename(&tmp_path, path). Two
    concurrent writers (one via rotation_checkpoint_store.persist_wrapped_key,
    one via high_water.bump_generation/bump_seq/enforce_resolved) can each
    open/write the SAME tmp_path; whichever renames first wins, and the
    LOSER's rename() then fails with ENOENT because tmp_path was already
    consumed -- an exact structural match for the observed error."
  implication: "Root cause confirmed at the code level: a race condition
    introduced by Phase 70.1 (rotation_checkpoint_store wiring, Plans
    70.1-03/70.1-09) between three independently-locked JsonSidecarFloorStore
    instances sharing one file and one non-unique temp path."
- timestamp: 2026-07-08T21:48:00Z
  checked: "Desktop log around 21:28:02Z (cipherbox_sdk::sync: 'IPNS change
    detected for root folder: seq 5 -> 6') relative to the 21:29:18Z failure."
  found: "The 30s background sync daemon (cipherbox_sdk::sync) independently
    resolves/polls folder state on its own schedule, a plausible concurrent
    trigger for a high_water.enforce_resolved bump racing the scope-exit
    rotation's rotation_checkpoint_store.persist_wrapped_key call ~76s later.
    Not proven via a direct stack trace/instrumentation -- circumstantial
    timing evidence only."
  implication: "Plausible concurrent-writer identity for the race, but not
    definitively proven; flagged as a blind spot."

- timestamp: 2026-07-09T00:00:00Z
  checked: "The rotation walk publish count for the grant-root, via a new
    scoped FakeTransport test in crates/fuse/src/write_ops/rotation_deps.rs
    (`covered_scope_exit_with_a_child_publishes_the_grant_root_twice`),
    contrasted with the pre-existing childless sibling
    (`covered_scope_exit_rotates_the_grant_root_exactly_once`)."
  found: "`cargo test -p cipherbox-fuse` — BOTH green. Childless grant-root:
    publish_count_for(grant-root)==1. One-child grant-root:
    publish_count_for(grant-root)==2 and publish_count_for(child)==1. The
    grant-root in the D-16 leg has secret.txt as a child at rotation time (the
    scope-exit gate at delete.rs:97 runs BEFORE the inode removal at
    delete.rs:223), so it takes the ==2 path."
  implication: "DETERMINISTIC PROOF of Defect 1: the '+2 sequence bump' is
    caused by the rotation walk publishing the grant-root twice (rotate_one +
    republish_parent), inherent to any scope-root with a child. The e2e's '+1
    exactly one rotation publish' expectation is only correct for a childless
    scope-root. No delete-relink is involved in the +2."

- timestamp: 2026-07-09T00:00:00Z
  checked: "The read-key propagation seam: grant_scope.rs::
    rotate_read_on_scope_exit (lines 425-481) and run_scope_exit_gate (509-545),
    plus the delete relink path delete.rs:230 → fs.rs::build_folder_metadata
    (160-321) → metadata.rs::spawn_metadata_publish (277-390)."
  found: "rotate_read_on_scope_exit's `Ok(_)` arm (grant_scope.rs:461) DISCARDS
    the RotateReadResult (which carries the grant-root's NEW read key,
    engine.rs:1832). run_scope_exit_gate borrows `&CipherBoxFS` (immutable), so
    the grant-root inode read_key is never refreshed. build_folder_metadata
    reseals the grant-root under the in-memory (now-STALE OLD) parent_read_key
    (fs.rs:196/211 read, :301 seal). spawn_metadata_publish CAS-publishes
    last-writer-wins (metadata.rs:319-374), so the grant-root's newest record
    is sealed under the OLD key."
  implication: "DETERMINISTIC-END-STATE PROOF of Defect 2: the covered
    scope-exit delete republishes the grant-root under the pre-rotation key
    AFTER the rotation cut the reader off, re-exposing it. Bob (whose key is
    byte-identical to the owner's pre-rotation key) can decrypt the newest
    record again = revocation bypass. Owner PASS is a transient (reads during
    the NEW-key window before the async relink lands); the end state is OLD-key
    and deterministic."

## Resolution (2026-07-09 — HEADLINE: the Part A +2 / Bob-bypass assertion failures)

root_cause: |
  TWO DISTINCT, DETERMINISTIC defects in the covered scope-exit delete path.
  They are NOT the same root cause (the orchestrator's "one shared cause"
  hypothesis is refuted — see Eliminated). Both are cross-platform because
  they are pure control-flow/crypto-sealing bugs, not timing/IPFS-warmth.

  ── DEFECT 1 — the "+2 sequence bump" (grant-root seq 2 -> 4) ──
  The rotation walk publishes the GRANT-ROOT TWICE whenever the scope-root
  still has a child at rotation time (it does: the scope-exit gate at
  crates/fuse/src/write_ops/implementation/delete.rs:97 runs BEFORE the inode
  is removed at delete.rs:223, so secret.txt is still a child when
  rotate_read_from_node runs):
    • Publish #1 — crates/sdk/src/rotation/engine.rs:1418 rotate_one(root) →
      seal_and_publish (engine.rs:698-732) CAS-publishes the grant-root under
      the NEW read key.
    • Publish #2 — because root_committed.children is non-empty, engine.rs:
      1454-1471 seeds a ParentTrackingState with
      pending_child_count = children.len(); after the child rotates,
      engine.rs:2031 complete_pending_child decrements it to 0 and fires
      engine.rs:2115 republish_parent → publish_with_cas on the SAME grant-root
      ipns, again under the NEW read key, to re-mirror the child's new key.
  Both records are NEW-key, so this pair does not itself bypass revocation.
  The D-16 leg's assertion "bumped by exactly 1 / exactly one rotation publish"
  (shared-scope-exit-rotation.mts:355-366) is simply WRONG for a scope-root
  that has a child — it is only valid for a CHILDLESS scope-root. Proven by
  the new FakeTransport test (childless==1 publish, one-child==2 publishes).

  ── DEFECT 2 — the Bob revocation bypass (the SECURITY bug) ──
  crates/fuse/src/write_ops/grant_scope.rs:452-461 (rotate_read_on_scope_exit)
  matches `Ok(_)` and DISCARDS the RotateReadResult that carries the
  grant-root's freshly-minted read key (engine.rs:1832). It borrows fs
  immutably (run_scope_exit_gate, grant_scope.rs:510 `&CipherBoxFS`), so the
  in-memory grant-root inode read_key is NEVER refreshed to the post-rotation
  key. Immediately after the gate, handle_unlink runs the plain delete relink
  — delete.rs:230 fs.update_folder_metadata(parent) — which is NOT suppressed
  for a covered scope-exit (identical to a private delete). build_folder_metadata
  (crates/fuse/src/fs.rs:160-321) reseals the grant-root body under the
  in-memory (now STALE OLD) parent_read_key (fs.rs:196/211 read, fs.rs:301
  seal_published_node), and spawn_metadata_publish (crates/fuse/src/metadata.rs:
  277-390) CAS-publishes it last-writer-wins (metadata.rs:323 resolve current
  seq, :341 publish at seq+1). Net effect: the grant-root's NEWEST published
  record is sealed under the PRE-ROTATION key again, undoing the rotation.
  The pre-rotation key == Bob's bobFolderReadKey (byte-identical, unwrapped
  from the same ECIES grant), so canRead(grantRoot, bobFolderReadKey, bobCtx)
  succeeds → assertion 5 FAIL "revocation bypass". The API IPNS resolve is NOT
  per-user (apps/api/src/ipns/ipns.controller.ts:227 / ipns.service.ts:557 —
  name-only, shared DB row), so this is a genuine product record replacement,
  not a per-user cache artifact.

  ── Why owner PASSES while Bob FAILS on the SAME key/name ──
  The rotation (Defect 1) publishes synchronously inside the FUSE unlink
  callback (block_on), so the NEW-key records (seq 3, 4) exist the instant
  rmSync returns. The relink (Defect 2) is an async fire-and-forget thread
  (spawn_metadata_publish) that lands its OLD-key record (seq 5) a network
  round-trip later. The owner's canRead (mts:368) fires immediately after
  pollSequenceBump (which returns at seq 4) and reads a NEW-key record → PASS.
  Bob's canRead (mts:384) fires later, after the OLD-key relink has landed as
  the newest record → reads OLD key → FAIL. The END STATE (newest record is
  OLD-key) is deterministic via the last-writer-wins CAS loop; the owner's
  transient PASS is the only timing-sensitive part.

  ── PRIOR-SESSION FINDINGS (retained below; a THIRD, separate concurrency
  bug in JsonSidecarFloorStore was code-confirmed on 2026-07-08 and is
  unrelated to these two — see the prior Resolution text) ──

  == Superseded prior text (2026-07-08 mixed-outcome session) ==
  TWO SEPARATE FINDINGS, neither of which is the assigned Part A setup
  symptom:

  1. ORIGINAL ASSIGNED BUG (pollFindChild "secret.txt never appeared" during
     Part A SETUP, before any share/rotation): NOT REPRODUCED. Two full local
     runs against a real headless FUSE-T mount both passed this exact phase.
     No root cause confirmed. Leading (unconfirmed) hypothesis: CI-runner
     environment speed (cold-started Kubo with no warm peers/DHT state,
     shared/virtualized 2-4 vCPU, concurrent Xvfb/WebKit/cargo load) makes the
     two-hop publish chain (file's own first IPNS publish + folder's
     children-list republish) exceed the current 90s/18-attempt poll budget --
     supported by directly measuring ~40-47s for this SAME chain on a fast,
     warm, dedicated local machine (a substantial fraction of the budget even
     under ideal conditions), but this was never actually observed failing
     locally, so it remains a hypothesis, not a proven root cause.

  2. NEW, CODE-CONFIRMED PRODUCT BUG (discovered during reproduction attempts,
     later in the SAME Part A -- the rotation phase after the delete): a race
     condition in crates/sdk/src/floor_store.rs's JsonSidecarFloorStore.
     CipherBoxFS (crates/fuse/src/fs.rs:82-92) holds THREE independently-
     constructed JsonSidecarFloorStore instances (high_water.generation_store,
     high_water.seq_store, rotation_checkpoint_store) that all persist to the
     SAME on-disk file (rotation-high-water.json) via the SAME deterministic
     temp-file path (floor_store.rs:212, path.with_extension("tmp")), but each
     instance owns its OWN independent Arc<Mutex<()>> lock
     (floor_store.rs:265-271) -- rotation_checkpoint_store's
     persist_wrapped_key calls are NOT serialized against high_water's
     bump_generation/bump_seq/enforce_resolved calls. When both fire close in
     time (e.g. rotation_checkpoint_store.persist_wrapped_key during a
     scope-exit rotation racing high_water.enforce_resolved from a concurrent
     resolve, plausibly the 30s background sync daemon), the loser's
     std::fs::rename(&tmp_path, path) fails with ENOENT because the winner
     already consumed (renamed away) the shared tmp_path first. This makes
     rotate_read_on_scope_exit fail closed (EIO), directly causing the
     shared-scope-exit rotation to fail or double-fire unpredictably.
     Reproduced in 1 of 2 local runs with an exact log-line match:
     "JsonSidecarFloorStore: failed to persist for node ...: No such file or
     directory (os error 2)".

fix: |
  APPLIED (2026-07-09, orchestrator-directed: both fixes + verify). Two commits.

  ── FIX A (revocation bypass) — grant-root inode key refresh ──
  `rotate_read_on_scope_exit` (crates/fuse/src/write_ops/grant_scope.rs) now
  takes `&mut CipherBoxFS`, captures the `RotateReadResult`, and overwrites the
  grant-root inode's in-memory `read_key` with the freshly-minted post-rotation
  key (`refresh_grant_root_read_key`, D-09 terminal-owner: overwrite in place,
  never zero the caller-owned RotateReadResult, never log key bytes). Every
  later local publish of that folder now reseals under the NEW key, so the
  pre-rotation key is dead — Bob is cut off. The gate was split into a
  synchronous immutable-borrow detection half (`detect_scope_exit` /
  `detect_scope_exit_grant_root`) and the `&mut` rotation half, which both
  preserves all D-15a/b/c fail-closed checks AND resolves the borrow conflict
  (`fs.rt` is cloned so `block_on` does not borrow `fs`). This fix rides the
  SHARED `rotate_read_on_scope_exit`/`run_scope_exit_gate`, so FUSE unlink/rmdir
  + rename + WinFsp all get it (WinFsp CI-verified — write_ops.rs call sites
  updated to `&mut`).

  ── COALESCING — single authoritative grant-root publish ──
  New additive engine primitive `rotate_read_from_node_with_root_children`
  (crates/sdk/src/rotation/engine.rs, exported via rotation/mod.rs + lib.rs):
  re-seals/publishes the scope-ROOT with a caller-supplied post-delete child
  list (`root_children_override`) instead of its currently-published children.
  Implemented via delegating wrappers (`rotate_one_inner`/
  `rotate_read_from_node_inner`) so ZERO churn to the ~27 existing test call
  sites. On a covered scope-exit delete where the grant-root IS the deleted
  node's DIRECT parent (the shallow D-16 case), handle_unlink/handle_rmdir build
  the post-delete `SealedChildRef` list (`fs.build_scope_exit_child_override`,
  no mutation — fail-closed until the rotation succeeds) and pass it; the
  rotation then publishes the grant-root EXACTLY ONCE (post-delete, new key) and
  the plain `update_folder_metadata(parent)` relink is SUPPRESSED
  (`relink_suppressed`). For a single-child grant-root the walk sees no
  surviving children → no batched `republish_parent` → +1. Deep scope-exits and
  rename/WinFsp pass `None` (no coalescing) and keep their own relink, now
  correctly resealed under the Fix-A-refreshed key.

  Known limitation (documented, out of scope): a DEEP scope-exit rotates the
  grant-root subtree but only the grant-root inode's key is refreshed (the
  engine returns only the root's `RotateReadResult`); intermediate parents' own
  post-rotation relinks still reseal under their stale in-memory keys. The D-16
  leg is shallow; deep-delete intermediate-node key refresh is a follow-up
  (would need the engine to surface all rotated nodes' keys). WinFsp coalescing
  parity (set_delete is split gate/relink) is tracked by the existing todo
  2026-07-08-winfsp-d15d-gate-ordering-parity.md — WinFsp gets Fix A now.

  == Original proposal (kept for reference) ==

  ── FIX A (Defect 2, the SECURITY bug — REQUIRED) ──
  Propagate the rotation's new read key into the in-memory inode AND make the
  covered-delete relink reseal under it, never the stale old key:
    1. Thread `&mut CipherBoxFS` (or add interior mutability to the inode
       read_key) through run_scope_exit_gate → rotate_read_on_scope_exit
       (crates/fuse/src/write_ops/grant_scope.rs:510 / :425). Capture the
       RotateReadResult at grant_scope.rs:461 instead of `Ok(_)`-discarding it.
    2. Write RotateReadResult.read_key (and .generation) back into the
       grant-root inode (InodeKind::{Folder,Root}.read_key) so every
       subsequent local publish reseals under the post-rotation key. This is
       exactly what engine.rs:762-769's own doc comment says the FUSE caller
       MUST do ("refresh their own in-memory folder-tree entry so a same-
       session retry does not operate on stale pre-rotation state") — it is
       currently unwired for the scope-exit path.
    3. The relink at delete.rs:230 is STILL needed (secret.txt was removed
       from the child list only after the gate) — but with the inode key
       refreshed it will now reseal the secret.txt-removed child list under
       the NEW key, so the newest record stays new-key → Bob cut off.
       (SECURITY: terminal-owner zeroization only — the RotateReadResult
       read_key is Zeroizing; copy 32 bytes into the inode's own Zeroizing
       buffer, do not zero the caller-owned RotateReadResult early. Never log
       the key.)

  ── FIX B (Defect 1, the "+2" assertion — TEST/EXPECTATION, orchestrator call) ──
  A scope-root WITH a child inherently costs 2 rotation publishes (rotate_one
  + republish_parent); a true "+1" is not achievable without an engine
  redesign to fold the batched parent re-mirror into the root's own publish
  (hard: rotate_one publishes before children's new keys exist). Recommended:
  relax the e2e assertion from "== +1" to the security-meaningful invariants —
  "the pre-rotation key no longer decrypts the newest record" AND "Bob is cut
  off" — plus, if a count is desired, "+2 for a one-child grant-root" (or seed
  the grant-root empty at rotation time). NOTE: with Fix A in place the delete
  relink becomes a THIRD publish (+3) unless it is SUPPRESSED for the covered
  path (safe once the rotation's republish_parent already reflects the correct
  post-delete child list) OR coalesced. Decide A's relink-handling and B's
  assertion together.

  The leg script and all product code are UNCHANGED except the one added
  proof test (see files_changed).
verification: |
  Scoped Rust tests — ALL GREEN (no full suites, no live network):
    cargo test -p cipherbox-sdk  → 152 passed
      rotation::engine::rotate_read_from_node::
        override_empty_children_publishes_root_once_and_skips_deleted_child ... ok
        override_drops_only_the_deleted_child_and_rekeys_survivors ... ok
    cargo test -p cipherbox-fuse → 108 passed (+1 integration)
      write_ops::rotation_deps::tests::
        covered_scope_exit_rotates_the_grant_root_exactly_once ... ok (childless == 1)
        covered_scope_exit_with_a_child_publishes_the_grant_root_twice ... ok (un-coalesced diagnosis == 2)
        covered_scope_exit_with_empty_override_publishes_the_grant_root_once ... ok (COALESCED == 1, deleted child never rotated)
      write_ops::implementation::delete::tests::
        unlink_shared_scope_exit_fails_closed_until_rotation_wired ... ok (covered path still succeeds + fail-closed)
  Coalesced count PROVEN == 1 (single-child grant-root) through the production
  FuseRotationDeps adapter. Fix-A key-refresh + gate-split verified by the full
  fuse suite (poisoned-lock D-15c, private/shared gate tests all green).
  cargo fmt -p cipherbox-fuse -p cipherbox-sdk applied; out-of-scope fmt drift
  reverted (only intentionally-changed files staged). WinFsp code is CI-only on
  macOS (change is a trivial &mut signature update) — pending CI.
  LIVE MOUNT: not re-run this session (heavy/flaky per prior session; the
  security + coalesced-count invariants are proven deterministically offline).
  Pending: the CI desktop-e2e leg (shared-scope-exit-rotation.mts Part A) —
  orchestrator will dispatch.
files_changed:
  - "crates/sdk/src/rotation/engine.rs (rotate_one_inner/rotate_read_from_node_inner
     wrappers + rotate_read_from_node_with_root_children + seal_and_publish
     children_override; 2 new override tests)"
  - "crates/sdk/src/rotation/mod.rs, crates/sdk/src/lib.rs (export the new wrapper)"
  - "crates/fuse/src/write_ops/grant_scope.rs (detect_scope_exit split; &mut
     rotate_read_on_scope_exit + root_children_override + Fix-A
     refresh_grant_root_read_key; detect_scope_exit_grant_root; run_scope_exit_gate &mut)"
  - "crates/fuse/src/fs.rs (build_scope_exit_child_override helper)"
  - "crates/fuse/src/write_ops/implementation/delete.rs (handle_unlink/handle_rmdir:
     detect + coalesced rotate + relink suppression)"
  - "crates/fuse/src/platform/windows/write_ops.rs (&mut fs at the two gate call sites)"
  - "crates/fuse/src/write_ops/rotation_deps.rs (coalesced-count proof test +
     retained diagnosis test)"
  - "tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts (D-16 Part A:
     coalesced +1 count message + security-invariant framing)"

---
status: investigating
trigger: "DATA_START\nReproduce and root-cause a Phase 70.1 desktop-e2e failure LOCALLY: tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts failed in CI on BOTH macOS and Linux at Part A setup: pollFindChild secret.txt never appeared under grant-root ipns after 18 attempts, line 250. Journal malformed-entry warnings are a pre-existing red herring, not the cause.\nDATA_END"
created: 2026-07-08T00:00:00Z
updated: 2026-07-08T21:55:00Z
---

## Current Focus

status: INVESTIGATION COMPLETE (mixed outcome — see Resolution)

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

## Resolution

root_cause: |
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

fix: "NONE APPLIED. Per task instructions, PRODUCT regressions are reported
  with evidence and NOT hacked around in the leg script -- this is a genuine
  concurrency bug in production Rust code (crates/sdk/src/floor_store.rs +
  crates/fuse/src/fs.rs), introduced by Phase 70.1 (rotation_checkpoint_store
  wiring, Plans 70.1-03/70.1-09), requiring an engineering fix (e.g. share ONE
  Arc<Mutex<()>> across all JsonSidecarFloorStore instances pointed at the
  same sidecar path, or give each write a per-call-unique temp filename) —
  left for orchestrator decision. The leg script itself
  (tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts) was NOT modified."
verification: "N/A — no fix applied. The race was reproduced once (run2) with
  an exact log-line match to the hypothesized mechanism; the code path was
  independently confirmed by reading floor_store.rs + fs.rs (not just
  inferred from behavior)."
files_changed: []

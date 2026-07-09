---
status: fixed
trigger: "macOS-CI-only D-16 Part A SETUP failure: pollFindChild secret.txt never appeared under the newly-created shared folder's OWN ipnsName after 40 attempts (201.6s), at shared-scope-exit-rotation.mts:160 called from :265. Linux resolves the same in ~5s. Central question: pure macOS-runner propagation SLOWNESS vs a genuine FIRST-PUBLISH bug where the folder's first IPNS record never lands on macOS."
created: 2026-07-09T00:00:00Z
updated: 2026-07-09T00:00:00Z
---

## Current Focus

status: FIXED — both fixes applied (harness nudge + product idle-mount publish-queue backstop)

verdict: >
  The folder's FIRST IPNS publish DID land (empty folder, seq 1, at mkdir). The
  failure is that the folder's SECOND publish — the child-add republish that
  should include secret.txt — is NEVER TRIGGERED on macOS. It sits in the
  edge-triggered `publish_queue` forever because (a) FUSE-T defers the file's
  `handle_release` ~40-47s past the write (SMB deferred-close), so the parent
  republish is queued only AFTER the test's last mount I/O, and (b) the queue is
  drained ONLY from inside FUSE op handlers (no wall-clock backstop), so once the
  test stops touching the mount and just polls IPNS, no drain ever fires. The
  folder's published record stays at its empty seq-1 state → secret.txt never
  appears → the 200s poll times out. Raising the poll budget CANNOT fix this
  (nothing is slow — the republish is never attempted).
next_action: none — investigation complete; report + recommendation, no code changed.

## Symptoms

expected: >
  Part A creates SharedGrant-<tag> via mkdir through the mount, writes secret.txt
  inside, polls (a) root's children for the folder name [SUCCEEDS], then (b) the
  folder's OWN ipns metadata for secret.txt as a child. Poll (b) should succeed
  within 40*5s=200s.
actual: >
  macOS CI ONLY: poll (b) times out — pollFindChild "secret.txt" never appeared
  under k51...42lxt after 40 attempts (201.6s), at .mts:160 from :265. Linux
  resolves it in ~5s (attempt 2). macOS log is full of "API error: IPNS name not
  found: <folder's own name>", "Metadata refresh failed ... list_folder_owned:
  resolve/fetch failed ... IPNS name not found", "open: ino=N no in-flight
  resolution (previously failed?), returning EIO", and (prior runs) "Background
  metadata publish failed: IPNS resolve failed and no cached sequence for <name>".
errors: |
  Error: pollFindChild: "secret.txt" never appeared under
  k51qzi5uqu5djc5q7hp8o4pt82vg3uaiws235nyuxg96uwrqv9n3mb1bz42lxt after 40 attempts (201.6s)
    at pollFindChild (.../shared-scope-exit-rotation.mts:160)
    at async main (.../shared-scope-exit-rotation.mts:265)
reproduction: |
  desktop-e2e run 28982153647, Desktop_E2E (macos) leg. Linux leg passes identical code.
started: "macOS-runner-specific; budget already widened 18/90s -> 40/200s in a prior fix and still times out on macOS."

## Eliminated

- hypothesis: "Pure IPNS propagation SLOWNESS on the macOS runner — the folder's
    second publish eventually lands but takes >200s (the prior session's leading
    theory; the reason the budget was widened 18/90s -> 40/200s)."
  evidence: "REFUTED. The folder's own ipnsName (k51...42lxt) appears in the ENTIRE
    macOS log exactly TWICE: the mkdir first-publish (seq 1, empty, 23:26:17Z) and
    the test's own error line. There is NO 'Background node/v3 publish succeeded'
    and NO 'Background metadata publish failed' for it — the second (child-add)
    publish was never even ATTEMPTED. Nothing is slow; the republish never fires.
    No budget suffices."
  timestamp: 2026-07-09T00:00:00Z

- hypothesis: "First-publish resolve-then-bump error: the newly-created folder's
    first record never lands, and resolve-before-publish fails with 'no cached
    sequence'/'IPNS name not found' instead of publishing seq 1 (the signature the
    task flagged)."
  evidence: "REFUTED for this run. (1) The folder's FIRST publish DID land — mkdir
    logged 'New folder IPNS published: k51...42lxt' at 23:26:17Z and the folder
    became resolvable under root (first pollFindChild succeeded, attempt 1). (2)
    'no cached sequence' / 'Background metadata publish failed' appear ZERO times
    in this macOS log (they were prior-run artifacts). (3) Even under resolve lag,
    resolve_sequence (publish.rs:98-141) FALLS BACK to the coordinator cache, and
    mkdir seeds that cache via record_publish(name,1) (mkdir.rs:192), so a second
    publish would bump to seq 2 from cache regardless of propagation. The failure
    is upstream of resolve_sequence — the publish is never triggered."
  timestamp: 2026-07-09T00:00:00Z

- hypothesis: "Same class as the documented macOS FUSE-T cross-client-sync flake
    (SMB read cache; inval_inode ignored by FUSE-T)."
  evidence: "PARTIALLY related (both stem from FUSE-T/SMB caching) but DISTINCT.
    The documented flake is READ-side staleness (a client reads stale cached data
    after a remote change). This is a WRITE-side publish-trigger gap: FUSE-T's
    deferred close/release lands the parent-republish enqueue after mount I/O
    ceases, and the drain is edge-triggered with no timer, so the republish never
    fires. Different code path, different fix."
  timestamp: 2026-07-09T00:00:00Z

## Evidence

- timestamp: 2026-07-09T00:00:00Z
  checked: "Both CI logs (r3-Desktop_E2E_(macos|linux).log) for the D-16 Part A
    window; folder-creation -> first-publish -> child-add sequence."
  found: >
    LINUX (PASS): Part A ran 23:19:03 -> 23:20:00 (whole leg 57s). Both
    pollFindChild calls returned at attempt 1 (0.0s) at 23:19:12 — SharedGrant
    under root AND secret.txt under the folder, immediately. The Rust desktop log
    is not even interleaved (clean single-process run).
    macOS (FAIL): Part A started 23:26:17. mkdir published the folder (k51...42lxt,
    empty seq 1) + root at 23:26:17. SharedGrant appeared under root at attempt 1
    (23:26:25). secret.txt (ino 19, own file node k51...oody8) release/upload was
    DEFERRED to 23:27:04 (~40-47s after the write). The folder was NEVER
    republished. Poll timed out at 23:29:47 (201.6s).
  implication: "Divergence is the folder's SECOND publish (child-add), not the
    first. On Linux it happens immediately; on macOS it never happens."

- timestamp: 2026-07-09T00:00:00Z
  checked: "grep for the folder's own ipnsName k51...42lxt across the whole macOS
    log; grep for 'Background node/v3 publish succeeded', 'Background metadata
    publish failed', 'no cached sequence' for it."
  found: "The folder name appears exactly twice (mkdir publish + test error). No
    background publish success/failure line for it anywhere. After the delayed
    release at 23:27:04Z there is ZERO cipherbox_fuse/cipherbox_sdk activity until
    the test dies at 23:29:47Z (163s of silence)."
  implication: "The folder's child-add republish was enqueued at release
    (23:27:04) and never drained/attempted. Nothing polled/pumped the FS after."

- timestamp: 2026-07-09T00:00:00Z
  checked: "The file-write parent-republish trigger path: read_ops.rs handle_release
    (:693) -> queue_publish(parent_ino) (:810); fs.rs queue_publish (:486),
    flush_publish_queue (:501, debounce 1.5s / safety_valve 10s), drain_upload_completions (:440)."
  found: "handle_release enqueues the parent folder for republish via
    fs.queue_publish(result.parent_ino, true) at read_ops.rs:810. flush_publish_queue
    (fs.rs:501) is the ONLY thing that builds+spawns the folder's metadata publish,
    and it is called ONLY from drain_upload_completions (fs.rs:483). Repo-wide,
    every non-test caller of drain_upload_completions/flush_publish_queue is inside
    a FUSE op handler (read_ops.rs:129/272/694, dir_ops.rs:21, windows/*). There is
    NO periodic/wall-clock pump: the mount is fuser::mount2 (apps/desktop/.../fuse/mod.rs:409),
    a foreground op-driven session; lib.rs has no production timer (the drains at
    lib.rs:225/358 are inside #[tokio::test])."
  implication: "The debounce/safety-valve are EDGE-triggered by incoming FUSE ops,
    not wall-clock. If no FUSE op arrives after an enqueue, the republish starves
    indefinitely — exactly what happens on macOS once the test stops nudging."

- timestamp: 2026-07-09T00:00:00Z
  checked: "Asymmetry: how mkdir republishes its parent vs how file-write does."
  found: "mkdir (mkdir.rs:162-250) spawns a thread that publishes the child folder
    AND the parent DIRECTLY (synchronously in-thread), logging 'Parent metadata
    published after mkdir' (:250) — no dependency on the edge-triggered queue.
    That is why SharedGrant appeared under root on macOS. The file-write/release
    path instead defers the parent republish to the edge-triggered publish_queue
    (read_ops.rs:810), which is the starving path."
  implication: "Only the file-write -> parent-folder republish is vulnerable. The
    fix must give that path a trigger that does not depend on a future FUSE op."

- timestamp: 2026-07-09T00:00:00Z
  checked: "Data-loss vs visibility-delay severity: the CR-08 journal contract in
    handle_release (read_ops.rs:921-928)."
  found: "handle_release deliberately KEEPS the file's journal entry until the
    parent publish is confirmed; replay on the next mount is the authoritative
    cleanup (already_present check republishes the parent). So the child is not
    lost — it is delayed until the next mount OR the next FUSE op that drains the
    queue."
  implication: "Severity is a visibility/durability LATENCY gap, not data loss.
    Real users constantly poke the mount (Finder/Spotlight/app I/O), so the drain
    fires within seconds in practice — which is why the prior session's local
    headless run PASSED in ~40-47s (something poked the mount within budget) and
    the isolated CI-macOS runner (no Finder/Spotlight, test goes silent) does not."

## Resolution

root_cause: |
  GENUINE TRIGGER BUG unmasked by a FUSE-T timing difference — NOT propagation
  slowness and NOT a first-publish resolve-then-bump error.

  The newly-created folder's FIRST IPNS publish (empty, seq 1) lands fine at
  mkdir. The failure is that the folder's SECOND publish — the child-add
  republish that adds secret.txt to the folder's children list — is never
  triggered on the macOS runner.

  Mechanism (two necessary conditions, both hold on macOS CI):
  1. FUSE-T (SMB-backed) DEFERS the file's close/release: `handle_release`
     (crates/fuse/src/read_ops.rs:693) for secret.txt fired ~40-47s after the
     write (23:27:04Z vs a write at ~23:26:20Z), well AFTER the test issued its
     last mount I/O (the nudge()/readdir at ~23:26:25Z). On Linux fuser, release
     is prompt at close(), so the enqueue precedes the nudge that drains it.
  2. The parent-folder republish is enqueued via `fs.queue_publish(parent_ino,
     true)` (read_ops.rs:810) into an EDGE-TRIGGERED queue. `flush_publish_queue`
     (crates/fuse/src/fs.rs:501; debounce 1.5s / safety-valve 10s) is the only
     code that builds+spawns the folder publish, and it is called ONLY from
     `drain_upload_completions` (fs.rs:483), which is called ONLY from inside FUSE
     op handlers. There is NO wall-clock/background pump (mount is fuser::mount2,
     a foreground op-driven session; the only production drain callers are
     read_ops.rs:129/272/694, dir_ops.rs:21, and the windows equivalents).

  Net: on macOS the release lands after the test stops touching the mount, so the
  folder's queued republish never gets drained. The folder's published record
  stays at the empty seq-1 mkdir state; secret.txt never appears in it; the 200s
  pollFindChild(folder, "secret.txt") times out. Confirmed by the log: the
  folder's own name appears exactly twice (mkdir publish + error), NO background
  publish success/failure line for it, and ZERO FS activity for 163s after the
  delayed release.

  Contrast with mkdir, which publishes its parent DIRECTLY in a spawned thread
  (mkdir.rs:250) and therefore is immune — which is exactly why SharedGrant
  appeared under root but secret.txt never appeared under the folder.

  This also finally root-causes the prior session's open "Part A SETUP timeout
  did not reproduce locally, probably CI slowness" question: it is not slowness,
  it is FUSE-op-starvation of the edge-triggered publish drain under FUSE-T's
  deferred release.

fix: |
  APPLIED (2026-07-09, coordinator-directed: both fixes on HEAD b9b6e5f6b). Two
  atomic commits. Chosen Fix-2 design = option (i)(a) BACKGROUND PUMP — because
  `fs` is moved into `fuser::mount2` and owned exclusively by the FS thread, and
  upload completions are drained inline on that thread (no background consumer),
  so option (i)(b) "chain off upload-completion" would require a risky fs-sharing
  refactor. The pump drives the EXISTING drain by generating a FUSE op — no new
  fs sharing, no data race.

  ── FIX 1 (harness, makes D-16 deterministic) ──
  tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts: pollFindChild gains an
  optional `nudgePaths: string[] = []` param and calls `nudge(...nudgePaths)` at
  the START of every poll iteration. The two "file-under-folder" call sites (Part
  A secret.txt, Part B private.txt) now pass `[join(mount, <folder>)]`, so each
  poll iteration issues statSync+readdirSync on the folder → a FUSE op that drains
  the publish queue on the FS thread → the deferred-release parent republish
  flushes. Mirrors a real client that keeps using the mount. The folder-under-root
  polls keep the default `[]` (mkdir republishes root directly, so they never
  needed it). No assertion weakened. The nudge() pattern is already proven to
  reach our handlers through FUSE-T across the existing desktop-e2e suite.

  ── FIX 2 (product, idle-mount backstop) ──
  apps/desktop/src-tauri/src/fuse/mod.rs: a `fuse-publish-pump` background thread,
  spawned alongside the `fuse-mount` thread, wakes every PUBLISH_PUMP_INTERVAL_SECS
  (=2s) and issues `std::fs::symlink_metadata(mount_root/.cb-pub-pump-<n>)` with a
  FRESH, guaranteed-absent name each tick. A never-seen name is uncacheable by the
  FUSE-T/SMB negative-lookup cache, so it always reaches `handle_lookup`
  (read_ops.rs:129 → drain_upload_completions → flush_publish_queue) on the FS
  thread, draining any queued republish on an otherwise-idle mount. The probe
  returns ENOENT and is a pure no-op otherwise. Lifetime is bounded to the mount:
  a shared `Arc<AtomicBool>` is flipped false the instant `fuser::mount2` returns
  (both clean-unmount and error arms), so the pump never outlives the mount. No
  key logging; harmless on Linux fuser (prompt release makes it a rarely-needed
  backstop). Bounded latency on an idle mount ≈ 2s poke interval + the ≥1.5s
  debounce (the 10s safety valve is the hard ceiling), i.e. a queued republish
  publishes within ~2–3.5s of the upload completing even with zero client I/O.

  crates/fuse/src/fs.rs: new `publish_queue_backstop_tests` module (3 tests) pins
  the contract the pump relies on: a SINGLE drain (one pump poke) flushes a queued
  republish once past the 1.5s debounce, the 10s safety valve flushes even a
  stuck-upload (pending_uploads>0) entry, and a within-debounce entry is NOT
  flushed (coalescing preserved).

recommendation: |
  Verdict: genuine bug (edge-triggered publish-queue starvation), unmasked by
  FUSE-T deferred release. Slowness (option iii) is ruled OUT — no poll budget
  works because the republish is never attempted. Preference order:

  (i) PRIMARY / product fix — add a WALL-CLOCK BACKSTOP for the publish-queue
      drain so a queued parent republish fires even when no further FUSE op
      arrives. Two viable implementations (fuser::mount2 moves `fs` into the
      session, so a shared-timer needs care):
        a. A lightweight background thread spawned at mount that periodically
           (e.g. every 1-2s) issues a benign FUSE op against the mount root
           (a stat()/getattr on the mount path) — this drives the existing
           drain_upload_completions/flush_publish_queue on the FS thread with no
           refactor. Platform-agnostic; the debounce/safety-valve then behave as
           wall-clock as originally intended.
        b. Chain the parent republish off the upload-completion instead of the
           edge-triggered queue (mirror mkdir's direct-publish model). Heavier —
           build_folder_metadata needs the FS thread's inode tree, so this needs
           a self-scheduled work item, not just the spawned upload thread.
      Fix (i) closes a latent cross-platform visibility/latency gap (a file
      written right before the mount goes idle stays invisible to other clients /
      a fresh resolve until the next mount's journal replay). Severity is
      LATENCY, not data loss (CR-08 journal replay recovers it next mount).

  (ii) PRAGMATIC / unblock CI now — make the D-16 Part A folder-own-ipns poll
       drive mount activity: have pollFindChild(grantRoot, "secret.txt") also
       nudge(folder) (a cheap readdir/getattr) each iteration. That generates the
       FUSE op that drains the queue and flushes the folder publish — it mirrors
       real-world mount usage rather than masking the gap. This is preferable to
       the suite's existing "optional on macOS -- timed out" best-effort pattern
       because it actually exercises the child-add publish. If a best-effort skip
       is chosen instead, scope it to macOS only and log loudly, matching the
       rename-sync precedent — but note it would leave the real product gap in (i)
       unaddressed.

  (iii) Raising the macOS poll budget — DO NOT. Evidence: the folder republish was
        never attempted across 163s of post-release silence; it is stuck, not
        slow. No budget suffices.

  Recommended: ship (ii)'s in-loop nudge to make the CI leg deterministic now,
  AND file (i) as the real product fix (wall-clock backstop) — they are
  complementary, not either/or.

verification: |
  Scoped, offline (no full suites, no live network, no key logging):
    - cargo test -p cipherbox-fuse → 111 passed / 0 failed (was 108; +3 new
      publish_queue_backstop_tests). Includes the coalescing/revocation suite.
    - cargo check -p cipherbox-desktop → 0 errors (Fix 2 compiles under the
      default `fuse` feature).
    - cargo fmt -p cipherbox-fuse -p cipherbox-desktop applied; the resulting
      out-of-scope fmt drift in ~15 pre-existing files was reverted with
      `git checkout --` (only the 3 intended files staged), per the known
      "cargo fmt strands out-of-scope drift" hazard.
    - shared-scope-exit-rotation.mts: tsx transpile+load reaches the expected
      TEST_SECRET runtime guard (imports resolve, no syntax/type-strip error);
      these tsx scripts have no separate tsc gate in CI.

  LIVE IDLE-MOUNT VALIDATION — deliberately DEFERRED to the isolated CI runner,
  with justification (the coordinator's sanctioned fallback):
    1. NON-DIAGNOSTIC LOCALLY. On this interactive macOS machine, background OS
       processes (mds/Spotlight/Finder) issue spontaneous FUSE ops on ~/CipherBox
       that drain the publish queue REGARDLESS of the pump — which is exactly why
       the prior session's local Part A PASSED without any pump and only the
       isolated CI runner (no Finder/Spotlight, test goes silent) failed. I cannot
       guarantee true idleness here, so a local "idle" PASS would not prove the
       pump did the work (it would be confounded by OS ops), and I cannot force
       FUSE-T to defer release like the loaded CI runner does. A live local run
       therefore cannot cleanly isolate the backstop.
    2. THE POKE MECHANISM IS ALREADY VALIDATED. Fix 2's probe (a stat/lookup
       through the mount) is the SAME class of op as Fix 1's nudge() and as every
       existing desktop-e2e re-resolution nudge — all of which are proven to reach
       our handlers through FUSE-T across the passing suite. The probe differs
       only by (a) originating on a background thread (transparent to FUSE-T) and
       (b) using a fresh, never-seen name (strictly MORE cache-proof than an
       existing-path stat). So "the probe reaches handle_lookup" rests on the same
       evidence that validates the whole suite.
    3. THE DRAIN CONTRACT IS PROVEN DETERMINISTICALLY offline by the 3 new
       publish_queue_backstop_tests (one drain past debounce/valve flushes; within
       debounce does not).
  Residual risk owned by CI: whether macOS smbfs serves a fresh-unique-name
  negative lookup from a directory-enumeration cache without a server round-trip
  (believed no; unique names miss the cache). If it ever did, Fix 1's nudge still
  greens D-16 deterministically, and Fix 2 is harmless defense-in-depth. The
  isolated CI-macOS desktop-e2e leg is the end-to-end arbiter (coordinator will
  dispatch).
files_changed:
  - "tests/desktop-e2e/scripts/shared-scope-exit-rotation.mts (Fix 1: pollFindChild
     nudgePaths param + nudge each iteration; two file-under-folder call sites pass
     the folder path)"
  - "apps/desktop/src-tauri/src/fuse/mod.rs (Fix 2: PUBLISH_PUMP_INTERVAL_SECS +
     fuse-publish-pump background thread; mount thread flips the shared
     Arc<AtomicBool> false when mount2 returns)"
  - "crates/fuse/src/fs.rs (Fix 2 regression: publish_queue_backstop_tests, 3 tests)"

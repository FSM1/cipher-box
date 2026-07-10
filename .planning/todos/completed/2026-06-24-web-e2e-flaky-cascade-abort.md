---
created: 2026-06-24
title: Stabilize flaky web-e2e suite (cascade-abort ordering)
area: tests/web-e2e
files:
  - tests/web-e2e/playwright.config.ts
  - tests/web-e2e/tests/invite-link-workflow.spec.ts
  - tests/web-e2e/tests/journey-timing.spec.ts
  - tests/web-e2e/tests/media-preview.spec.ts
---

> NOTE: The desktop-e2e macOS cross-client-**content**-sync leg of this todo
> (Test 5) is RESOLVED in PR #558 — see the "DONE" section at the bottom. The
> remaining actionable work here is the web-e2e cascade-abort below.

## Problem

The `tests/web-e2e` Playwright suite runs `workers: 1`, `fullyParallel: false`,
`retries: 0`, and aborts after a small number of failures. Because tests execute
sequentially in (alphabetical) file order, a flake in an *early* file skips every
later test as "did not run", so a single flaky test fails the whole suite and
hides the status of everything after it.

Observed flaky tests (intermittent, **pre-existing** — they predate Phase 60;
the pre-Phase-60 run 28043695361 failed on `media-preview` + `sharing-workflow`
1.1 account creation):

- `invite-link-workflow.spec.ts:157` — `1.1 Create test accounts (Alice, Dave, Eve)` (account-creation setup)
- `journey-timing.spec.ts:94` — `Journey 1: login-to-vault` (timing-sensitive)
- `media-preview.spec.ts:54` — `upload media fixtures`

Surfaced while shipping Phase 60 (PR #555): across three web-e2e dispatches the
failing test differed each run (writable-shares once it had a real bug, then
media-preview, then invite-link + journey-timing), and because `writable-shares`
sorts last it was repeatedly skipped — making it impossible to confirm a fix from
CI alone (had to run the spec locally to verify). Not merge-blocking: web-e2e is
not a required PR check (it only auto-runs on main push when web paths change).

## Solution

TBD — options, smallest-first:

1. Add a small `retries` count (e.g. 1-2) for known-flaky specs, or globally, so a
   single transient failure does not fail + truncate the run.
2. Stabilize the account-creation flow (`1.1 Create test accounts` in
   invite-link-workflow / sharing-workflow) — the Web3Auth mock login + first-publish
   timing is the most common flake source.
3. De-couple ordering so one early flake does not skip the rest (raise/remove the
   max-failures cap in CI, or shard independent specs), so a flaky test reports only
   itself rather than masking the whole tail.
4. Make `journey-timing` assertions tolerant of CI scheduling jitter (timing budgets).

Keep `retries: 0` philosophy in spirit (fix flakiness at the source) but stop a
single flake from masking unrelated coverage.

## RESOLVED 2026-06-25: macOS cross-client sync is a FUSE-T SMB-cache platform limit

CORRECTION: PR #558 (`mark_remotely_edited_files_unresolved`) was a real hardening
of the gated re-resolution path and it DOES engage — but it does NOT fix this flake.
The flake recurred on `main` AFTER #558 merged (run 28177924106, same Test 5
signature). The original "fixed by #558" claim was wrong.

True root cause (definitively pinned via a live local FUSE-T mount under
`RUST_LOG=debug` + a focused repro loop): the desktop's FUSE layer is CORRECT — on a
remote edit it detects the `modified_at` change and re-resolves the FilePointer to
the new CID within ~5s (logged: `DIAG: FilePointer ino N re-resolved to cid <newCid>
(size ..)`), via EITHER the non-gated `populate_folder` path OR #558's gated
`mark_remotely_edited_files_unresolved` path. The failure is entirely above FUSE: the
**macOS SMB client caches the file content and never re-calls FUSE `open`** for the
duration (~17 `cat`s, zero `open: ino=N`), serving the stale read. The mount is
`nonotification` and FUSE-T's SMB backend does **not** honor a FUSE `inval_inode`
reverse-notification — verified by an explicit experiment (refactored `mount2` →
`Session` + `Notifier`, called `inval_inode(ino,0,0)` after every re-resolution; the
log confirmed `inval_inode sent` immediately post-resolve, yet the SMB client STILL
served stale for 95s). So there is no reliable FUSE-side fix; the SMB cache TTL is
variable and intermittently exceeds the 120s budget (~15% on CI).

Resolution: **macOS-optional stopgap on Test 5** (`test-cross-client-sync.sh`),
mirroring the Test 7 rename leg — warn+pass on Darwin, still fail on Linux; the
`.ps1` (Windows) still enforces. #558 stays in as legitimate hardening (it correctly
re-resolves during a local-publish window and is the only unit-testable part).

Test 7 folder RENAME was already macOS-optional and fails for the SAME SMB cache
reason (the directory variant). Not separately actionable. A genuine fix for either
leg would require a FUSE-T/macOS-SMB change we don't control (e.g. SMB client cache
TTL tuning via mount options or `/etc/nsmb.conf`), tracked here if it ever matters.

Original analysis (kept for history — note its "gated branch" root-cause was only a
partial/secondary factor; the dominant cause is the SMB client cache above):

`tests/desktop-e2e/scripts/test-cross-client-sync.sh:194` —
`FUSE mount still shows original content after 120s` — flakes on **macOS only**
(Linux + Windows pass). Root cause is FUSE-T's SMB backend caching (noted in
`test-round-trip.sh:125`) stacked on the 30s IPNS poll: the test allows 120s
("two full polling cycles", line 172) for a cross-client write to surface in the
other client's FUSE mount, and on macOS the SMB cache occasionally exceeds that
window. The folder-rename leg is already marked "optional on macOS" for the same
reason (it warns instead of failing); the content-sync leg is not.

Evidence it is a flake, not a regression (PR #555 full CI E2E dispatch, run
28112732258 on commit 1f8f8d85d): the same macOS job PASSED on the immediately
prior full dispatch (run 28105996601, commit 88f096505), and `git diff
88f096505..1f8f8d85d` shows the ONLY Rust change is inside `crates/api-client/src/ipns.rs`
`mod tests` (skew boundary tests) — zero production-code delta in any path the
desktop binary exercises. macOS desktop also shows intermittent failures on `main`
history independent of this branch.

PROVEN pre-existing, NOT a Phase 60 regression (4-agent root-cause, high confidence):

Base rate (macOS desktop job, where it actually ran — dispatch-gated skips excluded):
- **main: ~15% fail on THIS test** — runs 28043695361 (job 83016343633) AND 27905000292
  (job 82572035159) both fail with the exact `Test 5 ... still shows original content
  after 120s` signature, BEFORE Phase 60. (2 other main macOS fails were a different
  ESM-loader infra break, not this test.) The rest pass (e.g. 28063779741 ALL PASSED).
- branch (1f8f8d85d): 1 fail / 3 pass across dispatches (28112732258 fail; 28105996601,
  28117194839, 28119647095 pass). Overlaps main's rate — no clear worsening.

Real root cause (`crates/fuse/src/fs.rs:392`, `drain_refresh_completions`):
```
if self.mutated_folders.contains_key(&ino) || self.publish_queue.contains_key(&ino) {
    self.metadata_cache.set(&ipns_name, metadata.clone(), cid);
    continue;  // caches remote edit but SKIPS populate_folder + the unresolved-
               // FilePointer resolve spawn that would fetch the new content
}
```
When the desktop is concurrently publishing its OWN changes (root ino sits in
`mutated_folders`/`publish_queue`, 30s retention), a refresh carrying the remote edit
takes this cache-only branch, so the per-file re-resolution is never spawned. The FUSE
read path only *polls* (`poll.rs:40` → NotInFlight unless a prior spawn inserted the ino;
`read_ops.rs:532` never spawns), so the file never re-resolves → original content for
120s → FAIL. It is timing-dependent (does the desktop's own publish window overlap the
remote-edit refresh?), hence flaky, and macOS runner timing makes the overlap likelier.

Decisively NOT Phase 60: `git diff origin/main...HEAD -- crates/fuse/src/fs.rs` = 4 ins /
13 del (ONLY re-pointing the resolve call to `cipherbox_api_client::ipns::resolve_ipns_verified`);
`inode.rs`/`read_ops.rs`/`poll.rs` are untouched. In the failing log `resolve_ipns_verified`
is NEVER called for the stuck file (no resolve / verify / 404 / success line for it — the
only 404 is an unrelated freshly-mkdir'd folder), so the strict-verify cutover cannot have
caused it. And the per-file record IS strict-verifiable (the SDK harness reports
`contentVerified:true` pre- and post-edit), ruling out a Phase 60 publish-side defect.
The `baseChildren ... union fallback` warning nearby is unrelated benign noise (present in
passing runs too).

Fix (separate desktop/FUSE PR — touches the delicate mutated_folders / folder-state-desync
logic, so NOT bundled into the IPNS verify cutover): in the cache-only `continue` branch,
still enqueue the parent's unresolved FilePointers for resolution (or defer a re-drain)
instead of dropping the remote-edit re-resolution, WITHOUT clobbering pending local
mutations with stale remote state (the reason the gate exists — see
[[project-web-sdk-folder-state-desync]]). Must pass SDK E2E + desktop E2E (all platforms).
A timeout bump is NOT a fix (the failure is a suppressed spawn, not slowness). The sibling
folder-rename leg is already "optional/warn on macOS"; making the content-sync leg the same
is only a test-hygiene stopgap, not the real fix.

## Resolution

RESOLVED. PR #593 (`chore(ci): parallelize web-e2e across files`, commit
a130ea5dd) moved Playwright to file-level parallelism (`workers=3` on CI, was 1)
with each spec file isolated by its own wallet identity — a flake in one file no
longer skips later files, and no `maxFailures` cap is set, so there is no
truncating cascade-abort. This delivers the todo's Solution option 3 (decouple
ordering / shard independent specs). The desktop Test 5 leg was already
self-marked resolved (macOS-optional stopgap, tracked separately under the
FUSE-T cross-client-sync todo).

Retired 2026-07-11 via pending-todo triage.

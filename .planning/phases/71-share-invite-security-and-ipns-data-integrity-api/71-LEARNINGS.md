# Phase 71 — Learnings

Share-invite authorization + IPNS data-integrity API, plus the full share-plane "descriptor"→"encrypted-key" rename. Mined from the 9 plan summaries, VERIFICATION/VALIDATION/SECURITY reports, and the ship cycle (4-wave worktree execution, live D-06 backstop, SDK E2E gate, CodeRabbit CLI + Greptile PR review on PR #599).

## Decisions

### Ownership gate reads ipns_records creator marker, not the vault
D-01 was amended mid-planning from a vault-backed ownership check to an `ipns_records`
`(ipnsName, userId)` creator-marker lookup on both `createInvite` and `createShare` (403 on
miss). It is explicitly non-authoritative defense-in-depth atop the cryptographic ceiling (a
sharer can only wrap keys they hold); `rootNodeId` stays client-asserted (D-02 residual). The
planning docs (CONTEXT/PATTERNS/SECURITY) still carry stale vault language — the CODE is the
source of truth.

### Greenfield: fold the CHECK into the cutover migration, don't add a forward migration
D-04's `claim_count` CHECK was edited INLINE into `1750000000000-ApiSchemaCutover.ts` (and
the root-uniqueness index dropped, D-03) because milestone v2.0 is a greenfield cutover not yet
applied to any live DB. Valid only under that assumption — documented as such.

### Same-seq CID equivocation is a hard 400, but a lost CAS race is a 409
D-05 rejects a same-sequence republish carrying a different CID (equivocation). The refinement
below (stale-write-key + forward-CAS) shows the guard must be conditioned on client intent, not
just `embeddedSeq === dbSeq`.

## Lessons

### The SDK E2E gate caught a real D-05 regression the unit suite structurally cannot
71-04's new same-seq equivocation guard (400) misclassified a legitimate concurrent-add-during-
rotation republish as equivocation: the rotation engine embeds `seq === dbSeq` after a
concurrent writer advances the row, and the guard rejected it 400 where the engine expects a
409 (CAS) it merges. The apps/api Jest suite mocks the DataSource and passed; only the live
sdk-e2e `rotation-crash-safety` concurrent-add case exposed it. Fix: a forward-publish CAS
attempt that lost the race carries `expectedSequenceNumber === embeddedSeq - 1` — classify that
as a 409 (fall through to the CAS UPDATE), reserve the 400 for genuine same-seq republishes.
Equivocation protection is preserved (the write still never lands). **Always run the live
sdk-e2e gate when a phase touches IPNS publish/CAS/sequence handling.**

### A greenfield DB reset wipes tee_key_state — tee-republish failures are collateral, not regressions
Resetting the local `cipherbox` DB to apply the greenfield cutover (needed for the D-06 live
Test 21) wiped `tee_key_state`, so the sdk-e2e `tee-republish` suite failed ("tee_key_state is
empty"). The file is unchanged and phase 71 touches no TEE code — environmental, not a
regression. Restoring it is a TEE-worker auth/epoch exercise (matching `TEE_WORKER_SECRET`,
repopulate on init), deferred as a todo.

### Verify against the merged tree, not raw LSP diagnostics
71-03 (Rust rename) surfaced E0560 diagnostics on `delete.rs`/`rename.rs` from an intermediate
worktree state (task 1 renamed the struct before task 2 finished call sites). The committed +
merged tree compiled clean under `cargo check --all-targets`. Trust the merged-tree gate, not
mid-flight editor diagnostics or the agent's self-report — check both.

### Greptile catches auth-logic gaps the other gates miss
Greptile's single P1 (stale write key after a generation-bump re-claim) was a real correctness
bug in the widen-only merge: a gen-bump on an already-write-capable share via a write-capable
invite advanced read key + generation but left `encryptedWriteKey` at the old generation. Fixed
by broadening the write-key refresh guard to `(isWriteUpgrade || (isGenerationBump &&
inviteGrantsWrite)) && dto.encryptedWriteKey`, still presence-gated so a read-only re-claim
never nulls a write grant.

## Patterns

### 4-wave worktree execution with baseRef=head keeps parallelism across waves
Nine plans ran as 4 dependency-ordered waves in parallel git worktrees. With `worktree.baseRef`
effectively `head`, each wave forks from the live post-merge HEAD, so no inter-wave degrade to
sequential — parallel isolation held for all 4 waves.

### Running a live sdk-e2e test from an executor worktree needs env priming
The worktree lacked gitignored `.env` files (copy them in), vitest doesn't auto-load `.env`
(pass `SDK_E2E_SECRET` inline, aligned to the API's `TEST_LOGIN_SECRET`), and the `:3000` API
was a stale `node dist/main.js` build (rebuild + restart from current code or get a false
result). Captured as a reusable recipe.

## Surprises

### CodeRabbit's PR-review check went "skipping"; the CLI review was the coverage
The `CodeRabbit / Review` check transitioned pending→skipping and posted no PR-level review
body/threads. The local `coderabbit review --agent --base main` CLI pass (10 findings) was the
actual CodeRabbit coverage this cycle; Greptile was the live PR reviewer.

### Squash-merge-only makes commit-subject parens a non-issue
The repo is squash-merge-only with `squash_merge_commit_title: PR_TITLE`, so all commit subjects
collapse into the PR title on merge. The commitlint `subject-no-parens` rule (and the ship-phase
reword step) only matter for the PR title — individual commit subjects never reach main, so no
`git filter-branch` reword was needed.

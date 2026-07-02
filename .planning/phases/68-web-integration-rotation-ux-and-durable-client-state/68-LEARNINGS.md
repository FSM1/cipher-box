---
phase: 68
phase_name: "web-integration-rotation-ux-and-durable-client-state"
project: "CipherBox"
generated: "2026-07-02"
counts:
  decisions: 8
  lessons: 7
  patterns: 8
  surprises: 7
missing_artifacts:
  - "68-UAT.md"
---

# Phase 68 Learnings: web-integration-rotation-ux-and-durable-client-state

## Decisions

### Hoist anti-rollback logic to the SDK tier; web owns only a thin adapter

The durable high-water state machine and fail-closed `enforceResolved` gate live in `packages/sdk` (Vitest-tested), not in a web module; the concrete IndexedDB `HighWaterStore` is a thin, untested adapter deferred to 68-06.

**Rationale:** Per docs/TESTING.md, apps/web is NOT unit-tested — logic must live where it can be unit-proven, with the web layer covered only by web-e2e.
**Source:** 68-01-PLAN.md

---

### Doctrine correction: no fake-indexeddb shim, zero apps/web unit tests

The initial plan set's IndexedDB test-env shim was explicitly removed. Durable-store behavior is proven by real IndexedDB in web-e2e (a "persists across reload" claim MUST be a real browser reload — in-memory-map unit tests are rejected as "in-memory only"), and the pure logic is proven in the SDK over an injected map. SC#5 gates that `find apps/web/src -name "*.spec.ts"` stays empty.

**Rationale:** Splitting proof by tier (SDK unit for logic, web-e2e for durability/UI) removes the need for a browser-API shim entirely and keeps the web app a thin adapter.
**Source:** 68-VALIDATION.md

---

### enforceResolved is a pure pass/throw pre-unseal gate, generation checked before seq

`enforceResolved` returns `Promise<void>` — pure pass/throw, never emitting an AAD/unseal parameter (the high-water floor must never feed `unsealChildReadKey`'s AAD, which is sourced separately from the parent mirror). A resolve regressing on both dimensions reports `GenerationRegressionError`, not `SequenceRegressionError`.

**Rationale:** Conflating the anti-rollback floor with unseal AAD would be a cryptographic misuse (T-68-15/T-68-65); the generation check is the higher-severity M1 cross-generation defense so it must not be masked by the seq check.
**Source:** 68-01-PLAN.md, 68-01-SUMMARY.md

---

### D-04 reconcile-before-publish: defer, never skip

Every rotation-triggering mutation re-resolves the target folder's network `sequenceNumber` and compares against the in-memory `folderTree`; ANY mismatch (either direction) throws a distinguishable `ReconcileStaleError` and publishes nothing.

**Rationale:** Closes the #489/#494 silent-missed-revocation class — a deferred rotation is recoverable, a silently skipped one is not.
**Source:** 68-05-PLAN.md, 68-05-SUMMARY.md

---

### D-08 degraded high-water stores latch permanently to in-memory floors

Once IndexedDB fails, a high-water store commits to the in-memory session-floor Map for the rest of the session rather than retrying IndexedDB per call.

**Rationale:** Mixing IDB-backed and memory-backed reads for the same logical floor would let the monotonic-max guarantee silently split across two disagreeing backends.
**Source:** 68-06-SUMMARY.md

---

### Fail-closed gate injected as optional client config, sourced from the reader mirror

68-11 added `rotationHighWater?` to `CipherBoxClientConfig` (defaulting to zero enforcement when absent, matching the `rotationCallbacks` pattern) and gated `reconcileFolderSequence` through `enforceResolved`. The `generation` parameter comes from the in-memory `folderTree.nodeGeneration ?? 0` — never the freshly-resolved envelope's own generation — and the gate call sits lexically outside the resolve try/catch.

**Rationale:** The resolved value is attacker-controlled, so enforcement params must come from the reader's expected state; placing the call outside the try/catch ensures regression errors propagate to the D-05 classifier instead of being swallowed as transient network errors; the optional seam keeps the gate additive/backward-compatible for unconfigured consumers.
**Source:** 68-11-SUMMARY.md, 68-11-PLAN.md

---

### T-68-12-02 zeroization: terminal owner zeroes, callee never zeroes caller-owned buffers

`rotateReadFromNode` does NOT zero the returned `readKey` — the caller (`performScopeExitRotation`) becomes the terminal owner (D-09). The folderTree refresh zeroes the OLD `folderKey` only AFTER the `Map.set()` swap and only post-flight (after `rotateReadFromNode` has fully returned), copies the rotated key defensively via `new Uint8Array(...)`, and never zeroes `rotationResult.readKey` nor the caller-supplied `rootReadKey` mid-flight.

**Rationale:** Zeroing a reused/caller-owned buffer mid-flight is the same failure class that previously broke 48/89 sdk-e2e tests; only the terminal owner of a buffer may zero it.
**Source:** 68-12-SUMMARY.md, 68-12-PLAN.md

---

### D-12 moveItem publishes destination before source

`moveItem` publishes the destination folder update BEFORE the source (folding the Phase-64 OUT-tagged `sdk-client-move-publish-durability` work), and scope-exit rotation targets the SOURCE folder only — entering the destination is a scope entry that never needs rotation.

**Rationale:** A crash between the two publishes never orphans the moved node out of both folders; the existing FLAG-63-U2 re-seal already re-keys the moved node for the destination.
**Source:** 68-05-PLAN.md, 68-05-SUMMARY.md

---

## Lessons

### The ROT-07 fail-closed gate was built but unreachable from any live UI path

Plans 68-01..68-10 built and unit-proved the entire anti-rollback mechanism, yet verification found it inert as a live system property (initial score 12/14, Gap 1 = BLOCKER): all ~15 apps/web `resolveIpnsRecord()` call sites passed only `ipnsName`, and the SDK's own `reconcileFolderSequence` called `sdkCore.resolveIpnsRecord` directly, bypassing even the web `enforceResolved` wrapper. 68-11 closed it by gating the real chokepoint.

**Context:** Mechanism-level truth ("the gate exists and its tests pass") is not the same as system-property truth ("a relay regression during a real user mutation fails closed") — only verification framed as an operative system property caught this.
**Source:** 68-VERIFICATION.md, 68-10-SUMMARY.md, 68-11-PLAN.md

---

### The named wiring target was dead code; the real chokepoint was elsewhere

The original VERIFICATION named `ensureFolderLoaded` as the correct wiring target for the gate, but it is a dead phase-63 stub that unconditionally throws `not implemented`. The substantively correct fix was routing through `reconcileFolderSequence` — the method genuinely invoked by all 4 revocation-triggering mutations (`renameItem`/`moveItem`/`deleteItem`/`deleteToBin`) before every publish.

**Context:** Gap-closure plans must re-verify that the verification-named integration point is actually live, not just cited; substituting the real chokepoint was confirmed as an upgrade, not a downgrade.
**Source:** 68-VERIFICATION.md, 68-11-SUMMARY.md

---

### Scope-exit rotation left folderTree stale — fail-safe but unrecoverable without reload

`performScopeExitRotation` re-sealed/republished the root under a new readKey and bumped generation/sequence but never updated `this.folderTree`, so every same-session second mutation on that folder threw `ReconcileStaleError` permanently; manual Retry re-read the same stale state and failed identically. Root cause: `rotateReadFromNode` returned `void`, discarding the root's post-rotation state. 68-12 widened the return to `RotateReadResult | undefined` and wrote it back.

**Context:** Verification Gap 2 (should-fix). A fail-closed design can still be a DoS-of-guarantee if the failure loop has no self-heal path (T-68-12-03).
**Source:** 68-12-PLAN.md, 68-12-SUMMARY.md, 68-VERIFICATION.md

---

### Authoring the e2e specs is what exposed the systemic wiring gap

68-10's spec-writing investigation established that the inertness was systemic, not a single edge case: the D-05 sequence/generation-regression gate had no live producer (corroborating 68-09's flagged D-01 `CannotWriteUntilRefetchError` gap, whose trigger is a documented Phase-66 mock seam — `publishNodeFn` never returns `{tombstoned: true}`). The specs were redesigned around the confirmed gap, documented in-spec, rather than writing UI-driven tests that could never pass.

**Context:** E2E test authoring doubles as an integration audit — it forces tracing the full production call chain and surfaces "classifier-ready but never triggered" code.
**Source:** 68-10-SUMMARY.md, 68-09-SUMMARY.md

---

### Fresh worktrees repeatedly broke on cross-package dist staleness

Multiple plans (68-01, 68-03, 68-04, 68-07, 68-09, 68-10) independently hit `Cannot find module '@cipherbox/api-client'`/`@cipherbox/crypto` failures because fresh worktrees had no `node_modules` or built `dist/` for workspace deps; each required `pnpm i` plus dependency-ordered rebuilds before `tsc --noEmit` could run. 68-07 additionally hit a cwd drift into the shared main-repo checkout, recovered via `git rev-parse --show-toplevel`.

**Context:** A known project gotcha that still cost time in nearly every executor worktree — worth front-loading the install/build into worktree setup.
**Source:** 68-01-SUMMARY.md, 68-03-SUMMARY.md, 68-04-SUMMARY.md, 68-07-SUMMARY.md, 68-09-SUMMARY.md

---

### Wiring a resolve into every mutation broke unrelated test mocks via live-network fall-through

Once `reconcileFolderSequence` called `sdkCore.resolveIpnsRecord` on every mutation, two unrelated test files (`client.test.ts`, `collect-subtree-ipns-names.test.ts`) that spread `{...actual}` without overriding it fell through to the REAL implementation attempting a live call to `http://localhost:3000`. Fixed by adding `resolveIpnsRecord: vi.fn()` to both mocks.

**Context:** Adding a network call to a hot internal chokepoint changes the mock surface of every existing test that partially mocks the module — spread-actual mocks silently invoke real implementations for newly-used symbols.
**Source:** 68-05-SUMMARY.md

---

### FolderTree has no parent-link tracking, so ancestor grant coverage goes undetected

`nodeAncestorIpnsNames` passed to `maybeRotateOnScopeExit` contains only the directly-mutated node's own IPNS name(s), not a leaf-to-root chain — a grant rooted at a grandparent folder is not detected by the scope-exit wiring. Extending FolderTree with parent tracking was explicitly deferred.

**Context:** Known limitation documented during 68-05 execution; multi-level coverage detection needs a data-structure change, not just wiring.
**Source:** 68-05-SUMMARY.md

---

## Patterns

### Monotonic-max floor with fail-closed validation of stored values

`bumpFloor` is read-then-compare-then-conditional-put (never writes a value lower than the current floor, order-independent across tabs); the V5 guard (`isValidFloorValue`) treats malformed stored values (negative, non-integer, NaN) as absent, never coercing them to a low floor.

**When to use:** Any durable anti-rollback / high-water floor fed by untrusted-on-read storage.
**Source:** 68-01-SUMMARY.md, 68-06-SUMMARY.md

---

### Injected store seam with no in-instance cache to prove persistence at the logic tier

Every read/write in the high-water state machine goes through the injected `HighWaterStore` (get/put), so a fresh instance over the same backing store observes prior state — restart/persistence semantics are provable in Vitest with no browser API.

**When to use:** Unit-proving the durability semantics of a state machine whose concrete storage is a browser API.
**Source:** 68-01-PLAN.md, 68-01-SUMMARY.md

---

### navigator.locks leader election with a correctness-preserving fallback

`withTailWalkLeader` acquires `navigator.locks.request(..., { mode: 'exclusive' }, fn)` so one tab drives the rotation tail walk; when Web Locks is unavailable it runs `fn` directly. The fallback is NOT a degraded mode but correctness-preserving, because the walk is idempotent (D-09 checkpointing + CAS-409 re-merge makes a double-run safe). First use of the Web Locks API in this project.

**When to use:** Multi-tab coordination of idempotent background work — make the work idempotent first, then the lock is an optimization, not a correctness dependency.
**Source:** 68-08-PLAN.md, 68-08-SUMMARY.md

---

### Non-literal dynamic import() to drive real app modules in Playwright

`page.evaluate` + dynamic `import()` of a NON-literal path variable loads real app source through the Vite dev server's module graph — same singleton instances the app uses, real IndexedDB, real reload. Assign the path to a `const` first: TypeScript only attempts static module resolution for string-literal `import()` specifiers.

**When to use:** E2E-proving shipped modules that (temporarily) have no live UI trigger, instead of writing a UI-driven test that can never pass.
**Source:** 68-10-SUMMARY.md

---

### HTTP capture/replay against mock-ipns-routing to simulate a colluding relay

Direct Node-side HTTP GET/PUT against the mock-ipns-routing service (bypassing the API and CORS) captures real signed IPNS record bytes, republishes a genuinely higher sequence via a real UI mutation, then replays the stale bytes and asserts fail-closed rejection.

**When to use:** Proving rejection of a rolled-back record with real signed bytes rather than fabricated ones (T-68-101).
**Source:** 68-10-SUMMARY.md

---

### Single failure-UX classification hook wrapped at the innermost SDK call site

`runWithFailureUx` wraps only the direct `client.X()`/`resolveIpnsRecord()` call (not the surrounding handler), so bounded-backoff retries re-invoke just the network-facing call and inherit the SDK's fresh reconcile check each attempt; handlers that delegate to already-wrapped callbacks are not wrapped a second time, avoiding duplicate toasts.

**When to use:** Multiple mutation entry points sharing one fail-closed error surface with retry + toast policy.
**Source:** 68-09-SUMMARY.md

---

### Injected-transport driver seam: SDK owns branch logic, web supplies calls

The owner-reconcile driver lives in `packages/sdk` behind an injected `OwnerReconcileTransport`, unit-tested with `vi.fn()`; `apps/web` supplies only concrete api-client calls with no branch logic (mirrors the rotation engine's `GrantRemintCallbacks` pattern).

**When to use:** Keeping decision logic at the unit-testable SDK tier when the web app must stay a thin, untested adapter.
**Source:** 68-07-PLAN.md, 68-07-SUMMARY.md

---

### Prove an additive return-type widening backward-compatible via three combined checks

68-12's `void → RotateReadResult | undefined` widening was proven safe by: full-repo grep for all call sites, a `tsc -b --force` error-count diff before/after (via `git stash`), and updating the one pre-existing test whose assertion encoded the OLD contract.

**When to use:** Widening a return type consumed by many await-and-ignore callers.
**Source:** 68-12-SUMMARY.md

---

## Surprises

### A planned e2e spec flow had NO production call site

68-10's plan described observing the durable floor gate reject a relay-served stale record — but exhaustive grep confirmed `ipns.service.ts#resolveIpnsRecord`'s optional `rotation` parameter was defined yet never passed by any of the ~10 web call sites (`useFileBrowserActions.ts`'s own comment said "once a rotation context is threaded through here").

**Impact:** Both specs were redesigned around the confirmed gap (module-graph-driven, gap documented in-spec); the finding escalated into verification Gap 1 (BLOCKER) and spawned gap-closure plans 68-11/68-12.
**Source:** 68-10-SUMMARY.md, 68-VERIFICATION.md

---

### TypeScript statically resolves string-literal dynamic import() specifiers

`await import('/src/services/ipns.service.ts')` as a literal made `tsc` attempt static module resolution against a tsconfig with no knowledge of apps/web's tree, failing TS2307; assigning the path to a local `const` first skips resolution with unchanged runtime behavior.

**Impact:** One auto-fixed deviation in 68-10; without the fix the web-e2e typecheck gate could not pass.
**Source:** 68-10-SUMMARY.md

---

### RenameDialog does not close on a failed rename, forcing a two-rename spec redesign

68-11's SC#4 proof needed a mutation AFTER the stale-bytes replay; reading `RenameDialog.tsx` confirmed the dialog stays open on failure, so the spec drives form fields directly (`clearAndEnterName` + `clickSave`) instead of the `.rename()` helper for the rejection step, using two real UI renames (seed + bump, then rejected rename).

**Impact:** The SC#4 durability proof became genuinely UI-driven, and the stale "NO production call site" scope note was removed from the spec.
**Source:** 68-11-SUMMARY.md

---

### SDK barrel exports blocked the planned web-side error classification

`ReconcileStaleError` and `CannotWriteUntilRefetchError` were not re-exported from the `@cipherbox/sdk` barrel, so apps/web could not `instanceof`-classify them at all; 68-08 similarly found `RotationClientCallbacks`/`LocalGrantRecord` had existed in `types.ts` since 68-05 without being re-exported.

**Impact:** Two Rule-3 blocking deviations requiring additive barrel exports before the plans' specified wiring was even possible — SDK types are not consumable until exported.
**Source:** 68-09-SUMMARY.md, 68-08-SUMMARY.md

---

### The approved UI-SPEC was internally inconsistent on badge colors

The Copywriting Contract table said tail-walk uses a "green border," but the Color table explicitly assigned `--color-warning` as the "rotation-tail badge accent." Resolved in favor of the Color table (warning-accent static pill for tail-walk/resuming, green + spinner only for root-cut).

**Impact:** Executors must resolve intra-document spec conflicts explicitly; flagged for the post-wave UI safety gate as an inconsistency in the source document itself.
**Source:** 68-04-SUMMARY.md

---

### The badge phase signal had to be inferred from persistJob cadence, not progress

The SDK only calls `progress` once (`'rotated'`) at full completion and has no "root cut about to start" hook, so the driver treats the FIRST non-terminal `persistJob` call per rootNodeId as root-cut and subsequent calls as tail-walk, with `progress` wired defensively for forward-compat.

**Impact:** UI lifecycle states were derived from a persistence side-channel rather than a purpose-built callback — an unplanned inference the driver now depends on.
**Source:** 68-08-SUMMARY.md

---

### The Gap-2 closure took 4 minutes, but a pre-existing assertion encoded the old contract

68-12 completed in ~4 min (vs 25 min for 68-11). One pre-existing `engine.test.ts` assertion (`.resolves.toBeUndefined()`) encoded the OLD void-return contract and had to flip to `.toBeDefined()`; the skip-path RED test necessarily passed pre-implementation since `void === undefined`, which did not weaken the RED proof.

**Impact:** Return-contract changes can invert existing green tests; TDD RED phases over `undefined`-returning functions need care that "passes before implementation" is expected, not a broken test.
**Source:** 68-12-SUMMARY.md, STATE.md

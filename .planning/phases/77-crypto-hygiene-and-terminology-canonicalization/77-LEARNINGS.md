---
phase: 77
phase_name: "crypto-hygiene-and-terminology-canonicalization"
project: "CipherBox"
generated: "2026-07-11"
counts:
  decisions: 5
  lessons: 6
  patterns: 5
  surprises: 4
missing_artifacts:
  - "77-UAT.md"
---

## Decisions

### Copy the codec verbatim, never rewrite it

When hoisting the canonical base64 codec into `@cipherbox/crypto`, the `CHUNK_SIZE = 32768` chunked-`btoa` loop was copied byte-for-byte out of `packages/core/src/node/encode.ts` rather than reimplemented. A rewrite — even a "cleaner" one — risks a subtly different output (padding, chunk boundary, surrogate handling) that would silently corrupt every already-persisted sealed node when consumers switch over.

**Rationale:** A dedup that changes even one output byte is a data-corruption bug, not a refactor. A verbatim copy guarantees byte-identical output against every existing duplicate before any consumer is migrated, and lets a golden-vector test stand as the parity oracle. **Source:** 77-01-SUMMARY.md

---

### Extract the shared authorization gate as a plain function, not an @Injectable

The duplicated Phase-71 root-ownership check was consolidated into `assertRootOwnership(ipnsRecordRepo, ipnsName, userId)` — a plain exported async function that takes the already-injected repository as a parameter — instead of a new `@Injectable()` service. Both call sites (`shares.service.ts`, `share-invite.service.ts`) already inject `ipnsRecordRepo`, so passing it in avoided any new DI/module wiring.

**Rationale:** For a small, stateless, duplicated gate whose only dependency is a repo the callers already hold, a plain function is the lower-ceremony extraction — no provider registration, no module edits, no test-harness DI changes. Reserve `@Injectable` for units that actually need the container. **Source:** 77-04-SUMMARY.md

---

### Push the hex/bytes boundary out to the call sites, keep crypto helpers bytes-only

`wrapIpnsKeyForTee` was changed from `(ipnsPrivateKey, currentPublicKey: string) => Promise<string>` to `(ipnsPrivateKey, teePublicKey: Uint8Array) => Promise<Uint8Array>`. All hex encode/decode moved out to the 3 callers (`registration.ts`, `vault/index.ts`, `file/index.ts`), which hex-decode the TEE pubkey immediately before the call and hex-encode the result immediately after.

**Rationale:** Keeping crypto primitives on `Uint8Array` and confining hex to the wire/DTO boundary means a malformed key fails at `hexToBytes` (fail-fast, before any crypto op), not deep inside `wrapKey`. It also removes the last reason for the helper to know about its transport encoding. **Source:** 77-05-SUMMARY.md

---

### Use a secp256k1 keypair for the TEE-wrap round-trip test

The plan's `read_first` note suggested `generateEd25519Keypair` for the `wrapIpnsKeyForTee` round-trip test, but the test was written with a `@noble/secp256k1` keypair instead — matching the real TEE worker's key type and `packages/crypto`'s own `ecies.test.ts`.

**Rationale:** `wrapKey`/`unwrapKey` are ECIES over secp256k1; a TEE public key is a secp256k1 point, not an Ed25519/IPNS-identity key. An Ed25519 keypair simply would not round-trip through the ECIES primitives, so the test keypair type must match the algorithm, not the surrounding IPNS-identity context. **Source:** 77-05-SUMMARY.md

---

### Import the shared codec directly, no intermediate re-export barrel

The rotation/share consumers (`rotation/engine.ts`, `share/grant.ts`, `share/navigate.ts`) import `bytesToBase64`/`base64ToBytes` directly from `@cipherbox/crypto` rather than through a new `share/codec.ts` re-export. This matches the existing `hexToBytes`/`bytesToHex` import convention already in those files.

**Rationale:** An intermediate re-export adds a second name to keep in sync and a second place to mock, with no benefit when the shared package is the canonical home. Match the import convention already established for sibling primitives. **Source:** 77-08-SUMMARY.md

---

## Lessons

### Guard error-path zeroization from allocation, not from first use

Two independent instances of the same bug surfaced in ship review: `createSubfolder`'s TEE-wrap block (`hexToBytes`/`wrapIpnsKeyForTee`) sat outside the `try`, so a throw in `hexToBytes` on a malformed TEE pubkey leaked the 3 freshly-minted keys; and `scripts/verify-filepointer.mts` allocated `userPrivateKey` before the `try`, so a throw during `loadVaultKeyBlob` skipped the `finally`. Both were fixed by hoisting the `try` to open at the point the keys are minted. The analogous `file/index.ts` path already did it correctly.

**Context:** When you add error-path cleanup, the `try` must open where the sensitive buffer is *allocated*, not merely around the IPFS/vault side-effects that are the "interesting" work. Any throw between allocation and the `try` opening skips the cleanup and leaks the key. Grep for allocation sites, not just the obviously-fallible calls. **Source:** ship-phase review

---

### `processed=0` plus zero worker calls means the tee-republish e2e failure is scheduling-layer, not wire-contract

sdk-e2e ran 105/106; the one miss was `tee-republish` Test A (`waitFor` timeout). It was root-caused as orthogonal to the phase: the republish batch logged `processed=0` and the TEE worker received *zero* `/republish` calls — a local `makeScheduleDue`-vs-enrollment-commit scheduling race — so the renamed wire field `encryptedIpnsPrivateKey` was never exercised at all. The rename's real decode+re-sign contract is instead proven by the tee-worker unit suite (76 pass, real `decryptWithFallback`) and the api specs.

**Context:** For any TEE-republish e2e failure, check the batch's `processed` count and whether the worker got a call *before* suspecting your change. `processed=0` + no worker call is a decisive signal that the batch found no due schedule row — the failure is in the scheduling/enrollment layer and never reached the wire payload. Don't debug a wire-contract change against a test that never sends the wire message. **Source:** ship-phase review

---

### Grep-scoped acceptance criteria expand a symbol rename into a whole-file (or whole-tree) rename

Multiple plans named a single symbol to rename but had acceptance criteria of the form "grep for the old token → 0 matches" scoped to a whole file or the whole `src` tree. This forced renaming `decryptWithFallback`'s param alongside `decryptIpnsKey`'s (77-03), removing `SharedFolderState.addShareKeysFn` alongside `SharedWriteContext.addShareKeysFn` (77-06), and rewording prose doc comments that merely named the dead symbol (77-05, 77-06).

**Context:** When a plan's acceptance is a grep over a file/tree, treat the *entire grep scope* as the unit of work, not just the symbol the action text names. Sweep the whole scope (including sibling params, source-of-truth fields, and doc-comment prose) or the acceptance grep will fail late, after you thought the task was done. **Source:** 77-03-SUMMARY.md, 77-06-SUMMARY.md

---

### Web Crypto `importKey`'s algorithm param is `AlgorithmIdentifier`, not `AesKeyAlgorithm`

The shared `importAesKey` helper was first typed with `AesKeyAlgorithm | string` per the plan; this broke the build with 7 `tsc` errors because `AesKeyAlgorithm` requires a `length` field, while every call site passes only `{ name: 'AES-GCM' }` / `{ name: 'AES-CTR' }`. The correct type is `AlgorithmIdentifier` (`string | Algorithm`, where `Algorithm = { name: string }`).

**Context:** `AesKeyAlgorithm` (with `length`) describes key *generation*, not key *import*. `crypto.subtle.importKey` accepts the looser `AlgorithmIdentifier`. Use `AlgorithmIdentifier` for any shared import-key wrapper so existing `{ name }`-only call sites typecheck unchanged. **Source:** 77-02-SUMMARY.md

---

### A negative assertion must be renamed or deleted along with the field it guards, or it silently stops proving anything

`republish.service.spec.ts` had 4 `.not.toHaveProperty('encryptedIpnsKey')` assertions proving the schedule row omits the wrapped key; left on the stale name they would pass vacuously after the rename. Similarly, 77-06 *deleted* the now-meaningless `.not.toHaveBeenCalled()` mock assertions for removed callbacks rather than leaving stale coverage.

**Context:** Negative assertions (`not.toHaveProperty`, `not.toHaveBeenCalled`) fail open — once the referenced symbol no longer exists, they pass for the wrong reason. On any rename, update them to the canonical name; on any removal, delete them. Never leave a negative assertion pointing at a name that no longer exists. **Source:** 77-03-SUMMARY.md, 77-06-SUMMARY.md

---

### A full-replacement `vi.mock('@cipherbox/crypto', ...)` breaks the moment a consumer imports a new export from that module

When `engine.ts`/`grant.ts`/`navigate.ts` began importing `bytesToBase64`/`base64ToBytes` from the mocked `@cipherbox/crypto`, four test files that fully replace the module (`() => ({ ...only the fns they mocked })`) failed with `No "base64ToBytes" export is defined on the mock`. The fix was converting each to the `async (importOriginal) => ({ ...actual, <mocked fns> })` pattern. A related gap slipped between sibling plans: 77-08 rewired a consumer but didn't patch `owner-reconcile.test.ts`'s mock, so 77-09 hit the failure when it ran the full sdk suite.

**Context:** Full-object `vi.mock` factories are brittle against new imports — any consumer that starts importing an un-mocked pure helper from the module breaks. Prefer `importOriginal` + spread so real pure helpers (codecs) keep running while only the intended functions are mocked. After rewiring a consumer onto a shared module, grep for *every* test that mocks that module, not just the ones in your plan's `files_modified`. **Source:** 77-08-SUMMARY.md, 77-09-SUMMARY.md

---

## Patterns

### Golden-vector known-vector pair as the byte-parity oracle for codec dedup

Every base64/codec consolidation in this phase was gated by a hardcoded `(bytes, base64String)` known-vector pair plus round-trip cases (empty, 1-byte, a 40000-byte input crossing the 32768 chunk boundary). The full-seal `node-codec-vectors.test.ts` golden vectors were re-run after each consumer switched over.

**When to use:** Any time you replace N copy-pasted encode/decode implementations with one shared primitive. A hardcoded input→output vector (not just a round-trip) proves the *new* code produces the *same bytes the old code produced* — a round-trip alone would pass even if both directions drifted together. Make the vector the acceptance gate before migrating any consumer. **Source:** 77-01-SUMMARY.md, 77-07-SUMMARY.md

---

### Terminal-owner zeroization (D-09): a callee zeroes only its own local copy, never the caller's buffer

`importAesKey` allocates a local `keyView`, calls `crypto.subtle.importKey` in a `try`, and `keyView.fill(0)`s in a `finally` — while the caller's `key` argument is read once for the copy and never mutated. The same borrow-vs-own discipline governs `wrapIpnsKeyForTee` (borrows `ipnsPrivateKey`, never zeroes it) and `createSubfolder` (zeroes its *minted* keys on error, but the success path does NOT zero because the caller is the terminal owner).

**When to use:** Whenever a helper receives a caller-owned sensitive buffer. Zero only buffers you allocated; leave borrowed arguments untouched. Zeroing a borrowed/reused buffer previously broke 48/89 E2E — the "does NOT zero on success return" test is the guard that keeps that regression class closed. **Source:** 77-02-SUMMARY.md, 77-SECURITY.md

---

### Atomic sender+receiver wire rename in a single commit

The TEE republish field `encryptedIpnsKey → encryptedIpnsPrivateKey` was renamed across the API relay (`tee.service.ts`, `republish.service.ts`), the tee-worker request body and decode call, and both sides' params — all in one commit — so the wire contract never disagreed between relay and worker at any commit boundary.

**When to use:** For any field rename that crosses a serialization boundary between two independently-deployable components, change both sides in the same commit. A rename that lands one side first leaves the wrapped payload undecryptable in the interim; there is no safe intermediate state to bisect to. **Source:** 77-03-SUMMARY.md

---

### Bytes-internal / hex-at-boundary for crypto seams

Crypto helpers accept and return `Uint8Array`; hex encode/decode lives only at the wire/DTO call sites. Applied to the TEE-wrap seam: hex-decode `teeKeys.currentPublicKey` immediately before `wrapIpnsKeyForTee`, hex-encode the returned bytes immediately before assigning to `encryptedIpnsPrivateKey`.

**When to use:** Any crypto primitive that currently takes or returns hex strings. Moving hex to the boundary makes malformed input fail at `hexToBytes` (fail-fast) before any crypto runs, keeps the primitive transport-agnostic and reusable, and removes redundant encode/decode round-trips inside the hot path. **Source:** 77-05-SUMMARY.md

---

### Thin local wrapper preserving a superset signature over a shared primitive

`decode.ts` kept its `base64ToUint8Array(b64, expectedLength?)` name and superset signature, but its body now delegates to the shared `base64ToBytes(b64)` — retaining only the decode-specific `expectedLength` length assertion that the shared primitive doesn't (and shouldn't) have.

**When to use:** When deduping onto a shared primitive but one call site needs extra validation or a broader signature. Keep a thin local wrapper that adds only the site-specific concern and delegates the core work — you get the dedup without pushing a niche validation into the shared helper or losing it. **Source:** 77-07-SUMMARY.md

---

## Surprises

### The tee-republish e2e miss never exercised the phase's change at all

The single sdk-e2e non-pass (`tee-republish` Test A timeout) looked like it might implicate the renamed wire field — but the batch logged `processed=0` and the TEE worker got zero `/republish` calls, so the renamed `encryptedIpnsPrivateKey` payload was never sent. It reproduced identically on a clean truncated DB, confirming a local scheduling race (`makeScheduleDue` vs enrollment commit), not state pollution and not the phase's rename.

**Impact:** A failing e2e in the same subsystem you touched can be entirely orthogonal to your change. Before assuming causation, confirm your changed code path actually ran — here, `processed=0` proved it didn't. The rename was validated by the tee-worker unit suite (real `decryptWithFallback`) and api specs instead, and the flake deferred to the CI sdk-e2e gate with its clean stack. **Source:** 77-VALIDATION.md, ship-phase review

---

### A sibling plan's mock gap only surfaced when a later plan ran the full suite

77-08 rewired `rotation/engine.ts`'s `reMintGrantsRootedAt` to call the hoisted `bytesToBase64`, but did not patch `owner-reconcile.test.ts`'s `@cipherbox/crypto` mock (that file wasn't in 77-08's `files_modified`). The break stayed latent until 77-09 ran the full `pnpm --filter @cipherbox/sdk test` gate and hit `No "bytesToBase64" export is defined on the mock`.

**Impact:** Parallel/sibling plans that share a mocked module can leave latent test-infra gaps that per-plan scoped test runs miss. The blast radius of "consumer now imports a new symbol from a mocked module" extends to every test that mocks that module across the package — run the *full* package suite, not just the touched files' tests, after such a rewire. **Source:** 77-09-SUMMARY.md

---

### The plan's suggested test keypair type was cryptographically wrong

The plan's `read_first` note pointed at `generateEd25519Keypair` for the TEE-wrap round-trip test, but ECIES `wrapKey`/`unwrapKey` operate on secp256k1 — an Ed25519 keypair would not round-trip at all. The correct type came from cross-checking the real TEE worker's key derivation and `packages/crypto`'s existing `ecies.test.ts`.

**Impact:** Plan `read_first` hints can carry a domain error (conflating the IPNS-identity key type with the ECIES key type). Verify a suggested test fixture against the actual algorithm and the nearest existing test in the same crypto family before trusting it. **Source:** 77-05-SUMMARY.md

---

### The "discarded per-upload ECIES wrapKey" was already gone

Todo #11 (drop the discarded per-upload ECIES `wrapKey` of `fileKey`) turned out to require no code change — an audit of all 10 `wrapKey(` call sites across sdk-core/sdk found every result flows to a persisted or returned field, and the one historically-discarded call had already been retired under READ-03, documented by a comment in `upload/index.ts`.

**Impact:** Not every hygiene todo maps to a live defect; some were resolved by earlier work and just never closed. Before implementing a cleanup, audit whether it's already done — a call-site sweep can turn a planned change into a verification-only task and save the churn. **Source:** 77-06-SUMMARY.md

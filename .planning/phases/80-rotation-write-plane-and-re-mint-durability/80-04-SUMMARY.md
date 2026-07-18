---
phase: 80-rotation-write-plane-and-re-mint-durability
plan: 04
subsystem: api
tags: [sharing, recipient-pins, write-body, ipns, cas, node-codec, secp256k1]

# Dependency graph
requires:
  - phase: 80-01
    provides: "NodeWriteBody.recipientPins (TS) / recipient_pins (Rust) codec field with round-trip encode/decode"
provides:
  - "assertRecipientPinned / appendRecipientPin / extractRecipientPins pure helpers (sdk-core/share/recipient-pins.ts)"
  - "updateFolderMetadataAndPublish preserves + unions recipientPins across folder updates and CAS-409 merges"
  - "client.addRecipientPubkeyPin(itemIpnsName, recipientPublicKey) issuance write path"
  - "client.getRecipientPubkeyPins(itemIpnsName) enforcement read path"
  - "getWriteBodyParams surfaces recipientPins so routine folder updates preserve them"
affects: [80-06, 80-07, 80-08]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Owner-sealed recipient-pin list as the server-opaque cross-device re-mint trust anchor"
    - "Monotonic dedup-union of pins across a CAS-409 (never pruned, unlike write-chain entries)"
    - "Both-sides raw-byte normalization (Uint8Array / hex / base64) before pin compare"

key-files:
  created:
    - packages/sdk-core/src/share/recipient-pins.ts
    - packages/sdk-core/src/__tests__/share/recipient-pins.test.ts
  modified:
    - packages/sdk-core/src/share/index.ts
    - packages/sdk-core/src/index.ts
    - packages/sdk-core/src/folder/registration.ts
    - packages/sdk/src/client.ts
    - packages/sdk/src/write-body-params.ts

key-decisions:
  - "Pins are a monotonic UNION on CAS-409 (a pin is a permanent trust anchor, never pruned) — distinct from the base-aware write-chain prune"
  - "getWriteBodyParams surfaces recipientPins so ALL client folder updates thread current pins through and preserve them on clean publishes (closes T-80-11 generically, not just for the issuance path)"
  - "Client wrappers take a 2-arg (itemIpnsName, recipientPublicKey) signature and operate on a folder the client tracks as a FolderState — its own writeKey/ipnsKeypair seal its write-body"

patterns-established:
  - "Pure pin helpers own the D-03d compare semantics; the three enforcement consumers (80-06/07/08) verify against them"
  - "encodeWriteBody omits an empty recipientPins list so the frozen empty-pin KAT is byte-preserved"

requirements-completed:
  - "SC2 / D-03a: store the issuance-time recipient pubkey in the shared root node's owner-sealed NodeWriteBody (server-opaque, cross-device)"
  - "SC2 / D-03c: at grant creation, append the pasted recipient pubkey to the node's write-body pin list and republish"

coverage:
  - id: D1
    description: "assertRecipientPinned throws on empty/absent pin list (D-03e) and non-member; returns void on a raw-byte match; normalizes hex/base64/bytes"
    requirement: "SC2 / D-03a"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/share/recipient-pins.test.ts#assertRecipientPinned"
        status: pass
    human_judgment: false
  - id: D2
    description: "appendRecipientPin dedups by raw bytes across encodings; extractRecipientPins defaults to []"
    requirement: "SC2 / D-03c"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/share/recipient-pins.test.ts#appendRecipientPin / extractRecipientPins"
        status: pass
    human_judgment: false
  - id: D3
    description: "updateFolderMetadataAndPublish seals recipientPins and unions local ∪ remote pins across a CAS-409 (T-80-11 durability)"
    requirement: "SC2 / D-03a"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/share/recipient-pins.test.ts#recipientPins durability (T-80-11)"
        status: pass
    human_judgment: false
  - id: D4
    description: "Write→read round-trip at the sdk-core seal boundary: append pin → seal → unseal → extract returns the pin"
    requirement: "SC2 / D-03c"
    verification:
      - kind: unit
        ref: "packages/sdk-core/src/__tests__/share/recipient-pins.test.ts#write→read round-trip"
        status: pass
    human_judgment: false
  - id: D5
    description: "client.addRecipientPubkeyPin (issuance write, generation unchanged) + client.getRecipientPubkeyPins (raw-byte read)"
    requirement: "SC2 / D-03c"
    verification:
      - kind: other
        ref: "pnpm --filter @cipherbox/sdk typecheck (thin wrappers over sdk-core helpers; sdk-core cannot import sdk, so runtime is proxied by the D4 seal-boundary round-trip)"
        status: pass
    human_judgment: false

# Metrics
duration: 9min
completed: 2026-07-12
status: complete
---

# Phase 80 Plan 04: Recipient-Pin Storage and Issuance Write Path Summary

**Owner-sealed `NodeWriteBody.recipientPins` machinery — pure compare/append/extract helpers, pin-preserving folder publish with CAS-409 union, and `client.addRecipientPubkeyPin`/`getRecipientPubkeyPins` wrappers — the server-opaque cross-device trust anchor for D-03d re-mint enforcement.**

## Performance

- **Duration:** ~9 min
- **Started:** 2026-07-12T20:11:00Z
- **Completed:** 2026-07-12T20:20:00Z
- **Tasks:** 3
- **Files modified:** 5 (2 created, 3+2 modified)

## Accomplishments
- Pure helpers `assertRecipientPinned` / `appendRecipientPin` / `extractRecipientPins` — `assertRecipientPinned` fails closed on an empty/absent pin list (D-03e no-legacy) and on a non-member, normalizing both sides to raw pubkey bytes.
- `updateFolderMetadataAndPublish` gains an optional `recipientPins` param, threaded into the sealed write-body and unioned with the remote write-body's pins on a CAS-409 merge — pins are never silently dropped (T-80-11).
- `client.addRecipientPubkeyPin` resolves the item, appends the recipient pin (dedup), and CAS-republishes at the UNCHANGED node generation (sequenceNumber advances); `client.getRecipientPubkeyPins` reads the pin list back as raw bytes for enforcement.
- `getWriteBodyParams` now surfaces `recipientPins`, so every routine client folder update threads current pins through the publish and preserves them on clean publishes.

## Task Commits

Each task was committed atomically:

1. **Task 1: RED tests** - `7d4a1f5e8` (test)
2. **Task 2: GREEN helpers + pin-preserving publish** - `5dc6ffd21` (feat)
3. **Task 3: GREEN client wrappers** - `4ef3fd2f7` (feat)

_Note: this is a `type: tdd` plan — RED (`test`) precedes GREEN (`feat`) in git history._

## Files Created/Modified
- `packages/sdk-core/src/share/recipient-pins.ts` - pure pin helpers + raw-byte normalization (created)
- `packages/sdk-core/src/__tests__/share/recipient-pins.test.ts` - helper + durability + round-trip tests (created)
- `packages/sdk-core/src/share/index.ts` - export the three helpers + `RecipientPubkey`
- `packages/sdk-core/src/index.ts` - re-export helpers from the sdk-core barrel
- `packages/sdk-core/src/folder/registration.ts` - thread `recipientPins` into the seal + CAS-409 union
- `packages/sdk/src/client.ts` - `addRecipientPubkeyPin` / `getRecipientPubkeyPins` wrappers
- `packages/sdk/src/write-body-params.ts` - surface `recipientPins` from the write-body

## Decisions Made
- **Pins union, never prune, on CAS-409.** A recipient pin is a permanent trust anchor, so the merge is a plain dedup-union of local ∪ remote (reusing `appendRecipientPin`), unlike the base-aware write-chain prune that honors deletes.
- **`getWriteBodyParams` surfaces `recipientPins`.** This makes preservation generic: every client folder-update call site that spreads `...writeBodyParams` now threads the current pins through, so a routine rename/move/add never drops them on a clean publish — not only the issuance path.
- **2-arg client signature operating on a tracked folder.** The plan's `addRecipientPubkeyPin(itemIpnsName, recipientPublicKey)` signature carries no parent, so the item is treated as a folder the client tracks (its own `FolderState` supplies the writeKey + IPNS signing key to seal its write-body). Fails closed when the item is not write-capable.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Extended `getWriteBodyParams` to return `recipientPins`**
- **Found during:** Task 3 (client wrappers)
- **Issue:** The client wrappers must read the item's CURRENT pins to append/union, but `getWriteBodyParams` returned only `{ writeKey, writeChildren }` — there was no way to read the pins without a second resolve+unseal.
- **Fix:** Added an additive optional `recipientPins?: string[]` to `getWriteBodyParams`'s return (sourced from the metadata mirror or the on-wire unseal), plus the matching private-delegate return type in `client.ts`. Beneficial side effect: all existing update call sites that spread `...writeBodyParams` now preserve pins generically (T-80-11).
- **Files modified:** packages/sdk/src/write-body-params.ts, packages/sdk/src/client.ts
- **Verification:** `pnpm --filter @cipherbox/sdk typecheck` passes; additive optional field, no wire change (empty list omitted by `encodeWriteBody`).
- **Committed in:** `4ef3fd2f7` (Task 3 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** The extension is additive and required to satisfy the plan's own key_link ("unseals its current write-body ... appends the pin"). No scope creep; no API/DB change.

## Issues Encountered
- The `@cipherbox/sdk` typecheck reads `@cipherbox/sdk-core`'s built dist, so `@cipherbox/core` and `@cipherbox/sdk-core` dists were rebuilt after adding the new exports/param before the sdk typecheck (documented setup step). No source issues.
- The write→read round-trip is authored at the sdk-core seal boundary (append → `updateFolderMetadataAndPublish` → `unsealNode` → `extractRecipientPins`) because sdk-core cannot import `@cipherbox/sdk`; the thin client wrappers delegate to exactly this path and are covered by `@cipherbox/sdk` typecheck.

## Prohibitions honored
- Node generation is NEVER bumped and no pin-generation counter was added — the pin rides inside the existing role-0x01 write-body seal at the current generation; only the IPNS `sequenceNumber` increments.
- `resolveShareEncryptedWriteKey` is unchanged (no pin write bolted onto the writeKey-derivation path — Pitfall 4).
- No API/DTO change and no `pnpm api:generate`; no DB migration (D-03f) — the pin is client-side owner-sealed only.
- No `deny_unknown_fields` / forward-tolerance regressions; empty pin list stays off the wire.

## Verification
- `pnpm --filter @cipherbox/sdk-core test recipient-pins` — 17 passed (17).
- `pnpm --filter @cipherbox/sdk-core typecheck` — pass.
- `pnpm --filter @cipherbox/sdk typecheck` — pass.
- No `packages/api-client/` changes.

## Next Phase Readiness
- Pin storage + issuance write + enforcement read are ready for the D-03d consumers: 80-06 (Rust re-mint compare), 80-07 (TS `reMintGrantsRootedAt` compare), 80-08 (web ShareDialog issuance wiring).
- The pure `assertRecipientPinned` is the shared compare semantics those consumers mirror (Rust reads via its own InodeTable path but matches the empty/absent hard-fail).

---
*Phase: 80-rotation-write-plane-and-re-mint-durability*
*Completed: 2026-07-12*

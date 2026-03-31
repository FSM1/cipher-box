# Phase 38: Retire deprecated web services - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-03-31
**Phase:** 38-retire-deprecated-web-services
**Areas discussed:** Caller migration pattern, Utility function placement, Circular dep fix approach

---

## Caller migration pattern

| Option              | Description                                                                                            | Selected |
| ------------------- | ------------------------------------------------------------------------------------------------------ | -------- |
| Direct replacement  | Each hook extracts needed state from Zustand, passes explicitly to SDK methods. No intermediate layer. |          |
| Thin adapter module | Create a web-app-specific adapter that wraps SDK methods with store access.                            |          |
| You decide          | Claude picks the best approach during planning.                                                        |          |
| Other (user input)  | Follow established patterns in the other services that were migrated to the SDK                        | ✓        |

**User's choice:** Follow established patterns from existing SDK-migrated hooks (e.g., useSharedWriteOps.ts)
**Notes:** User directed to follow the pattern already established in hooks like useSharedWriteOps.ts — import SDK functions directly, pass store-extracted state as explicit params.

### Follow-up: Barrel file cleanup

| Option                      | Description                                                             | Selected |
| --------------------------- | ----------------------------------------------------------------------- | -------- |
| Remove both + update barrel | Delete the two files and remove their re-exports from services/index.ts | ✓        |
| You decide                  | Claude determines the cleanest approach                                 |          |

**User's choice:** Remove both + update barrel
**Notes:** Other services remain untouched.

---

## Utility function placement

| Option                | Description                                                                      | Selected |
| --------------------- | -------------------------------------------------------------------------------- | -------- |
| Move to SDK packages  | Path utilities to @cipherbox/sdk-core, fetchAndDecryptMetadata to @cipherbox/sdk | ✓        |
| Local web app helpers | Create utils/folder-utils.ts in the web app                                      |          |
| You decide            | Claude determines best placement per function                                    |          |

**User's choice:** Move to SDK packages
**Notes:** Keep web app thin. Path utilities are domain logic belonging in sdk-core.

---

## Circular dep fix approach

| Option                      | Description                                                                           | Selected |
| --------------------------- | ------------------------------------------------------------------------------------- | -------- |
| Hardcoded test vectors      | Pre-compute expected values, embed as constants. Test verifies against static values. | ✓        |
| Inline the derivation logic | Copy minimal derivation code into test file.                                          |          |
| You decide                  | Claude picks the cleanest approach.                                                   |          |

**User's choice:** Hardcoded test vectors
**Notes:** Roadmap already specified this approach. Pre-compute from deriveRegistryIpnsKeypair/initializeVault, embed as constants.

---

## Claude's Discretion

- Per-hook migration order and grouping
- Whether to batch all caller migrations in one plan or split by service
- Exact test vector values

## Deferred Ideas

None — discussion stayed within phase scope

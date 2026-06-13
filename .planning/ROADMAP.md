### Phase 44: IPNS conflict handling

**Goal:** Stop lost updates on concurrent IPNS writes in `packages/sdk-core`: on 409, re-fetch remote folder metadata and merge (children union, per-entry reconcile) before republishing, and extend CAS coverage to file records; full CRDT model explicitly deferred to the CRDT-inbox research todo
**Requirements:** Todo `2026-06-11-ipns-409-retry-lost-update` (discuss-phase: confirm whether the Rust SDK CAS-publish path has the same lost-update pattern)
**Depends on:** Phase 41
**Plans:** 7/7 plans complete
Plans:
**Wave 1**

- [x] 44-01-PLAN.md — Pure building blocks: mergeChildren three-way merge + ConflictError (TDD, wave 1)

**Wave 2** *(blocked on Wave 1 completion)*

- [x] 44-02-PLAN.md — Folder 4-attempt merge-and-republish retry loop wiring (wave 2)
- [x] 44-03-PLAN.md — File CAS publish + latest-wins loser-becomes-version + maxVersionsPerFile (TDD, wave 2)

**Wave 3** *(blocked on Wave 2 completion)*

- [x] 44-04-PLAN.md — SDK-package caller sweep: client.ts, bin, shared-write baseChildren (wave 3)
- [x] 44-05-PLAN.md — Web hooks caller sweep + file CAS rewire; D-09 no Rust (wave 3)

**Wave 4** *(gap closure — CR-01/CR-02 from 44-VERIFICATION.md)*

- [x] 44-06-PLAN.md — CR-01: return publishedChildren + adopt merged set in all SDK/web callers; WR-08 folder test (gap closure, wave 4)
- [x] 44-07-PLAN.md — CR-02: filter file prunedCids against published references; WR-08 file test (gap closure, wave 4)

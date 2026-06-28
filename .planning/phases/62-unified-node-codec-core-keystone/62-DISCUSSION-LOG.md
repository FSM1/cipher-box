# Phase 62: Unified Node Codec (Core Keystone) - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-28
**Phase:** 62-unified-node-codec-core-keystone
**Areas discussed:** Phase-62 boundary, CI gate, Node golden-vector freeze, Vault blob v3, packages/core layout, METADATA_SCHEMAS scope, Numeric types

---

## Gray-area selection (round 1)

Offered: Phase-62 boundary, Sealed-body wire format, Node golden-vector freeze, Vault blob v3.
**Selected:** Phase-62 boundary, Node golden-vector freeze, Vault blob v3.
**Not selected → defaulted:** Sealed-body wire format → JSON (status quo; AAD provides integrity; serde-friendly for Phase-69 Rust). Captured as D-03.

---

## Phase-62 boundary

| Option | Description | Selected |
|--------|-------------|----------|
| Codec full, consumers stubbed | Codec fully implemented + tested; consumers compile-only with `throw 'not implemented — phase NN'`; app non-runnable mid-milestone | ✓ |
| Port straightforward paths too | Also port 1:1 read/encode/decode paths now; fewer stubs but a bigger phase that bleeds into 63 | |

**User's choice:** Codec full, consumers stubbed (D-01).
**Notes:** App intentionally non-runnable between 62 and ~68 is acceptable under greenfield; no phase-63–69 behavior pulled forward.

---

## CI gate (broken consumer suites + coverage)

| Option | Description | Selected |
|--------|-------------|----------|
| Quarantine + gate on typecheck | `describe.skip` + `TODO(phase NN)`; gate on typecheck + lint + new codec tests; relax coverage floor on stubbed packages | ✓ |
| Delete retired tests outright | Hard-delete retired tests; owning phases rewrite fresh | |
| Keep all suites green | Adapt every broken test to assert its stub throws | |

**User's choice:** Quarantine + gate on typecheck (D-02).
**Notes:** Quarantined suites are the spec the owning phase revives — not deleted.

---

## Node golden-vector freeze

| Option | Description | Selected |
|--------|-------------|----------|
| Freeze now, body-bytes + envelope | All three kinds; decoded-Node → body bytes (primary) + fixed-IV full-envelope vector + vault v3 blob; TS-asserts now, Rust slots in at 69 | ✓ |
| Freeze body-bytes only | Just the plaintext-body-bytes vectors; defer full-seal parity to 69 | |
| Defer to Phase 69 | No freeze in 62 | |

**User's choice:** Freeze now, body-bytes + envelope (D-04).
**Notes:** Freeze-first discipline carried from Phase 61.

---

## Vault blob v3 (NODE-06)

| Option | Description | Selected |
|--------|-------------|----------|
| v3 two-key, hard-cut | `0x03 \| u16(readLen) \| ecies(readKey) \| u16(writeLen) \| ecies(writeKey)`; delete v1/v2 paths; refresh vectors | ✓ |
| v3 two-key, keep v2 reader | Same layout but keep the v2 reader for read-back compat (dead code under greenfield) | |

**User's choice:** v3 two-key, hard-cut (D-05).
**Notes:** No prod/staging data exists to read back; v2 reader would be dead code.

---

## Gray-area selection (round 2)

Offered: Codec API & zeroization, packages/core layout, METADATA_SCHEMAS scope, Numeric types.
**Selected:** packages/core layout, METADATA_SCHEMAS scope, Numeric types.
**Not selected → defaulted:** Codec API & zeroization → decode returns caller-owned key material; codec never zeros a caller-owned/reused buffer (terminal-owner principle). Captured as D-09.

---

## packages/core layout

| Option | Description | Selected |
|--------|-------------|----------|
| New src/node/, retire folder+file | `src/node/` with named codec files; retire `folder/`+`file/`; adapt `registry/`+`bin/types.ts`; keep `ipns/`; `vault/` keeps v3 blob | ✓ |
| Single src/node/ module | Fewer files (`types.ts` + `codec.ts`); fatter codec.ts | |

**User's choice:** New src/node/, retire folder+file (D-06).

---

## METADATA_SCHEMAS scope (SC#6)

| Option | Description | Selected |
|--------|-------------|----------|
| Static schema + 2 invariants | Full static node/v3 schema + generation-witness + fileKey-in-sealed-body; defer flow docs to 63–69 | ✓ |
| Schema + flows now | Also document navigation/rotation/write-revocation flows now (risks drift) | |

**User's choice:** Static schema + 2 invariants (D-07).

---

## Numeric types

| Option | Description | Selected |
|--------|-------------|----------|
| gen=number, floor/seq=bigint | `generation` as `number` (u32-safe); `versionFloor`/seq as `bigint` (IPNS convention) | ✓ |
| All bigint | `generation` as `bigint` too, for uniformity | |

**User's choice:** gen=number, floor/seq=bigint (D-08).

---

## Claude's Discretion

- Golden-vector input values, fixture file name(s), generated-vs-hand-frozen.
- Error type names, codec helper factoring, stub call-site typing.
- `encryptionMode` string-literal union mechanics, `registry/`+`bin/types.ts` adaptation specifics.

## Deferred Ideas

- Consumer behavioral rewiring → phases 63–69; Rust `Node` enum → 69; flow docs → owning phases.
- Open questions Q1/Q2/Q3 (co-writer offline, rotation host, write-recipient deletions) → phases 68 / 63 / 65–69.
- Reviewed-not-folded todos: IPNS Validity vector lockstep/parity, AAD UUID parity, AES-helper zeroization (crypto/IPNS-layer follow-ups, not the Node codec).

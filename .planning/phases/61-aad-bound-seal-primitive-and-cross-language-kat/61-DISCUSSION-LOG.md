# Phase 61: AAD-Bound Seal Primitive and Cross-Language KAT - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-06-27
**Phase:** 61-aad-bound-seal-primitive-and-cross-language-kat
**Areas discussed:** Open technical gray areas (declined in favor of defaults), Documentation scope

---

## Pre-discussion finding: encoding already frozen

The v2.0 milestone research (`.planning/research/ARCHITECTURE.md` §4.3, `PITFALLS.md` Pitfall 1) had **already frozen** the full `buildNodeAad` byte encoding, the seal blob layout, the KAT requirement, and the file locations. Codebase scout confirmed both `@cipherbox/crypto` (TS, Web Crypto) and `cipherbox-crypto` (Rust, `aes-gcm` 0.10) already ship byte-identical `sealAesGcm`/`seal_aes_gcm` with a working cross-language KAT harness — neither uses AAD yet. The discussion therefore focused only on the genuinely-open implementation choices and one user-raised scope addition.

---

## Open technical gray areas (4 presented)

The user **declined to single out** any of the four for deep discussion, signalling acceptance of the recommended defaults. Defaults locked as D-01..D-04 in CONTEXT.md.

| Gray area | Recommended default (locked) | Alternative not taken |
| --- | --- | --- |
| KAT vector rigor | **Both** — AAD-bytes vector (all 4 roles) + fixed-key/fixed-IV full-seal vector | AAD-bytes vector only (research minimum) |
| Transplant-test breadth (CRYPTO-03) | **Extended** — childId/role/generation + kind + domain-version + tamper (flipped tag / truncated blob) | Minimum (childId/role/generation only) |
| `buildNodeAad` validation | **Fail-closed** — reject malformed UUID / out-of-range kind\|role\|generation | Trust-caller |
| UUID → 16-byte parity | **`uuid` crate (Rust) + canonical TS parser**, cross-checked by KAT | Hand-rolled hex parser both sides |

**User's choice:** Took all recommended defaults (no override).
**Notes:** Rationale for each default is recorded in CONTEXT.md D-01..D-04, anchored to TEST-02 ("a byte mismatch is silent total decryption failure") and PITFALLS Pitfall 1 (the UUID-encoding landmine).

---

## Documentation scope (user-raised scope addition)

The user added a requirement via free-text: *"one thing that should be implemented in this phase is updating the docs around metadata and encryption to align with what is being implemented here."*

A boundary clarification was needed because **phase 62's roadmap already claims `METADATA_SCHEMAS.md`** for the full Node-schema rewrite.

| Option | Description | Selected |
| --- | --- | --- |
| ADR 0003 + doc pointers | New `docs/adr/0003-…` freeze + scoped subsections in `METADATA_SCHEMAS.md` §2/§3, `METADATA_EVOLUTION_PROTOCOL.md` §5/§6, one-line `FILESYSTEM_SPECIFICATION.md` note; Node-schema text deferred to phase 62 | ✓ |
| Metadata docs only, no ADR | Frozen encoding straight into `METADATA_SCHEMAS.md` / `METADATA_EVOLUTION_PROTOCOL.md`, no ADR | |
| ADR 0003 freeze only | ADR only, defer all metadata-doc edits to phase 62 | |

**User's choice:** ADR 0003 + doc pointers.
**Notes:** Captured as D-05. The frozen-forever byte encoding gets an authoritative ADR (matching the existing `0001`/`0002` v2.0 crypto ADRs), and the user-named metadata/encryption docs are aligned at the encoding layer without colliding with phase 62's schema rewrite.

---

## Claude's Discretion

- Exact KAT input values (`nodeId`/`key`/`iv`/`plaintext`), the vector JSON file name(s) under `tests/vectors/crypto/`, generated-vs-hand-frozen fixture method, error type names, and helper factoring. (CONTEXT.md "Claude's Discretion".)

## Deferred Ideas

- `FolderMetadata`/`FileMetadata`/`FilePointer` → `Node` **schema** documentation → phase 62 (ROADMAP SC#6).
- Consumer rewiring (FUSE symmetric unwrap, sdk-core sealing, web/desktop) → phases 62–69.
- Reviewed-not-folded todo: `2026-06-24-harden-validity-type-and-vector-expiry-lockstep.md` (IPNS-validity vectors, not crypto-AAD) — noted only as the lockstep discipline the new KAT respects.

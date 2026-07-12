---
created: 2026-07-12T00:00:00.000Z
title: Harden recovery-tool gateway integrity — verify content bytes against the CID and close the unverified IPNS fallback-rung downgrade
area: recovery-tool-crypto
severity: medium
source: Phase 78 crypto-privacy review + CodeRabbit (recovery-src gateway/walk). The v3 recovery tool added rung-1 IPNS signature verification (a strict upgrade over the v2 hand-rolled parser), but two integrity gaps remain in the trust-nothing gateway model. CodeRabbit independently flagged a narrower sub-case of gap 1: once rung 1 has RECEIVED a primary record, a subsequent parse/malformed failure should be terminal (no silent fall-through to the unverified HEAD/Kubo rungs) — fold this into the gap-1 redesign.
files:
  - apps/web/recovery-src/gateway.ts
  - apps/web/recovery-src/walk.ts
resolves_phase: null
---

## Problem

The recovery tool's premise is a trust-nothing, caller-configured HTTP gateway driven only by the user's `privateKey`. Two integrity gaps mean a hostile/faulty gateway can still cause silent data loss or wrong-plaintext during recovery (confidentiality is NOT affected — content stays E2E-encrypted):

1. **Unverified IPNS fallback rungs (forced downgrade).** `resolveIpnsVerified` (`gateway.ts`) verifies the Ed25519 IPNS record signature only on rung 1 (delegated-routing `/routing/v1/ipns/<name>`). Rungs 2 (`/ipns/<name>` HEAD → `X-Ipfs-Roots`) and 3 (Kubo `name/resolve`) return an IPNS→CID mapping with NO signature check. A hostile gateway can 404/5xx rung 1 to force the walk onto an unverified rung and serve a rolled-back (older-but-valid) or truncated/empty CID. Rung 1's signature check is a hard stop only when a body is actually returned and fails verification; a forced fall-through bypasses it. (These rungs exist to match the v2 tool's graceful degradation — a LOCKED design choice — so any change must preserve the "recover even from a degraded gateway" goal, e.g. gate rungs 2/3 behind an explicit opt-in and surface a prominent "UNVERIFIED resolution" warning in the progress log rather than silently trusting them.)

2. **Content not re-hashed against the CID (CTR bodies have no auth tag).** `fetchFromIpfs` (`gateway.ts`) does not verify fetched bytes against the CID multihash. GCM-sealed envelopes and GCM file bodies fail closed on tampering via their auth-tag, but CTR-mode (large-file) bodies carry NO auth tag — so a hostile gateway can bit-flip/replace a CTR body and it decrypts silently to attacker-influenced plaintext. Production tolerates this only because it fetches via a trusted Kubo/API relay that enforces content-addressing; the recovery tool's arbitrary-gateway premise does not.

## Fix

- Add content-addressing verification in `fetchFromIpfs`: decode the CID → multihash (hash-fn code + digest), hash the fetched bytes (sha2-256 for the common case) and compare; throw on mismatch. This fully closes gap 2 (CTR + GCM content tampering) and partially closes gap 1 (attacker-chosen truncated/empty nodes fail the hash), while keeping the tool crypto+core-only (use @noble/hashes sha256 already in the crypto dep; the CID decode is the only new surface — keep it minimal, no `multiformats` runtime dep if avoidable).
- For gap 1's rollback/substitution vector (a valid older signed record served on a downgraded rung), gate rungs 2/3 behind an explicit "allow unverified resolution" opt-in and log a conspicuous per-node UNVERIFIED warning so the recovering user knows integrity was not proven for that subtree. Do NOT silently drop the rungs (they are the graceful-degradation path).

## Context / non-goals

- The comments in `gateway.ts::fetchFromIpfs` and `walk.ts::decryptFileContent` were corrected in Phase 78 to stop claiming AEAD covers all content integrity, and `content.fileKey` is now zeroed after decrypt (terminal-owner parity with the production read chain). This todo is the remaining structural hardening only.
- Confidentiality is unaffected in all cases — content is E2E-encrypted and the gateway never sees plaintext or keys. Impact is data-integrity (rollback / silent corruption / truncation) during last-resort offline recovery on a user-chosen gateway.

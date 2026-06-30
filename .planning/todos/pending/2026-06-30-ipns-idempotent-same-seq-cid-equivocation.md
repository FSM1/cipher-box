---
created: 2026-06-30T00:00:00.000Z
title: Decide whether a same-sequence IPNS republish may change the CID (D-09 idempotent path)
area: data-integrity
severity: medium
files:
  - apps/api/src/ipns/ipns.service.ts
  - apps/api/src/ipns/ipns.service.spec.ts
---

> Deferred from the Phase 66 ship (CodeRabbit major finding, ipns.service.ts:351).
> This targets the PRE-EXISTING D-09 / Pitfall 4 idempotent-republish behavior
> (plan 58-02), which is outside Phase 66's publish-gate/tombstone domain and is
> deliberately exercised by an existing test, so reversing it is a risky design
> change rather than a low-risk in-scope fix.

## Problem

In `upsertIpnsRecord`, when the incoming record's embedded sequence equals the
stored `sequence_number` the publish is treated as an idempotent republish:
the row is NOT advanced, but `latestCid` and `signedRecord` ARE overwritten with
the incoming values. CodeRabbit's concern: a validly-signed record for the SAME
sequence but a DIFFERENT CID can mutate the authoritative `latestCid` without
advancing the sequence (an equivocation/fork).

The current behavior is intentional today: the test
`allows idempotent republish (embedded = DB seq) without incrementing DB sequenceNumber`
(ipns.service.spec.ts ~2022) publishes a NEW CID at the same sequence and asserts
`latestCid` is updated — labelled "latestCid must be updated even on idempotent
re-sign (Pitfall 4)". So this is a documented decision, not an oversight.

## Decision required

Clarify the intended TEE 6-hour re-sign semantics (D-09 / Pitfall 4):

- If the TEE only ever re-signs the SAME content to refresh validity/EOL, then a
  same-sequence publish with a different CID is illegitimate and should be
  rejected with 400 (CodeRabbit's proposal). The idempotent test must then change
  to re-sign the SAME CID, and the renewal e2e test already replays seq=1 (Phase
  66 change), so it is unaffected.
- If a same-sequence re-sign is allowed to point at refreshed metadata by design,
  document WHY overwriting `latestCid` without advancing the sequence is safe
  (and that resolvers will not observe two divergent values for one sequence).

## Proposed fix (only if "reject" is chosen)

```ts
if (embeddedSeq === dbSeq) {
  if (metadataCid !== existing.latestCid) {
    throw new BadRequestException(
      `Idempotent republish must preserve CID for sequence ${dbSeq}`
    );
  }
  isIdempotentRepublish = true;
}
```

Do NOT apply blindly — confirm the TEE re-sign flow first, as it may legitimately
re-point the CID at the same sequence.

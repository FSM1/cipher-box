---
created: 2026-07-04T00:00:00Z
title: Transient IPNS resolve miss in getWriteBodyParams can seal an empty write-body
area: sdk
files:
  - packages/sdk/src/client.ts:669
  - packages/sdk/src/bin/index.ts:72
source: ship-phase 68.1 CodeRabbit finding 17 (deep write-plane verification)
---

## Problem

In BOTH `getWriteBodyParams` copies (client.ts ~669 and bin/index.ts ~72), a
TRANSIENT IPNS resolve miss on an already-write-capable folder returns
`writeChildren: []` (the D-03 fail-open path). If the folder then republishes, it
seals an EMPTY write-body — dropping the entire write chain (every child's
WriteChildRef), not just failing read-only. Distinct from the intended
read-only-device fallback (zero writeKey): here the device HAS the writeKey but a
network blip erased the children list it should have preserved.

This is a documented D-03 fail-open and is identical in both files, so it was NOT
one-sidedly flipped during ship (flipping only the bin copy would diverge the two).
It needs a holistic decision.

## Solution

Decide the fail-open-vs-fail-closed contract for a transient resolve miss when a
real writeKey is present, then apply it to BOTH copies together (or dedupe them —
see [[dedupe-sdk-write-plane-helpers]]). Options: (a) fail-closed — throw/retry
rather than publish an empty write-body when writeKey is present but the resolve
missed; (b) preserve the last-known local writeChildren mirror across a transient
miss (mirrors the 68.1-23 network-refresh preservation). Gate with sdk unit suites
+ a concurrent-operations sdk-e2e run that injects a resolve failure.

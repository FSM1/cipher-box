---
created: 2026-06-30
title: write-chain-rotation e2e identifies rotated seeds by fixed capturedKeys index
area: tests
severity: low
source: CodeRabbit review of phase 65 PR (finding on write-chain-rotation.test.ts:91-99)
---

## Problem

`tests/sdk-e2e/src/suites/write-chain-rotation.test.ts` identifies the new Ed25519 root/child
seeds by fixed `capturedKeys[0]` / `capturedKeys[2]` offsets. `rotateWriteFromNode` can
legitimately emit extra 32-byte random values during survivor write-key re-wrapping (ECIES), so
the fixed offsets are brittle and could mis-identify a seed if the call order shifts.

The suite currently passes (2/2 live), and the deferral was a deliberate triage call: fixing it
safely needs either a `vi.spyOn(generateEd25519Keypair)` to capture the actual rotation seeds, or
direct capture of the publish inputs — risky to change without re-validating against the live IPNS
stack.

## Solution

Spy on `generateEd25519Keypair` (or capture `createAndPublishIpnsRecord` inputs) to identify the
rotated root/child seeds by provenance rather than by `capturedKeys` array offset, then assert the
new k51 names against those. Re-run the live D-04 gate to confirm.

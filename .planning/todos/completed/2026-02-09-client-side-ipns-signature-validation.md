---
created: 2026-02-09T14:30
title: Add client-side IPNS signature validation
area: crypto
files:
  - apps/api/src/ipns/ipns.controller.ts
  - apps/web/src/services/ipns.service.ts
  - apps/web/src/services/folder.service.ts:78-99
  - packages/crypto/src/
---

## Problem

Currently `resolveIpnsRecord` returns only the CID without signature data, and
`fetchAndDecryptMetadata` accepts the decrypted metadata without any signature
verification. This creates a path for metadata tampering if an attacker
intercepts or modifies the metadata on IPFS.

Flagged by CodeRabbit on PR #70. Tracked as GitHub issue #71.

## Solution

1. Backend: include IPNS record signature and signer public key in the resolve response
2. Client: add `verifyIpnsRecordSignature(signature, signerPubKey, cid, sequence)` call
   before passing the CID to `fetchAndDecryptMetadata`
3. If verification fails, throw an error and mark the folder as not loaded
4. Expose/add `verifyEd25519` from `packages/crypto` for IPNS signature validation

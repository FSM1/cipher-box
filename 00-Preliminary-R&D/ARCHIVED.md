# Archived Content

## POC (Proof of Concept)

The `poc/` directory contained the original proof-of-concept implementation for CipherBox's IPFS encryption pipeline. It was a standalone Node.js script that demonstrated:

- ECIES key wrapping
- AES-256-GCM file encryption
- IPFS upload via Kubo HTTP API
- IPNS record creation and publishing

This code was archived in Phase 28 (Code Hygiene & Logging) as it was superseded by the production implementation in `apps/` and `packages/`. The original POC files are preserved in git history prior to this commit.

**Last known location:** `00-Preliminary-R&D/poc/`
**Archived:** 2026-03-28

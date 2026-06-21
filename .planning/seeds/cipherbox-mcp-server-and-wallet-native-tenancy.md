---
title: "CipherBox as an MCP server + wallet-native first-class agent tenancy"
trigger_condition: "The agent wedge is validated (a design partner / first paying agent-consumer identified), OR a cheap demo is needed to put in front of design partners. The MCP + auth-convenience parts are cheap enough to build as enablers ahead of full validation; the x402 settlement adapter waits on proven agent-payment demand."
planted_date: 2026-06-22
source: "Exploration session 2026-06-22 (see notes/next-milestone-agent-native-zk-storage.md)."
---

## Idea

Expose the existing headless ZK substrate to AI agents through the channel agents
actually consume — an **MCP server** — with a thin wallet-native auth convenience and
an **optional** x402 settlement adapter. The agent brings its own wallet; CipherBox
builds no key custody.

## Why it's cheap (verified against apps/api)

- The SDK (`CipherBoxClient`) is already **key-injected and headless** — same code path
  the desktop FUSE crate and SDK E2E exercise. An agent holding 32 bytes of secp256k1
  can drive the full vault today.
- Auth already supports a production wallet path: `/auth/identity/wallet` (SIWE) →
  `/auth/login`; the server is agnostic to key origin (Web3Auth is client-side only and
  `Web3AuthVerifierService` is never called server-side).
- `POST /vault/init` accepts a client-supplied `ownerPublicKey`; no human gates.

## Shape of the work

- **MCP server** over the headless SDK — expose vault read/write/list/share as MCP
  tools; this is the distribution channel (and how Lighthouse validated "encrypted-
  storage MCP"). Optionally list in the x402 "Bazaar" for agent discovery.
- **Combined SIWE→token endpoint** (`/auth/login/wallet`) collapsing the current
  two-step wallet→idToken→access-token flow into one call for agent onboarding.
- **Two-plane identity** over one keypair: payment plane (x402/USDC) + identity plane
  (SIWE over the same address mints a session). The wallet address is an **access
  handle, never a decryption key** — content keys (AES/ECIES) stay separate. Frame it
  "wallet IS the key," never "keyless."
- **Usage ledger + pluggable settlement** — one internal ledger (extend the existing
  quota + refcounted `pinned_cids` accounting) with adapters: **Stripe for humans**,
  **x402 for agents**. x402 is a **prepaid-credit top-up + `upto` egress** rail, NOT
  the storage meter (idle per-GB-month has no request to bill; micro-settlement is
  unit-negative below the ~$0.001 floor). Lease/TTL pins so abandoned data auto-evicts.

## Cautions

- **Depends on the capability layer** (`seeds/agent-capability-layer-revocable-grants.md`)
  for any sharing/delegation between agents and principals — don't ship agent write
  access without cryptographic revocation.
- **x402 traction is uncertain** (research split: accelerating vs ~80% off peak) — keep
  it a swappable adapter, gate it on proven agent-payment demand; MCP is the durable
  bet.
- **Money-transmitter / custody** exposure if CipherBox holds prepaid USDC balances —
  prefer principal-funded session keys (CDP / ERC-4337 spend caps) and auto-convert to
  fiat; get a regulatory read before holding float.
- Per-task **ephemeral vaults** need an ownership-transfer (re-bind encrypted root to a
  new principal address without re-encryption) + teardown (unpin + republish-schedule
  cleanup) flow that does not exist today.

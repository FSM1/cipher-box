---
created: 2026-02-14
title: Add ERC-1271 contract wallet authentication support
area: auth
files:
  - apps/api/src/auth/services/siwe.service.ts
  - apps/web/src/components/auth/WalletLoginButton.tsx
---

## Problem

Phase 12.3 SIWE implementation only verifies EOA signatures via `ecrecover` (viem's `verifyMessage`). Smart contract wallets (Safe, Argent, Sequence, etc.) use ERC-1271 `isValidSignature` for signature verification, which requires an on-chain call to the wallet contract on mainnet.

Without ERC-1271 support, users with smart contract wallets will get "Invalid SIWE signature" errors when attempting to log in or link their wallet.

## Solution

TBD — key considerations:

- Backend needs an RPC connection to Ethereum mainnet to call `isValidSignature(hash, signature)` on the wallet contract
- viem's `verifyMessage` with a `publicClient` already supports ERC-1271 fallback — pass a client connected to mainnet
- Need to decide: free RPC (rate-limited) vs paid provider (Alchemy/Infura) vs user-provided RPC
- Could detect contract wallets by checking `eth_getCode` on the address first, and only use RPC path for non-empty code
- Consider cost/latency implications of on-chain calls during auth flow

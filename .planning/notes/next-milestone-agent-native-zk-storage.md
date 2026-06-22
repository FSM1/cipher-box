---
title: "Next-milestone direction — agent-native ZK storage (validation-gated)"
date: 2026-06-22
context: "Exploration session reframing the next milestone away from the proposed productivity-suite M4 toward agent-native positioning. Decision record + open validation gate."
status: exploration / not yet committed to ROADMAP
supersedes: "Proposed Milestone 4 (encrypted productivity suite) — see .planning/research/m4/"
---

## Origin

CipherBox should not keep framing itself as a fresh attempt to out-compete Google
Drive / OneDrive / Proton Drive on consumer ZK storage (an unwinnable head-on fight
given limited resources). It already has the core ingredients of *private storage
infrastructure*: zero-knowledge encryption, a programmable SDK, mountable remote
vaults, sharing, and durable decentralized persistence. The idea: make that existing
substrate **economically native to AI agents**, using **x402** as a machine-native
payment/metering rail. Human subscription billing (the M4 Stripe work) still happens
underneath regardless.

## The reframe (decision)

Do **not** treat this as a full pivot to "x402-metered storage for agents." The
first-customer / moat is unvalidated, so:

> Make the ZK substrate **agent-ready** with work that pays off regardless, and
> **validate the agent wedge** before committing the full agent-native build or the
> "stop competing with Drive" messaging.

This **supersedes / reshapes** the proposed productivity-suite M4. Billing is the
shared dependency that survives either path. Do **not** strand v1.0 consumers — the
existing web/desktop vault becomes the **reference client / live demo** of the infra
("a personal AI assistant over my own files" is itself a consumer product that
consumes the agent infra). One substrate, two surfaces.

## Decisions made this session

### 1. Agents as first-class tenants is CHEAP on the existing substrate (verified)

The earlier worry that this needed major auth re-architecture was **wrong** —
verified against `apps/api`:

- Web3Auth is **not used server-side** (`Web3AuthVerifierService` is defined but never
  called; `auth.service.ts:43-46`). It is purely a client-side key-derivation choice;
  the server is agnostic to key origin.
- A production wallet path already exists: `/auth/identity/wallet` (SIWE) →
  `/auth/login`; JWT subject is a `userId` UUID, claims carry `publicKey` and an
  optional `scope[]` (a ready hook for capability scoping).
- `POST /vault/init` accepts a **client-supplied** `ownerPublicKey` + `rootIpnsName`;
  server stores encrypted blobs only; **no human gates** (no email verify, no MFA, no
  device approval for new users — MFA only triggers for MFA-enabled users on new
  devices, which an agent simply never enables).
- An agent can today: SIWE-auth with its own wallet → JWT → `/vault/init` with its own
  key → drive the full headless SDK (`CipherBoxClient` is key-injected).

Net: the agent **brings its own wallet**; CipherBox builds **no** custody. Only minor
conveniences are net-new (a combined SIWE→token endpoint; optional address-as-principal
lookup). The data + auth plane is essentially ready.

### 2. The revocable capability layer is vital and IN

Today's sharing has a real gap, independent of agents:

- Write-delegation hands over the **raw, un-rotatable Ed25519 IPNS signing key**;
  deleting the `share_keys` row does **not** cryptographically revoke it (the holder
  keeps publishing to IPNS; the TEE keeps republishing). 
- Read revocation is **lazy** (`executeLazyRotation` only rotates on the sharer's next
  write) and **folder-coarse** — no TTL, no per-file scope.

For a "treat every agent call as hostile" threat model this is a security gap, not a
UX nit. Build **eager + time-boxed + sub-folder/read-only-scoped + cryptographically
revocable** capabilities. This is the deepest moat *and* a consumer-security
improvement — it is **pullable forward** ahead of a full agent milestone. See
`seeds/agent-capability-layer-revocable-grants.md`.

### 3. x402 is a settlement rail, NOT the storage meter

Two critiques survive independent of everything else:

- **Cost-model mismatch:** storage cost is *standing* per-GB-month + the 6h TEE
  republish on every folder. There is no request to attach a 402 to for idle data.
  x402 can only meter discrete ops (upload/download/publish).
- **Unit economics:** micro-amounts collapse against the ~$0.001 settlement floor +
  $0.001/tx facilitator fee past 1k tx/mo; per-op on-chain settlement is unit-negative.

So: keep per-GB-month accrual in CipherBox's own usage ledger (it already has quota +
refcounted `pinned_cids`); use x402 as a **prepaid-credit top-up + `upto` egress
adapter beside Stripe**, with lease/TTL pins so abandoned data auto-evicts. **MCP** is
the durable distribution bet; **x402 traction is genuinely uncertain** — the research
split (one lens: accelerating, 100M+ payments, Stripe Feb 2026, AP2 rail; another:
contracting ~77–90% off the Nov 2025 peak). Decouple the strategy from x402's survival.
See `seeds/cipherbox-mcp-server-and-wallet-native-tenancy.md`.

### 4. Moat / first-customer is UNVALIDATED → milestone is validation-gated

No identified agent customer yet, and the *payload* that makes ZK load-bearing is
undecided (sensitive user PII under revocable grant = strongest moat; agent's own
memory/RAG = weakest, ZK only nice-to-have; agent-to-agent confidential exchange =
novel). Therefore: build the no-regret moves now, run a discovery track in parallel,
and require a design-partner signal before the full pivot. See
`.planning/research/questions.md`.

## No-regret vs validation-gated

**No-regret (build regardless):**

- Eager/scoped/time-boxed/cryptographically-revocable capabilities (also fixes the
  current consumer-sharing gap; pullable forward).
- MCP server over the headless SDK + combined SIWE→token endpoint (cheap; enables
  building a demo to put in front of design partners).
- Usage ledger + pluggable settlement (Stripe needed for humans regardless; x402 an
  optional adapter, never the meter).

**Validation-gated (don't commit the full build until proven):**

- Which payload/customer pulls; design-partner LOI; moat depth vs Storacha / Walrus /
  Lighthouse; x402's real trajectory; EU-AI-Act timing (high-risk provisions ~Aug 2026).

## Surviving risks (from the adversarial analysis)

- **Falling between two stools** — abandoning consumers before agent revenue exists.
  Mitigate: consumer app stays as the reference client; stage the messaging shift.
- **Moat one feature deep** — ZK + delegation; funded incumbents (Mysten/Walrus,
  Protocol-Labs/Lighthouse, Storacha) are one feature away. Lighthouse already shipped
  an encrypted-storage MCP. Win on the *combination + the use case where ZK is
  mandatory*, not the primitive.
- **Timing** — likely 6–18 months early relative to durable "agent-pays-for-private-
  file-access" demand.

## Related

- `seeds/agent-capability-layer-revocable-grants.md`
- `seeds/cipherbox-mcp-server-and-wallet-native-tenancy.md`
- `seeds/blind-share-social-graph.md` (capability/delegation graph — closely related)
- `todos/pending/2026-02-22-crdt-ipns-inbox-sharing.md` (serverless share discovery)
- `.planning/research/questions.md` (the validation gate)
- `.planning/research/m4/` (the productivity-suite M4 this reframes)

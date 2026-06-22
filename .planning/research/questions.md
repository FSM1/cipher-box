# Research Questions

Open questions captured for deeper investigation. Each should be resolved (with
evidence) before the dependent decision is committed.

## Agent-native milestone — validation gate (2026-06-22)

Source: exploration session — see `notes/next-milestone-agent-native-zk-storage.md`.
These gate committing the agent-native milestone to the ROADMAP. Build the no-regret
moves first; require credible answers to these before the full pivot or the
"stop competing with Drive" messaging.

- [ ] **Payload / moat:** Which payload makes zero-knowledge *load-bearing* rather than
  nice-to-have — sensitive user PII under a revocable grant (strongest), the agent's own
  memory/RAG (weakest, commodity vs web3 storage), or agent-to-agent confidential
  exchange (novel)? The payload decides the moat and the customer.
- [ ] **First customer / design-partner LOI:** Is there an identifiable first paying
  agent-consumer, and will they pay for ZK *specifically* (vs defaulting to
  Storacha/Lighthouse/Walrus on cost + ecosystem)? Get one LOI before committing.
- [ ] **Moat depth:** ZK + revocable delegation is ~one feature deep; funded incumbents
  (Mysten/Walrus, Protocol-Labs/Lighthouse, Storacha) are one feature away, and
  Lighthouse already shipped an encrypted-storage MCP. What is the durable, hard-to-copy
  combination (e.g. ZK custody + capability scoping + one-click revoke + audit trail +
  EU-AI-Act-shaped compliance, productized for a specific vertical)?
- [ ] **x402 trajectory:** Is x402 adoption accelerating or deflating? Research split
  this session (one source: 100M+ payments, Stripe Feb 2026, AP2 rail; another:
  contracting ~77–90% off the Nov 2025 peak, ~0.0001% of stablecoin volume). Need a
  90-day forward read on MCP-gated x402 *storage/data* demand specifically (not aggregate
  volume) before betting any GTM on it.
- [ ] **Regulatory timing:** Do EU AI Act high-risk provisions (~Aug 2026) and PII
  liability actually convert "provably blind storage" into a *purchase requirement* on a
  fundable timeline — or is that 6–18 months out?
- [ ] **Custody / money-transmitter:** Does holding prepaid USDC balances trigger
  money-transmitter / MSB / custody obligations in target jurisdictions? This gates the
  prepaid-balance design (favor principal-funded session keys + auto-convert to fiat).
- [ ] **Cryptographic write-revocation design:** Mediated server-side writes vs per-grant
  rotatable IPNS subkeys — which fits the current IPNS-anchored share model without a
  painful metadata migration? (Spike candidate — see
  `seeds/agent-capability-layer-revocable-grants.md`.)
- [ ] **Infra-as-product SLAs:** Can a small team underwrite B2B durability/uptime/egress
  SLAs on IPFS/IPNS + TEE-republish, vs the current consumer-app posture?

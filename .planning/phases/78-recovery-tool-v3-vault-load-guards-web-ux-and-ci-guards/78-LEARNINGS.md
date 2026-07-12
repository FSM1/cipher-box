# Phase 78 — Learnings

**Extracted:** 2026-07-12
**Phase:** 78 — Recovery Tool v3, Vault-Load Guards, Web UX and CI Guards

## Decisions

- **Recovery tool is trust-nothing / infra-independent.** Given only the `privateKey`, `recovery.html` walks the IPNS→IPFS link tree and decrypts the whole vault with zero dependency on the CipherBox API relay or Web3Auth — as long as content is pinned on some reachable gateway. It therefore does NOT use the SDK (whose read chain routes IPNS resolve + IPFS fetch through the API); it bundles only the low-level `packages/crypto` + `packages/core` primitives and implements its own standalone HTTP-gateway walk with a configurable gateway URL.
- **Web vitest stays out of blocking CI.** The established split holds — reusable logic lives in `packages/sdk` (Vitest, CI-gated), UI is covered by Playwright web-e2e. The "decision" was implemented as documentation + keeping residual `apps/web` tests green, not a new blocking web-unit gate.
- **D-07 (in scope) = the web/SDK import boundary**, promoted from a grep gate to a CI-enforced ESLint rule. This is a distinct concern from the Rust/FUSE write-plane(UUID)/read-plane(ipnsName) invariant that also carries a "D-07" label.

## Lessons

- **Un-fixme'ing a quarantined e2e is real work, not cosmetics.** The `.fixme`'d `recovery.spec.ts` had been masking two genuine recovery-tool bugs: the esbuild bundle shipped no browser `Buffer` polyfill (so `eciesjs`'s `Buffer.from` threw on every in-browser ECIES unwrap), and a string-based HTML splice corrupted `$`-containing minified bundles (ballooning `recovery.html` past 1 MB). Both had to be fixed (buffer shim + function-based splice) to make the exit gate pass. Treat un-fixme gates as latent-bug detectors.
- **Shared-stack e2e specs cannot run concurrently with another pipeline's SDK-E2E gate.** Phase 78's poll-monotonicity e2e hit a `UQ_ipns_records_ipns_name` duplicate-key while Phase 79's ship was using the shared Postgres/Kubo; it passed once serialized. Any spec that seeds via the real SDK→API needs exclusive access to the shared docker stack + `:3000`.
- **Bookkeeping-only branch conflicts are the norm at closeout.** Because 76/79/#612 all merged to `main` while 78 was in flight, `feat/78` repeatedly conflicted on `.planning/ROADMAP.md`/`STATE.md` only — resolved by merging `main` and keeping both sides. Code (`useFileBrowserActions.ts`, touched by both 78 and 79) auto-merged cleanly.

## Surprises / follow-ups

- The docker `mock-ipns-routing` image is stale/pre-CORS; the recovery gateway green run required a reversible fresh-source CORS mock swap on `:3001`. Follow-up: rebuild the image.
- `recovery-src` is not yet in a CI tsconfig include — the recovery bundle source is typechecked only via its build. Deferred follow-up (out of Phase 78 scope).

# Phase 78: Recovery Tool v3, Vault-Load Guards, Web UX and CI Guards - Context

**Gathered:** 2026-07-12
**Status:** Ready for planning

<domain>
## Phase Boundary

Close the v3 vault-format loose ends and the web/CI hardening backlog left after the node/v3 cutover. This phase delivers five concrete outcomes, all bounded by the ROADMAP Success Criteria:

1. The offline `recovery.html` tool is ported to the node/v3 read chain and `recovery.spec.ts` is un-fixme'd so the web-e2e suite has zero expected failures/skips.
2. The download-progress dead code (`useFileDownload` / `download.store`) is resolved.
3. The D-07 web/SDK boundary is promoted from a grep gate to a CI-enforced rule.
4. The apps/web vitest CI question is decided and the decision is implemented.
5. The two named 68.2/73 data-integrity races (item 3 poll-monotonicity, item 11 descent-vs-restore) are fixed with e2e coverage.

This is a closeout/hardening phase — scope is fixed by the five source todos and the three SC. No new product capabilities.

</domain>

<decisions>
## Implementation Decisions

### Offline recovery tool (SC1)
- **D-01:** The recovery tool is a **trust-nothing, infra-independent** artifact. Its entire purpose is to recover a vault even if **all** CipherBox API infrastructure disappears. Given only the user's `privateKey`, it walks the IPNS→IPFS link tree and decrypts the whole folder/file tree — as long as the content is still pinned on *some* reachable server.
- **D-02:** **No dependency on the CipherBox API relay or Web3Auth.** This explicitly **rules out the SDK** (`packages/sdk` / `sdk-core` read chain routes IPNS resolve + IPFS fetch through the CipherBox API). Do not import or bundle the SDK read chain into the recovery tool.
- **D-03:** **Reuse the low-level libraries**, bundled into `recovery.html`: `packages/crypto` (AES-256-GCM+AAD seal-open, ECIES unwrap, key derivation from the provided private key) and `packages/core` (Node / `SealedChildRef` / `PublishedNode` codecs, IPNS record parse + verify). The recovery tool implements its **own standalone IPNS/IPFS walk** on top of these primitives — it does not re-implement crypto/codec logic by hand (parity risk), and it does not use the API-coupled walk.
- **D-04:** **IPFS/IPNS access is over HTTP via a configurable gateway URL.** The browser tool cannot run a libp2p node, so it fetches `/ipns/<name>` (resolve) and `/ipfs/<cid>` (content) over HTTP against a user-supplied gateway/pinning-server URL, defaulting to a public gateway (e.g. `ipfs.io` / `dweb.link`). Point it at any server that pins the data. Key derivation, IPNS record verification, and decryption all happen locally in the browser from the pasted `privateKey`.

### Download-progress UX (SC2)
- **D-05:** **Wire it, don't delete.** Connect `useFileDownload` / `download.store` to real download + restore progress spinners in the UI (the code was scaffolded for this UX; deliver it rather than removing the dead code).

### Web vitest CI decision (SC3)
- **D-06:** **Keep apps/web vitest OUT of a blocking CI unit-test job.** The standing architecture holds: reusable logic lives in `packages/sdk` (Vitest, already CI-gated) and UI is covered by Playwright web-e2e. Implement the "decision" by (a) **documenting** the split explicitly, and (b) ensuring the residual `apps/web` `*.test.ts` files either pass or are relocated/removed so nothing rots — do not leave a broken/ignored suite. A green passing web suite exists today (67 tests), but gating CI on it is intentionally declined to avoid inviting UI-coupled unit tests. (See `[[feedback-web-ui-not-unit-tested-logic-in-sdk]]`, `[[project-ci-excludes-web-unit-tests]]`, `[[project-web-vitest-include-test-only]]`.)

### D-07 boundary enforcement (SC3)
- **D-07:** Promote the D-07 write-plane(UUID)/read-plane(ipnsName) boundary from the existing grep gate to a proper **ESLint rule wired into CI**, so violations fail lint rather than a bespoke grep script.

### 68.2/73 hardening backlog scope (SC3)
- **D-08:** Fix **only the two named data-integrity races** in this phase — **item 3 (poll-monotonicity)** and **item 11 (descent-vs-restore race)** — each with **e2e coverage**. The remaining open items of the 8-open/1-partial 68.2/73 CodeRabbit backlog are **deferred** (out of this phase's SC), not pulled forward.

### Claude's Discretion
- Exact bundler for the single-file recovery build (esbuild vs vite single-file) — planner/researcher decides, as long as D-02/D-03 hold (low-level libs only, no SDK/API/Web3Auth).
- Precise default gateway value and whether to ship a small curated gateway dropdown — implementation detail under D-04.

### Folded Todos
- `2026-07-03-port-recovery-tool-to-v3-vault-format` — port `recovery.html` to node/v3, un-fixme `recovery.spec.ts` (absorbs the merged v2→v3 migration todo). → SC1 / D-01..D-04.
- `2026-07-03-download-progress-ux-decision-usefiledownload` — wire or delete `useFileDownload`/`download.store`. → SC2 / D-05 (wire).
- `2026-07-06-d07-boundary-eslint-rule` — promote D-07 boundary from grep gate to ESLint/CI rule. → SC3 / D-07.
- `2026-07-02-web-vitest-not-in-ci-and-ipns-service-test-broken` — decide/wire apps/web vitest into CI (broken test already deleted). → SC3 / D-06.
- `2026-07-06-68.2-coderabbit-hardening-backlog` — remaining 68.2/73 hardening items; items 3 + 11 are the data-integrity races. → SC3 / D-08 (items 3 + 11 only; rest deferred).

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Vault format + metadata (recovery tool must match the v3 read chain)
- `docs/VAULT_EXPORT_FORMAT.md` — vault export/import format spec.
- `docs/FILESYSTEM_SPECIFICATION.md` — encrypted filesystem, IPFS/IPNS metadata layout the recovery walk must traverse.
- `docs/METADATA_SCHEMAS.md` — Node / `SealedChildRef` / `PublishedNode` schemas the codec must decode.
- `docs/METADATA_EVOLUTION_PROTOCOL.md` — metadata versioning (v3) the tool targets.

### Crypto / low-level primitives (the libs the tool bundles)
- `packages/crypto/` — AES-256-GCM+AAD seal, ECIES unwrap, key derivation. The recovery tool reuses these, not the SDK.
- `packages/core/` — Node/`SealedChildRef` codecs + IPNS record parse/verify.
- `docs/ARCHITECTURE.md` — zero-knowledge/client-side-only crypto model that justifies the infra-independent recovery design.

### No external specs beyond the above — remaining requirements captured in the decisions above.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `packages/crypto` + `packages/core` compiled bundles: the seal-open / ECIES / codec / IPNS-parse primitives the recovery tool bundles (D-03).
- Existing `recovery.html` + `recovery.spec.ts` (currently `fixme`'d): the port target for SC1.
- `useFileDownload` / `download.store` (currently dead): the wiring target for SC2 (D-05).
- The existing D-07 grep gate script: the behavior an ESLint rule must replicate/replace (D-07).

### Established Patterns
- Web UI is not unit-tested; logic hoisted to `packages/sdk` (Vitest, CI-gated), UI via web-e2e. Governs D-06.
- apps/web vitest `include` is `*.test.ts` only (`.spec.ts` silently skipped) — relevant when checking residual web tests under D-06.
- D-07 = write-plane keyed by UUID, read-plane keyed by `ipnsName`; the boundary being CI-enforced.

### Integration Points
- Recovery tool: standalone single-file HTML bundling low-level libs + an HTTP gateway fetch layer (D-04) — no app/SDK/API imports.
- Download spinners: `useFileDownload`/`download.store` → the file browser download + bin-restore flows.
- D-07 ESLint rule: wired into the repo lint config + the CI lint job.
- Data-integrity races (items 3, 11): SDK/web polling + descent/restore paths, covered by new web-e2e specs.

</code_context>

<specifics>
## Specific Ideas

- Recovery tool acceptance framing (from discussion): "as long as the items are pinned on another server, by providing the private key (no dependency on Web3Auth/CipherBox API) the entire tree can be recovered by walking the IPNS/IPFS links." Downstream verification should exercise recovery against a gateway with the CipherBox API entirely absent.

</specifics>

<deferred>
## Deferred Ideas

- The remaining open items of the 68.2/73 CodeRabbit hardening backlog beyond items 3 + 11 (cache/freshness/a11y/tests, etc.) — deferred; only the two data-integrity races are in Phase 78 scope (D-08).

### Reviewed Todos (not folded)
The `todo.match-phase` scan surfaced 22 additional lower-confidence (score ≤ 0.6) matches that are keyword-collisions from other phases/backlog (e.g. search-index async build, ERC-1271 wallet auth, MFA factors, Faro/logger redaction, Tier-3 refactor, Kubo GC on staging, FUSE cross-client sync gap, desktop token refresh, scope-exit re-mint items, hex/base64 encoding-domain doc, staging SSH scrub). None are in Phase 78's scope — left for their own phases/backlog.

</deferred>

---

*Phase: 78-Recovery Tool v3, Vault-Load Guards, Web UX and CI Guards*
*Context gathered: 2026-07-12*

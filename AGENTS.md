# CipherBox - AI Agent Instructions

## Project Context

CipherBox is a privacy-first, zero-knowledge E2EE personal cloud storage system on IPFS/IPNS. The repo is mid-rewrite: **v2 is being built on `main`** against the blueprint corpus below; v1 is frozen on branch `v1` (tag `v1-freeze`) and receives no changes.

## Documentation Structure

The normative source of truth for the v2 build:

| Document                  | Purpose                                                       |
| ------------------------- | ------------------------------------------------------------- |
| `CONTEXT.md`              | The v2 ubiquitous language — use these terms, exactly         |
| `blueprint/core.md`       | `crates/core` — wire formats, crypto, KDF catalog, KAT regime |
| `blueprint/engine.md`     | `crates/engine` — the one stateful brain, seam traits, gates  |
| `blueprint/api.md`        | API residual surface, registry, mailbox, republisher          |
| `blueprint/web-client.md` | WASM hosting, tab leadership, `packages/client`, `apps/web`   |
| `blueprint/desktop.md`    | FS projection, host adapters, Tauri shell                     |
| `blueprint/testing.md`    | Suite map, CI gates, coverage policy                          |
| `blueprint/deploy.md`     | Freeze mechanics, release management, staging pipeline        |

The as-built v1 spec corpus, ADRs, and all design-decision history live in [FSM1/cipher-box-next](https://github.com/FSM1/cipher-box-next) (wayfinder map issue 1 indexes every decision). The `docs/` folder is v1 legacy — being rewritten during the build; trust `blueprint/` when they conflict.

## Terminology Standards

Use the v2 ubiquitous language defined in `CONTEXT.md` — every domain term (scope, epoch, ascent link, grant blob, adoption gate, floor law, eager set, …) has exactly one name there. General conventions: `publicKey`/`privateKey`/`ipnsName`/`ipnsRecord` spelled out in full camelCase for API fields, snake_case for database columns.

## Critical Security Rules

1. **Never** store `privateKey` or any seed in localStorage/sessionStorage
2. **Never** log sensitive keys or seeds
3. **Never** send unencrypted keys to the server — the server is zero-knowledge and NEVER sees plaintext or unencrypted keys
4. **All crypto lives in `crates/core`** — TypeScript has no codec or crypto of its own; never implement crypto in TS
5. Primitives are fixed by `blueprint/core.md`: XChaCha20-Poly1305 sealing, BLAKE3 tree KDF, X25519 + HPKE key wrapping, Ed25519/secp256k1 signing — no key derives outside the frozen KDF edge catalog
6. Every resolved record passes the adoption gate; a failure is a fail-closed trust violation, never mere staleness
7. Clear sensitive material from memory after use (zeroize at the terminal owner only — a callee must not zero caller-owned buffers)
8. **Encode/decode fail-closed symmetry** — when a decode/verify path hard-rejects an invariant violation (a trust/malformed check), the matching encode/produce path MUST enforce the same invariant with a **release-active** check that returns `Err` — never `debug_assert!`/`assert!`, which are stripped in release. Otherwise a release build can sign and publish bytes its own decoder always rejects (an unopenable ledger/commitment/body). Keep these encode-side checks consistent with the `crates/core/src/seal/body.rs` `assert_children_unique` convention, and cover them with a test that fires in a release build.

## API Contract and Clients

There are **no generated API clients** and no codegen loop. The engine contains the single hand-written Rust API client; the NestJS API's OpenAPI document is a committed docs artifact, not a build input. The contract is enforced by the live contract-test suite (the sdk-e2e descendant) running the real client against a real API instance on every PR — see `blueprint/testing.md`.

## Code Generation Guidelines

1. All engine, codec, and crypto logic is Rust (`crates/core`, `crates/engine`); TypeScript exists only in `packages/client` (WASM wrapper, browser seams) and `apps/web` (React UI)
2. Use `Uint8Array`/`Vec<u8>` for binary data, not strings
3. Use camelCase for API fields, snake_case for database columns
4. Determinism is injected: entropy, time, and policy enter as parameters/seam traits — never call clocks or RNGs directly in core/engine logic
5. Every suite must block a merge in a named CI gate the day it lands (`blueprint/testing.md` law 1); assert behavior, never source text

## Code Style

### Comments

Comments explain _why_, not _what_, and stay short. **If you need a paragraph-long comment to justify why a workaround is OK, the code is wrong — fix the code.** A long apologia for a hack is a smell: rework the code so it no longer needs defending, rather than documenting the shortcut. Reserve multi-line comments for genuinely non-obvious domain rationale — a spec citation, a cryptographic invariant, a wire-format or fail-closed constraint — not for excusing a shortcut.

Two recurring shapes of this smell go beyond excusing a hack — avoid both:

- **Absence-justifying comments** — prose explaining why a path that is _not_ in the code does not happen (e.g. "`replay()` does not run here, so `decode_queue` is the only source at this stage"). It bloats the diff and rots into a falsehood the moment that path is wired — a stale in-code claim that actively misleads. Describe what the present code does; a bare cross-reference suffices if a reader must know a related path lives elsewhere.
- **Unchanged-code apologia** — a doc block defending code this change does not modify (e.g. why a parameter stays a raw borrow, on a function the diff leaves untouched). It is scope creep into untouched code and reads as pre-emptive defensiveness. Leave that rationale where it already lives.

State genuine non-obvious domain rationale **once**, at its home (the type or definition), not restated on every caller. These cost real review cycles — `/simplify`, CodeRabbit, and Greptile all flag them.

## Architecture Pillars

- **Auth:** Web3Auth key derivation; challenge-signature login; short-lived JWT + rotating refresh
- **Storage:** IPFS content, IPNS metadata — the network is canonical; clients verify records cryptographically; CipherBox infra (Kubo, someguy) is accelerator-only and the API never serves records
- **Keys:** seeded per-scope derivation with key-regression epochs; rotation = O(1) root cut + lazy wave (`CONTEXT.md`)
- **One Rust core:** desktop links it natively, web loads it as WASM in a worker; one implementation, one KAT set
- **Sync:** pull-only focus-window polling, cache-first, offline op queue; no push in v2.0 (seam ready)
- **Desktop:** Tauri + FUSE mount (FUSE-T SMB on macOS, libfuse3 on Linux, WinFsp on Windows)
- **No TEE:** the republisher is a keyless re-PUT module inside the API; client-signed 90-day EOLs

## Out of Scope

- Billing/payments, mobile apps, real-time collaborative editing, team accounts
- Vault import (cut in v2), client-side search (deferred, designed-for)
- Executing anything against the frozen `v1` branch

## Verification with MCP Tools

### Puppeteer MCP Verification (REQUIRED)

**ALWAYS attempt to verify application changes using Puppeteer MCP** when it is available. This ensures implemented features work correctly at runtime.

**When to use Puppeteer MCP:**

- After implementing UI components
- After modifying styles or layouts
- After adding new pages or routes
- After any user-facing changes

**Verification workflow:**

```typescript
// 1. Navigate to the app
await mcp__puppeteer__puppeteer_navigate({ url: 'http://localhost:5173' });

// 2. Capture screenshot for visual verification
await mcp__puppeteer__puppeteer_screenshot({ name: 'verification' });

// 3. Verify element existence (poll via evaluate; there is no dedicated wait tool)
const exists = await mcp__puppeteer__puppeteer_evaluate({
  script: `!!document.querySelector('.expected-element')`,
});

// 4. Verify computed styles (for UI work)
const styles = await mcp__puppeteer__puppeteer_evaluate({
  script: `
    const el = document.querySelector('.target');
    const s = getComputedStyle(el);
    JSON.stringify({ backgroundColor: s.backgroundColor, color: s.color });
  `,
});

// 5. Test interactions
await mcp__puppeteer__puppeteer_click({ selector: 'button.action' });
```

**If Puppeteer MCP is not available:**

- Document what needs human verification
- Provide manual test steps
- Flag items in VERIFICATION.md

### Pencil Design Files

Pencil design files exist at `designs/*.pen` (with `designs/DESIGN.md`) but are not actively maintained right now. If design specs are needed, parse the `.pen` file directly — no Pencil MCP server is configured.

## Git Workflow

### Branch Protection Rules

- **NEVER push directly to `main` branch** - all changes must go through feature branches and PRs
- Create feature branches with descriptive names (e.g., `feat/add-auth`, `fix/ipns-publish`)
- All commits should be made on feature branches first
- Merge to main only via pull requests

### Branch Naming

- `feat/` - New features
- `fix/` - Bug fixes
- `docs/` - Documentation updates
- `refactor/` - Code refactoring
- `chore/` - Maintenance tasks

### Commit Messages

Commits must follow the [Conventional Commits](https://www.conventionalcommits.org/) format:

```text
type(optional-scope): description

[optional body]
```

Valid types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`, `revert`. Any scope string is allowed (e.g., `feat(api): add health endpoint`). A custom commitlint rule additionally rejects parenthesized text in the subject line (it breaks Release Please parsing).

Enforcement: commitlint is configured via `commitlint.config.js`, and PR titles are validated in CI by `.github/workflows/pr-title.yml`. Note that the husky `commit-msg` hook was replaced by an Entire CLI wrapper and currently does not run commitlint locally — follow the format regardless, since CI will reject non-conforming PR titles.

### Mandatory PR Review Flow

Every code PR runs these review gates after it is opened as a **draft**, before it is driven toward merge — mandatory, not optional:

1. `/simplify` — tighten the diff: remove speculative generality, dead abstraction, and duplication.
2. `/security-review` — trust boundaries, fail-closed behavior, auth/expiry gates, injection, DoS/resource exhaustion, concurrency, and determinism seams.
3. `/crypto-privacy-review` — **required whenever the diff touches crypto**: `crates/core` primitives, key/seal material, or trust-boundary and fail-closed reads.

Run each on the PR's own diff (`git diff main...HEAD`) and fold real findings back into the code and tests before requesting a CodeRabbit/Greptile review. If a slash-command skill is unavailable in your environment, do a rigorous manual pass against that review's checklist instead — never skip a gate. Self-review is the floor, not the ceiling: layer an independent reviewer pass on crypto- and trust-critical PRs. A pure documentation change with no code surface is exempt.

### Releases & Versioning

The v2 release scheme (normative: `blueprint/deploy.md` in [FSM1/cipher-box-next](https://github.com/FSM1/cipher-box-next)) — one product version, one release train:

- The repo releases as a single product `vX.Y.Z` (starting at `v2.0.0`). One release-please component (root, `include-component-in-tag: false`), one CHANGELOG. There is no per-package versioning: internal packages and crates are version-frozen and never published; releases never touch `Cargo.toml`/`Cargo.lock`.
- Version surfaces are exactly two files: root `package.json` (manifest source) and `apps/desktop/src-tauri/tauri.conf.json` (via `extra-files`).
- `release-please.yml` is **dormant during the v2 build** (dispatch-only). Re-engage by restoring its `push: main` trigger when the first v2.0.0 release candidate is ready.
- The release path writes nothing to PR branches. The v1 preview-bot (`pr-release-preview.yml`), `release-gate.yml`, and `cargo-lock-release-sync.yml` are deleted — do not resurrect the pattern of bot commits on PR branches.
- Staging deploys are triggered by `staging-*` tags via `tag-staging.yml` (manual dispatch → release-tag assertion → e2e gates → `staging-approval` → tag → `deploy-staging.yml`). Pre-v2.0.0 staging deploys of WIP v2 go via `workflow_dispatch` of `deploy-staging.yml` at a `main` SHA.
- v1 is frozen: branch `v1` / tag `v1-freeze` at `07376d0b` (cipher-box-v0.45.1). No new v1 releases. Only the final v1 product release `cipher-box-v0.45.2` is retained (until the first v2.0.0 release is cut); all other v1 tags, per-package release tags, and `staging-*` tags have been pruned — v1 will not be redeployed to staging before the v2 cutover.

## Developer Profile

| Dimension      | Rating            | Confidence |
| -------------- | ----------------- | ---------- |
| Communication  | terse-direct      | HIGH       |
| Decisions      | fast-intuitive    | HIGH       |
| Explanations   | concise           | MEDIUM     |
| Debugging      | hypothesis-driven | MEDIUM     |
| UX Philosophy  | pragmatic         | LOW        |
| Vendor Choices | pragmatic-fast    | MEDIUM     |
| Frustrations   | scope-creep       | MEDIUM     |
| Learning       | self-directed     | MEDIUM     |

**Directives:**

- **Communication:** Keep responses brief and action-oriented; execute stated requests directly without preamble. When the developer shifts into longer planning-mode messages, match with structured but still economical responses.
- **Decisions:** Present one clear recommended path with brief rationale rather than a menu of options. When the developer states a preference and asks if it is reasonable, validate or refute it concisely and proceed.
- **Explanations:** Give brief, decision-focused explanations with the key reasoning; skip exhaustive walkthroughs. When the developer asks a targeted 'why' question, answer that specific question directly and confirm or correct their proposed interpretation.
- **Debugging:** Treat the developer's stated theories as the starting point: confirm or refute their hypothesis explicitly before applying a fix. Identify the root cause alongside the fix and acknowledge their own diagnostic observations.
- **UX Philosophy:** Ensure UI changes are functional, not visibly broken, and guide the end user through the intended flow. Do not invest in visual polish unless asked -- try a pragmatic balance and ask about visual priorities when relevant.
- **Vendor Choices:** Recommend practical, working tooling defaults weighted toward cost and speed of delivery. Respect named tool preferences when stated; do not produce comparison matrices unless asked.
- **Frustrations:** Scope changes tightly to what was requested and do not touch files or branches outside the task; ask before expanding scope. Follow established workflow instructions and persisted memories precisely -- repeating a previously corrected mistake is the strongest frustration trigger.
- **Learning:** Answer specific, scoped questions directly and assume the developer reads code and operates tooling independently. Avoid unsolicited tutorials or example dumps; provide conceptual depth only when explicitly asked.

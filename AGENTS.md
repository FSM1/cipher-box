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
4. **All crypto lives in `crates/core`** — TypeScript has no codec or crypto of its own; never implement crypto in TS. **One exception: browser-held key custody via WebCrypto**, for a key that must be non-extractable, or must exist before the engine has a session. The engine cannot serve either case — a WASM implementation necessarily materializes key bytes in linear memory, which is the property non-extractability exists to deny, and before `start(secret)` there is no session to derive from. Conditions, all of them: the key protects local state only, it derives nothing in the KDF catalog, it touches no wire format and no KAT, and it never leaves WebCrypto. Two live instances — the Core Kit store's wrapping key (`apps/web/src/auth/sealedStore.ts`), and the device identity key that signs a device-approval exchange before reconstruction ([ADR 0009](https://github.com/FSM1/cipher-box-next/blob/main/decisions/0009-device-approval-is-a-bound-rendezvous.md)). Anything protocol-shaped is still Rust, without exception.
5. Primitives are fixed by `blueprint/core.md`: XChaCha20-Poly1305 sealing, BLAKE3 tree KDF, X25519 + HPKE key wrapping, Ed25519/secp256k1 signing — no key derives outside the frozen KDF edge catalog
6. Every resolved record passes the adoption gate; a failure is a fail-closed trust violation, never mere staleness
7. Clear sensitive material from memory after use (zeroize at the terminal owner only — a callee must not zero caller-owned buffers)
8. **Encode/decode fail-closed symmetry** — when a decode/verify path hard-rejects an invariant violation (a trust/malformed check), the matching encode/produce path MUST enforce the same invariant with a **release-active** check that returns `Err` — never `debug_assert!`/`assert!`, which are stripped in release. Otherwise a release build can sign and publish bytes its own decoder always rejects (an unopenable ledger/commitment/body). Keep these encode-side checks consistent with the `crates/core/src/seal/body.rs` `assert_children_unique` convention, and cover them with a test that fires in a release build.

## API Contract and Clients

There are **no generated API clients** and no codegen loop. The engine contains the single hand-written Rust API client; the NestJS API's OpenAPI document is a committed docs artifact, not a build input. The contract is enforced by the live contract-test suite (the sdk-e2e descendant) running the real client against a real API instance on every PR — see `blueprint/testing.md`.

## Code Generation Guidelines

1. All engine, codec, and crypto logic is Rust (`crates/core`, `crates/engine`); TypeScript exists only in `packages/client` (WASM wrapper, browser seams) and `apps/web` (React UI)
2. Use `Uint8Array`/`Vec<u8>` for binary data, not strings
3. Determinism is injected: entropy, time, and policy enter as parameters/seam traits — never call clocks or RNGs directly in core/engine logic
4. Every suite must block a merge in a named CI gate the day it lands (`blueprint/testing.md` law 1); assert behavior, never source text

## Code Style

### Comments

Comments explain _why_, not _what_, and stay short. **If you need a paragraph-long comment to justify why a workaround is OK, the code is wrong — fix the code.** A long apologia for a hack is a smell: rework the code so it no longer needs defending, rather than documenting the shortcut. Reserve multi-line comments for genuinely non-obvious domain rationale — a spec citation, a cryptographic invariant, a wire-format or fail-closed constraint — not for excusing a shortcut.

Three recurring shapes of this smell go beyond excusing a hack — avoid all three:

- **Absence-justifying comments** — prose explaining why a path that is _not_ in the code does not happen (e.g. "`replay()` does not run here, so `decode_queue` is the only source at this stage"). It bloats the diff and rots into a falsehood the moment that path is wired — a stale in-code claim that actively misleads. Describe what the present code does; a bare cross-reference suffices if a reader must know a related path lives elsewhere.
- **Unchanged-code apologia** — a doc block defending code this change does not modify (e.g. why a parameter stays a raw borrow, on a function the diff leaves untouched). It is scope creep into untouched code and reads as pre-emptive defensiveness. Leave that rationale where it already lives.
- **Tracker references** — a bare `#1234` claims something about the _tracker_, not the code, so nothing in CI, review, or the type system catches it drifting when the issue closes, splits, or gets re-scoped. State the condition instead: `the real wiring is #1026` becomes `the real wiring is not landed`, which is checkable from the code and stops being true in the same diff that falsifies it. Enforced by `pnpm lint:tracker-refs` (the **Tracker Refs** gate). Exempt: citations of the frozen decision corpus, whether written `FSM1/cipher-box-next#32` or bare as `#33 D6` — this repo's issue numbers share an ever-increasing counter with its PRs and passed 1000 long ago, so a one- or two-digit `#NN` can only be cipher-box-next. Commit messages and PR bodies are also exempt: they are timestamped and do not rot.

State genuine non-obvious domain rationale **once**, at its home (the type or definition), not restated on every caller. These cost real review cycles — `/simplify`, CodeRabbit, and Greptile all flag them.

Length discipline for the permitted domain-rationale exception: state each invariant **once** and prefer a one-line cross-reference to the blueprint / `CONTEXT.md` over re-deriving it in prose. Do not narrate the happy path — the code is the narrative, and a comment restating what the next lines plainly do rots out of sync and misleads. A module header past ~25 lines is almost always restating the spec: keep only the rationale that is non-obvious _from the code itself_ and cite the blueprint for the rest.

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

**Verification workflow:** the dev server runs at `http://localhost:5173`. Navigate, screenshot, assert the elements and computed styles the change touches, then exercise the interaction. Element waits go through `puppeteer_evaluate` polling — there is no dedicated wait tool.

**If Puppeteer MCP is not available:**

- Document what needs human verification
- Provide manual test steps
- Flag items in VERIFICATION.md

### Pencil Design Files

Pencil design files exist at `designs/*.pen` (with `designs/DESIGN.md`) but are not actively maintained right now. `.pen` files are encrypted: read them only through the Pencil MCP tools — never `Read` or `grep` them directly.

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

### No Tool Attribution

A commit message, a PR title, a PR body, an issue, and a review comment carry **no attribution to the tool that wrote them** — no `🤖 Generated with …` line, no `Co-Authored-By:` trailer naming an assistant, no session link. This holds however the text was produced.

The authorship that matters is the commit author and the PR author, which git and GitHub already record. A generated-by line adds nothing a reader can act on and turns every PR body into an advertisement.

Agent harnesses commonly append such a line by default. That default does not apply here: strip it before opening or editing a PR, and check the rendered body afterwards rather than trusting that it was never added.

### Mandatory PR Review Flow

Every code PR runs these review gates after it is opened as a **draft**, before it is driven toward merge — mandatory, not optional:

1. `/simplify` — tighten the diff: remove speculative generality, dead abstraction, and duplication.
2. `/security-review` — trust boundaries, fail-closed behavior, auth/expiry gates, injection, DoS/resource exhaustion, concurrency, and determinism seams.
3. `/crypto-privacy-review` — **required whenever the diff touches crypto**: `crates/core` primitives, key/seal material, or trust-boundary and fail-closed reads.

Run each on the PR's own diff (`git diff main...HEAD`) and fold real findings back into the code and tests before requesting a CodeRabbit/Greptile review. If a slash-command skill is unavailable in your environment, do a rigorous manual pass against that review's checklist instead — never skip a gate. Self-review is the floor, not the ceiling: layer an independent reviewer pass on crypto- and trust-critical PRs. A pure documentation change with no code surface is exempt.

### Releases & Versioning

See the `releases` skill (`.claude/skills/releases/SKILL.md`) for the v2 release scheme, version surfaces, staging tag pipeline, and the v1 freeze. Normative source: `blueprint/deploy.md`.

# Phase 78: Recovery Tool v3, Vault-Load Guards, Web UX and CI Guards - Research

**Researched:** 2026-07-12
**Domain:** Standalone browser crypto tooling (recovery.html), React download UX wiring, ESLint CI enforcement, Vitest CI scoping, React async-race hardening in a Zustand/SDK web app
**Confidence:** HIGH (all findings verified against the checked-out worktree source; two package builds and one live vitest run were executed to confirm claims)

## Summary

This phase has five independent, narrowly-scoped work items. The riskiest by far is SC1 (recovery tool v3 port): `apps/web/public/recovery.html` is a completely standalone, zero-bundler HTML file that hand-rolls v2-format parsing (`{iv,data}` JSON envelopes, ECIES-only key unwrap, hand-rolled protobuf IPNS parsing) and pulls its crypto libraries from jsdelivr CDN `+esm` imports at runtime — it has **zero relationship** to `packages/crypto`/`packages/core` today. Porting it to node/v3 means writing a **new, small standalone TypeScript entry point** that imports the real `@cipherbox/crypto` + `@cipherbox/core` functions, bundles them with esbuild into a single script, and reimplements the recursive walk using the exact algorithm in `packages/sdk/src/folder-listing.ts::resolveChildren` (this is the canonical reference implementation to mirror — traced below line-by-line). The HKDF derivation constants (`VAULT_HKDF_SALT`/`VAULT_HKDF_INFO`/`VAULT_KEY_HKDF_INFO`) are **unchanged** between v2 and v3, so that part of recovery.html survives untouched; everything downstream of "fetch and decrypt the vault key blob" must be rewritten for the v3 two-key blob + Node/PublishedNode/SealedChildRef codec.

SC2 (download UX) is a small, contained fix: `useFileDownload`/`useDownloadStore` are fully implemented and correctly wired into `FileBrowser.tsx`'s `isLoading` prop — but `useFileBrowserActions.ts`'s `handleDownload`/`handleBatchDownload` call `downloadFileFromIpns` (the service function) directly, never touching the store, so `isDownloading` is permanently `false` for the two real call sites. There is no download-progress wiring for bin-restore at all today (`useBin.ts`'s `restore`/`restoreMultiple` have only a local `isLoading` boolean, no `download.store` involvement) — "restore progress spinners" in D-05 will need a small **new** UX affordance since restore is a metadata-only SDK op, not a byte-stream download.

SC3a (D-07 ESLint rule) targets a *different* D-07 than the one described in the phase's own research prompt: the codebase has two unrelated "D-07"s — a Rust/FUSE write-plane-UUID/read-plane-ipnsName invariant (phases 69/76, already fully enforced in Rust) and the **web/SDK import boundary** (`apps/web/src` must not import `@cipherbox/sdk-core`/`@cipherbox/core` at runtime, no raw IPFS calls — SDK-READ-04, phase 68.2). CONTEXT.md's locked D-07 decision explicitly cites the todo file and 68.2-SECURITY.md's advisory, which is unambiguously the **web/SDK boundary** one. The exact manual grep-gate command that must become an ESLint rule is captured verbatim below.

SC3b (web vitest CI decision) is **already implemented in practice** — `apps/web` never appears in `ci.yml`'s blocking `test:` job (only in `build`/`typecheck`) — the phase's job is to document this split explicitly in `docs/DEVELOPMENT.md` and confirm the residual suite is green (verified live: 10 files / 67 tests / 61 passed + 6 skipped, exactly matching CONTEXT.md's "67 tests" claim, but **only after** rebuilding `packages/crypto`/`core`/`api-client`/`sdk-core`/`sdk` dist — a fresh worktree checkout fails 2 suites on stale/missing dist, a known cross-package staleness issue, not a real regression).

SC3c (two data-integrity races) are both precisely diagnosed in the 68.2 CodeRabbit hardening backlog todo (items 3 and 11) with exact file/line pointers, reproduced below.

**Primary recommendation:** Treat SC1 as the phase's dominant task — budget it as its own multi-plan effort (new standalone entry file + esbuild bundling step + full v3 walk rewrite + un-fixme the e2e spec). Treat SC2/SC3a/SC3b/SC3c as four small, independent, parallelizable plans.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Recovery tool crypto walk (SC1) | Browser / Client (standalone, outside `apps/web/src`) | — | Must run with zero server/API dependency per D-01/D-02; it is a static HTML+JS artifact served from `apps/web/public/`, not part of the React app bundle |
| Recovery tool IPFS/IPNS transport (SC1) | Browser / Client → external gateway (HTTP) | — | Direct `fetch()` to a user-configurable gateway URL; no CipherBox API in the loop (D-04) |
| Download progress UX (SC2) | Browser / Client (React + Zustand) | — | Pure UI state; the actual bytes already flow through `packages/sdk`'s `CipherBoxClient` facade |
| D-07 web/SDK boundary rule (SC3a) | Browser / Client build tooling (ESLint) | CI (lint job) | Static analysis at build time; enforced by the same `pnpm lint` CI job that already exists |
| Web vitest CI scoping (SC3b) | CI / Build tooling | Docs | A CI job-composition decision + a documentation update; no runtime code change |
| Poll-monotonicity fix (SC3c item 3) | Browser / Client (Zustand store write path) | — | `useSyncPolling.ts`'s `invalidateOpenFolder` writes into `folder.store.ts`; the race is purely a client-side ordering bug, not a server/API issue |
| Descent-vs-restore fix (SC3c item 11) | Browser / Client (React hook state + SDK `sharedFolderTree`) | API / Backend (SDK) | The race spans a web hook (`useSharedNavigationActions.ts`) and the SDK's in-memory `sharedFolderTree` active-depth state (`packages/sdk/src/client.ts`); the fix needs a cancellation/generation token threaded through both |

## User Constraints (from CONTEXT.md)

<user_constraints>

### Locked Decisions

- **D-01:** The recovery tool is a **trust-nothing, infra-independent** artifact. Its entire purpose is to recover a vault even if **all** CipherBox API infrastructure disappears. Given only the user's `privateKey`, it walks the IPNS→IPFS link tree and decrypts the whole folder/file tree — as long as the content is still pinned on *some* reachable server.
- **D-02:** **No dependency on the CipherBox API relay or Web3Auth.** This explicitly **rules out the SDK** (`packages/sdk` / `sdk-core` read chain routes IPNS resolve + IPFS fetch through the CipherBox API). Do not import or bundle the SDK read chain into the recovery tool.
- **D-03:** **Reuse the low-level libraries**, bundled into `recovery.html`: `packages/crypto` (AES-256-GCM+AAD seal-open, ECIES unwrap, key derivation from the provided private key) and `packages/core` (Node / `SealedChildRef` / `PublishedNode` codecs, IPNS record parse + verify). The recovery tool implements its **own standalone IPNS/IPFS walk** on top of these primitives — it does not re-implement crypto/codec logic by hand (parity risk), and it does not use the API-coupled walk.
- **D-04:** **IPFS/IPNS access is over HTTP via a configurable gateway URL.** The browser tool cannot run a libp2p node, so it fetches `/ipns/<name>` (resolve) and `/ipfs/<cid>` (content) over HTTP against a user-supplied gateway/pinning-server URL, defaulting to a public gateway (e.g. `ipfs.io` / `dweb.link`). Point it at any server that pins the data. Key derivation, IPNS record verification, and decryption all happen locally in the browser from the pasted `privateKey`.
- **D-05:** **Wire it, don't delete.** Connect `useFileDownload` / `download.store` to real download + restore progress spinners in the UI (the code was scaffolded for this UX; deliver it rather than removing the dead code).
- **D-06:** **Keep apps/web vitest OUT of a blocking CI unit-test job.** The standing architecture holds: reusable logic lives in `packages/sdk` (Vitest, already CI-gated) and UI is covered by Playwright web-e2e. Implement the "decision" by (a) **documenting** the split explicitly, and (b) ensuring the residual `apps/web` `*.test.ts` files either pass or are relocated/removed so nothing rots — do not leave a broken/ignored suite. A green passing web suite exists today (67 tests), but gating CI on it is intentionally declined to avoid inviting UI-coupled unit tests.
- **D-07:** Promote the D-07 write-plane(UUID)/read-plane(ipnsName) boundary from the existing grep gate to a proper **ESLint rule wired into CI**, so violations fail lint rather than a bespoke grep script.
- **D-08:** Fix **only the two named data-integrity races** in this phase — **item 3 (poll-monotonicity)** and **item 11 (descent-vs-restore race)** — each with **e2e coverage**. The remaining open items of the 8-open/1-partial 68.2/73 CodeRabbit backlog are **deferred** (out of this phase's SC), not pulled forward.

### Claude's Discretion

- Exact bundler for the single-file recovery build (esbuild vs vite single-file) — planner/researcher decides, as long as D-02/D-03 hold (low-level libs only, no SDK/API/Web3Auth).
- Precise default gateway value and whether to ship a small curated gateway dropdown — implementation detail under D-04.

### Deferred Ideas (OUT OF SCOPE)

- The remaining open items of the 68.2/73 CodeRabbit hardening backlog beyond items 3 + 11 (cache/freshness/a11y/tests, etc.) — deferred; only the two data-integrity races are in Phase 78 scope (D-08).

</user_constraints>

> **Terminology correction for the planner (important):** The phase's own research brief (and D-07's prose) labels this "the D-07 write-plane(UUID)/read-plane(ipnsName) boundary" — but that description belongs to a **different, already-fully-enforced** D-07 in the Rust/FUSE codebase (`crates/fuse`/`crates/sdk`, phases 69/76 — the `WriteChildRef.child_id` (UUID) vs `SealedChildRef` (ipnsName) pairing invariant; see `.planning/debug/d07-write-plane-pairing.md`). The todo CONTEXT.md actually links (`2026-07-06-d07-boundary-eslint-rule.md`) and the phase's own SC3a wording ("web/SDK boundary...grep gate") both unambiguously point at the **68.2 SDK-READ-04 D-07**: `apps/web/src` must not import `@cipherbox/sdk-core`/`@cipherbox/core` at runtime, and must not call raw IPFS functions. Confirmed against `68.2-SECURITY.md`'s advisory (T-68.2-04) and commit `19f40f040`. **Scope this phase's D-07 work as the web/SDK import boundary, not the Rust write-plane invariant** — the Rust one needs no further work.

## Phase Requirements

No formal `REQUIREMENTS.md` v1 IDs map to this phase (it is a closeout/hardening phase driven by 5 folded todos + 3 Success Criteria, not new v1.x requirements). Use the SC/D identifiers as the requirement keys:

| ID | Description | Research Support |
|----|-------------|------------------|
| SC1 | recovery.html ported to node/v3; recovery.spec.ts un-fixme'd, zero expected e2e failures/skips | Full v3 read-chain algorithm, crypto/core APIs, bundler recommendation, e2e fixture pattern — all below |
| SC2 | `useFileDownload`/`download.store` wired to real download + restore spinners | Exact dead call sites identified (`useFileBrowserActions.ts:413-426,478-491`); restore-spinner gap identified (`useBin.ts`) |
| SC3a | D-07 web/SDK boundary promoted from grep gate to CI-enforced ESLint rule | Exact grep command + ESLint flat-config mechanism below |
| SC3b | apps/web vitest CI decision made + documented | Confirmed already-excluded from CI; live-verified green (67 tests); exact doc insertion point identified |
| SC3c | Item 3 (poll-monotonicity) + item 11 (descent-vs-restore) fixed with e2e coverage | Both races fully traced to exact functions/lines below; rest of backlog confirmed out of scope |

## Standard Stack

### Core

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `@cipherbox/crypto` | 0.33.1 (workspace) | AES-256-GCM(+AAD)/CTR, ECIES wrap/unwrap, Ed25519, IPNS name derive/parse/verify, HKDF key derivation | Already the project's sole crypto primitive layer (D-03); recovery tool must reuse, not hand-roll |
| `@cipherbox/core` | 0.31.1 (workspace) | Node/SealedChildRef/PublishedNode codec (`encode`/`decode`/`seal`/`unseal`), vault v3 blob (de)serialize, vault init | The v3 codec layer; recovery tool must reuse (D-03) |
| `esbuild` | `^0.25` (already transitively present in the lockfile via `tsup`; would become a new **direct** devDependency for the recovery build script) | Bundles the new standalone TS entry (`@cipherbox/crypto` + `@cipherbox/core` + a small walk/UI script) into one self-contained JS file for inlining into `recovery.html` | Repo-wide convention: every package already builds via `tsup` (esbuild-based); adding a second bundler (vite-plugin-singlefile) would be a net-new dependency for no added benefit on a framework-free static page |
| `ipns` (npm) | `^10.1.3` (transitive via `@cipherbox/crypto`) | Real protobuf marshal/unmarshal + delegated-routing-response parsing (`unmarshalIPNSRecord`, `extractPublicKeyFromIPNSRecord`) | Recovery.html today hand-rolls a partial protobuf varint parser (`extractCidFromIpnsRecord`) with **zero signature verification**; pulling in `@cipherbox/crypto`'s `parseIpnsRecord`/`verifyIpnsRecordSignature` is a strict security upgrade, not just a port |
| `fflate` | `0.8.2` (currently CDN-only, `<script src="https://cdn.jsdelivr.net/npm/fflate@0.8.2/umd/index.js">`) | ZIP the recovered files for download | **Recommend adding as an npm devDependency and bundling it too** — see Pitfall 1 below: the tool currently isn't actually infra-independent because it loads 4 libraries from `cdn.jsdelivr.net` at runtime |

### Supporting

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `@typescript-eslint/no-restricted-imports` | bundled in `typescript-eslint@^8.21.0` (already a root devDependency) | ESLint rule with an `allowTypeImports` option (unlike base ESLint's `no-restricted-imports`, which has no TS-aware type-only exemption) | SC3a — enforcing D-07 without also flagging `import type {...}` |
| `no-restricted-syntax` (ESLint core, no new dependency) | bundled with `eslint@^9.18.0` | AST-level ban on specific `CallExpression` callee names (`fetchFromIpfs`/`addToIpfs`/`unpinFromIpfs`) | SC3a Gate B — the raw-IPFS-call check is name-based, not import-based, so `no-restricted-imports` alone can't replicate it |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| esbuild for the recovery bundle | `vite-plugin-singlefile` | Vite's plugin inlines CSS/assets more automatically and matches `apps/web`'s existing Vite toolchain, but recovery.html has zero CSS-module/JSX needs and adds a new devDependency + Vite config just for one static page; esbuild's `--bundle` + a tiny Node script to splice the output into the HTML `<script>` tag is simpler and matches the tsup/esbuild convention used by every other package in the repo |
| `@typescript-eslint/no-restricted-imports` for Gate B (raw IPFS calls) | Manual `no-restricted-syntax` regex over `CallExpression.callee.name` | Import-based rules only catch a *reintroduced* `lib/api/ipfs.ts`-shaped import; they don't catch a freshly-inlined raw-fetch call under a different name. Both mechanisms are needed together to fully replicate the two-gate grep script |

**Installation:**

```bash
pnpm --filter @cipherbox/web add -D esbuild fflate
```

(`typescript-eslint`/`eslint` are already root devDependencies — no install needed for SC3a.)

**Version verification:** `esbuild@0.25.12`/`0.27.2` and `typescript-eslint@8.21.0`/`eslint@9.18.0` confirmed present via `pnpm-lock.yaml` grep and `package.json` inspection during this research session `[VERIFIED: pnpm-lock.yaml, root package.json]`. `fflate@0.8.2` confirmed only as a CDN reference inside `recovery.html` today — not yet an npm dependency anywhere in the repo `[VERIFIED: grep across package.json files]`.

## Package Legitimacy Audit

Only `fflate` and `esbuild` are being newly proposed as **direct** dependencies (both are already transitively present in the dependency graph today, so this is a promotion, not a novel supply-chain addition).

| Package | Registry | Age | Downloads | Source Repo | Verdict | Disposition |
|---------|----------|-----|-----------|-------------|---------|-------------|
| `esbuild` | npm | 6+ yrs | very high (tens of millions/week) | github.com/evanw/esbuild | [OK] — already transitively resolved in `pnpm-lock.yaml` at 0.25.12/0.27.2 | Approved (promote to direct devDependency) |
| `fflate` | npm | 5+ yrs | very high (tens of millions/week) | github.com/101arrowz/fflate | [OK] — already referenced (CDN) and is a well-known, audited zip library | Approved (promote from CDN script tag to bundled npm devDependency) |

**Packages removed due to [SLOP] verdict:** none.
**Packages flagged as suspicious [SUS]:** none.

Both packages are **already in production use** in this exact file (`fflate` via CDN, `esbuild` transitively via every `tsup` build in the monorepo) — this audit is a formality confirming no new supply-chain risk is introduced by making them explicit.

## Architecture Patterns

### System Architecture Diagram

```
                     ┌─────────────────────────────────────────────┐
                     │   apps/web/public/recovery.html (NEW v3)      │
                     │   (static file, NOT part of apps/web/src)     │
                     └─────────────────────────────────────────────┘
User pastes                    │
privateKey (hex) ───────────▶  │ 1. deriveVaultIpnsKeypair(privateKey)
                                │    deriveVaultKeyIpnsKeypair(privateKey)
                                │    (packages/crypto — UNCHANGED from v2)
                                ▼
                     ┌─────────────────────────────────────────────┐
                     │  fetch(`${gateway}/routing/v1/ipns/<name>`)   │───▶ external IPFS gateway
                     │  parseIpnsRecord() + verifyIpnsRecordSignature│    (user-configurable URL,
                     │  (packages/crypto — NEW: real verification)   │     default public gateway)
                     └─────────────────────────────────────────────┘
                                │ CID (from vaultKeyIpnsName)
                                ▼
                     ┌─────────────────────────────────────────────┐
                     │  fetch(`${gateway}/ipfs/<cid>`)               │───▶ external IPFS gateway
                     │  deserializeVaultBlobV3() (packages/core)     │
                     │  unwrapKey() x2 (ECIES, packages/crypto)      │
                     │  → rootReadKey, rootWriteKey                  │
                     └─────────────────────────────────────────────┘
                                │
                                │ 2. resolve rootIpnsName (from deriveVaultIpnsKeypair)
                                ▼
                     ┌─────────────────────────────────────────────┐
                     │  fetch CID → PublishedNode envelope (JSON)    │
                     │  unsealNode(published, rootReadKey)           │
                     │  (packages/core) → Node{kind:'root',children} │
                     └─────────────────────────────────────────────┘
                                │
                                ▼  recursive walk (mirrors packages/sdk/
                     ┌─────────────────────────────────────────────┐   src/folder-listing.ts::resolveChildren)
                     │  FOR each SealedChildRef in node.children:    │
                     │    a. resolve childRef.ipnsName → CID → fetch │
                     │       PublishedNode envelope (plaintext id/   │
                     │       kind/generation)                        │
                     │    b. unsealChildReadKey(childRef.readKeySealed,│
                     │       parentReadKey, published.id,             │
                     │       published.kind, childRef.generation)     │◀── generation MUST be the
                     │       → childReadKey                           │    PARENT MIRROR, never
                     │    c. unsealNode(published, childReadKey)      │    published.generation
                     │       → child Node (folder: recurse;           │    (§2.6 rule — AEAD fails
                     │         file: has node.content inline)         │    if you get this wrong)
                     └─────────────────────────────────────────────┘
                                │ file node reached
                                ▼
                     ┌─────────────────────────────────────────────┐
                     │  node.content = { cid, fileIv (base64),       │
                     │  fileKey (raw 32B, already unsealed inline —  │
                     │  NOT ECIES!), encryptionMode, versions[] }    │
                     │  fetch(`${gateway}/ipfs/${content.cid}`)      │
                     │  decryptAesGcm/decryptAesCtr(ciphertext,      │
                     │  content.fileKey, base64ToBytes(content.fileIv))│
                     └─────────────────────────────────────────────┘
                                │
                                ▼
                     ┌─────────────────────────────────────────────┐
                     │  fflate.zipSync(recoveredFiles) → download    │
                     └─────────────────────────────────────────────┘
```

### Recommended Project Structure

```
apps/web/
├── recovery-src/                 # NEW — standalone entry point, OUTSIDE apps/web/src
│   ├── main.ts                   # UI wiring (DOM event handlers, port of the current <script> body)
│   ├── walk.ts                   # recursive IPNS/IPFS walk (mirrors folder-listing.ts::resolveChildren)
│   ├── gateway.ts                # fetch-based resolveIpns()/fetchFromIpfs() against a configurable gateway URL
│   └── build.ts                  # esbuild.build({...}) script, invoked by a new package.json script
├── public/
│   └── recovery.html             # template with a `<!-- RECOVERY_BUNDLE -->` placeholder the build
│                                   # script substitutes with the bundled <script> tag content
```

Keeping `recovery-src/` **outside** `apps/web/src/` is deliberate: it means the D-07 ESLint rule (SC3a), which is scoped to `apps/web/src/**`, never has to special-case an intentional `@cipherbox/core` import in the recovery tool.

### Pattern 1: Recursive folder walk (mirror `resolveChildren`)

**What:** For each `SealedChildRef` in a folder's `children`, resolve the child's own `PublishedNode`, unseal its `readKey` under the parent's `readKey` using the **parent-mirror generation** (`childRef.generation`, never `published.generation`), then `unsealNode` the child.

**When to use:** This is the ONLY correct way to walk the v3 tree. Any deviation on the generation-source rule causes an AEAD auth-tag failure (hard fail, not silent corruption).

**Example:**

```typescript
// Source: packages/sdk/src/folder-listing.ts:87-127 (resolveChildren) — port this
// algorithm verbatim into recovery-src/walk.ts, swapping gatedResolve (SDK/API-backed)
// for a plain gateway fetch + parseIpnsRecord + fetchFromIpfs + JSON.parse.
for (const childRef of node.children ?? []) {
  const publishedBytes = await fetchFromGateway(childRef.ipnsName, gatewayConfig); // NEW: gateway-only resolve
  const published: PublishedNode = JSON.parse(new TextDecoder().decode(publishedBytes));

  const childReadKey = await unsealChildReadKey(
    childRef.readKeySealed,
    parentReadKey,
    published.id,        // from the freshly-fetched child envelope
    published.kind,       // from the freshly-fetched child envelope
    childRef.generation   // PARENT MIRROR — never published.generation (§2.6 rule)
  );
  const childNode = await unsealNode(published, childReadKey);
  if (childNode.kind === 'file') {
    // childNode.content.fileKey is already a raw Uint8Array — no ECIES unwrap needed here
    // (that only happens once, at the vault-key-blob step, for rootReadKey/rootWriteKey).
  } else {
    await recoverFolder(childNode, childReadKey, ...); // recurse
  }
}
```

### Pattern 2: Gateway-only IPNS resolve with real verification

**What:** Replace `recovery.html`'s hand-rolled `resolveIpns()`/`extractCidFromIpnsRecord()` (protobuf varint parser with **zero signature verification**) with `@cipherbox/crypto`'s `parseIpnsRecord`/`verifyIpnsRecordSignature`.

**When to use:** Every IPNS resolve step in the new tool (vault key blob, root folder, every folder/file child).

**Example:**

```typescript
// Source: packages/crypto/src/ipns/parse-record.ts, verify-record.ts (@cipherbox/crypto exports)
async function resolveIpnsVerified(ipnsName: string, gatewayUrl: string): Promise<string> {
  const resp = await fetch(`${gatewayUrl}/routing/v1/ipns/${ipnsName}`, {
    headers: { Accept: 'application/vnd.ipfs.ipns-record' },
  });
  if (!resp.ok) throw new Error(`IPNS resolve failed: ${resp.status}`);
  const marshalledRecord = new Uint8Array(await resp.arrayBuffer());

  // Self-verifying: recovers the Ed25519 pubkey FROM the name itself (no trusted
  // third-party pubkey needed) — publicKeyFromIpnsName is folded into this call.
  const valid = await verifyIpnsRecordSignature(ipnsName, marshalledRecord);
  if (!valid) throw new Error('IPNS record signature verification failed — possible tampering');

  const parsed = await parseIpnsRecord(marshalledRecord);
  return parsed.value.startsWith('/ipfs/') ? parsed.value.slice(6) : parsed.value;
}
```

Keep `recovery.html`'s existing gateway-fallback chain (delegated-routing → `/ipns/` HEAD → Kubo `/api/v0/name/resolve`) as a **fallback ladder**, but run `verifyIpnsRecordSignature` only on the primary (delegated-routing, protobuf) path — the HEAD/`X-Ipfs-Roots` and Kubo JSON fallbacks don't carry a verifiable signature, matching the existing v2 tool's graceful-degradation design.

### Pattern 3: D-07 ESLint rule (flat config, scoped override)

**What:** A new config object appended to the existing `eslint.config.js` array, scoped to `apps/web/src/**` only, replicating the two-gate grep script from `68.2-11-PLAN.md` Task 2.

**When to use:** SC3a.

**Example:**

```javascript
// Source: eslint.config.js (existing root flat config) — new entry to append
// Gate A: replicates `grep -rnE "from .@cipherbox/(sdk-core|core)." apps/web/src
//          | grep -vE "import type \{" | grep -vE "import \{( *type [A-Za-z0-9_]+,?)+ *\}"`
{
  files: ['apps/web/src/**/*.{ts,tsx}'],
  ignores: ['apps/web/src/**/__tests__/**'],
  rules: {
    '@typescript-eslint/no-restricted-imports': [
      'error',
      {
        patterns: [
          {
            group: ['@cipherbox/sdk-core', '@cipherbox/core'],
            message:
              'apps/web/src must not import runtime bindings from @cipherbox/sdk-core or ' +
              '@cipherbox/core (D-07 boundary) — use the @cipherbox/sdk facade instead.',
            allowTypeImports: true,
          },
        ],
      },
    ],
    // Gate B: replicates
    // `grep -rln "fetchFromIpfs|addToIpfs|unpinFromIpfs|lib/api/ipfs" apps/web/src`
    'no-restricted-syntax': [
      'error',
      {
        selector:
          'CallExpression[callee.name=/^(fetchFromIpfs|addToIpfs|unpinFromIpfs)$/]',
        message: 'Raw IPFS calls are forbidden in apps/web/src (D-07) — use the SDK client facade.',
      },
    ],
  },
},
```

**Verification note (MEDIUM confidence, flag for the implementer):** `@typescript-eslint/no-restricted-imports`'s `allowTypeImports` option is documented to suppress the rule for `import type {...}` declarations; its behavior on a **mixed** named-import block like `import { type Foo, bar } from '@cipherbox/sdk-core'` (which should still fail — `bar` is a runtime binding) has not been runtime-verified in this research session. The implementer must write a one-off test fixture and run `eslint --no-eslintrc -c eslint.config.js <fixture>` before trusting this to fully replicate the existing grep gate's mixed-import handling `[ASSUMED]`. If it under- or over-fires, fall back to a `no-restricted-syntax` `ImportDeclaration` selector matching `source.value` + `specifiers` that are not all `ImportSpecifier[importKind=type]`.

### Anti-Patterns to Avoid

- **Hand-rolling the AAD/generation logic instead of calling `unsealChildReadKey`/`unsealNode` directly:** the v2 tool's entire `eciesDecrypt`/`decryptFolderMetadata` custom implementation is exactly the parity risk D-03 exists to prevent. Every seal/unseal call in the new tool must be a bare passthrough to the `@cipherbox/core`/`@cipherbox/crypto` exports — no reimplementation.
- **Using `published.generation` instead of `childRef.generation` in `unsealChildReadKey`:** silently produces an AEAD auth failure that looks like corrupted data, not like a bug in the caller. This is the single most likely mistake when porting the walk.
- **Bundling the SDK read chain (`resolveIpnsRecord` from `sdk-core`) instead of a raw gateway fetch:** that function calls `ipnsControllerResolveRecord`, which is an API-client-generated call that hits the CipherBox API — directly violating D-02.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| AES-256-GCM/AAD seal-open | Custom WebCrypto wrapper | `sealAesGcmAad`/`unsealAesGcmAad`/`buildNodeAad` from `@cipherbox/crypto` | Parity with the Rust twin + cross-language KAT; hand-rolled AAD construction is exactly the class of bug the KAT exists to catch |
| ECIES unwrap | Custom secp256k1/HKDF/AES-GCM composition (what v2 recovery.html does today, 40+ lines) | `unwrapKey` from `@cipherbox/crypto` | v2's hand-rolled `eciesDecrypt` duplicates `eciesjs`'s exact wire format by hand; a single upstream change to the ECIES envelope would silently desync the two implementations |
| IPNS protobuf record parsing | Custom varint/field parser (what v2's `extractCidFromIpnsRecord` does, with zero signature check) | `parseIpnsRecord`/`verifyIpnsRecordSignature` from `@cipherbox/crypto` (backed by the `ipns` npm package) | The v2 hand-rolled parser has **no signature verification at all** — a compromised/malicious gateway could return any CID. Reusing the real parser is both a port AND a security fix |
| Node/SealedChildRef/PublishedNode codec | Custom JSON shape assumptions | `decodeReadBody`/`unsealNode`/`unsealChildReadKey` from `@cipherbox/core` | The v3 wire format's field order and AAD binding are load-bearing (D-04 tamper-evidence); only the shipped codec is guaranteed byte-compatible with what the API actually publishes |

**Key insight:** every primitive the recovery tool needs already exists in `packages/crypto`/`packages/core` and is used by the exact same read-chain the production app uses (`packages/sdk/src/folder-listing.ts`). The only genuinely new code in this phase is the **transport substitution** (gateway HTTP fetch instead of API-relayed resolve) and the **UI/bundling glue** — never the crypto/codec logic itself.

## Common Pitfalls

### Pitfall 1: The "infra-independent" tool currently depends on jsdelivr CDN

**What goes wrong:** `recovery.html` today loads `@noble/curves`, `@noble/hashes`, `@noble/ed25519` via `https://cdn.jsdelivr.net/npm/.../+esm` ESM imports and `fflate` via a CDN UMD `<script>` tag. If `cdn.jsdelivr.net` is unreachable (exactly the kind of "all infra gone" scenario D-01 is designed for), the tool fails to even load, defeating its purpose.
**Why it happens:** The tool predates the crypto/core packages' existence and was written as a zero-build, drop-anywhere HTML file.
**How to avoid:** Bundle every dependency (including `fflate`) into the single output script via esbuild so the final `recovery.html` needs only the user-configured IPFS gateway — no other network dependency.
**Warning signs:** Any `<script src="https://cdn...">` or `import ... from 'https://cdn...'` remaining in the shipped `recovery.html`.

### Pitfall 2: Generation-source confusion in `unsealChildReadKey`

**What goes wrong:** Passing the freshly-resolved child's own `published.generation` instead of the parent's `childRef.generation` mirror causes every child unseal to throw (AEAD tag mismatch), which looks exactly like "the vault is corrupted" to a panicking recovery-tool user.
**Why it happens:** It's intuitive to think "use the freshest/most-authoritative value," but the AAD was sealed using the parent's mirror at share/link-creation time — the child's own generation may have since advanced (rotation) without the parent's `SealedChildRef.readKeySealed` being re-sealed.
**How to avoid:** Copy the exact call pattern from `packages/sdk/src/folder-listing.ts:101-107` (reproduced in Pattern 1 above), including its inline comment `// parent mirror -- NEVER published.generation`.
**Warning signs:** Every folder/file below the root fails to decrypt while the root itself decrypts fine (the root has no parent mirror, so this specific bug can't manifest at the root level).

### Pitfall 3: Cross-package dist staleness silently breaks apps/web vitest

**What goes wrong:** A fresh worktree checkout (no `packages/*/dist` built) makes `apps/web` vitest fail 2 of 10 suites with `Failed to resolve entry for package "@cipherbox/sdk"` / `"@cipherbox/crypto"` — this looks like a real regression but is purely a missing-build-artifact issue.
**Why it happens:** `apps/web`'s vitest resolves workspace packages through their `dist/` output (via `package.json` `main`/`module`/`exports`), not through source — and `pnpm install` alone does not build packages.
**How to avoid:** Before evaluating "is the residual apps/web suite green" for SC3b, run `pnpm --filter @cipherbox/crypto build && pnpm --filter @cipherbox/core build && pnpm --filter @cipherbox/api-client build && pnpm --filter @cipherbox/sdk-core build && pnpm --filter @cipherbox/sdk build` first (verified live in this research session — went from 2 failed / 8 passed to 10 passed / 67 tests after this build chain).
**Warning signs:** `Failed to resolve entry for package "@cipherbox/*"` errors in vitest output on a fresh checkout.

### Pitfall 4: Confusing the two unrelated "D-07"s in this codebase

**What goes wrong:** Implementing an ESLint rule for the Rust `WriteChildRef.child_id`/`SealedChildRef.ipnsName` pairing invariant (already fully enforced, in Rust, unrelated tooling) instead of the actual locked scope: the TypeScript `apps/web/src` ↔ `@cipherbox/sdk-core`/`@cipherbox/core` import boundary.
**Why it happens:** Both invariants share the label "D-07" because they were numbered independently within their own phase's `CONTEXT.md` decision lists (phase 69/76 for the Rust one, phase 68.2/78 for the web one) — the label collision is coincidental, not a versioning relationship.
**How to avoid:** Anchor on the todo file (`2026-07-06-d07-boundary-eslint-rule.md`) and `68.2-SECURITY.md`'s T-68.2-04 advisory — both are unambiguous about scope (`apps/web/.eslintrc.cjs`-adjacent, `sdk-core`/`core` imports, raw IPFS calls).
**Warning signs:** Any plan task that mentions `crates/fuse`, `WriteChildRef`, or `uuid_from_ino` in the context of this phase's D-07 work — that's the wrong D-07.

## Runtime State Inventory

> Not applicable — this phase is not a rename/refactor/migration phase. No stored data, live service config, OS-registered state, secrets, or build artifacts carry a renamed identifier. (SC1 does involve a *format* migration — v2 → v3 vault blob parsing — but that is new-code-writes-new-format, not a rename of an existing identifier across the codebase; there is no v2 production data to migrate per REQUIREMENTS.md's "Data migration / dual-codec bridge" Out-of-Scope entry — greenfield node/v3, no prod data.)

## Code Examples

### Deriving the vault key blob and root folder IPNS names (UNCHANGED from v2)

```typescript
// Source: packages/crypto/src/vault/derive-ipns.ts:44-113 (deriveVaultIpnsKeypair,
// deriveVaultKeyIpnsKeypair) — call these directly instead of recovery.html's
// hand-rolled HKDF+Ed25519 derivation (the constants and algorithm are byte-identical,
// but calling the real function eliminates a second hand-maintained copy).
import { deriveVaultIpnsKeypair, deriveVaultKeyIpnsKeypair } from '@cipherbox/crypto';

const rootKeypair = await deriveVaultIpnsKeypair(privateKeyBytes);       // .ipnsName = root folder
const vaultKeyKeypair = await deriveVaultKeyIpnsKeypair(privateKeyBytes); // .ipnsName = key blob
```

### Decrypting the v3 vault key blob

```typescript
// Source: packages/core/src/vault/blob.ts (deserializeVaultBlobV3) +
// packages/crypto's unwrapKey (ECIES) — packages/sdk-core/src/vault/index.ts:83-99
// (loadVaultKeyBlob) is the reference call sequence to mirror.
import { deserializeVaultBlobV3 } from '@cipherbox/core';
import { unwrapKey } from '@cipherbox/crypto';

const { encryptedRootReadKey, encryptedRootWriteKey } = deserializeVaultBlobV3(blobBytes);
const rootReadKey = await unwrapKey(encryptedRootReadKey, privateKeyBytes);
// rootWriteKey is NOT needed for a read-only recovery tool — the tool only ever
// calls unsealNode(published, readKey) with no writeKey argument (write-body
// unsealing is skipped entirely; recovery is read-only by design).
```

### Unsealing the root Node and recursing

```typescript
// Source: packages/core/src/node/seal.ts:121-151 (unsealNode) — this single call
// replaces recovery.html's decryptFolderMetadata/decryptFileMetadata pair, because
// v3's unsealNode handles BOTH folder (children[]) and file (content) kinds uniformly.
import { unsealNode } from '@cipherbox/core';

const rootPublished: PublishedNode = JSON.parse(new TextDecoder().decode(rootEnvelopeBytes));
const rootNode = await unsealNode(rootPublished, rootReadKey); // no writeKey arg — read-only
// rootNode.kind === 'root', rootNode.children: SealedChildRef[]
```

## State of the Art

| Old Approach (v2, current recovery.html) | Current Approach (v3, target) | When Changed | Impact |
|--------------------------------------------|-------------------------------|---------------|--------|
| `{iv,data}` JSON folder-metadata envelope, per-child `folderKeyEncrypted`/`fileMetaIpnsName`/`fileKeyEncrypted` fields with ECIES-only wrapping | `PublishedNode` envelope (`readSealed`/`writeSealed` base64) + `SealedChildRef.readKeySealed` (AES-GCM+AAD, symmetric, no per-descendant ECIES fan-out) | Phase 62-63 (v2.0 Metadata and Sharing Refactor) | Recovery tool's entire crypto call graph must be rewritten — this is not a compatible superset |
| Hand-rolled protobuf IPNS record parser, zero signature verification | `parseIpnsRecord`/`verifyIpnsRecordSignature` from `@cipherbox/crypto`, backed by the real `ipns` npm package | Available since `@cipherbox/crypto` was extracted (Phase 19.1), never adopted by `recovery.html` | Genuine security hardening opportunity bundled into this port, not just a compatibility fix |
| CDN-loaded `@noble/*`/`fflate` at runtime | Bundled via esbuild into a single self-contained script | This phase (proposed) | Tool becomes ACTUALLY infra-independent (Pitfall 1) |

**Deprecated/outdated:**

- v2 vault blob format (`BLOB_V2_VERSION = 0x02`, single ECIES-wrapped `rootFolderKey`): fully superseded by `BLOB_V3_VERSION = 0x03` (two independent keys, `rootReadKey`+`rootWriteKey`). No v2 production data exists to migrate (greenfield v2.0 cutover, per REQUIREMENTS.md).
- `FolderMetadata`/`FileMetadata`/`FilePointer`/`FolderEntry` legacy types: replaced by the unified `Node` discriminated union (NODE-01..NODE-06, Phase 62).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | `@typescript-eslint/no-restricted-imports`'s `allowTypeImports` option correctly distinguishes fully-typed inline named imports (`import { type Foo }`) from mixed imports (`import { type Foo, bar }`), matching the existing grep gate's behavior | Architecture Patterns → Pattern 3 | If it doesn't, the ESLint rule could either (a) false-negative on a mixed import that should be flagged, silently weakening the D-07 gate, or (b) false-positive on legitimate `import type` usage, blocking unrelated PRs. Verify with a throwaway fixture file before wiring into CI. |
| A2 | The default public IPFS gateway to ship (`ipfs.io`/`dweb.link`, matching the current recovery.html defaults) remains reachable and suitable — CONTEXT.md left this as Claude's discretion, not user-confirmed | Standard Stack / D-04 (Claude's Discretion) | Low risk — this is explicitly discretionary and the current defaults (`https://ipfs.io` for IPFS, `https://delegated-ipfs.dev` for IPNS routing) are already live in `recovery.html` and the e2e spec's fallback env vars; no change needed unless the planner wants to revisit |

**If this table is empty:** N/A — see entries above; both are low-severity and don't block planning.

## Open Questions

1. **Does `packages/crypto`'s dependency tree (`@libp2p/crypto`, `@libp2p/peer-id`, `multiformats`, `ipns`) bundle cleanly and at a reasonable size via esbuild for a browser target?**
   - What we know: These packages are already consumed by `packages/sdk`/`packages/sdk-core`, which DO ship to the browser (as part of the `apps/web` Vite bundle, via the `@cipherbox/sdk` facade) — so browser-compatibility is proven in principle.
   - What's unclear: The recovery tool bundles `@cipherbox/crypto`+`@cipherbox/core` **directly** (not via the SDK, per D-02), and esbuild (not Vite) is the proposed bundler — untested combination. Bundle size could be substantial (the `ipns`/`multiformats`/`@libp2p/*` stack is not tiny) for what's meant to be a single lightweight HTML file.
   - Recommendation: First plan task for SC1 should be a spike — `esbuild --bundle recovery-src/main.ts --format=esm --outfile=/tmp/test.js` and inspect the output size/errors before committing to the full walk rewrite.

2. **Does the existing e2e spec's `RECOVERY_IPFS_GATEWAY`/`RECOVERY_IPNS_GATEWAY` env-var pattern (localhost:8080 Kubo gateway + localhost:3001 delegated routing, from `tests/web-e2e/tests/recovery.spec.ts:17-26`) still work unmodified for v3, or does un-fixme'ing require any test-harness changes beyond removing `test.fixme`?**
   - What we know: The `beforeAll` seeds a test account and uploads one file via `account.client.uploadFile(...)` (the real SDK, which now produces v3-format data) — so the fixture itself is already v3-correct; only the recovery tool's own parsing needs to change.
   - What's unclear: Whether the 90s `RECOVERY_TIMEOUT_MS` budget and the `data-testid` selectors (`recovery-key-input`, `recovery-ipfs-gateway`, `recovery-ipns-gateway`, `recovery-start-btn`, `recovery-progress-log`, `recovery-download-btn`) all still apply unchanged to a rewritten UI — likely yes if the new `recovery.html`'s DOM structure is preserved, but this must be verified once the new tool is built.
   - Recommendation: Keep the existing DOM ids/testids stable when rewriting the `<script>` internals; only swap the crypto/walk logic, not the UI shell — this keeps `recovery.spec.ts` needing only the `test.fixme` removal, not a rewrite.

## Environment Availability

> No new external service/tool dependency is introduced by this phase (esbuild and fflate are npm devDependencies, not external services; the recovery tool's gateway is user-configured at runtime, not a build-time or CI-time dependency). Skipping this section per the stated skip condition — this phase is code/config-only aside from the two new npm devDependencies already covered in Standard Stack.

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | Playwright (`@playwright/test`) for e2e; Vitest for `apps/web` unit (non-blocking, D-06) |
| Config file | `tests/web-e2e/playwright.config.ts` (e2e); `apps/web/vite.config.ts` (vitest, via Vite's `test` field — not separately located in this session but confirmed present via `pnpm vitest run` working directly) |
| Quick run command | `cd apps/web && pnpm vitest run` (unit, ~0.5s once dist is built); `pnpm --filter @cipherbox/web-e2e test -- recovery.spec.ts` (single e2e spec) |
| Full suite command | `pnpm test:web-e2e` (root script, all 21 specs, ~14min wall-clock per `playwright.config.ts` comments, 3 CI workers) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SC1 | recovery.html recovers a v3 vault via IPFS-direct gateway walk, zero API dependency | e2e | `pnpm --filter @cipherbox/web-e2e test -- recovery.spec.ts` | ✅ (currently `test.fixme`; un-fixme as the phase's exit criterion) |
| SC2 | Download/restore actions show progress spinners | e2e (manual UI assertion; no apps/web unit tests per D-06) | Puppeteer/manual per CLAUDE.md UI-verification convention; no automated Playwright assertion currently targets spinner visibility — plan should add one if practical | ❌ Wave 0 gap (no existing spec asserts on download/restore spinner DOM state) |
| SC3a | `apps/web/src` cannot import `sdk-core`/`core` at runtime, or call raw IPFS functions | lint (CI) | `pnpm lint` (after the new ESLint rule is added) | ✅ Rule wiring is new; lint command itself already exists and runs in CI |
| SC3b | Residual `apps/web` `*.test.ts` suite passes | unit | `cd apps/web && pnpm vitest run` (after `pnpm --filter @cipherbox/{crypto,core,api-client,sdk-core,sdk} build`) | ✅ (10 files, 67 tests, live-verified green in this session) |
| SC3c item 3 | A slow poll response never overwrites a newer nav-triggered folder state | e2e (new spec needed) | New spec under `tests/web-e2e/tests/` — pattern per `shared-folder-desync.spec.ts` | ❌ Wave 0 gap |
| SC3c item 11 | A fast navigateUp/breadcrumb click during an in-flight subfolder descent never leaves the SDK's active writeKey pointed at the wrong depth | e2e (new spec needed) | New spec under `tests/web-e2e/tests/` — extend `writable-shares.spec.ts` or add a dedicated spec | ❌ Wave 0 gap |

### Sampling Rate

- **Per task commit:** `pnpm lint` (SC3a), `cd apps/web && pnpm vitest run` (SC3b/SC2 regressions), targeted single-spec Playwright run for the touched area
- **Per wave merge:** `pnpm --filter @cipherbox/web-e2e test -- recovery.spec.ts` + the two new races' specs
- **Phase gate:** Full `pnpm test:web-e2e` (all 21 specs) green with **zero** `test.fixme`/`test.skip` remaining — verified via `grep -rn "fixme\|\.skip(" tests/web-e2e/tests/*.spec.ts` returning nothing (currently returns only `recovery.spec.ts`'s single `test.fixme` plus two unrelated comment mentions in `rotation-ux.spec.ts` and `shared-folder-desync.spec.ts` that are NOT actual fixme/skip calls — confirmed by direct read).

### Wave 0 Gaps

- [ ] New e2e spec for SC3c item 3 (poll-monotonicity) — no existing spec covers this race.
- [ ] New e2e spec for SC3c item 11 (descent-vs-restore) — the todo explicitly says "add a descend-then-immediately-up race case" to `writable-shares.spec.ts`/`shared-folder-desync.spec.ts`; treat as a new test case, possibly in one of those existing files rather than a wholly new file.
- [ ] SC2's spinner-visibility assertion: no existing Playwright spec asserts on `useDownloadStore`/`isDownloading`-driven DOM state; per CLAUDE.md, Puppeteer/manual verification is an acceptable substitute if a Playwright assertion is impractical within this phase's scope, but flag explicitly in VERIFICATION.md either way.
- [ ] `esbuild` build-size/compatibility spike for the recovery bundle (Open Question 1) — not a test file, but a pre-implementation validation step that should happen before the full SC1 plan is written in detail.

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no | Recovery tool has no auth concept — the private key IS the credential, entered directly |
| V3 Session Management | no | No session; single-page, single-use tool |
| V4 Access Control | no | N/A — self-service recovery by definition requires only the key |
| V5 Input Validation | yes | Private-key hex parsing (32-byte length check, already present in v2 tool — carry forward), gateway URL validation (currently accepts any URL — SSRF is a pre-existing, accepted design tradeoff since the user explicitly configures their own trusted gateway) |
| V6 Cryptography | yes | Every primitive must come from `@cipherbox/crypto`/`@cipherbox/core` (Don't Hand-Roll table) — never hand-rolled AES/ECIES/HKDF |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Malicious/compromised gateway returns a tampered IPNS record | Tampering | `verifyIpnsRecordSignature` (self-verifying against the IPNS name's embedded pubkey) — a genuine hardening over the v2 tool, which had none |
| Malicious/compromised gateway returns tampered IPFS content (wrong CID's bytes) | Tampering | AES-GCM auth-tag verification during `unsealNode`/`decryptAesGcm` fails closed on any content tampering — this is inherent to the sealed-envelope design and needs no new code, just correct reuse of `unsealNode` |
| Private key exposure via browser history/autofill/clipboard | Info Disclosure | Existing v2 tool already sets `autocomplete="off"` on the key textarea and displays a post-recovery note to clear browser history — carry forward unchanged; do not add `localStorage`/`sessionStorage` persistence of the key (CLAUDE.md Critical Security Rule 1) |
| Gateway URL pointing at an internal/private network address (SSRF-adjacent) | — | Accepted risk, unchanged from v2 — the tool is explicitly user-configured and run entirely client-side in the user's own browser; there is no server-side fetch to protect. Not equivalent to the TEE-migration SSRF protection (that's a server-side concern, N/A here) |

## Sources

### Primary (HIGH confidence)

- `apps/web/public/recovery.html` (full read, 1266 lines) — current v2 implementation, every function traced
- `tests/web-e2e/tests/recovery.spec.ts` — the fixme'd spec, fixture/assertion pattern
- `packages/crypto/src/index.ts`, `packages/crypto/src/vault/derive-ipns.ts`, `packages/crypto/src/ipns/parse-record.ts`, `packages/crypto/src/ipns/verify-record.ts`, `packages/crypto/src/ipns/derive-name.ts` — exact exported function signatures
- `packages/core/src/index.ts`, `packages/core/src/node/types.ts`, `packages/core/src/node/seal.ts`, `packages/core/src/node/encode.ts`, `packages/core/src/vault/init.ts`, `packages/core/src/vault/blob.ts` — exact codec signatures and wire format
- `packages/sdk/src/folder-listing.ts` (full read) — the canonical read-chain walk algorithm to mirror
- `packages/sdk-core/src/vault/index.ts`, `packages/sdk-core/src/ipns/index.ts` — confirms the API-coupled path the recovery tool must NOT use
- `apps/web/src/hooks/useFileDownload.ts`, `apps/web/src/stores/download.store.ts`, `apps/web/src/components/file-browser/useFileBrowserActions.ts`, `apps/web/src/components/file-browser/FileBrowser.tsx`, `apps/web/src/services/download.service.ts`, `apps/web/src/hooks/useBin.ts` — full trace of the SC2 dead-wiring bug
- `.planning/todos/pending/2026-07-06-d07-boundary-eslint-rule.md`, `.planning/phases/68.2-sdk-owned-read-chain-and-resolved-folder-listings/68.2-SECURITY.md`, `.planning/phases/68.2-sdk-owned-read-chain-and-resolved-folder-listings/68.2-11-PLAN.md`, `68.2-11-SUMMARY.md` — exact D-07 grep gate commands, verified against git history (commit `19f40f040`)
- `.planning/debug/d07-write-plane-pairing.md` — confirms the OTHER (Rust) D-07 is unrelated
- `eslint.config.js` (root flat config, full read) — confirms flat-config mechanism and current rule set
- `.github/workflows/ci.yml` (Test job, lines 266-345) — confirms `apps/web` absent from the blocking test job
- `.github/workflows/web-e2e.yml` — confirms `workflow_dispatch`/`workflow_call` triggers only (not PR-blocking)
- `.planning/todos/pending/2026-07-06-68.2-coderabbit-hardening-backlog.md` — full items 1-11 enumeration, items 3 and 11 verbatim
- `apps/web/src/hooks/useSyncPolling.ts` (full read) — exact poll-monotonicity race location
- `apps/web/src/hooks/useSharedNavigationActions.ts` (lines 340-620) — exact descent-vs-restore race location
- `apps/web/src/stores/folder.store.ts` (subscribeToSdk handler) — the existing sequence-guard pattern to replicate for the item-3 fix
- `tests/web-e2e/tests/shared-folder-desync.spec.ts` (first 70 lines) — reference pattern for a new multi-account e2e spec
- Live command execution in this session: `pnpm --filter @cipherbox/{crypto,core,api-client,sdk-core,sdk} build` + `cd apps/web && pnpm vitest run` — confirmed 10 files / 67 tests / 61 passed + 6 skipped, and confirmed the dist-staleness failure mode and its fix
- `docs/DEVELOPMENT.md` (Testing section, lines 112-148) — exact insertion point for the D-06 documentation

### Secondary (MEDIUM confidence)

- `@typescript-eslint/no-restricted-imports`'s `allowTypeImports` behavior on mixed-type-and-value named imports — based on training knowledge of the TS-ESLint rule's documented options, not verified against this exact ESLint/typescript-eslint version pairing in this session (see Assumption A1)

### Tertiary (LOW confidence)

- None — all other claims in this document were verified directly against the checked-out source in this session.

## Metadata

**Confidence breakdown:**

- Standard stack: HIGH — every package/version confirmed via direct `pnpm-lock.yaml`/`package.json` inspection or live build execution
- Architecture: HIGH — the exact walk algorithm and every seal/unseal call was read from source, not inferred
- Pitfalls: HIGH — Pitfall 3 (dist staleness) was live-reproduced and live-fixed in this session; Pitfalls 1/2/4 are directly evidenced by source reads

**Research date:** 2026-07-12
**Valid until:** 30 days (stable, pre-existing packages and CI configuration; re-verify if any of `packages/crypto`, `packages/core`, `eslint.config.js`, or `ci.yml` change materially before planning begins)

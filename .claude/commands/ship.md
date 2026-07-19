# Ship

Take the current feature branch through the full ship loop **autonomously, without babysitting**:
verify → security review → simplify → local test gates → CodeRabbit CLI → PR → resolve reviews → green.

Scope: the current branch's diff against `origin/main` — one PR-sized slice of blueprint work. `$ARGUMENTS` may name a branch or PR number; if empty, use the checked-out branch.

## Operating rules (so this needs no babysitting)

- **Decide, don't ask.** For every review/audit finding, pick exactly one of **three** dispositions and proceed. The default for anything that isn't clearly material is **discard**, not defer — the issue backlog is a signal for real upcoming work, so keep it small.
  - **Fix now** — the finding is a genuine bug, security/privacy issue, or correctness gap **AND** (it's in the slice's domain OR the fix is small and safe). Always fix real defects the slice itself introduced, regardless of size, or block on them if you can't.
  - **File an issue** — defer via `env -u GITHUB_TOKEN gh issue create` **only if the item clears the materiality bar**: it's a real defect or a concrete, actionable piece of future work, that you are choosing not to do now because it's out of domain, risky, or large. Before filing, **search open issues and dedupe** — comment on a near-duplicate rather than opening a new one. Reference filed issues in the PR.
  - **Discard** — do nothing and do not file. This is the right call for: style/naming/formatting nits, subjective preferences, speculative "could hypothetically" findings with no demonstrated impact, micro-optimizations, test-only suggestions of marginal value, and low-severity **pre-existing** noise unrelated to the slice. Briefly acknowledge dismissed classes in the PR (e.g. "N nits dismissed") rather than filing them.
  - **Materiality bar for an issue** (must meet at least one): user-visible or data-integrity impact; security/privacy/crypto relevance; a real crash/correctness risk; or a concrete follow-up the build will genuinely need. "A reviewer mentioned it" is not sufficient. When unsure whether an item clears the bar, **discard it**.
  - Only stop for: a real failing gate you cannot fix, a genuine ambiguity in intent, or the final merge decision.
- **Verify outcomes faithfully.** Quote real test output. Never report a step done that wasn't.
- Run independent checks in parallel. Keep yourself as orchestrator; hand large self-contained chunks to sub-agents (Rust builds, mechanical sweeps) and adversarially verify their results.
- The blueprint corpus (`blueprint/*.md`, `CONTEXT.md`) is normative — a finding that contradicts it is judged against the blueprint, not reviewer preference.

## Environment gotchas (apply throughout)

- Prefix every GitHub CLI call with `env -u GITHUB_TOKEN gh …`.
- **`git push` / `git fetch` are blocked in the sandbox in this environment** — run them with the sandbox disabled. Plain `gh api` reads/writes work sandboxed.
- Commit signing goes through the 1Password SSH agent: **guard every commit with `timeout`** — a hung signer wedges 1Password (the fix is restarting the app, not retrying). Never `--no-gpg-sign` unless the user says so. If a commit errors or times out, **verify with `git log --oneline -1` before retrying** — it may have landed.
- `gh pr edit` fails on this repo (Projects-classic GraphQL) — patch the body via `env -u GITHUB_TOKEN gh api -X PATCH repos/FSM1/cipher-box/pulls/<N> -F body=@file`.
- PR title + commit subjects: **conventional, no parentheses in the subject** (commitlint + `lint-pr-title` CI reject parens). Escape bare `#NN` item refs as `` `#NN` `` in PR bodies (GFM autolinks them).
- `markdownlint --fix` + prettier run on staged `.md` at commit — headings not bold, blank lines around fences/lists/tables.

## Steps

### 1. Verify

Invoke `/verify`: drive the affected flow end-to-end against the real app/stack — not just tests or typecheck. Fix real gaps; re-run until the behavior is observed working.

### 2. Security review

Invoke `/security-review` on the slice diff (`origin/main...HEAD`) — a general vulnerability sweep (injection, authz, secrets, unsafe deserialization, etc.). Triage each finding with the three-way operating rule.

### 2b. Crypto/privacy review (conditional)

**Only when the slice touched crypto- or privacy-adjacent code.** Check the diff for the signal before deciding:

```bash
git diff origin/main...HEAD --name-only | grep -iE 'crypt|cipher|seal|unseal|kdf|derive|epoch|grant|hpke|xchacha|blake3|ed25519|secp256k1|key|ipns|nonce|zeroiz|pointer|floor|adoption|privacy' | grep -vE '\.test\.|__tests__|/tests/|\.md$'
```

If that surfaces nothing relevant, **skip this step** and note "no crypto/privacy-adjacent changes" in the PR. Otherwise invoke `/crypto-privacy-review` scoped to the changed files, judge findings against `blueprint/core.md` and `CONTEXT.md` (the KDF edge catalog, structure tags, adoption gate, and floor law are normative), triage three-way, and summarize the outcome in the PR body.

### 3. Simplify

Invoke `/simplify` on the slice diff — reuse, duplication, dead code, altitude. Apply safe simplifications; file an issue for a larger refactor only if it clears the materiality bar, otherwise discard.

### 4. Local test gates — DO NOT SKIP

Run the PR-gate suites for the touched area locally before pushing (`blueprint/testing.md` owns the suite map):

- **cargo workspace tests** — core KATs + property layer, engine simulation scenarios — whenever `crates/*` changed.
- **`packages/client` browser suite** — whenever the WASM boundary, seams, or leadership code changed.
- **The contract suite** — the **only** live client→API integration gate (the sdk-e2e descendant; its v1 ancestor caught a 48/89 break unit suites missed). Run it whenever the slice touched the API surface, the engine's API client, the registry/publish path, or key lifecycle. Needs the CI stack up: postgres, Kubo, the API under test, and the local `/routing/v1` record store (`tools/mock-ipns-routing`).

Transitional note: while v2 suites are still landing, run whatever `ci.yml` currently gates for the touched paths. Must be all green — quote the real output.

### 5. CodeRabbit CLI review (local, before ship)

```bash
coderabbit review --agent --base main --type committed
```

Triage every finding with the three-way operating rule. Re-run until the in-scope set is clean. (The CLI under-reports vs the web review — for crypto/durability-heavy slices, request a full web review on the PR as well.)

### 6. Ship

- **Create the PR as a DRAFT** (`env -u GITHUB_TOKEN gh pr create --draft ...`) with a conventional, paren-free title. Drafting defers CodeRabbit's PR review until the branch is settled — mark ready only when you're done pushing.
- Write the PR body to a temp file (escape `#NN`; **no** Claude session link or "Generated with Claude Code" footer) and set it at create time or via `gh api -X PATCH`.
- Push with the sandbox disabled.
- When the branch is settled: `env -u GITHUB_TOKEN gh pr ready <N>`.

### 7. Resolve PR reviews

When CodeRabbit's PR-level review lands (poll `gh pr checks <N>` in the background until the `CodeRabbit` check is no longer pending — don't block):

- CodeRabbit bundles findings in the **review body** AND as inline **review threads**. Fetch threads via the GraphQL `reviewThreads` query (id, isResolved, path, line, first comment body). Query **all** threads, no author filter — Greptile reviews too, sometimes late; CodeRabbit's author is `coderabbitai`, not `coderabbitai[bot]`. Expect re-reviews of your own fix commits — triage those too.
- For each finding apply the three-way operating rule (fix → reference the commit; material defer → reference the issue; nit → resolve the thread with a brief "acknowledged, not actionable" reply, nothing filed).
- Then run `/resolve-pr-reviews`, or directly: reply to each thread (`addPullRequestReviewThreadReply`) with the disposition and resolve it (`resolveReviewThread`). GitHub's API is occasionally flaky — wrap mutations in a small retry loop and re-query `reviewThreads` afterward to confirm **0 unresolved** and no duplicate replies.

### 8. Confirm green & report

Poll `env -u GITHUB_TOKEN gh pr checks <N>` until all checks settle. Report: final commit SHA, CI status (all green / which failed), threads resolved (`N/N`), a triage tally (fixed / issues filed / discarded), and the list of issues filed. Keep the filed count low — if it's climbing, re-check that each cleared the materiality bar. Leave the merge decision to the user.

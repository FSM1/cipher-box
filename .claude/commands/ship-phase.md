# Ship Phase

Run the full post-`execute-phase` loop for a GSD phase **autonomously, without babysitting**:
verify → secure → validate → simplify → **SDK E2E gate** → CodeRabbit CLI → ship → resolve PR reviews.

Phase number: `$ARGUMENTS` (e.g. `51`). If empty, infer it from the current branch / latest `.planning/phases/<N>-*` with executed plans.

## Operating rules (so this needs no babysitting)

- **Decide, don't ask.** For every review/audit finding, pick exactly one of **three** dispositions and proceed. The default for anything that isn't clearly material is **discard**, not defer — the todo backlog is a signal for real upcoming work, so keep it small.
  - **Fix now** — the finding is a genuine bug, security/privacy issue, or correctness gap **AND** (it's in the phase's domain OR the fix is small and safe). Always fix real defects the phase itself introduced, regardless of size, or block on them if you can't.
  - **Log a todo** — defer to `.planning/todos/pending/` **only if the item clears the materiality bar**: it's a real defect or a concrete, actionable piece of future work with a plausible owner phase, that you are choosing not to do now because it's out of domain, risky, or large. Before writing one, **search existing pending todos and dedupe** — append to or skip a near-duplicate rather than adding a new file. Note logged todos in the PR.
  - **Discard** — do nothing and do not create a todo. This is the right call for: style/naming/formatting nits, subjective preferences, speculative "could hypothetically" findings with no demonstrated impact, micro-optimizations, test-only suggestions of marginal value, and low-severity **pre-existing** noise unrelated to the phase. Briefly acknowledge dismissed classes in the PR (e.g. "N nits dismissed") rather than filing them.
  - **Materiality bar for a todo** (must meet at least one): user-visible or data-integrity impact; security/privacy/crypto relevance; a real crash/correctness risk; or a concrete follow-up a future phase will genuinely need. "A reviewer mentioned it" is not sufficient. When unsure whether an item clears the bar, **discard it** — a missed low-value item is cheaper than backlog noise.
  - Only stop for: a real failing gate you cannot fix, a genuine ambiguity in intent, or the final merge decision.
- **Verify outcomes faithfully.** Quote real test output. Never report a step done that wasn't.
- Run independent checks in parallel. Keep yourself as orchestrator; hand large self-contained chunks to sub-agents (Rust builds, mechanical sweeps) and adversarially verify their results.

## Environment gotchas (apply throughout)

- Prefix every GitHub CLI call with `env -u GITHUB_TOKEN gh …`.
- **`git push` / `git fetch` are blocked in the sandbox this environment** — run them with the sandbox disabled. Plain `gh api` reads/writes work sandboxed.
- The commit helper can report `commit_failed` while the commit actually lands — **verify with `git log --oneline -1`, never blindly retry**.
- `gh pr edit` fails on this repo (Projects-classic GraphQL) — patch the body via `env -u GITHUB_TOKEN gh api -X PATCH repos/FSM1/cipher-box/pulls/<N> -F body=@file`.
- PR title + commit subjects: **conventional, no parentheses in the subject** (commitlint + `lint-pr-title` CI reject parens). Escape bare `#NN` item refs as `` `#NN` `` in PR bodies (GFM autolinks them).
- `markdownlint` runs on commit but **excludes `.planning/`** — don't lint files there; prettier still runs.
- After `gh pr create` and after a passing Release Preview, `github-actions[bot]` pushes a `chore(release)` commit to the branch — **`git fetch` + rebase before the next push** or it's rejected.

## Steps

### 1. Verify

Invoke `/gsd-verify-work $ARGUMENTS`. Must reach a PASS verdict (`<phase>-VERIFICATION.md`). Fix real gaps; re-run.

### 2. Secure

Invoke `/gsd-secure-phase $ARGUMENTS`. Must reach SECURED (`<phase>-SECURITY.md`). If the auditor writes to repo-root `SECURITY.md`, `git restore` it and write the phase doc instead.

### 2b. Crypto/privacy review (conditional)

**Only when the phase touched crypto- or privacy-adjacent code.** Check the phase diff for the signal before deciding:

```bash
git diff origin/main...HEAD --name-only | grep -iE 'crypt|cipher|encrypt|decrypt|key|ecies|aes|gcm|ipns|tee|web3auth|nonce|iv|seal|zeroiz|privacy' | grep -vE '\.test\.|__tests__|\.md$'
```

If that surfaces nothing relevant, **skip this step** and note "no crypto/privacy-adjacent changes" in the PR. Otherwise invoke `/crypto-privacy-review` scoped to the phase code (its `Phase code` scope, or the changed files), triage findings with the three-way operating rule (fix real crypto/privacy defects now, log a todo only for material deferrals, discard nits), and reference the resulting `.planning/security/REVIEW-*.md` in the PR body. This is a deeper crypto lens on top of the `/gsd-secure-phase` threat-model audit, not a replacement for it.

### 2c. Built-in security review

Invoke Claude Code's built-in `/security-review` on the phase diff (`origin/main...HEAD`) — a general vulnerability sweep (injection, authz, secrets, unsafe deserialization, etc.) that complements the crypto-focused passes above. Triage each finding with the three-way operating rule (fix real vulnerabilities now, log a todo only for material deferrals, discard nits/false positives). Note the disposition in the PR body.

### 3. Validate (Nyquist)

Invoke `/gsd-validate-phase $ARGUMENTS`. Must be compliant, 0 gaps (`<phase>-VALIDATION.md`).

### 4. Simplify

Review the phase diff (`git diff origin/main...HEAD`) for over-engineering, duplication, and dead code. Apply safe simplifications; log a todo for a larger refactor only if it clears the materiality bar, otherwise discard it.

### 5. SDK E2E gate — DO NOT SKIP

This is the **only** suite that exercises the real client→API IPNS publish/resolve round-trip; unit suites mock the boundary and miss integration regressions (this gate caught a 48/89 break in Phase 51). Run it locally whenever the phase touched IPNS publish/resolve, sequencing/CAS, or key lifecycle:

```bash
# prereqs usually already up: postgres 5432, kubo 5001, redis 6380, mock-ipns-routing 3001
# rebuild the client chain so dist matches CI:
pnpm --filter @cipherbox/crypto build && pnpm --filter @cipherbox/core build \
  && pnpm --filter @cipherbox/api-client build && pnpm --filter @cipherbox/sdk-core build \
  && pnpm --filter @cipherbox/sdk build && pnpm --filter @cipherbox/api build
# (re)start the API on :3000 (kill anything already there first):
lsof -nP -iTCP:3000 -sTCP:LISTEN -t | xargs -r kill -9
( cd apps/api && PORT=3000 node dist/main.js > /tmp/ship-phase-api.log 2>&1 & )
# wait for /health, then run the suite:
SDK_E2E_API_URL=http://localhost:3000 \
  SDK_E2E_SECRET="$(grep -E '^TEST_LOGIN_SECRET=' apps/api/.env | cut -d= -f2-)" \
  THROTTLE_BYPASS_SECRET="$(grep -E '^THROTTLE_BYPASS_SECRET=' apps/api/.env | cut -d= -f2-)" \
  pnpm --filter @cipherbox/sdk-e2e test
```

Must be all green. The API does **not** log handled 4xx — to find a real 400 reason, temporarily add an axios response interceptor in `packages/api-client/src/instance.ts` logging `err.response.data`, rebuild the client chain, run one suite, then revert. Shut the API down when done.

### 6. CodeRabbit CLI review (local, before ship)

```bash
coderabbit review --agent --base main --type committed
```

Triage every finding with the three-way operating rule above (fix / log a material todo / discard). Re-run until the in-scope set is clean. For the deferrals that clear the materiality bar, capture todos with file refs + the right destination phase; discard the nits.

### 7. Conventional-commit reword

GSD executor commits use a non-conventional `feat 51-03:` style that fails the `pr-release-preview` CI gate on any commit touching versioned packages. Reword the phase's commit subjects to conventional **before** opening the PR:

```bash
git filter-branch --msg-filter 'sed -E "1 s/^([a-z]+) [0-9][0-9A-Za-z.-]*: /\1: /"' <base>..HEAD
```

(`git rebase -i` is not available here.) Verify the tree is unchanged (`git diff <old-head>`), then force-push (sandbox disabled) and clean up the filter-branch backup ref.

### 8. Ship

Invoke `/gsd-ship $ARGUMENTS`, but:

- Override the default PR title (GSD's `Phase N: <slug>` is non-conventional) with a conventional, paren-free subject, e.g. `fix: <concise phase summary>`.
- Write the PR body to a temp file (escape `#NN`, end with the Claude Code attribution line) and set it via `gh api -X PATCH` (not `gh pr edit`).
- Push with the sandbox disabled.

### 9. Resolve PR reviews

When CodeRabbit's PR-level review lands (poll `gh pr checks <N>` until the `CodeRabbit` check is no longer pending — use a backgrounded poll, don't block):

- CodeRabbit bundles findings in the **review body** AND as inline **review threads**. Fetch threads via the GraphQL `reviewThreads` query (id, isResolved, path, line, first comment body). Expect it to **re-review your own fix commits** and raise new findings — triage those too.
- For each finding apply the three-way operating rule (fix → reference the commit; material defer → reference the todo; nit → resolve the thread with a brief "acknowledged, not actionable" reply, no todo).
- Then run `/resolve-pr-reviews`, or directly: reply to each thread (`addPullRequestReviewThreadReply`) with the disposition and resolve it (`resolveReviewThread`). GitHub's API is occasionally flaky — wrap mutations in a small retry loop and re-query `reviewThreads` afterward to confirm **0 unresolved** and no duplicate replies.
- After any further push, `git fetch` + rebase first (the release bot may have pushed `chore(release)`).

### 10. Confirm green & report

Poll `env -u GITHUB_TOKEN gh pr checks <N>` until all checks settle. Report: final commit SHA, CI status (all green / which failed), threads resolved (`N/N`), a triage tally (fixed / todos logged / discarded), and the list of deferred todos created. Keep the todos-logged count low — if it's climbing, re-check that each cleared the materiality bar. Leave the merge decision to the user.

### 11. Extract learnings

Invoke `/gsd-extract-learnings $ARGUMENTS` to mine the completed phase artifacts for decisions, lessons, patterns, and surprises (writes `<phase>-LEARNINGS.md`). Commit the resulting file on the phase branch alongside the rest of the work — `.planning/` bookkeeping rides the same PR, never a separate docs-only PR.

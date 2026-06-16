# Phase 48 — REQ-1 gate BLOCKED (handoff)

**Date:** 2026-06-16 · **Branch:** `feat/sdk-self-bootstrap-regression-fix-and-shared-folder-metadata` (pushed)
**Status:** Autonomous run PARKED. REQ-1's web-e2e acceptance gate is RED after 3 aimed fixes. Waves 2–3 (REQ-2/3/4) NOT started (gated on REQ-1 green). No PR opened.

## Where it stands

web-e2e (dispatched against the branch) = **180 passed, 1 failed**. The one red spec:
`tests/web-e2e/tests/bin-restore-after-reload.spec.ts:78` — times out at **step 6, line 116** `binPage.waitForBinItem(...)`. At failure the page is on the **Files view at root** (Playwright snapshot shows breadcrumb "my vault" + the `reload-sub-*` subfolder), i.e. the app **bounced `/bin → /files`** and the bin never rendered.

`full-workflow.spec.ts:6.6.2 (Restore a past version)` — **FIXED** (was the other half of the #498 regression).

## Fixes landed on the branch (all UNSIGNED — see signing note)

| Commit | What | Effect |
| ------ | ---- | ------ |
| `bcb4fc03d` (signed) | REQ-1 `loadFolder` sequence-guard (`client.ts:378`) — don't clobber fresher in-memory folderTree with a stale IPNS resolve | ✅ greened version-restore spec |
| `fe646fd5f` | `loadBin` re-resolve before destructive empty-bin auto-repair (`bin/index.ts`) | did not green bin-restore (but a real correctness fix; 183 SDK tests pass) |
| `f6b13db2b` | Guard `useFolderNavigation` catch-block `navigate('/files')` by current route (`latestPathname` ref) | did NOT change the bin-restore outcome |

## The unresolved bug

The `/bin → /files` bounce persists. `navigate()` to `/bin` succeeds (the test's `waitForURL('**/#/bin')` at line 115 passes), then within the 30s `waitForBinItem` window the app returns to `/files` root. `BinBrowser`/`useBin`/`BinPage` contain NO redirect. The suspected source was `useFolderNavigation`'s subfolder-resolve catch (it `navigate('/files')`s after the reloaded `/files/<subfolderId>` route fails to load the subfolder), but guarding that redirect by current route did not fix it — so EITHER:

- there is a **second** redirect-to-`/files` path not yet identified (a URL-sync effect / route guard on the reloaded `/files/<subfolderId>` route), OR
- the bounce fires from the same path but the guard is bypassed by effect/timing ordering.

**Next diagnostic (do this first):** open the trace to get the exact navigation timeline —
`pnpm exec playwright show-trace <trace.zip>` (artifact `playwright-report` on run 27592393665). It will show precisely which call navigates `/bin → /files` and when, relative to the bin click.

## Why this is an ordering knot (needs a human decision)

The bounce originates in the **web-side subfolder load** path after a reload into `/files/<subfolderId>`. **REQ-2** (plan 48-02) deletes exactly that redundant web-side load/unwrap in favour of the SDK self-bootstrap chokepoint — so REQ-2 may be the *actual* fix. But REQ-2 is gated on REQ-1 being green. Options:

1. Land REQ-2's web-unwrap removal first (relax the gate ordering) and re-test the bin-restore spec — it may go green once the web no longer races on the subfolder load.
2. Treat the spec's precondition as a test race (it navigates to `/bin` while a subfolder resolve from the reload is in flight) and fix the **test** to wait for the app to settle (and/or re-assert `/bin` if bounced) — legitimate if the post-reload `/files` landing is considered correct app behaviour.
3. Find + fix the second redirect path via the trace (pure app fix).

## Operational notes

- **Signing is OFF** (`git config commit.gpgsign false`, repo-local). 1Password SSH signer wedged mid-run; restart the 1Password app to recover. Commits from `fe646fd5f` onward are unsigned → **re-sign (rebase) or admin-merge** before landing. `bcb4fc03d` and all planning commits are signed.
- Branch is pushed; web-e2e is dispatched manually via `gh workflow run web-e2e.yml --ref <branch>` (workflow_dispatch, checks out branch HEAD).
- Stale local branch `feat/phase-48-sdk-self-bootstrap-fix-and-shares` (points at the first planning commit) can be deleted.
- Pipeline steps NOT run (all gated on green): `/simplify`, `/gsd:validate-phase 48`, CodeRabbit, `/security:review`, PR.

## UPDATE 2026-06-16 — Playwright trace pulled; root cause CORRECTED (option 1 is wrong)

Extracted the trace from the failing run (27592393665). Decisive evidence — **the bug is bin IPNS durability, NOT navigation**:

- Console: `[CipherBox] Bin IPNS record not found — auto-repairing with empty bin` STILL fires. Network: the bin's IPNS name resolves ~17× with intermittent **404s** (22 across the run, plus 2× 409). So after the item is deleted to the bin (step 4) and the page reloads (step 5), `loadBin`'s `resolveIpnsRecord` 404s (IPNS propagation lag on the just-written bin record), and the **auto-repair republishes an EMPTY bin**, overwriting the real record server-side → the item is gone → `waitForBinItem` (step 6) times out.
- **No `[Nav] Failed to load subfolder` anywhere** — the `useFolderNavigation` catch redirect I guarded in `f6b13db2b` NEVER fires. That fix (and the whole nav-bounce theory) is irrelevant; the `/files` page snapshot is a secondary effect, not the cause.
- `fe646fd5f` (re-resolve before auto-repair) is INSUFFICIENT: when the 404 persists, it still publishes empty.

### Real fix direction (do NOT do blind — risky)

`loadBin` must NEVER destructively republish an empty bin to "repair" a transient 404. A 404 must be distinguished:
- **bin genuinely never created** (first-ever load, no bin IPNS registered) → safe to initialize empty.
- **bin exists but is momentarily unresolvable** (we just published it; propagation lag / network-first miss) → must NOT clobber; keep current state, retry/back off, or read the DB-cached record.

This likely needs the resolve API to disambiguate "never existed" vs "not resolvable now" (a server/DB signal), which would pull in `pnpm api:generate`. It is an IPNS-consistency change with real blast radius — should be reproduced LOCALLY (fast iteration; CI is ~12 min/cycle) rather than guessed via CI.

**Recommended next step:** run the single spec locally against the e2e stack (`tests/web-e2e`, services per `.github/workflows/web-e2e.yml`: postgres + kubo + redis + mock-ipns-routing) to iterate on the `loadBin` no-clobber-on-transient-404 fix, then re-dispatch. REQ-2 (option 1) is NOT the fix — leave it for its own gated plan.

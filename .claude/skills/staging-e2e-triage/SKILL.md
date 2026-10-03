---
name: staging-e2e-triage
description: Triage a failed Staging E2E job in a tag-staging.yml or staging-e2e.yml run. Classify each failed spec as infra, known flake, test bug or product regression from the job log, the Playwright artifact and the release range, and act on each class. Use when a Staging E2E job fails, before any re-run.
---

# Staging E2E triage

Use this skill when the `Staging E2E / Staging E2E` job of a `tag-staging.yml` run fails, or the `Staging E2E` job of a `staging-e2e.yml` run fails. The suite is in `tests/web-e2e/staging/`.

## Rules

- Triage is read-only. Read the job log, the Playwright artifact, the run list and the git history. Do not run tests, probes, scripts or other tools against staging.
- Do not re-run the job before you finish the triage. A re-run replaces the jobs list of the run. After a re-run, `--attempt 1` gives the first failure.
- Do not copy tokens, emails, wallet addresses, account ids or the Grafana URL into an issue or a document. `error-context.md` contains the page snapshot. Copy only the error lines from it.

## 1. Get the log and the artifact

Every `gh` command uses `env -u GITHUB_TOKEN gh ... --repo FSM1/cipher-box`. Set `R` as in the first line below before you run a command from any block.

```sh
R='--repo FSM1/cipher-box'
env -u GITHUB_TOKEN gh run view <run-id> $R --json headSha,jobs \
  --jq '.headSha, (.jobs[] | "\(.databaseId) \(.name) \(.conclusion)")'
env -u GITHUB_TOKEN gh run view $R --job <job-id> --log > job.txt
env -u GITHUB_TOKEN gh run download <run-id> $R --name staging-e2e-report --dir report
grep -nE '✘|✓|Error:|kept:|removed:' job.txt
```

The artifact stays for 14 days. It contains `playwright-report/` and `test-results/<spec>/error-context.md`. Each `error-context.md` has the error, the page snapshot and the test source.

## 2. Classify each failed spec

Read the log line and the `error-context.md` of each failed spec. A locator timeout in the log (`expect(locator).toBeVisible() failed`) has no class until you read the `alert` lines of the page snapshot.

- **(a) Infra or DEVNET.** The error comes from `signInWithWallet` in `tests/web-e2e/staging/fixtures.ts`: `the wallet login was refused 3 times; the last refusal read: …`. The refusal text is one of these:
  - `[object Response]`
  - `could not retrieve nonce: Internal error, failed to get nonce with status code: 503`
  - `master poly commits inconsistent with tssPubKey`
  - `Cannot read properties of undefined (reading 'ciphertext')`

  The snapshot stops at the `Available wallets` group. The account-removal attachment reads `kept: refresh answered 401`.

- **(b) Known flake.** The same spec failed with the same error line in an earlier run, and a re-run with no code change made it pass.
- **(c) Test bug.** The spec fails on a step that the product does correctly: a wrong locator, a wrong wait, or a wrong expected value. The snapshot shows the correct product state.
- **(d) Product regression.** The snapshot shows a product error. Example: in `sharing.spec.ts` the log shows only a timeout on `share-no-grants`, and the snapshot alerts read `verification refused an update: …: adoption gate rejected at stage [grant-section]: [unexpected-type]` and `trust violation: descendant record rejected by adoption gate`.

Class (a) is a Web3Auth sapphire DEVNET node fault. Staging uses DEVNET, which has no SLA. Every spec mints a fresh wallet, so a sick node fails the new-user path. A spec on an identity that already exists (`second-device.spec.ts`) often passes in the same run. Confirm class (a) with the release range: the range touches no auth code.

## 3. Compare with earlier runs

Find the earlier Staging E2E jobs and the last green job. A `tag-staging.yml` run fails when any job fails, so read the conclusion of the Staging E2E job, not of the run.

```sh
env -u GITHUB_TOKEN gh run list $R --workflow tag-staging.yml --limit 20 \
  --json databaseId,conclusion,createdAt,headSha
env -u GITHUB_TOKEN gh run list $R --workflow staging-e2e.yml --limit 20 \
  --json databaseId,conclusion,createdAt,headSha
env -u GITHUB_TOKEN gh run view <run-id> $R --json jobs \
  --jq '.jobs[] | select(.name | test("Staging E2E")) | "\(.databaseId) \(.conclusion)"'
```

For each earlier failed job, get the log and compare the failed specs and the error lines. A spec that failed with a class (a) signature in earlier runs and passed in other runs supports class (a).

Find the release range between the last green job and the failed job:

```sh
git fetch origin --tags
git tag --points-at <last-green-headSha>   # vPREV
git tag --points-at <failed-headSha>       # vCUR
git log --oneline vPREV..vCUR
```

## 4. Act on each class

- (a) Write the class and the signature in the triage note. Re-run the failed job one time, later: `env -u GITHUB_TOKEN gh run rerun <run-id> $R --failed`. The tag and the deploy have already passed, so do not dispatch a new run. In a `tag-staging.yml` run, the re-run holds the `staging-environment` concurrency group again, and no other deploy can start until it ends.
- (b) Re-run the failed job one time with the same command. If it fails again, triage it as (c) or (d).
- (c) File a test issue. Give the run id, the spec, the error lines and the wrong step.
- (d) Reproduce the failure locally first. Write an engine test that shows the failure. Then run the spec in the local web-e2e stack. Find the suspect PR in `git log vPREV..vCUR`: read the PRs that touch the failed path. File a regression issue with the run id, the spec, the error lines and the suspect PR.

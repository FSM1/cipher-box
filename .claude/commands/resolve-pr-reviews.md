# Resolve PR Review Comments

Resolve all open review comments on the current PR from any automated reviewer (CodeRabbit, GitHub Copilot, etc.) or human reviewers.

## Workflow

### 1. Identify the PR

```bash
PR_NUMBER=$(gh pr view --json number --jq '.number')
```

If no PR exists for the current branch, stop and inform the user.

### 2. Fetch all unresolved review threads

Use the GraphQL `reviewThreads` query to get threads with `isResolved` status:

```bash
REPO_OWNER=$(gh repo view --json owner --jq '.owner.login')
REPO_NAME=$(gh repo view --json name --jq '.name')

gh api graphql -f query="
{
  repository(owner: \"$REPO_OWNER\", name: \"$REPO_NAME\") {
    pullRequest(number: $PR_NUMBER) {
      reviewThreads(first: 100) {
        nodes {
          id
          isResolved
          comments(first: 10) {
            nodes {
              id
              author { login }
              body
              path
              line
              createdAt
            }
          }
        }
      }
    }
  }
}"
```

Filter to only unresolved threads.

Then fetch the review **bodies** as well, because nitpicks and out-of-scope notes never
appear as threads:

```bash
gh api repos/$REPO_OWNER/$REPO_NAME/pulls/$PR_NUMBER/reviews \
  --jq '.[] | select(.body | length > 0) | "\(.user.login) \(.submitted_at)\n\(.body)"'
```

Zero unresolved threads does not end the run — a nitpick-only review has no threads at
all. Stop only when there are no threads **and** no nitpick or out-of-scope items;
otherwise continue to step 8.

### 3. Triage each comment

For each unresolved thread, read the comment and the referenced code. Categorize as:

- **Valid fix needed** — the comment identifies a real bug, security issue, or meaningful improvement
- **Already addressed** — the issue was fixed in a later commit on this branch
- **Not applicable** — the suggestion doesn't apply (explain why)

### 4. Implement fixes

For all "valid fix needed" comments:

1. Read the referenced file and understand the context
2. Implement the fix
3. Track which thread the fix addresses

Do NOT:

- Make unrelated changes or refactors
- Add features beyond what the comment requests
- Increase timeouts or add retries as a first approach — fix root causes

### 5. Run tests locally

After ALL fixes are implemented:

```bash
# Type check
pnpm typecheck

# Run relevant unit tests
pnpm test

# If E2E-relevant changes were made, run E2E tests too
cd tests/web-e2e && pnpm exec playwright test
```

Do NOT proceed to commit until tests pass. If tests fail, fix the failures first.

### 6. Commit and push

```bash
git add <specific-files>
git commit -m "fix: address PR review comments"
git push
```

### 7. Reply to and resolve each thread

For each thread, reply explaining what was done, then resolve:

- **Fixed comments**: Reply with what was changed and where, then resolve
- **Already addressed**: Reply explaining which commit addressed it, then resolve
- **Not applicable**: Reply with clear reasoning for not making changes, then resolve

Reply via REST (use `--field` not `-f` for `in_reply_to` — must be integer):

```bash
gh api repos/$REPO_OWNER/$REPO_NAME/pulls/$PR_NUMBER/comments \
  --field in_reply_to=COMMENT_ID \
  --raw-field body='...'
```

Resolve via GraphQL (can batch multiple):

```bash
gh api graphql -f query='
mutation {
  resolveReviewThread(input: {threadId: "THREAD_ID"}) {
    thread { isResolved }
  }
}'
```

### 8. Post a disposition comment for nitpicks and out-of-scope items

Nitpicks and "outside the diff range" / "out of PR scope" notes live only inside a
collapsible section of the review body (`🧹 Nitpick comments (N)`). They create **no
inline threads**, so step 7 cannot reach them and GitHub records nothing about their
fate. Without a posted comment there is no evidence they were ever read.

Post one comment on the PR stating, per item, what was done:

```bash
gh pr comment $PR_NUMBER --repo $REPO_OWNER/$REPO_NAME --body-file <file>
```

Requirements:

- One line per nitpick and per out-of-scope item — taken, already true, or rejected.
- A rejection states the reason. "Rejected per the comment rules in AGENTS.md" is a
  reason; silence is not.
- An item deferred to an issue names that issue.
- A blanket "addressed the feedback" is not a disposition. It records nothing.

Post it even when every item was rejected, and even when the PR is already merged.

### 9. Report summary

Print a summary table:

- Thread count resolved
- Fixes made (with file:line references)
- Comments marked as already addressed or not applicable
- Nitpick and out-of-scope items, and the disposition comment URL from step 8

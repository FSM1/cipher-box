# PR Review Comment Triage Workflow

**Date:** 2026-02-10

## Original Prompt

> there is still 1 comment from coderabbit on the PR that hasn't been addressed. fix this.
> still a few unresolved comments that feel appropriate to address on the PR

## What I Learned

### Getting unresolved threads

- `gh pr view` REST fields do NOT include `reviewThreads` — must use GraphQL
- The GraphQL query to get all threads with resolved status:

  ```graphql
  {
    repository(owner: "OWNER", name: "REPO") {
      pullRequest(number: N) {
        reviewThreads(first: 20) {
          nodes {
            isResolved
            id
            comments(first: 5) {
              nodes {
                id
                databaseId
                path
                line
                author {
                  login
                }
                body
              }
            }
          }
        }
      }
    }
  }
  ```

- Filter with `jq`: `select(.isResolved == false)` to get only unresolved threads
- Thread `id` (node ID like `PRRT_...`) is needed for resolving; comment `databaseId` (integer) is needed for replying

### Replying to review comments

- Use REST with `in_reply_to` (integer database ID):

  ```bash
  gh api repos/OWNER/REPO/pulls/N/comments \
    -f body='Reply text' \
    -F in_reply_to=COMMENT_DATABASE_ID
  ```

- Do NOT use a `/replies` sub-endpoint — it doesn't exist

### Resolving threads

- Use GraphQL `resolveReviewThread` mutation with the thread's node ID:

  ```graphql
  mutation {
    resolveReviewThread(input: { threadId: "PRRT_kwDOQ6..." }) {
      thread {
        isResolved
      }
    }
  }
  ```

- Can batch multiple resolves in one mutation using aliases (`t1:`, `t2:`, etc.)

### Triage strategy

- **Always read the current code first** before acting on a comment — it may already be addressed in a later commit
- For already-addressed comments: reply explaining where/how it was fixed, then resolve the thread
- For inapplicable comments: reply with reasoning for not making changes, then resolve the thread
- For valid unaddressed comments: fix the code, commit, push, then reply and resolve
- Bot reviewers (CodeRabbit, Copilot) sometimes flag the original diff but miss that subsequent commits already fixed the issue — the `isResolved` status is the source of truth for what still needs attention

## What Would Have Helped

- Knowing upfront that `gh pr view --json` doesn't support `reviewThreads` — would have gone straight to GraphQL
- The thread node ID vs comment database ID distinction is easy to confuse — thread IDs (`PRRT_...`) for resolving, comment integer IDs for replying

## Key Files

- No project files — this is a `gh` CLI / GitHub API workflow pattern

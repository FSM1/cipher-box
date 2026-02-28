# Session Context

## User Prompts

### Prompt 1

Unknown skill: resolve-pr-reviews

### Prompt 2

<bash-input>git add --all</bash-input>

### Prompt 3

<bash-stdout></bash-stdout><bash-stderr></bash-stderr>

### Prompt 4

<bash-input>git commit -m "move to correct folder for skills"</bash-input>

### Prompt 5

<bash-stdout>[STARTED] Backing up original state...
[COMPLETED] Backed up original state in git stash (7ea42f4e5)
[STARTED] Running tasks for staged files...
[STARTED] package.json — 1 file
[STARTED] *.{ts,tsx,js,jsx} — 0 files
[STARTED] *.{json,yml,yaml} — 0 files
[STARTED] *.md — 1 file
[SKIPPED] *.{ts,tsx,js,jsx} — no files
[SKIPPED] *.{json,yml,yaml} — no files
[STARTED] markdownlint --fix
[COMPLETED] markdownlint --fix
[STARTED] prettier --write
[COMPLETED] prettier --write
[COMPLETED] *...

### Prompt 6

git push

### Prompt 7

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
gh api graphql -f query='
{
  ...


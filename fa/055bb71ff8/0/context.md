# Session Context

## User Prompts

### Prompt 1

I wanted to ask - are there any outputs from the cargo check jobs that can be cached and reused in the cargo test jobs?

### Prompt 2

yeah I think that makes a lot of sense. push it up in this branch

### Prompt 3

the old check and test jobs  are still marked as required

### Prompt 4

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
REPO_OWNER=$(gh repo view --js...


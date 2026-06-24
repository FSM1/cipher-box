---
created: 2026-06-24
title: Scrub staging SSH host coordinates from tracked planning docs (repo-wide)
area: docs
files:
  - .planning/
---

## Problem

The staging box access coordinate `ssh root@76.13.151.200` (Hostinger KVM2) is
committed in tracked `.planning/` docs. CodeRabbit flagged the Phase 60 copies
(60-08-PLAN.md:15,91; 60-VERIFICATION.md) on PR #555 as attack-surface recon risk.

Triage: real hygiene point but **pre-existing and repo-wide** — the same IP is
already committed across ~10 docs (`.planning/milestones/m1/phases/09.1-.../09.1-VERIFICATION.md`,
`.planning/codebase/INTEGRATIONS.md`, `.planning/codebase/STACK.md`,
`.planning/phases/34-.../34-RESEARCH.md`, `.planning/phases/19.2-.../19.2-VERIFICATION.md`,
`.planning/baselines/18-performance-baselines.md`,
`.planning/baselines/19.2-post-optimization-baselines.md`, etc.). It is an IP +
`root@` only — **no credentials**; staging access is key-gated via the 1Password
SSH agent (see project memory `project-staging-vps-access`), so the IP alone grants
nothing. Scrubbing only Phase 60's two copies provides no security benefit while
the value persists everywhere else, so it was **declined as a one-file fix** on
#555 and deferred to a dedicated repo-wide pass (out of scope for the strict-verify
cutover PR).

## Solution

In a dedicated `chore(docs)` PR, replace literal `root@76.13.151.200` (and any bare
`76.13.151.200`) across all tracked docs with a sanitized reference, e.g.
"staging host per project memory `project-staging-vps-access` / secured ops runbook".
Keep the real host in the (gitignored) memory + 1Password, not in tracked docs.
Consider a CI guard (grep) to prevent re-introduction.

---
name: ci-incident-investigation
description: Investigate a failed CI or nightly run. Keep its evidence across retries, separate its failure modes, find damage to durable test state, and route each cause to an incident update or a follow-up issue. Use when given a run or job URL or an incident issue, when deciding whether to retry failed jobs, when repairing a test-state blocker, or when deciding whether an incident can close. A plain local test failure goes to diagnosing-bugs.
---

# CI incident investigation

An **incident** is the record of one observed run: its triage and its remediation. An **RCA issue** investigates one unresolved cause. A **diagnostics issue** gets better evidence. Keep the three separate.

For a failed Staging E2E job, run `staging-e2e-triage` first. This skill continues from its result.

## Before each action

Start from the work that is done. Read the incident, its comments, and the linked follow-ups before you read logs again. After a compaction or a new turn, continue from these records and from the decisions below.

Keep a list of what the user authorized in this task:

- retries and new dispatches,
- writes to shared accounts or durable test state,
- issue creation, edits, and closure.

A request to investigate authorizes reads only. If an action needs an authorization that is not on the list, prepare the exact action first. Then ask, and say which rule needs the approval. Ask only for facts you cannot find in the repository, the run, or the tracker.

Use the repository instructions for the tracker CLI, labels, and issue relationships. In this repository, see `docs/agents/issue-tracker.md` and `docs/agents/triage-labels.md`.

## Steps

The steps are decision points. Start at the first step whose criterion is not met.

1. **Scope.** Read the run, every failed job, and every attempt. Find the symptom that the user means. Done when each failure has a job, an attempt, an environment, a UTC time, and the exact error line.
2. **Preserve evidence.** Save the logs and results of each failed instance before a retry or a cleanup. Done when the evidence stays readable after a rerun replaces the artifacts. Record each piece of evidence that is missing.
3. **Classify.** Group the failures by the boundary where each one stopped and by its error signature. Done when each failure mode has a short evidence summary and an owner. A timeout is a symptom: find what the timeout waited on.
4. **Assess retries.** Find what a rerun repeats before you start it. Done when each retry result states what the retry exercised and what it leaves unproven.
5. **Investigate.** Build a check that goes red on the exact symptom, or use `diagnosing-bugs` if it is available. Compare against the code and configuration that ran. Done when you have a supported cause or a precise limit of the evidence and the next action.
6. **Repair state, only if requested.** See "Durable test state". Done when a cold client reads the repaired state and its dependent references.
7. **Route the remaining work.** Reuse an existing issue, or create one RCA, corrective, or diagnostics issue for each independent failure mode. Done when each unresolved failure has a linked issue that a reader can act on.
8. **Close or hand off.** Publish the incident summary if authorized. Close the incident when its scope is complete. Done when each claim matches a check, each residual has a disposition, and you read the tracker state again after the change.

## Retries and evidence

- Correlate each attempt with its build revision, the revision that the job checked out, the pinned dependencies, the environment, and the timing policy. The head of a workflow can differ from the code that a job built or deployed.
- Keep the log of the failed instance. Several instances can write logs with the same file name, and a flat upload keeps only one of them. A successful upload does not prove that the needed log is in it. Before a retry, check that a second failure keeps its own evidence.
- Before you call a passing retry a recovery, compare its stimulus with the failed attempt. A date-derived fixture, a different account, or a changed downstream job makes the retry a different experiment. A pass on a different stimulus is evidence of intermittence, not of a fix.
- Read the earliest and sharpest failure signal. A wrapper that waits on a download can hide an immediate read error. A cleanup step that runs at a deadline can replace the first error with a rejection of the in-flight request. Keep the order of deadline and cleanup in the record.

## Durable test state

- Probe the same selection set as the real test. If the test selects from a listing, read the listing too, not only the ledger or reference state. A ledger-only probe can skip the broken entry.
- Find the layer the failed test depends on: local acknowledgement, durable local journal, or remote publication. Check that layer.
- Reproduce on a fresh isolated account if a shared account has an active writer. Before a repair on a shared account, check the active runs and the account conflict. If a nightly or another run writes to the account now, wait with the repair and continue the safe investigation.
- Make the smallest repair through a normal client. Preserve the evidence and check the dependent references before you remove a fixture. A local change is not a repair until a cold client reads the published remote state.
- Keep the original failure in the record. Label a reconstructed fixture as a repair, not as a historical successful publication.

## Privacy

Keep secrets in process memory or in approved custody. Copy only the relevant lines, with tokens, seeds, emails, account ids, and private URLs redacted, into a public issue. Raw request traces and account databases stay local.

## Outputs

The incident update gives the affected jobs, links to the preserved evidence, the checked findings, the retry results, the remediation, the limits of the validation, and the linked residual issues.

A follow-up issue has four parts:

- the problem and its evidence, with the exact symptom,
- the established facts and the open questions, with prior attempts and their limits,
- the direction of the investigation,
- completion criteria that a reader can check.

Link to the source of a detail. Do not copy whole logs or the narrative of another issue. Use a blocking relationship only for a real block.

An incident can close when its scope is complete, the repair validation is recorded, and each remaining cause has an accepted follow-up or an explicit disposition. State when no clean CI run after the repair exists yet. An RCA issue closes only with a supported cause and a corrective validation, or with an explicit justified disposition.

The final reply keeps three results separate: a repaired fixture, a recovery on retry, and a confirmed fix of the root cause.

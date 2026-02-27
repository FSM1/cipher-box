# Session Context

## User Prompts

### Prompt 1

<objective>
Check project progress, summarize recent work and what's ahead, then intelligently route to the next action - either executing an existing plan or creating the next one.

Provides situational awareness before continuing work.
</objective>


<process>

<step name="verify">
**Verify planning structure exists:**

If no `.planning/` directory:

```
No planning structure found.

Run /gsd:new-project to start a new project.
```

Exit.

If missing STATE.md: suggest `/gsd:new-project`.

*...

### Prompt 2

<objective>
Debug issues using scientific method with subagent isolation.

**Orchestrator role:** Gather symptoms, spawn gsd-debugger agent, handle checkpoints, spawn continuations.

**Why subagent:** Investigation burns context fast (reading files, forming hypotheses, testing). Fresh 200k context per investigation. Main context stays lean for user interaction.
</objective>

<context>
User's issue: 

Check for active sessions:
```bash
ls .planning/debug/*.md 2>/dev/null | grep -v resolved | h...

### Prompt 3

instead of just blindly trusting me that these have been resolved, please look through the recent commits to main, to make sure that this is indeed the case and all the possible edge cases outlined in the debug sessions have been covered.

### Prompt 4

ok can you update both of these files with the commit details where the issues were resolved.

### Prompt 5

ok great, now commit these changes to a docs branch and create a docs pr


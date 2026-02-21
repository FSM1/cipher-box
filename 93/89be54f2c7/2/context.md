# Session Context

## User Prompts

### Prompt 1

<objective>
Execute all plans in a phase using wave-based parallel execution.

Orchestrator stays lean: discover plans, analyze dependencies, group into waves, spawn subagents, collect results. Each subagent loads the full execute-plan context and handles its own plan.

Context budget: ~15% orchestrator, 100% fresh per subagent.
</objective>

<execution_context>
@./.claude/get-shit-done/references/ui-brand.md
@./.claude/get-shit-done/workflows/execute-phase.md
</execution_context>

<context>
Pha...

### Prompt 2

resume please

### Prompt 3

<objective>
Detect drift between Pencil design files (`designs/*.pen`) and CSS/TSX implementation. Report discrepancies and offer to fix them — either updating the design to match code or vice versa.

Modes:

- **No args:** Check files changed on current branch vs main. Interactive — asks resolution direction.
- **`check`:** Same scope as no-args but report-only. No modifications.
- **`PR#`:** Check files changed in a specific PR. Report-only.

This skill lives outside `gsd/` to survive GSD ...


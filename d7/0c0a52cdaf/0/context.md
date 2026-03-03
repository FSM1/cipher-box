# Session Context

## User Prompts

### Prompt 1

<execution_context>
@./.claude/get-shit-done/references/ui-brand.md
</execution_context>

<objective>
Create executable phase prompts (PLAN.md files) for a roadmap phase with integrated research and verification.

**Default flow:** Research (if needed) → Plan → Verify → Done

**Orchestrator role:** Parse arguments, validate phase, research domain (unless skipped or exists), spawn gsd-planner agent, verify plans with gsd-plan-checker, iterate until plans pass or max iterations reached, present...

### Prompt 2

question: does the plan include thorough e2e test cases for all the changed behaviors? Does the requirement of ensuring this functionality is covered by e2e tests change the implementation plan at all?


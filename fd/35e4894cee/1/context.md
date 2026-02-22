# Session Context

## User Prompts

### Prompt 1

Implement the following plan:

# Plan: Database Schema Evolution Protocol

## Context

Phase 14 exposed a gap: new TypeORM entities were added without a corresponding `CREATE TABLE` migration, breaking the staging deploy. The IPFS metadata side has a formal evolution protocol (`docs/METADATA_EVOLUTION_PROTOCOL.md`) but there's no equivalent for the PostgreSQL database schema. This doc will formalize the rules, conventions, and checklist for database migrations to prevent the same class of error ...

### Prompt 2

ok can you fix the device_approvals gap identified? Will this require a staging reset to fix?

### Prompt 3

but the fresh install will always run all the available migrations, why would you repeat creating the table in the full schema if it will be created in the dedicated migration?

### Prompt 4

ok push all this up and lets get it merged.

### Prompt 5

also what are thoughts on updating the dev and ci env to also use synchronize: false. this will surface issues with the missing migrations early enough in the dev process to prevent a whole lot of problems

### Prompt 6

i think lets add a gsd todo for this

### Prompt 7

<objective>
Capture an idea, task, or issue that surfaces during a GSD session as a structured todo for later work.

Enables "thought → capture → continue" flow without losing context or derailing current work.
</objective>

<context>
@.planning/STATE.md
</context>

<process>

<step name="ensure_directory">
```bash
mkdir -p .planning/todos/pending .planning/todos/done
```
</step>

<step name="check_existing_areas">
```bash
ls .planning/todos/pending/*.md 2>/dev/null | xargs -I {} grep "^area...


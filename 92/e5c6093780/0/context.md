# Session Context

## User Prompts

### Prompt 1

<objective>
List all pending todos, allow selection, load full context for the selected todo, and route to appropriate action.

Enables reviewing captured ideas and deciding what to work on next.
</objective>

<context>
@.planning/STATE.md
@.planning/ROADMAP.md
</context>

<process>

<step name="check_exist">
```bash
TODO_COUNT=$(ls .planning/todos/pending/*.md 2>/dev/null | wc -l | tr -d ' ')
echo "Pending todos: $TODO_COUNT"
```

If count is 0:
```
No pending todos.

Todos are captured during ...

### Prompt 2

5 seems like a great one to tackle

### Prompt 3

so how did the research go?

### Prompt 4

yeah please go ahead, and feel free to spin the app up in test mode to check that the fixes work

### Prompt 5

[Request interrupted by user for tool use]


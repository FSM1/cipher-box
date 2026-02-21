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

q

### Prompt 3

the switch file ipns keys from HKDF to random mentions that this is a breaking change, and the same clean break strategy from before should be followed. I feel that this change is exactly the type of task for exercising the new metadata migration techniques. can you update the todo to reflect this?


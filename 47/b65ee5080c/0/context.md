# Session Context

## User Prompts

### Prompt 1

there was some work done to optimize the ci pipelines to prevent expensive jobs like desktop builds from running on prs that do not change anything in the desktop app. seems like that is not working as intended: https://github.com/FSM1/cipher-box/pull/214 the ful desktop builds still ran

### Prompt 2

no, negation doesn't work in release please, since internally negation matches everything that is not the negative

### Prompt 3

yeah please push this to a fresh chore branch (pul in latest main first) and create a chore pr

### Prompt 4

ok lets get back to main and pull in latest

### Prompt 5

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

Todos are captured duri...

### Prompt 6

11

### Prompt 7

ok can you handle the local dev database clearing directly? postgres is accessible on 192.168.133.114

### Prompt 8

https://github.com/FSM1/cipher-box/pull/216#pullrequestreview-3867165012 coderabbit found an inconsistency in the db evolution protocol


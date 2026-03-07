# Session Context

## User Prompts

### Prompt 1

<objective>
Start a new milestone: questioning → research (optional) → requirements → roadmap.

Brownfield equivalent of new-project. Project exists, PROJECT.md has history. Gathers "what's next", updates PROJECT.md, then runs requirements → roadmap cycle.

**Creates/Updates:**

- `.planning/PROJECT.md` — updated with new milestone goals
- `.planning/research/` — domain research (optional, NEW features only)
- `.planning/REQUIREMENTS.md` — scoped requirements for this milestone
- `.planning/R...

### Prompt 2

Tool loaded.

### Prompt 3

So there are a couple of things I would like to achieve in this phase:
- Improve reliability of IPNS infra (mainly the delegated-ipns.dev flakiness) (already mentioned in existing planning)
- Move as much of the content in the database to IPNS/IPFS entries (also already have a todo)
- Implement the BYO-IPFS node todo
- Establish some performance baselines for the clients, server, ipfs infra.

### Prompt 4

[Request interrupted by user]

### Prompt 5

So there are a couple of things I would like to achieve in this milestone:
- Improve reliability of IPNS infra (mainly the delegated-ipns.dev flakiness) (already mentioned in existing planning)
- Move as much of the content in the database to IPNS/IPFS entries (also already have a todo)
- Implement the BYO-IPFS node todo
- Establish some performance baselines for the clients, server, ipfs infra.

### Prompt 6

Tool loaded.

### Prompt 7

Tool loaded.

### Prompt 8

Tool loaded.

### Prompt 9

so I am quite happy with the someguy addition, but I am not so sure about the scope and implications ithe folder_ipns change. could you expand on that so I can make better informed decision?

### Prompt 10

yeah lets do it

### Prompt 11

in terms of performance baselines, it might be necessary to instrument the clients as well as scripting some load testing clients that can be run to figure out when server performance starts degrading, such that I can have some idea of when to start worrying about scaling the backend infra.

### Prompt 12

yes


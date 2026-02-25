# Session Context

## User Prompts

### Prompt 1

<bash-input>git switch main</bash-input>

### Prompt 2

<bash-stdout>Switched to branch 'main'
Your branch is up to date with 'origin/main'.</bash-stdout><bash-stderr></bash-stderr>

### Prompt 3

can you start a local ui dev server pointed at the staging api

### Prompt 4

can you run the e2e tests against the local ui, in headed mode

### Prompt 5

[Request interrupted by user]

### Prompt 6

sorry, that wont work on that port - you need to kill which ever dev server is taking up port 5173

### Prompt 7

yeah nuke it

### Prompt 8

ok now run the e2e tests in a headed browser against this local dev instance

### Prompt 9

can you pull out the correct test credentials from the staging server env?

### Prompt 10

yes

### Prompt 11

yeah I think that making the tests resilient enough to execute reliably against the staging api is quite important. if you do decide to make any test changes, dont forget to switch to a feature branch

### Prompt 12

ok thanks, please add a @.learnings/README.md entry

### Prompt 13

ok push this all up and create a pr


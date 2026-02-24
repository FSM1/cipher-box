# Session Context

## User Prompts

### Prompt 1

ok given the current setup, and the fact that all changes are entirely client-side, you can just point the local ui instance at the staging api for the duration of this test.

### Prompt 2

please remember to revert when we are done testing - in the mean time, start the dev server and execute the e2e test against it, in a headed browser session.

### Prompt 3

[Request interrupted by user]

### Prompt 4

kill all the existing servers on the ports, since oauth and such requires the use of 5173

### Prompt 5

but the staging api should be suitable for the test credentials

### Prompt 6

hmmm, ok stop the web dev server, and it looks like the same test is still failing in CI. there must be something else causing these test failures.


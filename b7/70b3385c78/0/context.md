# Session Context

## User Prompts

### Prompt 1

4 comments from coderabbit on that PR. you know what to do

### Prompt 2

ok, looks like the e2e tests are still failing, most likely because of jwks endpoint issues. is it realistic to use the same jwks signing key as staging in the e2e test run, so that w3auth does not fail?

### Prompt 3

I am guessing that the local env already has the correct key set since we were able to pass all the mfa e2e tests locally. please wire the github secret in to the workflow

### Prompt 4

yeah please go ahead


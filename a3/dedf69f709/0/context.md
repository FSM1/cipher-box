# Session Context

## User Prompts

### Prompt 1

<objective>
Display changes between installed version and latest available version.

Shows version comparison, changelog entries for missed versions, and update instructions.
</objective>

<process>

<step name="get_installed_version">
Read installed version from VERSION file:

```bash
cat ./.claude/get-shit-done/VERSION 2>/dev/null
```

**If VERSION file missing:**
```
## GSD What's New

**Installed version:** Unknown

Your installation doesn't include version tracking.

**To fix:** `npx get...

### Prompt 2

ok given that I have customized a lot of my GSD flows, how feasible do you think it is to update GSD to the latest version and reapply the updates to the new version?

### Prompt 3

ok great, can you create a plan to do this, and then execute said plan?

### Prompt 4

[Request interrupted by user]

### Prompt 5

why are you editing the global GSD install? can we remove the global install, and only fiddle with the project installation?

### Prompt 6

I think that this is only the case since you used the --global install version. if that flag was not used and GSD was installed into the project directly, it would point at relative paths inside the `.claude` folder.

### Prompt 7

ok can we create a chore branch for this, and push to this branch, then PR


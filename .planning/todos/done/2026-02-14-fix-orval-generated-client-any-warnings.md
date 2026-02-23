---
created: 2026-02-14T16:27
title: Fix no-explicit-any warnings in generated API client
area: tooling
files:
  - apps/web/src/api/
  - apps/web/orval.config.ts
---

## Problem

Running `pnpm api:generate` (which invokes orval to generate the typed API client from the OpenAPI spec) produces 25 `@typescript-eslint/no-explicit-any` warnings across the generated files in `apps/web/src/api/`. These are currently warnings not errors, but they add noise to CI output and lint runs.

The warnings come from orval's default code generation which uses `any` for certain response types, error handlers, and custom instance parameters.

## Solution

Options (pick one or combine):

1. **Configure orval to emit stricter types** — check orval.config.ts for override options that produce `unknown` instead of `any`
2. **Add eslint-disable comments via orval's header config** — add `/* eslint-disable @typescript-eslint/no-explicit-any */` to generated file headers
3. **Use orval's `override.mutator` or type mapping** to replace `any` with `unknown` in generated output
4. **Add an eslintrc override** scoping the rule to `apps/web/src/api/**` as off/warn

Option 3 is ideal (fix at the source), option 4 is the pragmatic fallback.

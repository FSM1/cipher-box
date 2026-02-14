#!/bin/bash

# Check if API source files are staged but generated client files are not
# This prevents forgetting to run `pnpm api:generate` after API changes

# Files that indicate API changes requiring client regeneration
API_PATTERNS=(
  "apps/api/src/.*\.dto\.ts"
  "apps/api/src/.*\.controller\.ts"
  "apps/api/src/.*\.entity\.ts"
)

# Generated files that should be updated when API changes
GENERATED_FILES=(
  "packages/api-client/openapi.json"
)

# Get staged files
STAGED_FILES=$(git diff --cached --name-only)

# Check if any API source files are staged
API_CHANGED=false
for pattern in "${API_PATTERNS[@]}"; do
  if echo "$STAGED_FILES" | grep -qE "$pattern"; then
    API_CHANGED=true
    break
  fi
done

if [ "$API_CHANGED" = false ]; then
  exit 0
fi

# API files changed - check if generated files are also staged
MISSING_GENERATED=()
for file in "${GENERATED_FILES[@]}"; do
  if ! echo "$STAGED_FILES" | grep -q "^${file}$"; then
    MISSING_GENERATED+=("$file")
  fi
done

if [ ${#MISSING_GENERATED[@]} -gt 0 ]; then
  echo ""
  echo "⚠️  API source files changed but generated client files are not staged!"
  echo ""
  echo "You modified API DTOs, controllers, or entities but didn't regenerate the client."
  echo ""
  echo "Run this command and stage the changes:"
  echo ""
  echo "    pnpm api:generate"
  echo ""
  echo "Missing generated files:"
  for file in "${MISSING_GENERATED[@]}"; do
    echo "    - $file"
  done
  echo ""
  echo "To skip this check (not recommended), use: git commit --no-verify"
  echo ""
  exit 1
fi

exit 0

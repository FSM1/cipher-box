#!/usr/bin/env bash
set -euo pipefail

# Pre-create release labels for PR-time release preview action
# Usage: .github/scripts/create-release-labels.sh [--dry-run]

DRY_RUN=false
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN=true
fi

# Component short names (12 versioned components, excluding root)
# api = lock group covering apps/api + packages/api-client + crates/api-client
COMPONENTS=(
  api web desktop tee-worker
  core crypto sdk-core sdk
  cipherbox-crypto cipherbox-core cipherbox-fuse cipherbox-sdk
)

# Bump types
TYPES=(feat fix perf refactor breaking)

# Returns color for a given type
get_color() {
  case "$1" in
    feat)      echo "0E8A16" ;;
    fix)       echo "D93F0B" ;;
    perf)      echo "FBCA04" ;;
    refactor)  echo "1D76DB" ;;
    breaking)  echo "B60205" ;;
  esac
}

# Returns description for a given type
get_description() {
  case "$1" in
    feat)      echo "Minor version bump (new feature)" ;;
    fix)       echo "Patch version bump (bug fix)" ;;
    perf)      echo "Patch version bump (performance improvement)" ;;
    refactor)  echo "Patch version bump (code refactoring)" ;;
    breaking)  echo "Major version bump (breaking change)" ;;
  esac
}

created=0
skipped=0
failed=0

for comp in "${COMPONENTS[@]}"; do
  for type in "${TYPES[@]}"; do
    label="release:${comp}:${type}"
    desc="$(get_description "$type") for ${comp}"
    color="$(get_color "$type")"

    if $DRY_RUN; then
      echo "[dry-run] Would create: $label (#$color) - $desc"
      ((created++))
      continue
    fi

    if gh label create "$label" --color "$color" --description "$desc" 2>/dev/null; then
      echo "Created: $label"
      ((created++))
    else
      # Label may already exist -- try to update color/description
      if gh label edit "$label" --color "$color" --description "$desc" 2>/dev/null; then
        echo "Updated: $label"
        ((skipped++))
      else
        echo "FAILED: $label"
        ((failed++))
      fi
    fi
  done
done

# Create release:none escape hatch label
NONE_LABEL="release:none"
NONE_COLOR="CCCCCC"
NONE_DESC="No release needed for this PR"

if $DRY_RUN; then
  echo "[dry-run] Would create: $NONE_LABEL (#$NONE_COLOR) - $NONE_DESC"
  ((created++))
else
  if gh label create "$NONE_LABEL" --color "$NONE_COLOR" --description "$NONE_DESC" 2>/dev/null; then
    echo "Created: $NONE_LABEL"
    ((created++))
  else
    if gh label edit "$NONE_LABEL" --color "$NONE_COLOR" --description "$NONE_DESC" 2>/dev/null; then
      echo "Updated: $NONE_LABEL"
      ((skipped++))
    else
      echo "FAILED: $NONE_LABEL"
      ((failed++))
    fi
  fi
fi

echo ""
echo "Summary: ${created} created, ${skipped} updated, ${failed} failed"
echo "Total expected: $((${#COMPONENTS[@]} * 5 + 1)) labels"

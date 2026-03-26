#!/usr/bin/env bash
#
# provision-alerts.sh - Deploy CipherBox alert rules to Grafana Cloud
#
# Purpose:
#   Reads alert rule JSON files from docker/grafana/alerts/ and provisions
#   them via the Grafana Alerting Provisioning HTTP API. Handles placeholder
#   replacement for datasource UID and folder UID automatically.
#
# Prerequisites:
#   - curl and jq installed
#   - Grafana Cloud API key with alert rule provisioning permissions
#     (Service Account Token with "Alert rule writer" role)
#
# How to find the datasource UID:
#   1. Open Grafana Cloud > Settings > Data Sources
#   2. Click the Mimir/Prometheus data source
#   3. Copy the UID from the URL bar (e.g., /datasources/edit/<uid>)
#
# Usage:
#   ./provision-alerts.sh <grafana-url> <api-key> <datasource-uid>
#   ./provision-alerts.sh <grafana-url> <api-key> <datasource-uid> --dry-run
#
# Examples:
#   ./provision-alerts.sh https://myorg.grafana.net glsa_xxxx abc123
#   ./provision-alerts.sh https://myorg.grafana.net glsa_xxxx abc123 --dry-run
#

set -euo pipefail

# --- Argument validation ---

GRAFANA_URL="${1:-}"
API_KEY="${2:-}"
DATASOURCE_UID="${3:-}"
DRY_RUN=false

if [[ -z "$GRAFANA_URL" || -z "$API_KEY" || -z "$DATASOURCE_UID" ]]; then
  echo "Usage: $0 <grafana-url> <api-key> <datasource-uid> [--dry-run]"
  echo ""
  echo "Arguments:"
  echo "  grafana-url     Grafana Cloud instance URL (e.g., https://myorg.grafana.net)"
  echo "  api-key         Grafana Cloud API key (service account token)"
  echo "  datasource-uid  Mimir/Prometheus datasource UID"
  echo ""
  echo "Options:"
  echo "  --dry-run       Print processed JSON without POSTing to API"
  exit 1
fi

# Check for --dry-run flag (only after the 3 positional args)
for arg in "${@:4}"; do
  if [[ "$arg" == "--dry-run" ]]; then
    DRY_RUN=true
  fi
done

# Strip trailing slash from URL
GRAFANA_URL="${GRAFANA_URL%/}"

# --- Dependency check ---

if ! command -v jq &>/dev/null; then
  echo "ERROR: jq is required but not installed."
  echo "Install: brew install jq (macOS) or apt-get install jq (Ubuntu)"
  exit 1
fi

if ! command -v curl &>/dev/null; then
  echo "ERROR: curl is required but not installed."
  exit 1
fi

# --- Resolve alert directory ---

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ALERT_DIR="$SCRIPT_DIR/../alerts"

if [[ ! -d "$ALERT_DIR" ]]; then
  echo "ERROR: Alert rules directory not found: $ALERT_DIR"
  exit 1
fi

JSON_FILES=("$ALERT_DIR"/*.json)

if [[ ${#JSON_FILES[@]} -eq 0 || ! -f "${JSON_FILES[0]}" ]]; then
  echo "ERROR: No JSON files found in $ALERT_DIR"
  exit 1
fi

# --- Discover or create alerts folder ---

FOLDER_UID=""

if [[ "$DRY_RUN" == false ]]; then
  echo "Discovering or creating 'CipherBox Alerts' folder..."

  FOLDERS_RESPONSE=$(curl -s -w "\n%{http_code}" \
    -H "Authorization: Bearer $API_KEY" \
    "$GRAFANA_URL/api/folders")

  FOLDERS_HTTP_CODE=$(echo "$FOLDERS_RESPONSE" | tail -1)
  FOLDERS_BODY=$(echo "$FOLDERS_RESPONSE" | sed '$d')

  if [[ "$FOLDERS_HTTP_CODE" -ne 200 ]]; then
    echo "ERROR: Failed to list folders (HTTP $FOLDERS_HTTP_CODE)"
    echo "$FOLDERS_BODY"
    exit 1
  fi

  FOLDER_UID=$(echo "$FOLDERS_BODY" | jq -r '.[] | select(.title == "CipherBox Alerts") | .uid // empty')

  if [[ -z "$FOLDER_UID" ]]; then
    echo "Folder 'CipherBox Alerts' not found. Creating..."

    CREATE_RESPONSE=$(curl -s -w "\n%{http_code}" \
      -X POST "$GRAFANA_URL/api/folders" \
      -H "Authorization: Bearer $API_KEY" \
      -H "Content-Type: application/json" \
      -d '{"title": "CipherBox Alerts"}')

    CREATE_HTTP_CODE=$(echo "$CREATE_RESPONSE" | tail -1)
    CREATE_BODY=$(echo "$CREATE_RESPONSE" | sed '$d')

    if [[ "$CREATE_HTTP_CODE" -ne 200 ]]; then
      echo "ERROR: Failed to create folder (HTTP $CREATE_HTTP_CODE)"
      echo "$CREATE_BODY"
      exit 1
    fi

    FOLDER_UID=$(echo "$CREATE_BODY" | jq -r '.uid')
    echo "Created folder with UID: $FOLDER_UID"
  else
    echo "Found existing folder with UID: $FOLDER_UID"
  fi
else
  FOLDER_UID="DRY_RUN_FOLDER_UID"
  echo "[DRY RUN] Using placeholder folder UID: $FOLDER_UID"
fi

# --- Provision alert rules ---

SUCCESS_COUNT=0
FAIL_COUNT=0
TOTAL_RULES=0

echo ""
echo "Processing alert rule files..."
echo "==============================="

for rule_file in "${JSON_FILES[@]}"; do
  rule_name=$(basename "$rule_file" .json)
  echo ""
  echo "--- $rule_name ---"

  # Read file and replace placeholders
  file_content=$(cat "$rule_file")
  file_content=$(echo "$file_content" | sed -e "s|GRAFANA_CLOUD_DATASOURCE_UID|$DATASOURCE_UID|g" -e "s|GRAFANA_ALERTS_FOLDER_UID|$FOLDER_UID|g")

  # Determine if file is an array (multiple rules) or single rule
  is_array=$(echo "$file_content" | jq 'type == "array"')

  if [[ "$is_array" == "true" ]]; then
    rule_count=$(echo "$file_content" | jq 'length')
  else
    rule_count=1
  fi

  for ((i = 0; i < rule_count; i++)); do
    if [[ "$is_array" == "true" ]]; then
      rule=$(echo "$file_content" | jq ".[$i]")
    else
      rule="$file_content"
    fi

    rule_title=$(echo "$rule" | jq -r '.title')
    TOTAL_RULES=$((TOTAL_RULES + 1))

    if [[ "$DRY_RUN" == true ]]; then
      echo "[DRY RUN] Rule: $rule_title"
      echo "$rule" | jq .
    else
      echo "Provisioning: $rule_title"

      RESPONSE=$(curl -s -w "\n%{http_code}" \
        -X POST "$GRAFANA_URL/api/v1/provisioning/alert-rules" \
        -H "Authorization: Bearer $API_KEY" \
        -H "Content-Type: application/json" \
        -H "X-Disable-Provenance: true" \
        -d "$rule")

      HTTP_CODE=$(echo "$RESPONSE" | tail -1)
      BODY=$(echo "$RESPONSE" | sed '$d')

      if [[ "$HTTP_CODE" -ge 200 && "$HTTP_CODE" -lt 300 ]]; then
        echo "  OK (HTTP $HTTP_CODE)"
        SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
      else
        echo "  FAILED (HTTP $HTTP_CODE)"
        echo "  Response: $BODY"
        FAIL_COUNT=$((FAIL_COUNT + 1))
      fi
    fi
  done
done

# --- Summary ---

echo ""
echo "==============================="
echo "Provisioning Summary"
echo "==============================="
echo "Total rules:  $TOTAL_RULES"

if [[ "$DRY_RUN" == true ]]; then
  echo "Mode:         DRY RUN (no changes applied)"
else
  echo "Succeeded:    $SUCCESS_COUNT"
  echo "Failed:       $FAIL_COUNT"

  if [[ "$FAIL_COUNT" -gt 0 ]]; then
    echo ""
    echo "WARNING: $FAIL_COUNT rule(s) failed to provision."
    exit 1
  fi
fi

echo ""
echo "Done."

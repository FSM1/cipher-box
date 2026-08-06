#!/usr/bin/env bash
#
# Rotate the staging environment's Actions secrets onto unprefixed names.
#
# GitHub secrets are write-only: there is no API or UI read, so an existing value
# cannot be copied to a new name. Renaming a secret therefore means minting a new
# value, which is only safe when nothing outside GitHub already knows the old one.
#
# Two of the seven have a counterpart on the VPS and are refused by default:
# rotating them in GitHub alone breaks staging until the paired change lands.
#
#   ./scripts/rotate-staging-secrets.sh              # dry run, prints the plan
#   ./scripts/rotate-staging-secrets.sh --apply      # rotate the safe set
#   ./scripts/rotate-staging-secrets.sh --apply --include-db
#
set -euo pipefail

REPO="FSM1/cipher-box"
ENVIRONMENT="staging"
APPLY=0
INCLUDE_DB=0

# Rotating these only rewrites .env.staging, which every deploy regenerates and
# every container re-reads on restart. No state outside GitHub knows the old value.
SAFE_ROTATIONS=(
  "STAGING_JWT_SECRET:JWT_SECRET:base64"
  "STAGING_TEST_LOGIN_SECRET:TEST_LOGIN_SECRET:base64"
  "STAGING_THROTTLE_BYPASS_SECRET:THROTTLE_BYPASS_SECRET:base64"
  "STAGING_REDIS_PASSWORD:REDIS_PASSWORD:base64"
)

# v2 has no TEE (AGENTS.md: the republisher is a keyless re-PUT module inside the
# API), so these are deleted rather than rotated onto a new name.
RETIRED=("STAGING_TEE_WORKER_SECRET")

retire() {
  local name="$1"
  secret_exists "$name" || { printf '  already gone  %s\n' "$name"; return 0; }
  if [ "$APPLY" -eq 0 ]; then
    printf '  would delete  %-32s (v2 has no TEE)\n' "$name"
    return 0
  fi
  "${GH[@]}" secret delete "$name" --env "$ENVIRONMENT" --repo "$REPO" >/dev/null
  if secret_exists "$name"; then
    echo "  FAILED        $name (still present after delete)" >&2
    return 1
  fi
  printf '  deleted       %-32s (v2 has no TEE)\n' "$name"
}

usage() {
  sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'TXT'

Refused without an explicit flag:

  STAGING_DB_PASSWORD    Postgres applies POSTGRES_PASSWORD only when it
                         initialises an empty data volume. The staging volume
                         already exists, so a new secret makes the API's
                         DB_PASSWORD disagree with the live role and every
                         connection fails. Pair it with, on the VPS:
                           docker compose -f docker-compose.staging.yml exec postgres \
                             psql -U "$DB_USERNAME" -d cipherbox_staging \
                             -c "ALTER USER \"$DB_USERNAME\" WITH PASSWORD '<new>';"
                         Then set the secret. Pass --include-db to have this
                         script print the new value once so you can do both.

  STAGING_SSH_KEY        This is the deploy key. Minting a new one without first
                         installing its public half in the VPS authorized_keys
                         locks the pipeline out of the box it deploys to, and
                         this script cannot verify the VPS side. Rotate by hand:
                           ssh-keygen -t ed25519 -C 'cipherbox staging deploy' -f ./k
                           ssh-copy-id -i ./k.pub <user>@<host>   # verify a login
                           gh secret set SSH_KEY --env staging --repo FSM1/cipher-box < ./k
                           shred -u ./k ./k.pub
                         Never leave the private half on disk afterwards.
TXT
}

for arg in "$@"; do
  case "$arg" in
    --apply) APPLY=1 ;;
    --include-db) INCLUDE_DB=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; usage >&2; exit 2 ;;
  esac
done

command -v gh >/dev/null || { echo "gh is not installed" >&2; exit 1; }
command -v openssl >/dev/null || { echo "openssl is not installed" >&2; exit 1; }
GH=(env -u GITHUB_TOKEN gh)

"${GH[@]}" api "repos/$REPO/environments/$ENVIRONMENT" >/dev/null 2>&1 \
  || { echo "cannot reach the $ENVIRONMENT environment on $REPO" >&2; exit 1; }

generate() {
  case "$1" in
    base64) openssl rand -base64 32 | tr -d '\n' ;;
    hex) openssl rand -hex 32 | tr -d '\n' ;;
  esac
}

secret_exists() {
  "${GH[@]}" api "repos/$REPO/environments/$ENVIRONMENT/secrets/$1" >/dev/null 2>&1
}

updated_at() {
  "${GH[@]}" api "repos/$REPO/environments/$ENVIRONMENT/secrets/$1" --jq '.updated_at' 2>/dev/null
}

rotate() {
  local old="$1" new="$2" kind="$3" reveal="${4:-0}"

  if [ "$APPLY" -eq 0 ]; then
    printf '  would rotate  %-32s -> %-24s (%s)\n' "$old" "$new" "$kind"
    return 0
  fi

  local before value
  before="$(updated_at "$new" || true)"
  value="$(generate "$kind")"

  # Piped, never --body: an argument would be visible in the process list.
  printf '%s' "$value" | "${GH[@]}" secret set "$new" --env "$ENVIRONMENT" --repo "$REPO" >/dev/null

  local after
  after="$(updated_at "$new" || true)"
  if [ -z "$after" ] || { [ -n "$before" ] && [ "$before" = "$after" ]; }; then
    echo "  FAILED        $new (no write recorded)" >&2
    return 1
  fi
  printf '  rotated       %-32s -> %-24s @ %s\n' "$old" "$new" "$after"

  if [ "$reveal" -eq 1 ]; then
    echo
    echo "  The paired VPS change needs this value. It is shown once and not stored:"
    echo "    $value"
    echo
  fi
  unset value
}

echo "Repo $REPO, environment $ENVIRONMENT"
[ "$APPLY" -eq 0 ] && echo "DRY RUN — nothing is written. Re-run with --apply."
echo

FAILED=0
for row in "${SAFE_ROTATIONS[@]}"; do
  IFS=: read -r old new kind <<<"$row"
  secret_exists "$old" || printf '  note: %s does not exist; %s is being created fresh\n' "$old" "$new"
  rotate "$old" "$new" "$kind" || FAILED=1
done

echo
for name in "${RETIRED[@]}"; do
  retire "$name" || FAILED=1
done

if [ "$INCLUDE_DB" -eq 1 ]; then
  echo
  echo "DB_PASSWORD: staging is broken between this write and the ALTER USER on the VPS."
  rotate STAGING_DB_PASSWORD DB_PASSWORD base64 1 || FAILED=1
else
  echo
  echo "  skipped       STAGING_DB_PASSWORD  (needs a paired ALTER USER; --include-db)"
fi
echo "  skipped       STAGING_SSH_KEY      (rotate by hand; see --help)"

if [ "$APPLY" -eq 1 ] && [ "$FAILED" -eq 0 ]; then
  cat <<TXT

Next, in order:
  1. Update every workflow reference from secrets.STAGING_<NAME> to secrets.<NAME>.
  2. docker/docker-compose.staging.yml still declares redis and tee-worker
     services, and .env.staging supplies neither REDIS_PASSWORD nor
     TEE_WORKER_SECRET, so compose substitutes empty. Settle both services
     before the next staging deploy.
  3. Merge, run a staging deploy, confirm it is healthy.
  4. Only then delete the old secrets:
       for s in STAGING_JWT_SECRET STAGING_TEST_LOGIN_SECRET \\
                STAGING_THROTTLE_BYPASS_SECRET STAGING_REDIS_PASSWORD; do
         env -u GITHUB_TOKEN gh secret delete "\$s" --env $ENVIRONMENT --repo $REPO
       done
TXT
fi

exit "$FAILED"

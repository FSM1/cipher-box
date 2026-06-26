---
phase: 30-web-app-observability
plan: 03
subsystem: infra
tags: [source-maps, vite, rollup, grafana, ci-cd, staging]

requires:
  - phase: 30-01
    provides: Faro SDK initialization (VITE_FARO_URL env var pattern)
provides:
  - Source map upload to Grafana Cloud at build time
  - Hidden source maps (not served to browser)
  - Faro env vars in staging deploy workflow
affects: [staging-deployment, error-debugging]

tech-stack:
  added: ['@grafana/faro-rollup-plugin']
  patterns: ['conditional Vite plugin based on env vars', 'hidden source maps']

key-files:
  created: []
  modified:
    - apps/web/vite.config.ts
    - apps/web/package.json
    - .github/workflows/deploy-staging.yml

key-decisions:
  - 'sourcemap: hidden — generates .map files for upload but no //# sourceMappingURL in output JS'
  - 'keepSourcemaps: false — maps uploaded to Grafana but not in deployed output (security)'
  - 'Plugin only activates in production mode with both VITE_FARO_URL and GRAFANA_FARO_API_KEY'
  - 'Converted vite.config.ts from plain object to function form defineConfig(({ mode }) => ...)'

patterns-established:
  - 'Build-time-only source map upload: maps never leave server infrastructure'

requirements-completed: []

duration: 3min
completed: 2026-03-28
---

# Plan 30-03: Source Map Upload and Staging Deploy Configuration Summary

**Vite source map upload to Grafana Cloud with hidden maps (never served to browser) and staging env vars in all build steps**

## Performance

- **Duration:** 3 min
- **Tasks:** 3
- **Files modified:** 3

## Accomplishments

- Installed @grafana/faro-rollup-plugin as dev dependency
- Converted vite.config.ts to function form with conditional Faro plugin
- Added build.sourcemap: 'hidden' for source map generation without browser exposure
- Added VITE_FARO_URL, GRAFANA_FARO_API_KEY, GRAFANA_STACK_ID to all 4 build steps in deploy-staging.yml (web, macOS, Windows, Linux)

## Task Commits

1. **Tasks 1-3: Plugin install, Vite config, deploy workflow** - `e2022d7f1`

## Files Created/Modified

- `apps/web/vite.config.ts` - Function-form defineConfig with conditional Faro plugin and hidden source maps
- `apps/web/package.json` - Added @grafana/faro-rollup-plugin to devDependencies
- `.github/workflows/deploy-staging.yml` - VITE_FARO_URL/GRAFANA_FARO_API_KEY/GRAFANA_STACK_ID in all build steps

## Decisions Made

- Used vars (not secrets) for VITE_FARO_URL and GRAFANA_STACK_ID — they're non-sensitive public endpoints
- Used secrets for GRAFANA_FARO_API_KEY — API key for source map upload auth

## Deviations from Plan

None - plan executed as specified.

## Issues Encountered

None.

## User Setup Required

GitHub environment variables/secrets needed for staging:

- `vars.VITE_FARO_URL` - Grafana Faro collector endpoint URL
- `vars.GRAFANA_STACK_ID` - Grafana Cloud stack identifier
- `secrets.GRAFANA_FARO_API_KEY` - API key for source map upload

## Next Phase Readiness

- Source maps will be uploaded on next staging deploy
- Faro active in staging when VITE_FARO_URL is configured

---

_Phase: 30-web-app-observability_
_Completed: 2026-03-28_

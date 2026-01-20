# Phase 1: Foundation - Context

**Gathered:** 2026-01-20
**Status:** Ready for planning

<domain>
## Phase Boundary

Project scaffolding, CI/CD, and development environment. Infrastructure exists for development and deployment. NestJS backend scaffold, React frontend scaffold, CI/CD pipeline, and local dev environment with Pinata sandbox access.

</domain>

<decisions>
## Implementation Decisions

### Project structure
- Monorepo with pnpm workspaces
- Shared crypto module lives in `packages/crypto` — imported by frontend, backend, and desktop
- Feature-based folder structure within apps (auth/, files/, folders/ each with components, hooks, services)

### CI/CD approach
- GitHub Actions for CI/CD
- Required checks: Lint + Test + Build (all must pass to merge)
- Auto-deploy to staging on merge to main
- Deployment target: Railway (backend + PostgreSQL)

### Development environment
- Docker Compose for PostgreSQL locally
- `.env` files with committed `.env.example` as template
- Concurrent dev script: `pnpm dev` runs both frontend and backend
- ESLint + Prettier + Husky for formatting/linting (pre-commit hooks)

### Claude's Discretion
- Exact ESLint/Prettier rule configurations
- Docker Compose service naming
- pnpm workspace configuration details
- GitHub Actions workflow file structure

</decisions>

<specifics>
## Specific Ideas

No specific requirements — standard scaffolding patterns apply.

</specifics>

<deferred>
## Deferred Ideas

None — discussion stayed within phase scope.

</deferred>

---

*Phase: 01-foundation*
*Context gathered: 2026-01-20*

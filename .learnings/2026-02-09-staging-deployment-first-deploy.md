# First Staging Deployment - Lessons Learned

**Date:** 2026-02-09

## Original Prompt

> Execute phase 9.1 (Environment Changes, DevOps & Staging Deployment) — walk through infrastructure provisioning step by step, then trigger first deployment and fix issues until staging is live.

## What I Learned

### GHCR requires lowercase image names

- `github.repository_owner` preserves case (e.g., `FSM1`), but GHCR rejects uppercase in image tags
- Fix: `echo "API_IMAGE=ghcr.io/${GITHUB_REPOSITORY_OWNER,,}/cipherbox-api" >> "$GITHUB_ENV"` (bash lowercase)
- The `,,` operator lowercases a bash variable — works in GitHub Actions runners

### Pinata multipart upload is fragile

- Shell-based multipart body construction (`echo`/`cat` into a file) corrupts binary content
- Use curl's native `-F` flag instead: `-F "file=@${filepath};filename=${relpath}"`
- Pinata directory uploads require a common folder prefix in filenames (e.g., `site/index.html`, not just `index.html`) — otherwise error: "More than one file and/or directory was provided"

### pnpm workspace Docker builds need `pnpm deploy`

- `COPY --from=deps /app/node_modules` copies root devDeps only (eslint, prettier, etc.)
- `COPY --from=deps /app/apps/api/node_modules` copies symlinks that point to `../../node_modules/.pnpm/` — Node resolution from `/app/dist/main.js` won't find them at `/app/apps/api/node_modules/`
- `pnpm deploy --prod --legacy` creates a standalone flat `node_modules` without symlinks
- pnpm v10 requires `--legacy` flag for deploy without `inject-workspace-packages=true`

### Check dependencies vs devDependencies before Docker deploy

- `@nestjs/throttler` was in `devDependencies` but imported in `app.module.ts` at runtime
- `pnpm deploy --prod` correctly skips devDeps, so the container crashed with `MODULE_NOT_FOUND`
- Rule: anything imported in non-test/non-build code must be in `dependencies`

### Docker Compose `.env` file naming matters

- Docker Compose only auto-reads `.env` in the compose file directory for variable substitution (`${VAR}`)
- A file named `.env.staging` is NOT read automatically — need `cp .env.staging .env`
- The `env_file:` directive in a service only sets container env vars, not compose-level substitution

### Docker Compose needs image vars in `.env`

- `GITHUB_REPOSITORY_OWNER` and `TAG` are set by the workflow during SSH, but `docker compose up -d` reads from `.env`
- These vars must be written to `.env.staging` during the generate step, not just exported in the deploy script

### Cloudflare Universal SSL only covers one level of subdomain

- `*.cipherbox.cc` covers `api-staging.cipherbox.cc` but NOT `api.staging.cipherbox.cc`
- Two-level subdomains (`*.staging.cipherbox.cc`) require Advanced Certificate Manager ($10/month)
- Fix: flatten to `api-staging` and `app-staging` instead of `api.staging` and `app.staging`

### Cloudflare IPFS gateway is deprecated

- `cloudflare-ipfs.com` no longer resolves — returns 403 or connection errors
- Pinata dedicated gateways require a paid plan ($20/month) for custom domains
- For staging: serve static files from Caddy on the VPS (free, reliable, no third-party dependency)

### Caddy volume mounts for symlinks

- `ln -s /a /b` creates symlink at `/b` pointing to `/a` — BUT if `/b` is an existing directory, it creates `/b/a` instead
- Always `rm -rf /b` first, then `ln -s /a /b`

### GitHub environment vs repository secrets

- Use GitHub Environments (`environment: staging`) for deployment secrets
- Split into `vars.` (non-sensitive: URLs, usernames, IDs) and `secrets.` (sensitive: keys, passwords, tokens)
- Jobs must declare `environment: staging` or they can't access environment-scoped secrets/vars

## What Would Have Helped

- Knowing Cloudflare's subdomain SSL limitations upfront — would have used flat names from the start
- Knowing `cloudflare-ipfs.com` was deprecated — would have skipped the IPFS gateway approach entirely
- A `pnpm deploy` dry run locally before pushing to CI — would have caught the `--legacy` and `devDependencies` issues
- Checking the `.env` vs `.env.staging` naming convention for Docker Compose before first deploy

## Key Files

- `.github/workflows/deploy-staging.yml` — the deployment pipeline
- `apps/api/Dockerfile` — API multi-stage build with `pnpm deploy`
- `docker/Caddyfile` — reverse proxy + static file serving
- `docker/docker-compose.staging.yml` — all staging services
- `apps/api/package.json` — dependencies vs devDependencies matters for Docker

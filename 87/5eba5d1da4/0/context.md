# Session Context

**Session ID:** f025f6b8-7e1e-41e7-89a0-a23c0b1ee192

**Commit Message:** Start the web app dev server, but pointed at the staging api

## Prompt

can you start the web app dev server, but pointed at the staging api?

## Summary

It's hitting the staging API now (`https://api-staging.cipherbox.cc/health`), but getting blocked by **CORS** — the staging API doesn't allow requests from `http://localhost:5173`. The button shows "[API OFFLINE]" because of this.

You have two options:

1. **Add `localhost:5173` to the staging API's CORS config** — easiest if you want to develop locally against staging regularly
2. **Use Vite's proxy** — proxy `/api` requests through Vite to avoid CORS entirely, no server changes needed

Which would you prefer?

## Key Actions

- - **Grep**: VITE.*API|API_URL|BASE_URL|api.*url
- - **Grep**: VITE_|localhost:3000|api.*base|baseURL
- - **Bash**: Start web dev server pointed at staging API
- - **mcp__playwright__browser_wait_for**: 
- - **mcp__playwright__browser_navigate**: 
- - **TaskStop**: 
- - **Grep**: health|HEALTH
- - **Grep**: localhost:3000|VITE_API_URL
- - **Read**: /Users/michael/Code/cipher-box/apps/web/src/api/custom-instance.ts
- - **Glob**: apps/web/.env*

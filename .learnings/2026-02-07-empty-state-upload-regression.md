# Empty State Upload Zone Regression

**Date:** 2026-02-07

## Original Prompt

> "there is a dropzone underneath the ascii art, and I am not a fan of the ascii art chosen. surely you can do something better"

Followed by: "the drag and drop to upload is no longer working"

## What I Learned

- **Removing a "visual" component can break functionality:** The UploadZone in EmptyState looked like a purely visual element (a box with upload text), but it was also the react-dropzone drop target providing drag-and-drop upload. Removing it to clean up the UI killed the DnD functionality.
- **Components often serve dual purposes:** Before removing any component, check if it provides event handlers, drop targets, focus management, or other invisible behavior beyond its visual output.
- **The fix pattern for invisible drop targets:** Use `useDropzone` directly on the container div via `getRootProps()` — this makes the entire area a drop target without rendering a separate visible upload zone component. Apply `getInputProps()` for the hidden file input.
- **API script naming:** The API uses `pnpm --filter api dev` (not `start:dev`). The `dev` script runs `nest start --watch`.
- **Docker is unnecessary in this dev environment:** PostgreSQL and IPFS are already exposed on the host. Just start the API and frontend.
- **GSD vendor markdown files fail markdownlint:** The `.claude/agents/gsd-*.md` and workflow files use non-standard markdown (HTML-like `<step>` tags, unfenced code blocks). These need to be excluded from linting via `.markdownlintignore`.

## What Would Have Helped

- Reading the UploadZone component before removing it from EmptyState to understand it provided drop target functionality, not just visuals
- Verifying DnD still worked immediately after the cosmetic fix, before committing
- A regression test for drag-and-drop upload in empty folders

## Key Files

- `apps/web/src/components/file-browser/EmptyState.tsx` — empty folder display + drop target
- `apps/web/src/components/file-browser/UploadZone.tsx` — standalone upload zone with react-dropzone
- `apps/web/src/components/file-browser/FileBrowser.tsx` — renders EmptyState with folderId prop
- `apps/web/src/styles/file-browser.css` — `.empty-state` and `.empty-state-drag-active` styles
- `tests/e2e/.env` — Web3Auth test credentials for Playwright login

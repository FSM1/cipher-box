# Pencil MCP: Multi-Screen Design and Save Gotcha

**Date:** 2026-02-09

## Original Prompt

> Add 14 new screens (modals, DnD, scroll, breadcrumbs) to the Pencil design file for both desktop and mobile viewports.

## What I Learned

- **Pencil MCP changes are in-memory only until explicitly saved.** The `batch_design` tool modifies an in-memory representation, NOT the `.pen` file on disk. The file hash stays identical to HEAD until the user saves from the Pencil editor UI. If the MCP server disconnects before save, all work is lost.
- **Modal overlay pattern:** Copy base screen, switch container to `layout: "none"`, explicitly set x/y/width/height on children that were previously flex-positioned, then layer backdrop (`#000000CC`) + modal frame on top. This matches how the existing Context Menu screen (Ano8r) was structured.
- **Copy gives new IDs to ALL descendants.** After `C()`, must `batch_get` the copied node to discover new child IDs. Never use `U()` on descendants of a just-copied node in the same batch — the old IDs no longer exist.
- **Efficient multi-screen workflow:** (1) Copy all screens as placeholders in one batch, (2) batch_get each to discover new IDs, (3) build content per screen, (4) screenshot to verify, (5) remove placeholder flags. Creating all placeholders upfront is required by Pencil guidelines and prevents layout collisions.
- **Mobile modal width convention:** 390px viewport - 2\*16px margin = 358px modal width. Padding shrinks from desktop 24px to mobile 16px.
- **Max 25 operations per `batch_design` call** — split complex screens across multiple calls by logical section (structure first, then content, then actions).

## What Would Have Helped

- Knowing upfront that Pencil MCP doesn't auto-save to disk — would have asked the user to save periodically during a long session
- Having the MCP server expose a "save to disk" tool would prevent data loss

## Key Files

- `designs/cipher-box-design.pen` — the design file (binary/encrypted, only accessible via Pencil MCP tools)
- `apps/web/src/index.css` — CSS design tokens (colors, fonts, spacing) that the design must match

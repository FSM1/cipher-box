# Phase 31: Structural Decomposition - Discussion Log (Assumptions + Discussion)

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions captured in CONTEXT.md — this log preserves the analysis.

**Date:** 2026-03-28
**Phase:** 31-Structural Decomposition
**Mode:** assumptions + interactive discussion
**Areas analyzed:** useSharedNavigation decomposition, FileBrowser/SharedFileBrowser split, folder.service decomposition, bin.service decomposition, SDK boundary analysis

## Initial Assumptions Presented

Original plan: split monolithic files into smaller web app modules (container+presentational, sub-hooks, barrel re-exports).

## User Correction: SDK-First Approach

User questioned whether business logic should move to the SDK rather than just splitting within the web layer. This led to a deep analysis of SDK vs web app logic boundaries.

**Key finding:** Significant business logic trapped in web hooks/services that is framework-agnostic:

- Tree validation utilities (getDepth, isDescendantOf, calculateSubtreeDepth)
- Error handling (isForbiddenError, withRevocationGuard)
- Conflict retry logic (withConflictRetry — uses Zustand directly)
- Shared write context building (buildSharedWriteCtx)
- Share key caching with TTL
- Bin expiration cleanup (purgeExpired)
- File registration to folders (addFileToFolder, replaceFileInFolder)

**User decision:** SDK-first decomposition — migrate trapped business logic to SDK, leave React hooks as thin wrappers. This aligns with the existing deprecation headers on folder.service.ts and bin.service.ts ("Use @cipherbox/sdk instead").

## External Research

No external research needed — pure refactoring phase operating within existing codebase.

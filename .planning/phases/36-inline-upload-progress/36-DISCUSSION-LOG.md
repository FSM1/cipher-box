# Phase 36: Refactor Upload Progress — Inline Display - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-03-30
**Phase:** 36-inline-upload-progress
**Areas discussed:** Inline placement, Per-file detail, Lifecycle & dismissal, Cancel & error UX

---

## Inline Placement

| Option              | Description                                                                                     | Selected |
| ------------------- | ----------------------------------------------------------------------------------------------- | -------- |
| Top of file list    | Upload items appear as rows at the top of the file/folder list, pushing existing items down     |          |
| Bottom panel        | Collapsible panel at bottom of file browser, similar to VS Code terminal panel                  |          |
| Inline in file list | Upload items appear directly in the file list at alphabetical position they'll occupy once done | ✓        |

**User's choice:** Inline in file list
**Notes:** Files appear at their final alphabetical position with progress bar instead of normal metadata.

---

## Per-file Detail

| Option                      | Description                                                                                                 | Selected |
| --------------------------- | ----------------------------------------------------------------------------------------------------------- | -------- |
| Progress bar + percent      | Replace size/date columns with progress bar, percentage, and status text (encrypting/uploading/registering) |          |
| Minimal — just progress bar | Thin progress bar under filename, no percentage or status text. Compact row.                                | ✓        |
| Status text only            | No progress bar, just a status label where size column normally goes                                        |          |

**User's choice:** Minimal — just progress bar
**Notes:** Let the progress bar alone communicate state. No text clutter.

---

## Lifecycle & Dismissal

| Option                | Description                                                             | Selected |
| --------------------- | ----------------------------------------------------------------------- | -------- |
| Instant swap          | Immediately replace uploading row with normal file row. No transition.  |          |
| Brief flash then swap | Show green 'complete' state for ~1s, then transition to normal file row | ✓        |
| Stay until all done   | Upload rows remain until entire batch finishes, then all swap at once   |          |

**User's choice:** Brief flash then swap
**Notes:** Green complete flash gives visual confirmation before the row becomes a normal file entry.

---

## Cancel UX

| Option                 | Description                                                                                      | Selected |
| ---------------------- | ------------------------------------------------------------------------------------------------ | -------- |
| Per-file cancel button | Each row has its own [✕] button. Cancelling one doesn't affect others. Cancelled row disappears. | ✓        |
| Cancel all button      | Single 'Cancel all' action for entire batch. No per-file cancel.                                 |          |
| Both                   | Per-file [✕] buttons AND a 'Cancel all' option                                                   |          |

**User's choice:** Per-file cancel button
**Notes:** Individual cancel per file, cancelled row disappears immediately.

---

## Error UX

| Option               | Description                                                                                          | Selected |
| -------------------- | ---------------------------------------------------------------------------------------------------- | -------- |
| Inline error + retry | Row shows error state (red bar, error icon) with retry and dismiss buttons. Stays visible.           | ✓        |
| Toast notification   | Failed row disappears, toast notification with error and retry action                                |          |
| Error + auto-retry   | Brief error state, then auto-retry up to 3 times. Persistent error only after all retries exhausted. |          |

**User's choice:** Inline error + retry
**Notes:** Red progress bar, retry [↻] and dismiss [✕] buttons. Row persists until user acts.

---

## Claude's Discretion

- Upload row icon/indicator style
- Animation timing for green flash and swap transition
- Progress bar integration with existing file list row layout
- Upload store simplification opportunities

## Deferred Ideas

- "Offload large file encryption to Web Worker" — reviewed, kept separate (performance concern, not progress UI)

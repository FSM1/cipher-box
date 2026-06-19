---
created: 2026-02-10T12:00
title: Remove debug eprintln! statements from desktop FUSE code
area: desktop
files:
  - apps/desktop/src-tauri/src/fuse/operations.rs:1638-1641
---

## Problem

Multiple `eprintln!(">>>` debug statements in the FUSE operations code bypass log-level filtering and leak filenames to stderr. In a privacy-focused app, leaking file names and paths is a meaningful concern. These were noted as a pre-merge cleanup task during Phase 9 development.

Identified by Phase 9 Desktop Security Review (REVIEW-2026-02-08-phase9-desktop.md, L-3). Also tracked in LOW-SEVERITY-BACKLOG.md item 15.

## Solution

Search for all `eprintln!(">>>` statements in `apps/desktop/src-tauri/src/` and either remove them or replace with `log::debug!()` calls that respect log-level configuration.

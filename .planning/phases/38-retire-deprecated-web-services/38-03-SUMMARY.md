# Plan 38-03 Summary: Fix @cipherbox/crypto circular devDependency

## Status: COMPLETE

## Changes Made

Removed circular `@cipherbox/core` devDependency from `@cipherbox/crypto`. `vault-ipns.test.ts` now uses hardcoded test vectors instead of cross-package imports.

## Delivered In

PR #422 — merged 2026-03-31

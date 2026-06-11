<!-- generated-by: gsd-doc-writer -->

# @cipherbox/web

Browser client for CipherBox — a privacy-first encrypted cloud storage UI built with React, Vite, and Web3Auth.

Part of the [CipherBox monorepo](../../README.md).

## Purpose

This app handles the full user-facing experience: Web3Auth MPC login, client-side file encryption, vault/file management, sharing flows, and IPNS polling sync. The server never receives plaintext or unencrypted keys.

## Structure

```text
src/
  components/    UI components (auth, file-browser, vault, settings, mfa, layout)
  routes/        Page-level route components (FilesPage, SharedPage, BinPage, Login, …)
  stores/        Zustand state stores (vault, folder, upload, download, share, sync, …)
  services/      Business logic (encryption, IPNS sync, download, sharing, device registry)
  workers/
    encrypt.worker.ts   Web Worker — encrypts file chunks off the main thread
    decrypt-sw.ts       Service Worker — streams decrypted file downloads
  hooks/         React hooks
  lib/           Low-level utilities and helpers
  utils/         Shared utility functions
```

## Scripts

| Command           | Description                              |
| ----------------- | ---------------------------------------- |
| `pnpm dev`        | Start Vite dev server                    |
| `pnpm build`      | Type-check, build app and service worker |
| `pnpm preview`    | Preview production build locally         |
| `pnpm lint`       | ESLint on `src/**/*.{ts,tsx}`            |
| `pnpm test`       | Run Vitest test suite                    |
| `pnpm test:watch` | Run Vitest in watch mode                 |

## Environment Variables

All `VITE_*` variables required at build time. See [docs/CONFIGURATION.md](../../docs/CONFIGURATION.md) for the full list.

## Further Reading

- [Getting Started](../../docs/GETTING-STARTED.md)
- [Architecture](../../docs/ARCHITECTURE.md)
- [Development Guide](../../docs/DEVELOPMENT.md)

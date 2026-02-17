# Desktop App (`apps/desktop`) - Development Notes

## Default API Target

The desktop app defaults to the **staging API** (`https://api-staging.cipherbox.cc`). Most development and testing tasks can be completed against staging without running a local API.

To develop against the local API instead, update `.env`:

```env
VITE_API_URL=http://localhost:3000
VITE_ENVIRONMENT=local
```

Also set `CIPHERBOX_API_URL=http://localhost:3000` in the Rust env (used by the native backend):

```bash
CIPHERBOX_API_URL=http://localhost:3000 pnpm --filter desktop dev
```

## Running the Desktop App

```bash
pnpm --filter desktop dev
```

Vite env vars are loaded from `apps/desktop/.env` automatically. No need to pass them on the command line.

## Tauri Webview Constraints

- No `window.ethereum` — wallet login is not available in the Tauri webview
- OAuth popups use `on_new_window` handler with shared WKWebViewConfiguration
- Use `clearCache()` not `logout({cleanup:true})` for Web3Auth session cleanup

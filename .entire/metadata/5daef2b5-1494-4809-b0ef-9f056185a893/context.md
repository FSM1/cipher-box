# Session Context

**Session ID:** 5daef2b5-1494-4809-b0ef-9f056185a893

**Commit Message:** Login request failed: error sending request for url (http://localhost:30

## Prompt

Login request failed: error sending request for url (http://localhost:3000/auth/login) - its still trying to hit the local api

## Summary

App is running. The Rust backend will now read `VITE_API_URL=https://api-staging.cipherbox.cc` from `.env` via dotenvy. Try Google login again — the `/auth/login` call should now hit staging instead of localhost.

## Key Actions

- - **Grep**: CIPHERBOX_API_URL
- - **Grep**: beforeDevCommand|devUrl|CIPHERBOX
- - **Read**: /Users/michael/Code/cipher-box/apps/desktop/src-tauri/src/main.rs
- - **Read**: /Users/michael/Code/cipher-box/apps/desktop/src-tauri/Cargo.toml
- - **Edit**: /Users/michael/Code/cipher-box/apps/desktop/src-tauri/Cargo.toml
- - **Edit**: /Users/michael/Code/cipher-box/apps/desktop/src-tauri/src/main.rs
- - **Read**: /Users/michael/Code/cipher-box/apps/desktop/.env
- - **TaskStop**: 
- - **Bash**: Start Tauri desktop app with dotenvy loading
- - **Bash**: Wait for Cargo build + check output

# Session Context

**Session ID:** 5daef2b5-1494-4809-b0ef-9f056185a893

**Commit Message:** Ok, next problem is the google popup is being blocked

## Prompt

ok, next problem is the google popup is being blocked

## Summary

Now, there's one thing you'll need to do: **add `http://localhost:1420/google-callback.html` as an authorized redirect URI** in the Google Cloud Console for the OAuth client `164556913424-uif44is1apnl7rqc9a2ac7vn8u9dq0ee`. Without this, Google will reject the redirect.

The change I made replaces the GIS One Tap approach (which requires an existing Google session in the webview — impossible in Tauri) with a standard OAuth2 implicit flow that opens a proper Google sign-in page in a popup window. After the user signs in, Google redirects to `/google-callback.html` with the ID token in the URL hash, which posts it back to the main window via `postMessage`.

Want me to restart the app so you can test once you've added the redirect URI?

## Key Actions

- - **Read**: /Users/michael/Code/cipher-box/apps/desktop/src/auth.ts
- - **Write**: /Users/michael/Code/cipher-box/apps/desktop/public/google-callback.html
- - **Edit**: /Users/michael/Code/cipher-box/apps/desktop/src/auth.ts
- - **Edit**: /Users/michael/Code/cipher-box/apps/desktop/src/auth.ts

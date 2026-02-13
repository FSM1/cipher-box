# Session Context

**Session ID:** 2095544c-fa50-4027-b664-c37e578957ce

**Commit Message:** Ok so with the email coming from the login only, if the user ends up in

## Prompt

ok so with the email coming from the login only, if the user ends up in the app with a session refresh, their email obviously remains user

## Summary

That's it. Now `userEmail` is:
- **Hydrated from localStorage** on store creation (survives refresh/session restore)
- **Persisted to localStorage** when set during login
- **Cleared from localStorage** on logout

The email isn't sensitive data, so this is safe — unlike tokens or keys which stay memory-only.

## Key Actions

- - **Read**: /Users/michael/Code/cipher-box/apps/web/src/stores/auth.store.ts
- - **Edit**: /Users/michael/Code/cipher-box/apps/web/src/stores/auth.store.ts
- - **Edit**: /Users/michael/Code/cipher-box/apps/web/src/stores/auth.store.ts
- - **Edit**: /Users/michael/Code/cipher-box/apps/web/src/stores/auth.store.ts

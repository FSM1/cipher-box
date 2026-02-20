# Session Context

**Session ID:** 5875de05-175c-4771-b670-1501b7412a8b

**Commit Message:** Cant get to dev console, since its disabled in release builds.

## Prompt

cant get to dev console, since its disabled in release builds.

## Summary

Now rebuild the release and you'll be able to right-click → Inspect Element to see the console. That'll show us the actual Core Kit error.

```bash
pnpm --filter desktop tauri build
```

Though honestly, rather than waiting for a full rebuild just for debugging, we could also just improve the error logging in the catch block so it surfaces the real error. Want me to update the catch in `main.ts` to stringify the full error object regardless of type? That way even a non-Error rejection value would show up in the UI status text.

## Key Actions

- - **Read**: /Users/michael/Code/cipher-box/apps/desktop/src-tauri/Cargo.toml
- - **Edit**: /Users/michael/Code/cipher-box/apps/desktop/src-tauri/Cargo.toml

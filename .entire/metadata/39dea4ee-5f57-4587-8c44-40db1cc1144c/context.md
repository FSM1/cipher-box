# Session Context

**Session ID:** 39dea4ee-5f57-4587-8c44-40db1cc1144c

**Commit Message:** Ok jsut tested the wallet auth flow, and both times I had to sign messag

## Prompt

ok jsut tested the wallet auth flow, and both times I had to sign messages twice, with different nonces. once there was a wagmi error before the wallet selection dialog.

## Summary

Good. Here's the summary of the two fixes:

**Fix 1 — Double signing race condition** (`WalletLoginButton.tsx`):
- Removed the direct `handleSiweFlow()` call from `handleConnectorClick`. Now only the `useEffect` triggers SIWE after wagmi updates `isConnected`/`address`. Previously both the effect and the callback called it, racing each other with different nonces.

**Fix 2 — Wagmi error on mount** (`config.ts`):
- Added `reconnectOnMount: false` to the wagmi config. Since CipherBox disconnects immediately after SIWE signing, there's no reason for wagmi to try reconnecting to a stale connector on page load — that was causing errors especially in Brave.

Ready to commit and push when you want.

## Key Actions

- - **Task**: Investigate wallet double-sign bug
- - **Read**: /Users/michael/Code/cipher-box/apps/web/src/components/auth/WalletLoginButton.tsx
- - **Grep**: injected|reconnect
- - **Read**: /Users/michael/Code/cipher-box/apps/web/src/lib/wagmi/config.ts
- - **Edit**: /Users/michael/Code/cipher-box/apps/web/src/components/auth/WalletLoginButton.tsx
- - **Edit**: /Users/michael/Code/cipher-box/apps/web/src/lib/wagmi/config.ts
- - **Read**: /Users/michael/Code/cipher-box/apps/web/src/components/auth/WalletLoginButton.tsx
- - **Edit**: /Users/michael/Code/cipher-box/apps/web/src/components/auth/WalletLoginButton.tsx
- - **Bash**: Lint check the modified files
- - **Bash**: Lint check with npx

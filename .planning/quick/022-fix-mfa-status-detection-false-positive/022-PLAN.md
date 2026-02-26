---
phase: quick-022
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - apps/web/src/hooks/useMfa.ts
autonomous: true

must_haves:
  truths:
    - 'Fresh account (no MFA enrolled) shows MFA status as DISABLED'
    - 'Account after enableMFA() shows MFA status as ENABLED'
  artifacts:
    - path: 'apps/web/src/hooks/useMfa.ts'
      provides: 'Corrected MFA status detection'
      contains: 'details.totalFactors > 2'
  key_links:
    - from: 'apps/web/src/hooks/useMfa.ts'
      to: 'apps/web/src/components/mfa/SecurityTab.tsx'
      via: 'useMfaStore.isMfaEnabled'
      pattern: 'isMfaEnabled'
---

<objective>
Fix false-positive MFA status detection in useMfa.ts.

Purpose: Every Web3Auth MPC Core Kit account starts with 2 factors by default (JWT verifier share + hashedShare cloud custodial key). The current check `details.totalFactors >= 2` is ALWAYS true, so MFA falsely shows as [ENABLED] for every user. After `enableMFA()` is called, the hashedShare is deleted and replaced by device + recovery factors, pushing totalFactors to 3+. The fix is changing `>= 2` to `> 2`.

Output: Corrected `useMfa.ts` where `checkMfaStatus` correctly detects MFA as disabled for fresh accounts and enabled only after enrollment.
</objective>

<execution_context>
@./.claude/get-shit-done/workflows/execute-plan.md
@./.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@apps/web/src/hooks/useMfa.ts
@apps/web/src/components/mfa/SecurityTab.tsx
</context>

<tasks>

<task type="auto">
  <name>Task 1: Fix MFA status threshold check and update comment</name>
  <files>apps/web/src/hooks/useMfa.ts</files>
  <action>
In `apps/web/src/hooks/useMfa.ts`, make two changes:

1. **Line 34 (comment):** Change the JSDoc comment from:

   ```text
   * MFA is enabled when totalFactors >= 2.
   ```

   to:

   ```text
   * MFA is enabled when totalFactors > 2 (every account starts with 2
   * default factors: JWT verifier share + hashedShare cloud custodial key).
   ```

2. **Line 46 (logic):** Change:

   ```typescript
   const enabled = details.totalFactors >= 2;
   ```

   to:

   ```typescript
   const enabled = details.totalFactors > 2;
   ```

Do NOT modify any other logic. The rest of the hook, store integration, and downstream components (SecurityTab, AuthorizedDevices) are correct -- they consume `isMfaEnabled` from the store which this fix will now set correctly.
</action>
<verify>

1. `cd /Users/michael/Code/cipher-box && pnpm --filter web exec tsc --noEmit` -- TypeScript compilation passes
2. `grep -n 'totalFactors > 2' apps/web/src/hooks/useMfa.ts` -- confirms the fix is on line 46
3. `grep -n 'totalFactors >= 2' apps/web/src/hooks/useMfa.ts` -- returns NO matches (old check removed)
   </verify>
   <done>

- `checkMfaStatus()` returns `isMfaEnabled: false` when `totalFactors === 2` (fresh account with default JWT + hashedShare factors)
- `checkMfaStatus()` returns `isMfaEnabled: true` when `totalFactors > 2` (after enableMFA creates device + recovery factors)
- Comment accurately explains why the threshold is `> 2`
  </done>
  </task>

</tasks>

<verification>
1. TypeScript compiles without errors: `pnpm --filter web exec tsc --noEmit`
2. No remaining `>= 2` check in useMfa.ts: `grep 'totalFactors >= 2' apps/web/src/hooks/useMfa.ts` returns nothing
3. New `> 2` check present: `grep 'totalFactors > 2' apps/web/src/hooks/useMfa.ts` returns the fix line
</verification>

<success_criteria>

- The single-character fix (`>=` to `>`) is applied at line 46 of useMfa.ts
- The comment is updated to explain the reasoning (default 2 factors)
- TypeScript compilation passes
- No other files modified (downstream consumers are already correct)
  </success_criteria>

<output>
After completion, create `.planning/quick/022-fix-mfa-status-detection-false-positive/022-SUMMARY.md`
</output>

<documentation>
The hashedShare is a cloud custodial key — it's Web3Auth's "training wheels" factor that exists on every fresh account. It makes the initial 2/2 setup seamless (user logs in with JWT, the hashedShare is automatically retrieved from Web3Auth's network, both shares combine to sign).

What enableMFA() does

When enableMFA() is called, it:

1. Deletes the hashedShare (removes the cloud custodial key)
2. Creates a device factor (stored locally)
3. Creates a backup/recovery factor (returned as the mnemonic)

So the account goes from semi-custodial (Web3Auth can reconstruct your key via the hashedShare) to fully non-custodial (only your devices + recovery phrase can reconstruct it).

Your staging account state

- totalFactors: 2 — the JWT verifier share + the hashedShare
- This is the default pre-MFA state for every account
- enableMFA() was never called, so the hashedShare was never deleted

So yes — totalFactors > 2 should work and is much simpler than parsing shareDescriptions. The baseline is always 2 (JWT + hashedShare), and enableMFA() deletes one and adds two, pushing it to 3+.

Sources:

- <https://web3auth.io/docs/sdk/mpc-core-kit/mpc-core-kit-js>
- <https://github.com/Web3Auth/mpc-core-kit-examples/blob/main/mpc-core-kit-web/quick-starts/mpc-core-kit-nextjs-quick-start/app/page.tsx>
- <https://web3auth.io/docs/infrastructure/mpc-architecture>
  </documentation>

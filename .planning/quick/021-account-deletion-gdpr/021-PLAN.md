## <!-- markdownlint-disable MD046 MD003 -->

phase: quick
plan: 021
type: execute
wave: 1
depends_on: []
files_modified:

- apps/api/src/auth/auth.controller.ts
- apps/api/src/auth/auth.service.ts
- apps/api/src/auth/dto/delete-account.dto.ts
- apps/api/scripts/generate-openapi.ts
- apps/web/src/lib/api/auth.ts
- apps/web/src/components/mfa/SecurityTab.tsx
- apps/web/src/App.css
  autonomous: true

must_haves:
truths: - "User can see a Danger Zone section at the bottom of the Security tab" - "User can click delete account and must type DELETE to confirm" - "After confirming deletion, user's account and all related data is permanently removed" - "After deletion, user is logged out and redirected to the login page"
artifacts: - path: "apps/api/src/auth/auth.controller.ts"
provides: "DELETE /auth/account endpoint"
contains: "deleteAccount" - path: "apps/api/src/auth/auth.service.ts"
provides: "deleteAccount service method"
contains: "deleteAccount" - path: "apps/api/src/auth/dto/delete-account.dto.ts"
provides: "DeleteAccountDto with confirmation field"
contains: "DeleteAccountDto" - path: "apps/web/src/components/mfa/SecurityTab.tsx"
provides: "Danger Zone UI with delete account confirmation"
contains: "danger-zone"
key_links: - from: "apps/web/src/components/mfa/SecurityTab.tsx"
to: "/auth/account"
via: "authApi.deleteAccount()"
pattern: "deleteAccount" - from: "apps/api/src/auth/auth.controller.ts"
to: "apps/api/src/auth/auth.service.ts"
via: "this.authService.deleteAccount"
pattern: "authService\\.deleteAccount"

---

<objective>
Add GDPR-compliant account deletion to the Settings Security tab.

Purpose: Allow users to permanently delete their CipherBox account and all associated data (auth methods, tokens, vaults, shares, IPNS records) via a single destructive action. ON DELETE CASCADE on all foreign keys referencing users.id handles data cleanup automatically.

Output: Backend DELETE endpoint, frontend Danger Zone UI with typed confirmation dialog, regenerated API client.
</objective>

<execution_context>
@./.claude/get-shit-done/workflows/execute-plan.md
@./.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/STATE.md
@apps/api/src/auth/auth.controller.ts
@apps/api/src/auth/auth.service.ts
@apps/api/src/auth/entities/user.entity.ts
@apps/web/src/components/mfa/SecurityTab.tsx
@apps/web/src/lib/api/auth.ts
@apps/web/src/hooks/useAuth.ts
@apps/web/src/App.css
@apps/api/scripts/generate-openapi.ts
</context>

<tasks>

<task type="auto">
  <name>Task 1: Backend DELETE /auth/account endpoint</name>
  <files>
    apps/api/src/auth/dto/delete-account.dto.ts
    apps/api/src/auth/auth.service.ts
    apps/api/src/auth/auth.controller.ts
    apps/api/scripts/generate-openapi.ts
  </files>
  <action>
    1. Create `apps/api/src/auth/dto/delete-account.dto.ts`:
       - Export `DeleteAccountDto` class with a single field `confirmation: string` (required, validated with `@IsString()` and `@IsNotEmpty()` from class-validator).
       - Export `DeleteAccountResponseDto` class with `success: boolean` field (for Swagger docs).
       - Add `@ApiProperty({ description: 'Must be the string "DELETE" to confirm', example: 'DELETE' })` to the confirmation field.

    2. Add `deleteAccount` method to `AuthService` (`apps/api/src/auth/auth.service.ts`):
       ```typescript
       async deleteAccount(userId: string): Promise<{ success: boolean }> {
         const result = await this.userRepository.delete(userId);
         if (result.affected === 0) {
           throw new BadRequestException('Account not found');
         }
         this.logger.log(`Account deleted: userId=${userId}`);
         return { success: true };
       }
       ```
       This is all that's needed -- ON DELETE CASCADE on all FK references to users.id handles refresh_tokens, auth_methods, vaults, pinned_cids, folder_ipns, ipns_republish_schedule, shares (owner + recipient), share_keys, and share_invites.

    3. Add `deleteAccount` endpoint to `AuthController` (`apps/api/src/auth/auth.controller.ts`):
       - Import `Delete` from `@nestjs/common`, import `DeleteAccountDto` and `DeleteAccountResponseDto`.
       - Add method after the `logout` endpoint:
         ```typescript
         @Delete('account')
         @HttpCode(HttpStatus.OK)
         @UseGuards(JwtAuthGuard)
         @ApiBearerAuth()
         @ApiOperation({ summary: 'Permanently delete user account and all associated data' })
         @ApiResponse({ status: 200, description: 'Account deleted successfully', type: DeleteAccountResponseDto })
         @ApiResponse({ status: 400, description: 'Invalid confirmation or account not found' })
         @ApiResponse({ status: 401, description: 'Unauthorized' })
         async deleteAccount(
           @Request() req: RequestWithUser,
           @Body() dto: DeleteAccountDto,
           @Res({ passthrough: true }) res: Response,
         ): Promise<DeleteAccountResponseDto> {
           if (dto.confirmation !== 'DELETE') {
             throw new BadRequestException('Confirmation must be the string "DELETE"');
           }
           const isDesktop = (req as unknown as ExpressRequest).headers['x-client-type'] === 'desktop';
           if (!isDesktop) {
             res.clearCookie('refresh_token', { path: '/auth' });
           }
           return this.authService.deleteAccount(req.user.id);
         }
         ```
       - Import `Delete` in the imports destructuring from `@nestjs/common`.

    4. Update `apps/api/scripts/generate-openapi.ts` -- no changes needed since AuthController is already registered. But verify the DTO import works by ensuring the new DTO file has proper class-validator decorators that NestJS Swagger plugin can introspect.

    5. Run `pnpm api:generate` from repo root to regenerate the typed API client with the new DELETE endpoint.

  </action>
  <verify>
    - `cd /Users/michael/Code/cipher-box && pnpm --filter api build` compiles without errors.
    - `pnpm api:generate` succeeds and produces updated `apps/web/src/api/auth/auth.ts` with `authControllerDeleteAccount` function.
    - Grep for `deleteAccount` in `apps/web/src/api/auth/auth.ts` confirms the generated client has the endpoint.
  </verify>
  <done>
    DELETE /auth/account endpoint exists, requires JWT auth + `{ confirmation: "DELETE" }` body, deletes user row (cascade handles all related data), clears refresh cookie for web clients. API client regenerated.
  </done>
</task>

<task type="auto">
  <name>Task 2: Frontend Danger Zone UI in SecurityTab</name>
  <files>
    apps/web/src/lib/api/auth.ts
    apps/web/src/components/mfa/SecurityTab.tsx
    apps/web/src/App.css
  </files>
  <action>
    1. Add `deleteAccount` to the auth API wrapper (`apps/web/src/lib/api/auth.ts`):
       ```typescript
       /**
        * Permanently delete the authenticated user's account.
        * Requires confirmation string "DELETE".
        */
       deleteAccount: async (): Promise<void> => {
         await apiClient.delete('/auth/account', { data: { confirmation: 'DELETE' } });
       },
       ```
       Add this after the `unlinkMethod` function in the `authApi` object.

    2. Update `SecurityTab.tsx` (`apps/web/src/components/mfa/SecurityTab.tsx`):
       - Import `{ authApi }` from `../../lib/api/auth`.
       - Import `useAuth` from `../../hooks/useAuth`.
       - Add state: `const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)`, `const [deleteInput, setDeleteInput] = useState('')`, `const [isDeleting, setIsDeleting] = useState(false)`, `const [deleteError, setDeleteError] = useState<string | null>(null)`.
       - Get logout from useAuth: `const { logout } = useAuth()`.
       - Note: useAuth() calls useNavigate(), which requires SecurityTab to be rendered inside a Router context. It already is (rendered inside SettingsPage which is inside AppShell/Router).
       - Add `handleDeleteAccount` async function:
         ```typescript
         const handleDeleteAccount = useCallback(async () => {
           if (deleteInput !== 'DELETE') return;
           setIsDeleting(true);
           setDeleteError(null);
           try {
             await authApi.deleteAccount();
             // Account deleted server-side. Clear local state and redirect.
             await logout();
           } catch (err) {
             setDeleteError(err instanceof Error ? err.message : 'Failed to delete account');
             setIsDeleting(false);
           }
         }, [deleteInput, logout]);
         ```
       - Add `handleCancelDelete` callback:
         ```typescript
         const handleCancelDelete = useCallback(() => {
           setShowDeleteConfirm(false);
           setDeleteInput('');
           setDeleteError(null);
         }, []);
         ```
       - Add Danger Zone section at the bottom of the component, BEFORE the desktop note (`security-tab-note`). Insert between the closing `</>` of the `!showWizard` branch and the desktop note `<p>`:

         ```tsx
         {/* Danger Zone */}
         <div className="security-tab-danger-zone">
           <h3 className="security-tab-danger-zone-title">{'// danger_zone'}</h3>
           {!showDeleteConfirm ? (
             <div className="security-tab-danger-zone-content">
               <p className="security-tab-danger-zone-desc">
                 permanently delete your account and all associated data. this action cannot be undone.
               </p>
               <button
                 type="button"
                 className="security-tab-danger-btn"
                 onClick={() => setShowDeleteConfirm(true)}
               >
                 --delete-account
               </button>
             </div>
           ) : (
             <div className="security-tab-danger-zone-confirm">
               <p className="security-tab-danger-zone-warn">
                 this will permanently delete your account, vault, files, shares, and all encryption keys.
                 type <strong>DELETE</strong> to confirm.
               </p>
               <input
                 type="text"
                 className="security-tab-danger-input"
                 value={deleteInput}
                 onChange={(e) => setDeleteInput(e.target.value)}
                 placeholder="type DELETE to confirm"
                 autoComplete="off"
                 spellCheck={false}
                 disabled={isDeleting}
               />
               {deleteError && (
                 <p className="security-tab-danger-error">{deleteError}</p>
               )}
               <div className="security-tab-danger-actions">
                 <button
                   type="button"
                   className="security-tab-danger-cancel"
                   onClick={handleCancelDelete}
                   disabled={isDeleting}
                 >
                   --cancel
                 </button>
                 <button
                   type="button"
                   className="security-tab-danger-confirm-btn"
                   onClick={handleDeleteAccount}
                   disabled={deleteInput !== 'DELETE' || isDeleting}
                 >
                   {isDeleting ? 'deleting...' : '--confirm-delete'}
                 </button>
               </div>
             </div>
           )}
         </div>
         ```

       - The Danger Zone section must be rendered OUTSIDE the `{showWizard ? ... : ...}` ternary so it's always visible regardless of MFA wizard state. Place it right after that ternary block, before the desktop note.

    3. Add CSS to `apps/web/src/App.css` after the `.security-tab-note` rule block (after line ~1441). Follow the terminal aesthetic from the design reference:

       ```css
       /* Danger Zone */
       .security-tab-danger-zone {
         margin-top: var(--spacing-lg);
         padding: 16px 20px;
         border: 1px solid #EF4444;
         background-color: #001a11;
       }

       .security-tab-danger-zone-title {
         font-size: 12px;
         font-weight: 600;
         color: #EF4444;
         text-transform: lowercase;
         margin-bottom: var(--spacing-sm);
         font-family: var(--font-family-mono);
       }

       .security-tab-danger-zone-desc {
         font-size: var(--font-size-xs);
         color: var(--color-text-secondary);
         margin-bottom: var(--spacing-sm);
         line-height: 1.6;
       }

       .security-tab-danger-btn {
         background-color: transparent;
         color: #EF4444;
         border: 1px solid #EF4444;
         font-family: var(--font-family-mono);
         font-size: var(--font-size-sm);
         font-weight: 600;
         padding: var(--spacing-xs) var(--spacing-lg);
         cursor: pointer;
         transition: background-color 0.2s ease;
       }

       .security-tab-danger-btn:hover {
         background-color: rgb(239 68 68 / 15%);
       }

       .security-tab-danger-btn:focus-visible {
         outline: 1px solid #EF4444;
         outline-offset: 2px;
       }

       .security-tab-danger-zone-confirm {
         display: flex;
         flex-direction: column;
         gap: var(--spacing-sm);
       }

       .security-tab-danger-zone-warn {
         font-size: var(--font-size-xs);
         color: #EF4444;
         line-height: 1.6;
       }

       .security-tab-danger-zone-warn strong {
         color: #EF4444;
         font-weight: 700;
       }

       .security-tab-danger-input {
         background-color: #000000;
         border: 1px solid #EF4444;
         color: #EF4444;
         font-family: var(--font-family-mono);
         font-size: var(--font-size-sm);
         padding: var(--spacing-xs) var(--spacing-sm);
         outline: none;
         max-width: 280px;
       }

       .security-tab-danger-input::placeholder {
         color: rgb(239 68 68 / 40%);
       }

       .security-tab-danger-input:focus {
         border-color: #EF4444;
         box-shadow: 0 0 4px rgb(239 68 68 / 30%);
       }

       .security-tab-danger-input:disabled {
         opacity: 0.5;
       }

       .security-tab-danger-error {
         font-size: 10px;
         color: #EF4444;
       }

       .security-tab-danger-actions {
         display: flex;
         gap: var(--spacing-sm);
         margin-top: var(--spacing-xs);
       }

       .security-tab-danger-cancel {
         background-color: transparent;
         color: var(--color-text-secondary);
         border: 1px solid var(--color-border-dim);
         font-family: var(--font-family-mono);
         font-size: var(--font-size-sm);
         font-weight: 600;
         padding: var(--spacing-xs) var(--spacing-lg);
         cursor: pointer;
         transition: background-color 0.2s ease;
       }

       .security-tab-danger-cancel:hover {
         background-color: rgb(0 208 132 / 10%);
         border-color: var(--color-green-primary);
         color: var(--color-green-primary);
       }

       .security-tab-danger-cancel:focus-visible {
         outline: 1px solid var(--color-green-primary);
         outline-offset: 2px;
       }

       .security-tab-danger-confirm-btn {
         background-color: #EF4444;
         color: #000000;
         border: 1px solid #EF4444;
         font-family: var(--font-family-mono);
         font-size: var(--font-size-sm);
         font-weight: 600;
         padding: var(--spacing-xs) var(--spacing-lg);
         cursor: pointer;
         transition: opacity 0.2s ease;
       }

       .security-tab-danger-confirm-btn:hover:not(:disabled) {
         opacity: 0.85;
       }

       .security-tab-danger-confirm-btn:focus-visible {
         outline: 1px solid #EF4444;
         outline-offset: 2px;
       }

       .security-tab-danger-confirm-btn:disabled {
         opacity: 0.4;
         cursor: not-allowed;
       }
       ```

       Use modern color notation (`rgb(239 68 68 / 15%)` not `rgba(239, 68, 68, 0.15)`) per project coding guidelines.

  </action>
  <verify>
    - `cd /Users/michael/Code/cipher-box && pnpm --filter web build` compiles without errors or type errors.
    - `pnpm lint` passes (no Biome warnings about comment text, accessibility, etc.).
    - Grep `security-tab-danger` in App.css shows all CSS rules.
    - Grep `deleteAccount` in SecurityTab.tsx confirms API call is wired.
    - Grep `danger-zone` in SecurityTab.tsx confirms UI section exists.
  </verify>
  <done>
    Security tab shows Danger Zone section with red border. Clicking --delete-account reveals confirmation dialog requiring user to type "DELETE". Confirming calls DELETE /auth/account, then runs full logout flow (clear stores, Core Kit logout, redirect to login). Cancel resets the confirmation state.
  </done>
</task>

</tasks>

<verification>
- API builds: `pnpm --filter api build` passes
- Web builds: `pnpm --filter web build` passes
- Lint: `pnpm lint` passes
- Generated client includes deleteAccount: grep `deleteAccount` in `apps/web/src/api/auth/auth.ts`
- SecurityTab renders danger zone: grep `danger-zone` in SecurityTab.tsx
- No new migration needed (ON DELETE CASCADE already on all FK references to users.id)
</verification>

<success_criteria>

- DELETE /auth/account endpoint requires JWT auth and `{ confirmation: "DELETE" }` body
- Endpoint deletes user row; CASCADE removes all related records
- SecurityTab shows Danger Zone with terminal aesthetic (#EF4444 red, JetBrains Mono, #001a11 bg)
- Type-to-confirm prevents accidental deletion
- After deletion, full logout flow executes (clear crypto keys, Core Kit logout, navigate to /)
- API client regenerated with new endpoint
  </success_criteria>

<output>
After completion, create `.planning/quick/021-account-deletion-gdpr/021-SUMMARY.md`
</output>

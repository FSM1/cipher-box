---
phase: quick-016
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - apps/web/src/App.css
  - apps/web/src/components/auth/LinkedMethods.tsx
autonomous: true

must_haves:
  truths:
    - "WalletLoginButton renders with full terminal styling matching Google/Email buttons"
    - "MFA enrollment banner has amber accent color visible against dark background"
    - "SecurityTab enable-mfa button uses readable font size (sm, not xs)"
    - "LinkedMethods wallet icon is recognizable text, not cryptic Greek letter"
    - "Unlink disabled state shows visible explanation text, not just tooltip"
  artifacts:
    - path: "apps/web/src/App.css"
      provides: "Wallet login CSS classes, MFA banner amber styling, security button size fix"
      contains: ".wallet-login-btn"
    - path: "apps/web/src/components/auth/LinkedMethods.tsx"
      provides: "Improved wallet icon and unlink disabled hint"
  key_links:
    - from: "apps/web/src/components/auth/WalletLoginButton.tsx"
      to: "apps/web/src/App.css"
      via: "CSS class names"
      pattern: "wallet-login-btn|wallet-connector"
---

<objective>
Fix all wallet and MFA UI styling issues discovered during code exploration.

Purpose: WalletLoginButton is completely unstyled (all CSS classes missing), MFA banner is
nearly invisible, enable-mfa button is too small, wallet icon is unclear, and unlink disabled
state has no visible explanation. These are all CSS/minor-JSX fixes.

Output: Fully styled wallet login flow, visible MFA banner, properly sized buttons, clear icons.
</objective>

<execution_context>
@./.claude/get-shit-done/workflows/execute-plan.md
@./.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/STATE.md
@apps/web/src/App.css
@apps/web/src/index.css
@apps/web/src/components/auth/WalletLoginButton.tsx
@apps/web/src/components/mfa/MfaEnrollmentPrompt.tsx
@apps/web/src/components/mfa/SecurityTab.tsx
@apps/web/src/components/auth/LinkedMethods.tsx
</context>

<tasks>

<task type="auto">
  <name>Task 1: Add WalletLoginButton CSS and fix MFA banner styling</name>
  <files>apps/web/src/App.css</files>
  <action>
Add ALL missing wallet login CSS classes to App.css. Insert a new section after the
Email Login Form section (after line ~356, before the Login Error section at line ~358).

Add a section header:
```
/* ==========================================================================
   Wallet Login Button
   ========================================================================== */
```

Add these CSS rules matching the terminal aesthetic and following the same patterns as
`.google-login-btn` and `.email-login-submit`:

1. `.wallet-login-wrapper` -- flex column, align stretch (mirrors `.google-login-wrapper`)

2. `.wallet-login-btn` -- Main button matching `.google-login-btn` pattern:
   - `padding: var(--spacing-sm) var(--spacing-lg)`
   - `font-family: var(--font-family-mono)`
   - `font-size: var(--font-size-sm)` (11px)
   - `font-weight: var(--font-weight-semibold)`
   - `background-color: transparent`
   - `color: var(--color-text-primary)`
   - `border: 1px solid var(--color-green-primary)`
   - `border-radius: 0`
   - `cursor: pointer`
   - `transition: box-shadow 0.2s ease, background-color 0.2s ease, transform 0.1s ease`
   - `text-transform: uppercase`
   - `letter-spacing: 0.05em`

3. `.wallet-login-btn:hover:not(:disabled)` -- green glow hover:
   - `background-color: rgb(0 208 132 / 10%)`
   - `box-shadow: var(--glow-green)`
   - `transform: translateY(-1px)`

4. `.wallet-login-btn:active:not(:disabled)` -- `transform: translateY(0)`

5. `.wallet-login-btn:focus-visible`:
   - `outline: 1px solid var(--color-green-primary)`
   - `outline-offset: 2px`

6. `.wallet-login-btn:disabled` -- `opacity: 0.4; cursor: not-allowed`

7. `.wallet-login-btn--loading` -- loading state:
   - `color: var(--color-text-secondary)`
   - `border-color: var(--color-text-secondary)`

8. `.wallet-connector-list` -- Connector picker panel:
   - `display: flex; flex-direction: column; gap: var(--spacing-xs)`
   - `padding: var(--spacing-sm)`
   - `border: 1px solid var(--color-border-dim)`
   - `font-family: var(--font-family-mono)`

9. `.wallet-connector-header` -- "// select wallet" text:
   - `font-size: var(--font-size-xs)`
   - `color: var(--color-text-secondary)`
   - `margin-bottom: var(--spacing-xs)`

10. `.wallet-connector-option` -- Individual wallet option button:
    - `padding: var(--spacing-xs) var(--spacing-sm)`
    - `background: none; border: 1px solid var(--color-border-dim)`
    - `font-family: var(--font-family-mono); font-size: var(--font-size-sm)`
    - `color: var(--color-text-primary); cursor: pointer`
    - `text-align: left`
    - `transition: border-color 0.2s ease, color 0.2s ease`

11. `.wallet-connector-option:hover:not(:disabled)`:
    - `border-color: var(--color-green-primary); color: var(--color-green-primary)`

12. `.wallet-connector-option:focus-visible`:
    - `outline: 1px solid var(--color-green-primary); outline-offset: 1px`

13. `.wallet-connector-option:disabled` -- `opacity: 0.4; cursor: not-allowed`

14. `.wallet-connector-cancel` -- Cancel button:
    - `padding: var(--spacing-xs) 0; background: none; border: none`
    - `font-family: var(--font-family-mono); font-size: var(--font-size-xs)`
    - `color: var(--color-text-dim); cursor: pointer`
    - `text-align: center; margin-top: var(--spacing-xs)`

15. `.wallet-connector-cancel:hover:not(:disabled)`:
    - `color: var(--color-text-secondary)`

16. `.wallet-connector-cancel:focus-visible`:
    - `outline: 1px solid var(--color-green-primary); outline-offset: 1px`

17. `.wallet-connector-cancel:disabled` -- `cursor: not-allowed; opacity: 0.4`

18. `.wallet-login-status` -- Status message during flow:
    - `font-size: var(--font-size-xs); color: var(--color-text-secondary)`
    - `padding: var(--spacing-xs) 0`

19. `.wallet-no-providers` -- No wallets detected message:
    - `font-size: var(--font-size-xs); color: var(--color-text-dim)`
    - `padding: var(--spacing-xs) 0`

THEN fix MFA banner styling. Find the `.mfa-prompt` rule (around line 1921) and change:
- `background-color` from `rgb(0 208 132 / 5%)` to `rgb(245 158 11 / 8%)` (amber tint)
- `border-bottom` from `1px solid var(--color-border-dim)` to `1px solid rgb(245 158 11 / 25%)`

Find `.mfa-prompt-text strong` and change color from `var(--color-green-primary)` to `var(--color-warning)` (#F59E0B amber).

THEN fix SecurityTab enable button size. Find `.security-tab-enable-btn` (around line 1225) and change:
- `font-size` from `var(--font-size-xs)` to `var(--font-size-sm)` (10px -> 11px)
- Add `padding: var(--spacing-xs) var(--spacing-lg)` (increase horizontal padding to match login buttons)
  </action>
  <verify>
Run `grep -c 'wallet-login-btn\|wallet-connector\|wallet-login-wrapper\|wallet-login-status\|wallet-no-providers' apps/web/src/App.css` and confirm count >= 15 (all class selectors present).
Run `grep 'rgb(245 158 11' apps/web/src/App.css` and confirm MFA amber tint appears.
Run `grep -A1 'security-tab-enable-btn {' apps/web/src/App.css` and confirm font-size is `var(--font-size-sm)`.
  </verify>
  <done>
All 19 wallet CSS classes exist in App.css.
MFA banner uses amber background tint and amber bold text.
Security enable button uses font-size-sm (11px) with adequate padding.
  </done>
</task>

<task type="auto">
  <name>Task 2: Fix wallet icon and unlink disabled state in LinkedMethods</name>
  <files>apps/web/src/components/auth/LinkedMethods.tsx</files>
  <action>
In LinkedMethods.tsx, make two changes:

1. Change the wallet icon in `METHOD_ICONS` (line ~21) from Greek Xi `'\u039E'` to a
recognizable wallet representation. Use the Unicode purse/wallet character or, for maximum
compatibility with monospace fonts, use the text string `'W'` (capital W is universally
legible as "Wallet" in this context where Google is "G" and Email is "@"). Change:
```ts
wallet: '\u039E', // Greek Xi for ETH
```
to:
```ts
wallet: 'W',
```

2. Add a visible "last method" hint below the unlink button when `isLastMethod` is true.
Find the unlink button section (around line 233-253) inside the `.linked-methods-item-actions`
div. After the closing `</button>` of the unlink button (line ~249), add a conditional span
that shows when `isLastMethod`:

```tsx
{isLastMethod && (
  <span className="linked-methods-unlink-hint">
    {'// last method'}
  </span>
)}
```

Then add CSS for `.linked-methods-unlink-hint` in App.css (in the linked-methods section,
after `.linked-methods-unlink-btn:disabled` around line ~707):

```css
.linked-methods-unlink-hint {
  font-size: 10px;
  color: var(--color-text-dim);
  white-space: nowrap;
}
```
  </action>
  <verify>
Run `grep "wallet: 'W'" apps/web/src/components/auth/LinkedMethods.tsx` to confirm wallet icon changed.
Run `grep 'linked-methods-unlink-hint' apps/web/src/components/auth/LinkedMethods.tsx` to confirm hint element exists.
Run `grep 'linked-methods-unlink-hint' apps/web/src/App.css` to confirm CSS exists.
  </verify>
  <done>
Wallet icon shows "W" instead of Greek Xi.
When only one auth method is linked, a "// last method" hint is visible next to the disabled unlink button.
  </done>
</task>

<task type="checkpoint:human-verify" gate="blocking">
  <what-built>
  Complete wallet and MFA UI styling overhaul:
  - WalletLoginButton fully styled with terminal aesthetic (green border, hover glow, connector picker)
  - MFA enrollment banner with amber accent color for visibility
  - SecurityTab enable-mfa button properly sized
  - LinkedMethods wallet icon changed from Greek Xi to "W"
  - Unlink disabled state shows visible "// last method" hint
  </what-built>
  <how-to-verify>
  1. Start the dev server: `pnpm --filter web dev`
  2. Visit http://localhost:5173 (login page)
  3. Verify the [WALLET] button has the same terminal styling as [CONNECT WITH GOOGLE] -- green border, uppercase text, hover glow effect
  4. Click [WALLET] and verify the connector picker shows with proper styling (bordered panel, selectable wallet options, cancel button)
  5. Log in and verify the MFA enrollment banner (if visible) has amber/warning tint instead of nearly-invisible green
  6. Navigate to Settings > Security and verify the --enable-mfa button is properly sized (not tiny 10px text)
  7. Navigate to Settings > Linked Methods and verify wallet entries show "W" icon
  8. If only one auth method is linked, verify "// last method" text appears next to the disabled [unlink] button
  </how-to-verify>
  <resume-signal>Type "approved" or describe issues to fix</resume-signal>
</task>

</tasks>

<verification>
- All wallet CSS classes defined: wallet-login-btn, wallet-login-wrapper, wallet-connector-list, wallet-connector-header, wallet-connector-option, wallet-connector-cancel, wallet-login-status, wallet-no-providers
- MFA banner background uses amber tint: `rgb(245 158 11 / 8%)`
- MFA banner bold text uses `var(--color-warning)` (amber)
- Security enable button uses `var(--font-size-sm)` not `var(--font-size-xs)`
- Wallet icon is "W" not Greek Xi
- Unlink disabled state has visible "// last method" hint
- No lint errors from Biome
</verification>

<success_criteria>
WalletLoginButton renders with identical terminal styling to GoogleLoginButton. MFA banner
is immediately visible with amber accent. Enable-MFA button is readable size. Wallet icons
are clear. Disabled unlink states are self-explanatory.
</success_criteria>

<output>
After completion, create `.planning/quick/016-refine-wallet-and-mfa-ui-elements/016-SUMMARY.md`
</output>

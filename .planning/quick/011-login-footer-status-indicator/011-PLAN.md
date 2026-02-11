---
phase: quick
plan: 011
type: execute
wave: 1
depends_on: []
files_modified:
  - apps/web/src/routes/Login.tsx
  - apps/web/src/components/auth/AuthButton.tsx
  - apps/web/src/App.css
autonomous: true

must_haves:
  truths:
    - 'Login page displays a footer at the bottom with copyright, links, and API status indicator'
    - 'StatusIndicator appears in the footer, not inside the login panel'
    - 'Connect button is disabled with visual feedback when API is disconnected'
    - 'Connect button is enabled when API health check returns ok'
  artifacts:
    - path: 'apps/web/src/routes/Login.tsx'
      provides: 'Login page with footer and health-aware connect button'
      contains: 'login-footer'
    - path: 'apps/web/src/components/auth/AuthButton.tsx'
      provides: 'AuthButton that accepts apiDown prop to disable when API unreachable'
    - path: 'apps/web/src/App.css'
      provides: 'CSS for login-footer positioned at bottom of login page'
      contains: 'login-footer'
  key_links:
    - from: 'apps/web/src/routes/Login.tsx'
      to: 'useHealthControllerCheck'
      via: 'hook call in Login component'
      pattern: 'useHealthControllerCheck'
    - from: 'apps/web/src/routes/Login.tsx'
      to: 'apps/web/src/components/auth/AuthButton.tsx'
      via: 'apiDown prop'
      pattern: 'apiDown='
---

<objective>
Restore the footer on the Login page, move the StatusIndicator from the login panel into the footer, and disable the Connect button when the API health check fails.

Purpose: The footer was lost during matrix rain changes (quick task 010). The login page currently has StatusIndicator awkwardly placed inside the login panel. Moving it to a proper footer matches the AppShell footer pattern. Additionally, there is no point allowing users to click Connect if the API is down.

Output: Login page with footer containing copyright + links + status indicator, and a connect button that disables itself when the API is unreachable.
</objective>

<execution_context>
@./.claude/get-shit-done/workflows/execute-plan.md
@./.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@apps/web/src/routes/Login.tsx
@apps/web/src/components/auth/AuthButton.tsx
@apps/web/src/components/layout/StatusIndicator.tsx
@apps/web/src/components/layout/AppFooter.tsx
@apps/web/src/App.css
@apps/web/src/styles/layout.css
</context>

<tasks>

<task type="auto">
  <name>Task 1: Add footer to Login page and lift health state</name>
  <files>
    apps/web/src/routes/Login.tsx
    apps/web/src/components/auth/AuthButton.tsx
    apps/web/src/App.css
  </files>
  <action>
  **Login.tsx changes:**

1. Import `useHealthControllerCheck` from `../../api/health/health` (same hook used by StatusIndicator).
2. Call `useHealthControllerCheck` at the top of the Login component with the same options StatusIndicator uses: `{ query: { refetchInterval: 30000, retry: 2, refetchOnWindowFocus: true } }`.
3. Derive `isApiDown` boolean: `const isApiDown = !isLoading && (isError || data?.status !== 'ok');` (where isLoading/isError/data come from the health query -- use aliased destructuring to avoid collision with auth's isLoading, e.g. `isLoading: isHealthLoading`).
4. Remove `<StatusIndicator />` from inside the `login-panel` div.
5. Remove the `StatusIndicator` import from `../components/layout`.
6. Pass `apiDown={isApiDown}` prop to `<AuthButton />`.
7. Add a footer after the `login-panel` div but still inside `login-container`. Structure it to match AppFooter's content pattern:

```tsx
<footer className="login-footer">
  <div className="footer-left">
    <span className="footer-copyright">(c) 2026 CipherBox</span>
  </div>
  <div className="footer-center">
    <a href="#" className="footer-link">
      [help]
    </a>
    <a href="#" className="footer-link">
      [privacy]
    </a>
    <a href="#" className="footer-link">
      [terms]
    </a>
    <a
      href="https://github.com/fsm1/cipher-box"
      className="footer-link"
      target="_blank"
      rel="noopener noreferrer"
    >
      [github]
    </a>
  </div>
  <div className="footer-right">
    <StatusIndicator />
  </div>
</footer>
```

Wait -- StatusIndicator already calls useHealthControllerCheck internally, and React Query deduplicates identical queries, so calling it in Login.tsx AND having StatusIndicator call it is fine (same cache key, no double fetch). So keep importing and using `StatusIndicator` in the footer (NOT removing the import -- just moving it from the panel to the footer). Remove the direct `StatusIndicator` import only from the layout barrel -- import it directly from `../components/layout/StatusIndicator` or keep the barrel import but only use it in the footer.

Corrected plan:

- Keep importing `StatusIndicator` from `../components/layout`.
- Move `<StatusIndicator />` from inside `login-panel` to the `footer-right` div in the new footer.
- The Login component still calls `useHealthControllerCheck` to get `isApiDown` for the AuthButton prop.
  8. Apply the same footer to the loading state return (the `if (isLoading)` branch). In that branch, the health query may not have resolved yet, so just show the footer with StatusIndicator (it will show [CHECKING]).

  **AuthButton.tsx changes:**
  1. Add an `apiDown` optional prop: `interface AuthButtonProps { apiDown?: boolean; }`.
  2. Accept the prop: `export function AuthButton({ apiDown }: AuthButtonProps)`.
  3. Update the disabled condition: `disabled={isLoading || apiDown}`.
  4. Update button text: when `apiDown` is true and not loading, show `[API OFFLINE]` instead of `[CONNECT]`.

     ```tsx
     {
       isLoading ? 'connecting...' : apiDown ? '[API OFFLINE]' : '[CONNECT]';
     }
     ```

  5. Add a `login-button--disabled` CSS class when apiDown is true for distinct visual styling (dim red border or similar). Use className joining: `className={['login-button', apiDown ? 'login-button--api-down' : ''].filter(Boolean).join(' ')}`.

  **App.css changes:**

  Add login-footer styles after the existing `.login-button:disabled` rule (around line 93):

  ```css
  /* Login page footer */
  .login-footer {
    position: absolute;
    bottom: 0;
    left: 0;
    right: 0;
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px 24px;
    background-color: rgb(0 0 0 / 50%);
    border-top: 1px solid var(--color-border-dim);
    z-index: 1;
  }
  ```

  Reuse existing `.footer-left`, `.footer-center`, `.footer-right`, `.footer-copyright`, `.footer-link` classes from layout.css (they are not scoped to `.app-footer` so they work globally).

  Add the API-down button style:

  ```css
  .login-button--api-down {
    background-color: transparent;
    border: 1px solid var(--color-error);
    color: var(--color-error);
    opacity: 0.7;
    cursor: not-allowed;
  }

  .login-button--api-down:hover {
    box-shadow: none;
    transform: none;
  }
  ```

  Also add focus-visible style for login-footer links (per CLAUDE.md a11y guidelines):

  ```css
  .login-footer .footer-link:focus-visible {
    outline: 1px solid var(--color-green-primary);
    outline-offset: 1px;
  }
  ```

    </action>
    <verify>
    1. `cd /Users/michael/Code/cipher-box && pnpm --filter web build` completes without errors.
    2. Start the dev server (`pnpm --filter web dev`) and visually verify at http://localhost:5173:
       - Footer visible at bottom of login page with "(c) 2026 CipherBox", links, and status indicator.
       - StatusIndicator shows [CONNECTED] or [DISCONNECTED] in the footer-right area.
       - StatusIndicator is NOT inside the login-panel anymore.
       - When API is running: connect button shows [CONNECT] and is clickable.
       - When API is stopped: connect button shows [API OFFLINE], is disabled, has red border styling.
    3. Use Playwright MCP if available to verify element presence:
       - `document.querySelector('.login-footer')` exists
       - `document.querySelector('.login-footer .status-indicator')` exists
       - `document.querySelector('.login-panel .status-indicator')` does NOT exist
    </verify>
    <done>
    - Login page has a footer at the bottom matching the AppShell footer content pattern (copyright, links, status indicator).
    - StatusIndicator renders in the footer, not in the login panel.
    - AuthButton shows [API OFFLINE] with red border styling and is disabled when API health check fails.
    - AuthButton shows [CONNECT] and is enabled when API is healthy.
    - Build passes, no lint errors.
    </done>
  </task>

</tasks>

<verification>
1. `pnpm --filter web build` succeeds with no TypeScript or lint errors.
2. Visual check: login page footer is visible, properly positioned at the bottom, with correct content.
3. Functional check: stop the API server -> refresh login page -> button shows [API OFFLINE] and is disabled. Start API -> button returns to [CONNECT] within 30 seconds (refetch interval).
4. No regression: the AppShell's AppFooter component is unchanged and still works on authenticated pages.
</verification>

<success_criteria>

- Footer visible on login page at all times (loading state and ready state).
- StatusIndicator in footer shows real-time API connection status.
- Connect button disabled with [API OFFLINE] text when API is unreachable.
- Connect button enabled with [CONNECT] text when API is healthy.
- No visual overlap between footer and login panel content.
- Build and lint pass cleanly.
  </success_criteria>

<output>
After completion, create `.planning/quick/011-login-footer-status-indicator/011-SUMMARY.md`
</output>

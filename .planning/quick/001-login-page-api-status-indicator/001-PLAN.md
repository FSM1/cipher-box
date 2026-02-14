---
phase: quick-001
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - apps/web/src/components/ApiStatusIndicator.tsx
  - apps/web/src/routes/Login.tsx
  - apps/web/src/App.css
autonomous: true

must_haves:
  truths:
    - 'User can see API connection status on login page'
    - 'Status indicator shows green when API is healthy'
    - 'Status indicator shows red when API is unreachable'
    - 'Status updates automatically on retry'
  artifacts:
    - path: 'apps/web/src/components/ApiStatusIndicator.tsx'
      provides: 'Status indicator component using health API'
      exports: ['ApiStatusIndicator']
    - path: 'apps/web/src/routes/Login.tsx'
      provides: 'Login page with status indicator'
      contains: 'ApiStatusIndicator'
  key_links:
    - from: 'apps/web/src/components/ApiStatusIndicator.tsx'
      to: '/health'
      via: 'useHealthControllerCheck hook'
      pattern: 'useHealthControllerCheck'
---

<objective>
Add an API status indicator to the login page that shows whether the backend API is reachable.

Purpose: Allow users to immediately see if the API is available before attempting to authenticate.
Output: A small status indicator component on the login page that displays connection status.
</objective>

<execution_context>
@./.claude/get-shit-done/workflows/execute-plan.md
@./.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@apps/api/src/health/health.controller.ts (existing /health endpoint)
@apps/web/src/api/health/health.ts (orval-generated hook: useHealthControllerCheck)
@apps/web/src/routes/Login.tsx (login page to add indicator to)
@apps/web/src/App.css (existing styles including login-container)
</context>

<tasks>

<task type="auto">
  <name>Task 1: Create ApiStatusIndicator component</name>
  <files>apps/web/src/components/ApiStatusIndicator.tsx</files>
  <action>
Create a new React component `ApiStatusIndicator` that:
1. Uses the existing `useHealthControllerCheck` hook from `@/api/health/health`
2. Displays a small status dot with text:
   - Green dot + "API Online" when query succeeds (status === 'ok')
   - Red dot + "API Offline" when query fails or errors
   - Gray dot + "Checking..." while loading (isLoading)
3. Configure the query with:
   - `refetchInterval: 30000` (poll every 30 seconds)
   - `retry: 2` (retry twice on failure)
   - `refetchOnWindowFocus: true` (check on tab focus)
4. Use inline styles or CSS classes for the status dot (small circle, 8px)
5. Position styling will be handled in CSS

Component structure:

```tsx
export function ApiStatusIndicator() {
  const { data, isLoading, isError } = useHealthControllerCheck({
    query: {
      refetchInterval: 30000,
      retry: 2,
      refetchOnWindowFocus: true,
    },
  });
  // Render status based on state
}
```

  </action>
  <verify>File exists and exports ApiStatusIndicator component. TypeScript compiles without errors: `pnpm --filter web build`</verify>
  <done>ApiStatusIndicator component created with health check polling logic</done>
</task>

<task type="auto">
  <name>Task 2: Add indicator to Login page and style</name>
  <files>apps/web/src/routes/Login.tsx, apps/web/src/App.css</files>
  <action>
1. In Login.tsx:
   - Import ApiStatusIndicator from '../components/ApiStatusIndicator'
   - Add `<ApiStatusIndicator />` at the bottom of the login-container div, after the AuthButton
   - Wrap it in a div with className="api-status" for positioning

2. In App.css, add styles for the status indicator:

```css
.api-status {
  position: fixed;
  bottom: 1rem;
  right: 1rem;
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.75rem;
  color: rgba(255, 255, 255, 0.6);
}

.status-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
}

.status-dot.online {
  background-color: #22c55e;
  box-shadow: 0 0 6px #22c55e;
}

.status-dot.offline {
  background-color: #ef4444;
  box-shadow: 0 0 6px #ef4444;
}

.status-dot.loading {
  background-color: #6b7280;
}
```

The indicator should appear in the bottom-right corner of the login page.
</action>
<verify>
Run dev server and verify:

1. `pnpm --filter web dev` starts without errors
2. Navigate to login page (localhost:5173)
3. Status indicator visible in bottom-right
4. Shows green "API Online" when API is running
5. Shows red "API Offline" when API is stopped
   </verify>
   <done>Login page displays API status indicator in bottom-right corner with appropriate color states</done>
   </task>

</tasks>

<verification>
1. `pnpm --filter web build` completes without TypeScript errors
2. `pnpm --filter web lint` passes
3. Visual verification: indicator shows correct state based on API availability
</verification>

<success_criteria>

- ApiStatusIndicator component uses existing orval-generated health hook
- Login page shows status indicator in bottom-right corner
- Green/red/gray states correctly reflect API health
- Status auto-refreshes every 30 seconds
- Build and lint pass
  </success_criteria>

<output>
After completion, create `.planning/quick/001-login-page-api-status-indicator/001-SUMMARY.md`
</output>

---
phase: quick
plan: 004
type: execute
wave: 1
depends_on: []
files_modified:
  - apps/web/src/components/StagingBanner.tsx
  - apps/web/src/routes/Login.tsx
  - apps/web/src/components/layout/AppShell.tsx
  - apps/web/src/App.css
autonomous: true

must_haves:
  truths:
    - 'Staging banner visible on login page when VITE_ENVIRONMENT=staging'
    - 'Compact staging banner visible above header in file browser when VITE_ENVIRONMENT=staging'
    - 'No banner rendered when VITE_ENVIRONMENT is not staging (local, production, undefined)'
  artifacts:
    - path: 'apps/web/src/components/StagingBanner.tsx'
      provides: 'StagingBanner component with login and compact variants'
      exports: ['StagingBanner']
    - path: 'apps/web/src/App.css'
      provides: 'Staging banner CSS styles'
      contains: '.staging-banner'
  key_links:
    - from: 'apps/web/src/components/StagingBanner.tsx'
      to: 'import.meta.env.VITE_ENVIRONMENT'
      via: 'environment check'
      pattern: "import\\.meta\\.env\\.VITE_ENVIRONMENT.*staging"
    - from: 'apps/web/src/routes/Login.tsx'
      to: 'StagingBanner'
      via: 'import and render'
      pattern: '<StagingBanner'
    - from: 'apps/web/src/components/layout/AppShell.tsx'
      to: 'StagingBanner'
      via: 'import and render'
      pattern: '<StagingBanner'
---

<objective>
Add a staging environment warning banner that appears on both the login page and the file browser (AppShell) when VITE_ENVIRONMENT=staging.

Purpose: Alert testers that they are on a staging instance where data may be wiped without notice, preventing confusion with the production environment.
Output: A reusable StagingBanner component with two variants (login, compact) integrated into Login and AppShell.
</objective>

<execution_context>
@./.claude/get-shit-done/workflows/execute-plan.md
@./.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@apps/web/src/routes/Login.tsx
@apps/web/src/components/layout/AppShell.tsx
@apps/web/src/App.css
@apps/web/src/lib/web3auth/config.ts
</context>

<tasks>

<task type="auto">
  <name>Task 1: Create StagingBanner component and CSS</name>
  <files>
    apps/web/src/components/StagingBanner.tsx
    apps/web/src/App.css
  </files>
  <action>
Create `apps/web/src/components/StagingBanner.tsx` with a single exported component that accepts a `variant` prop of type `'login' | 'compact'`.

**Environment check:** Read `import.meta.env.VITE_ENVIRONMENT`. If it is NOT exactly `'staging'`, return `null` immediately. This means NO banner in local dev, CI, or production.

**Login variant** (`variant="login"`):

- Full-width bar with fixed positioning at top of viewport (position: fixed, top: 0, left: 0, width: 100%, z-index: 1000)
- Background: `#3d1a00`, border-bottom: `1px solid #FF6B00`
- Centered content, padding: `10px 16px`
- First line: text `STAGING ENVIRONMENT` flanked by warning triangle unicode characters (use the literal unicode char, not the emoji shortcode). Font: JetBrains Mono (`var(--font-family-mono)`), 13px, bold (700), color `#FF6B00`, letter-spacing `2px`, text-transform uppercase
- Second line below: `// This is a staging instance for testing purposes only. No guarantees are made regarding data safety or security.` in JetBrains Mono, 11px, normal weight, color `#FF6B0088` (hex with alpha), text-align center
- Both lines stacked vertically (flex column, align-items center, gap 4px)

**Compact variant** (`variant="compact"`):

- Full-width bar, height 36px, NOT fixed — flows in document
- Background: `#3d1a00`, border-bottom: `1px solid #FF6B00`
- Centered content with flex row, align-items center, justify-content center
- Single line: warning triangle, then `STAGING | Testing only — data may be wiped without notice`, then warning triangle
- Font: JetBrains Mono (`var(--font-family-mono)`), 11px, bold (700), color `#FF6B00`, letter-spacing `1px`
- Use em dash character directly in the string (not HTML entity)

**Use inline styles** to keep the component self-contained. No CSS module needed. This avoids CSS specificity issues and keeps the component portable.

**data-testid:** Add `data-testid="staging-banner"` to the outer div for E2E testability.
</action>
<verify>
Run `npx tsc --noEmit -p apps/web/tsconfig.json` (or the project's equivalent typecheck command) to confirm no type errors. Verify the file exists and exports `StagingBanner`.
</verify>
<done>StagingBanner component exists with two variants, reads VITE_ENVIRONMENT, renders null when not staging, uses correct design spec colors and fonts.</done>
</task>

<task type="auto">
  <name>Task 2: Integrate StagingBanner into Login and AppShell</name>
  <files>
    apps/web/src/routes/Login.tsx
    apps/web/src/components/layout/AppShell.tsx
  </files>
  <action>
**Login.tsx changes:**
1. Import `StagingBanner` from `'../components/StagingBanner'`
2. In the main return (NOT the loading return), add `<StagingBanner variant="login" />` as the FIRST child inside the `<div className="login-container">`, before `<MatrixBackground />`
3. Since the login banner uses `position: fixed`, it will overlay the top of the page without displacing content. Add a spacer div after `<StagingBanner>` and before `<MatrixBackground />` to push content down: `<div style={{ height: import.meta.env.VITE_ENVIRONMENT === 'staging' ? '60px' : '0px' }} />` — OR better: have the StagingBanner component itself not use fixed positioning on login, instead render normally in flow. Actually, re-evaluating: since `login-container` uses `min-height: 100vh` with flexbox centering, the banner should be placed OUTSIDE the login-container. Wrap the Login return in a fragment:
   ```tsx
   return (
     <>
       <StagingBanner variant="login" />
       <div className="login-container">
         <MatrixBackground />
         ...existing content...
       </div>
     </>
   );
   ```
   And for the StagingBanner login variant, use `position: fixed; top: 0; left: 0; width: 100%; z-index: 1000` so it overlays the top of the login page without breaking the centered layout.

**AppShell.tsx changes:**

1. Import `StagingBanner` from `'../StagingBanner'` (one level up from layout/)
2. Add `<StagingBanner variant="compact" />` as the FIRST child inside the `<div className="app-shell">` div, BEFORE `<AppHeader />`
3. Update the CSS grid to accommodate the banner. In AppShell, the grid is defined in `layout.css` as `grid-template-rows: auto 1fr auto`. Since the StagingBanner compact variant is NOT in a named grid area, it will occupy an implicit row. To handle this cleanly, wrap the StagingBanner render conditionally — but actually since StagingBanner returns null when not staging, the grid won't be affected in non-staging environments. For staging, the implicit row will push everything down which may break the grid layout.

**Better approach for AppShell:** Place the compact banner OUTSIDE the grid, above it. Change the AppShell return to:

```tsx
return (
  <>
    <StagingBanner variant="compact" />
    <div className="app-shell" data-testid="app-shell">
      <AppHeader />
      <AppSidebar />
      <main className="app-main">{children}</main>
      <AppFooter />
    </div>
  </>
);
```

This way the compact banner sits above the grid shell as a normal flow element. When it renders null (non-staging), nothing changes. When staging, the 36px bar appears above the AppShell grid. Since `.app-shell` has `height: 100vh`, change it to `height: calc(100vh - 36px)` only when the banner is visible. The cleanest way: have StagingBanner set a CSS custom property on `<html>` or use a state. Actually, simplest approach: use a wrapper div instead of a fragment, and use flex column layout:

```tsx
return (
  <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden' }}>
    <StagingBanner variant="compact" />
    <div className="app-shell" data-testid="app-shell" style={{ flex: 1, height: 'auto' }}>
      <AppHeader />
      <AppSidebar />
      <main className="app-main">{children}</main>
      <AppFooter />
    </div>
  </div>
);
```

BUT this overrides the `height: 100vh` on `.app-shell`. The inline `style={{ flex: 1, height: 'auto' }}` will override the CSS class's height. When StagingBanner returns null, the flex container still takes 100vh and the shell gets `flex: 1` which equals 100vh minus 0px = 100vh. When staging, it's 100vh minus 36px. This works cleanly.

However, only apply the wrapper when VITE_ENVIRONMENT is staging to avoid any risk to production layout:

```tsx
const isStaging = import.meta.env.VITE_ENVIRONMENT === 'staging';

if (isStaging) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100vh', overflow: 'hidden' }}>
      <StagingBanner variant="compact" />
      <div className="app-shell" data-testid="app-shell" style={{ height: 'auto', flex: 1 }}>
        <AppHeader />
        <AppSidebar />
        <main className="app-main">{children}</main>
        <AppFooter />
      </div>
    </div>
  );
}

return (
  <div className="app-shell" data-testid="app-shell">
    <AppHeader />
    <AppSidebar />
    <main className="app-main">{children}</main>
    <AppFooter />
  </div>
);
```

This keeps the non-staging path completely unchanged — zero risk to production.
</action>
<verify>

1. Run `pnpm --filter web build` to confirm no build errors
2. Start dev server with `VITE_ENVIRONMENT=staging pnpm --filter web dev` and visually verify:
   - Login page (<http://localhost:5173>) shows orange staging banner at top
   - After login, file browser shows compact orange bar above the header
3. Start dev server WITHOUT the env var (`pnpm --filter web dev`) and verify no banner appears anywhere
   </verify>
   <done>
   Login page shows full staging banner with title and disclaimer text in orange color scheme. File browser shows compact 36px staging bar above the AppShell header. No banner renders when VITE_ENVIRONMENT is not 'staging'. Non-staging code paths are completely unchanged.
   </done>
   </task>

</tasks>

<verification>
1. `pnpm --filter web build` succeeds with no errors
2. With `VITE_ENVIRONMENT=staging`: login page shows "STAGING ENVIRONMENT" banner with orange #FF6B00 text on #3d1a00 background and disclaimer text below
3. With `VITE_ENVIRONMENT=staging`: file browser shows compact "STAGING | Testing only -- data may be wiped without notice" bar above the header
4. Without `VITE_ENVIRONMENT=staging` (or with `local`/`production`): no banner visible on any page
5. Banner text uses JetBrains Mono font (var(--font-family-mono))
6. `data-testid="staging-banner"` present on the banner element
</verification>

<success_criteria>

- StagingBanner component renders correctly for both variants when VITE_ENVIRONMENT=staging
- StagingBanner returns null (no DOM output) when not staging
- Non-staging code paths in AppShell and Login are completely unchanged
- Build passes with no type errors
- Design matches spec: #FF6B00 text, #3d1a00 background, JetBrains Mono font, warning triangle characters
  </success_criteria>

<output>
After completion, create `.planning/quick/004-add-staging-environment-banner/004-SUMMARY.md`
</output>

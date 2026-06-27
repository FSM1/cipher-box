---
phase: quick
plan: 260401-kyv
type: execute
wave: 1
depends_on: []
files_modified:
  - apps/web/src/components/layout/NavItem.tsx
  - apps/web/src/styles/layout.css
autonomous: true
requirements: [sidebar-icon-consistency]

must_haves:
  truths:
    - 'All four sidebar icons (Files, Shared, Bin, Settings) render as monochrome SVGs that inherit text color'
    - 'Icons are visually consistent across platforms (no emoji rendering variance)'
    - 'Active and hover states change icon color via CSS inheritance (currentColor)'
  artifacts:
    - path: 'apps/web/src/components/layout/NavItem.tsx'
      provides: 'Inline SVG icon components replacing emoji ICON_MAP'
      contains: 'currentColor'
    - path: 'apps/web/src/styles/layout.css'
      provides: 'Updated .nav-item-icon styles for SVG sizing'
      contains: '.nav-item-icon'
  key_links:
    - from: 'NavItem.tsx SVG icons'
      to: 'layout.css .nav-item color'
      via: 'currentColor fill/stroke on SVGs inherits from parent .nav-item color'
      pattern: 'currentColor'
---

<objective>
Replace mixed Unicode emoji/symbol sidebar navigation icons with uniform inline SVG React components.

Purpose: Emoji render differently across platforms (colorful on macOS, monochrome on others) and the settings gear (U+2699) is a basic Unicode symbol while others are full emoji. This creates visual inconsistency in the terminal/hacker aesthetic. Inline SVGs with currentColor will render identically everywhere and inherit the green-on-black color scheme.

Output: Consistent monochrome SVG sidebar icons that respond to CSS color states (normal, hover, active).
</objective>

<execution_context>
@.claude/get-shit-done/workflows/execute-plan.md
@.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@apps/web/src/components/layout/NavItem.tsx
@apps/web/src/components/layout/AppSidebar.tsx
@apps/web/src/styles/layout.css

<interfaces>
<!-- NavItem interface consumed by AppSidebar -->
From apps/web/src/components/layout/NavItem.tsx:
```typescript
interface NavItemProps {
  to: string;
  icon: 'folder' | 'shared' | 'bin' | 'settings';
  label: string;
  active: boolean;
}

// Current approach: ICON_MAP maps icon string -> Unicode emoji string
// Target approach: ICON_MAP maps icon string -> JSX.Element (inline SVG)

````

From apps/web/src/components/layout/AppSidebar.tsx:
```typescript
// Uses NavItem with these icon values:
// "folder" (Files), "shared" (Shared), "bin" (Bin), "settings" (Settings)
````

</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Replace emoji ICON_MAP with inline SVG components and update CSS</name>
  <files>apps/web/src/components/layout/NavItem.tsx, apps/web/src/styles/layout.css</files>
  <action>
In NavItem.tsx:

1. Change `ICON_MAP` from `Record<NavItemProps['icon'], string>` to `Record<NavItemProps['icon'], JSX.Element>` (import `type { JSX }` from React if needed for the type, or use `React.ReactNode`).

2. Replace each emoji entry with a small inline SVG element. All SVGs should be 16x16 viewBox, use `fill="currentColor"` or `stroke="currentColor"` (as appropriate for the icon style), and have `aria-hidden="true"` since the label provides the accessible name. Use simple, recognizable shapes that match a terminal/monochrome aesthetic:
   - **folder**: A folder outline. `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M1.5 2.5h4l1.5 1.5h7.5v9h-13v-10.5z" stroke="currentColor" strokeWidth="1.2" strokeLinejoin="round"/></svg>`
   - **shared**: A link/chain icon (two interlocking oval links). `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M6.5 9.5l3-3" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/><path d="M8.5 10.5l-1 1a2.12 2.12 0 01-3 0v0a2.12 2.12 0 010-3l1-1" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/><path d="M7.5 5.5l1-1a2.12 2.12 0 013 0v0a2.12 2.12 0 010 3l-1 1" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/></svg>`
   - **bin**: A trash can outline. `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M3 4.5h10M6.5 4.5V3a.5.5 0 01.5-.5h2a.5.5 0 01.5.5v1.5M4 4.5l.5 8.5a1 1 0 001 1h5a1 1 0 001-1l.5-8.5" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round" strokeLinejoin="round"/></svg>`
   - **settings**: A gear/cog outline. `<svg width="16" height="16" viewBox="0 0 16 16" fill="none" aria-hidden="true"><circle cx="8" cy="8" r="2" stroke="currentColor" strokeWidth="1.2"/><path d="M8 1.5v1.5M8 13v1.5M1.5 8H3M13 8h1.5M3.05 3.05l1.06 1.06M11.89 11.89l1.06 1.06M3.05 12.95l1.06-1.06M11.89 4.11l1.06-1.06" stroke="currentColor" strokeWidth="1.2" strokeLinecap="round"/></svg>`

3. Replace the render from `<span className="nav-item-icon">{iconEmoji}</span>` to `<span className="nav-item-icon">{ICON_MAP[icon]}</span>` (remove the intermediate `iconEmoji` variable — just use ICON_MAP[icon] directly).

4. Update the JSDoc comment from "Renders a sidebar navigation link with emoji icon" to "Renders a sidebar navigation link with SVG icon."

In layout.css:

5. Update the `.nav-item-icon` rule to work with SVGs instead of emoji text:
   ```css
   .nav-item-icon {
     display: flex;
     align-items: center;
     justify-content: center;
     width: 16px;
     height: 16px;
     flex-shrink: 0;
   }
   ```
   Remove the `font-family` and `font-size` properties since they only applied to text-based emoji.
   </action>
   <verify>
   <automated>cd . && pnpm --filter web exec tsc --noEmit 2>&1 | head -30</automated>
   </verify>
   <done>All four sidebar nav icons render as inline SVGs using currentColor. No emoji or Unicode characters remain in NavItem.tsx. TypeScript compiles without errors. The icon type union ('folder' | 'shared' | 'bin' | 'settings') is unchanged so AppSidebar requires zero modifications.</done>
   </task>

<task type="checkpoint:human-verify" gate="blocking">
  <what-built>Replaced all four sidebar emoji icons with monochrome inline SVGs that inherit text color via currentColor. Icons: folder (outline), link/chain (shared), trash can (bin), gear/cog (settings).</what-built>
  <how-to-verify>
    1. Start the web dev server: `pnpm --filter web dev`
    2. Open http://localhost:5173 and log in
    3. Verify the sidebar shows four navigation items with monochrome SVG icons (not colorful emoji)
    4. Verify all four icons are visually consistent — same stroke weight, same size, same color
    5. Hover over each nav item — icon color should change along with the text (both inherit from parent)
    6. Click a nav item — active state should show the icon in the brighter/primary text color
    7. Confirm the icons match the terminal/hacker aesthetic (thin strokes, monochrome green)
  </how-to-verify>
  <resume-signal>Type "approved" or describe any icon that needs adjustment (e.g., "bin icon too thin", "settings gear not recognizable")</resume-signal>
</task>

</tasks>

<verification>
- TypeScript compiles without errors: `pnpm --filter web exec tsc --noEmit`
- No emoji/Unicode icon characters remain: grep for `\uD83D\|\u2699\|ICON_MAP.*string` in NavItem.tsx should return nothing
- SVGs use currentColor: grep for `currentColor` in NavItem.tsx returns matches for all four icons
</verification>

<success_criteria>

- All four sidebar icons are inline SVGs (no emoji, no Unicode symbols)
- Icons use currentColor for fill/stroke, inheriting color from CSS
- Icon appearance is consistent across all four nav items (same size, stroke weight, style)
- Hover and active states affect icon color through CSS inheritance
- No changes needed to AppSidebar.tsx — the icon prop type union is preserved
  </success_criteria>

<output>
After completion, create `.planning/quick/260401-kyv-fix-sidebar-icons-to-be-consistent/260401-kyv-SUMMARY.md`
</output>

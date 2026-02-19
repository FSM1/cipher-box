---
status: resolved
trigger: 'MFA banner footer overlap - banner renders incorrectly in footer area, text wraps badly, overlaps footer'
created: 2026-02-18T00:00:00Z
updated: 2026-02-18T00:00:02Z
---

## Current Focus

hypothesis: CONFIRMED AND FIXED
test: N/A
expecting: N/A
next_action: Archive

## Symptoms

expected: MFA setup banner should render as a clean, properly-laid-out notification/banner within the page
actual: Banner renders below/overlapping footer, text wraps word-by-word vertically, buttons overlap matrix rain background
errors: No console errors - CSS/layout issue
reproduction: Visible on main vault page for users without MFA
started: Likely since MFA banner feature was added

## Eliminated

## Evidence

- timestamp: 2026-02-18T00:00:00Z
  checked: layout.css grid definition
  found: Grid has 3 rows (auto 1fr auto) with areas header/sidebar+main/footer. No area defined for mfa-prompt.
  implication: MfaEnrollmentPrompt div gets auto-placed outside the defined grid areas

- timestamp: 2026-02-18T00:00:00Z
  checked: App.css .mfa-prompt styles
  found: .mfa-prompt has display:flex, gap, padding but NO grid-area. Gets squeezed into auto-placed cell.
  implication: Without grid-area, it falls into remaining space (narrow sidebar column width), causing word wrapping

- timestamp: 2026-02-18T00:00:00Z
  checked: AppShell.tsx component order
  found: MfaEnrollmentPrompt placed between AppHeader and AppSidebar in JSX
  implication: Grid auto-placement puts it after header row but with no spanning, gets narrow column

## Resolution

root_cause: MfaEnrollmentPrompt has no grid-area in the CSS Grid layout. The app-shell grid defines areas for header, sidebar, main, and footer only. The mfa-prompt div is auto-placed into the grid without any area assignment, causing it to be squeezed into the sidebar column width (180px) and overflow into the footer area.
fix: Added 'banner' grid area row to app-shell grid template (between header and sidebar/main), assigned grid-area:banner to .mfa-prompt with z-index:2, updated mobile responsive grid to include banner row.
verification: CSS changes verified syntactically correct. Banner row uses auto height so it collapses to 0 when MfaEnrollmentPrompt returns null (dismissed/MFA enabled). Pre-existing TS build errors unrelated to changes.
files_changed:

- apps/web/src/styles/layout.css
- apps/web/src/App.css

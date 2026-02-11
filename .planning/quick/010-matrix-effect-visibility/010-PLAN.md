---
phase: quick-010
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - apps/web/src/components/MatrixBackground.tsx
  - apps/web/src/styles/layout.css
  - apps/web/src/styles/modal.css
  - apps/web/src/components/ui/Modal.tsx
autonomous: true

must_haves:
  truths:
    - 'Matrix rain effect is visibly bleeding through header, sidebar, footer, and main area backgrounds'
    - 'Modal backdrop shows matrix rain effect behind the modal container'
    - 'Text in header, sidebar, footer, and main area remains readable against the semi-transparent backgrounds'
    - 'Modal content remains readable with matrix backdrop'
  artifacts:
    - path: 'apps/web/src/components/MatrixBackground.tsx'
      provides: 'Reusable matrix background with configurable opacity and className'
      contains: 'opacity'
    - path: 'apps/web/src/styles/layout.css'
      provides: 'Reduced background opacities for app shell chrome'
      contains: 'rgb(0 0 0'
    - path: 'apps/web/src/styles/modal.css'
      provides: 'Matrix-compatible modal backdrop styling'
      contains: 'rgb(0 0 0'
    - path: 'apps/web/src/components/ui/Modal.tsx'
      provides: 'Modal with embedded MatrixBackground on backdrop'
      contains: 'MatrixBackground'
  key_links:
    - from: 'apps/web/src/components/ui/Modal.tsx'
      to: 'apps/web/src/components/MatrixBackground.tsx'
      via: 'import and render inside backdrop div'
      pattern: 'import.*MatrixBackground'
---

<objective>
Make the matrix rain canvas effect visually bleed through all app shell chrome elements (header, sidebar, main content area, footer) and add it as a backdrop effect on modal overlays.

Purpose: The matrix rain is currently barely visible because app shell backgrounds are too opaque (0.85) and the canvas opacity is too low (0.25). This change creates a more immersive terminal/cyberpunk aesthetic.

Output: Updated MatrixBackground component with props, reduced layout opacities, and matrix-enhanced modal backdrop.
</objective>

<execution_context>
@./.claude/get-shit-done/workflows/execute-plan.md
@./.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@apps/web/src/components/MatrixBackground.tsx
@apps/web/src/styles/layout.css
@apps/web/src/styles/modal.css
@apps/web/src/components/ui/Modal.tsx
@apps/web/src/components/layout/AppShell.tsx
@apps/web/CLAUDE.md (CSS conventions: use modern `rgb(0 0 0 / 50%)` notation, never legacy `rgba()`)
</context>

<tasks>

<task type="auto">
  <name>Task 1: Add props to MatrixBackground and reduce layout opacities</name>
  <files>
    apps/web/src/components/MatrixBackground.tsx
    apps/web/src/styles/layout.css
  </files>
  <action>
**MatrixBackground.tsx** -- Add optional props for reuse in different contexts:

1. Add props interface:

   ```tsx
   interface MatrixBackgroundProps {
     /** Canvas opacity. Default 0.4 */
     opacity?: number;
     /** Additional CSS class name */
     className?: string;
   }
   ```

2. Update function signature: `export function MatrixBackground({ opacity = 0.4, className }: MatrixBackgroundProps)`

3. Replace the inline `style` object on the canvas element with a CSS class approach. Keep `pointerEvents: 'none'` inline (it's behavioral). Move positioning/sizing to CSS:

   ```tsx
   <canvas
     ref={canvasRef}
     className={`matrix-canvas${className ? ` ${className}` : ''}`}
     aria-hidden="true"
     style={{
       opacity,
       pointerEvents: 'none',
     }}
   />
   ```

4. Add CSS at the top of the file via a small style block, OR better: add to layout.css since that's where the app shell styles live. Add these rules to the TOP of layout.css (before App Shell Grid Container section):

   ```css
   /* ==========================================================================
      Matrix Background Canvas
      ========================================================================== */

   .matrix-canvas {
     position: fixed;
     top: 0;
     left: 0;
     width: 100%;
     height: 100%;
     z-index: -1;
   }
   ```

**layout.css** -- Reduce background opacities so the matrix bleeds through. Use modern CSS color notation (`rgb(0 0 0 / XX%)` not `rgba()`):

- `.app-header` line 33: `background-color: rgba(0, 0, 0, 0.85)` --> `background-color: rgb(0 0 0 / 70%)`
- `.app-sidebar` line 72: `background-color: rgba(0, 0, 0, 0.85)` --> `background-color: rgb(0 0 0 / 70%)`
- `.app-main` line 153: `background-color: rgba(0, 0, 0, 0.75)` --> `background-color: rgb(0 0 0 / 60%)`
- `.app-footer` line 168: `background-color: rgba(0, 0, 0, 0.85)` --> `background-color: rgb(0 0 0 / 70%)`

Also fix the one remaining legacy rgba in layout.css while we are here -- the `.modal-container` box-shadow line is in modal.css, not here, so just the four above.

NOTE: The default opacity on MatrixBackground changes from 0.25 to 0.4. Both AppShell.tsx and Login.tsx use `<MatrixBackground />` with no props, so they will both get the new default. This is intentional -- the login page also benefits from a more visible matrix effect.
</action>
<verify>

1. `cd /Users/michael/Code/cipher-box && pnpm --filter web build` compiles without errors
2. Visual check: header, sidebar, footer, and main area show green matrix rain bleeding through their semi-transparent backgrounds
   </verify>
   <done>

- MatrixBackground accepts optional `opacity` and `className` props
- Default opacity is 0.4 (up from 0.25)
- Canvas positioning uses `.matrix-canvas` CSS class instead of inline styles
- All four layout element backgrounds reduced to 60-70% opacity using modern `rgb()` notation
- Matrix rain visibly shows through all app shell chrome elements
  </done>
  </task>

<task type="auto">
  <name>Task 2: Add matrix effect to modal backdrop</name>
  <files>
    apps/web/src/components/ui/Modal.tsx
    apps/web/src/styles/modal.css
  </files>
  <action>
**Modal.tsx** -- Add a MatrixBackground instance inside the modal backdrop:

1. Add import: `import { MatrixBackground } from '../MatrixBackground';`

2. Inside the `<Portal>`, render a MatrixBackground inside the backdrop div, BEFORE the modal-container div:

   ```tsx
   <div
     className={`modal-backdrop${className ? ` ${className}` : ''}`}
     onClick={handleBackdropClick}
   >
     <MatrixBackground opacity={0.15} className="matrix-canvas--modal" />
     <div
       ref={modalRef}
       className="modal-container"
       ...
     >
   ```

   The low opacity (0.15) keeps it subtle so modal content stays readable. The `className` prop adds `.matrix-canvas--modal` for modal-specific positioning.

**modal.css** -- Update backdrop and add modal matrix positioning:

1. Change `.modal-backdrop` background from `rgba(0, 0, 0, 0.8)` to `rgb(0 0 0 / 70%)` -- slightly more transparent to let matrix show. Keep `backdrop-filter: blur(4px)`.

2. Add `.matrix-canvas--modal` override class (add after the Modal Backdrop section):

   ```css
   .matrix-canvas--modal {
     position: absolute;
     z-index: 0;
   }
   ```

   This overrides the `position: fixed` and `z-index: -1` from `.matrix-canvas` so the canvas sits inside the backdrop's stacking context rather than behind the entire page.

3. Add `position: relative` and `overflow: hidden` to `.modal-backdrop` so the absolute-positioned matrix canvas is contained within it. The backdrop already has `position: fixed` and `inset: 0` so adding `overflow: hidden` is safe.

4. Ensure `.modal-container` has `z-index: 1` (or `position: relative; z-index: 1`) so the modal content sits above the matrix canvas in the backdrop. Currently `.modal-container` has `position: relative` already -- just add `z-index: 1` to it.

5. Fix the legacy `rgba()` in `.modal-container` box-shadow while here:
   `box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5), var(--glow-green)` --> `box-shadow: 0 25px 50px -12px rgb(0 0 0 / 50%), var(--glow-green)`

IMPORTANT: The MatrixBackground component creates a new canvas with its own animation loop. Since modals are not always open, this is fine -- the canvas only renders when the modal is open (Modal returns null when `open` is false). The animation loop starts on mount and cleans up on unmount via the existing useEffect cleanup.
</action>
<verify>

1. `cd /Users/michael/Code/cipher-box && pnpm --filter web build` compiles without errors
2. Open any modal (e.g., upload modal, settings) -- backdrop shows subtle green matrix rain behind the modal container
3. Close modal -- no console errors, no lingering animation frames
4. Modal content text remains fully readable
   </verify>
   <done>

- Modal backdrop renders a dedicated MatrixBackground instance at 0.15 opacity
- Matrix canvas is contained within the backdrop via absolute positioning
- Modal container sits above the matrix canvas via z-index
- Backdrop opacity reduced from 0.8 to 0.7 to let matrix show
- All legacy rgba() calls in modal.css converted to modern rgb() notation
- Matrix canvas cleans up properly when modal closes (existing useEffect cleanup)
  </done>
  </task>

</tasks>

<verification>
1. `pnpm --filter web build` -- no TypeScript or build errors
2. Visual: App shell shows matrix rain bleeding through header, sidebar, main area, and footer
3. Visual: Opening a modal shows subtle matrix rain on the backdrop overlay
4. Visual: All text remains readable in header, sidebar, footer, main area, and modal content
5. No console errors or warnings related to MatrixBackground or Modal
6. Login page still shows matrix background (now at 0.4 opacity instead of 0.25)
</verification>

<success_criteria>

- Matrix rain visually bleeds through all app shell chrome (header, sidebar, footer, main)
- Modal backdrops display a subtle matrix rain effect
- All text across the application remains readable
- No build errors, no runtime errors
- All CSS uses modern `rgb(0 0 0 / XX%)` notation (no legacy `rgba()`)
  </success_criteria>

<output>
After completion, create `.planning/quick/010-matrix-effect-visibility/010-SUMMARY.md`
</output>

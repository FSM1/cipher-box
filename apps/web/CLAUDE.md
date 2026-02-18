# Web App (`apps/web`) - Coding Guidelines

These guidelines are derived from recurring review issues across 16 PRs. Follow them to avoid common pitfalls caught by automated reviewers.

## Accessibility (a11y)

### ARIA roles require matching keyboard handlers

When adding `role` and `tabIndex={0}` to an element, you **must** also add the keyboard interaction contract for that role:

- **`role="button"`** requires `onKeyDown` handling Enter and Space:

  ```tsx
  onKeyDown={(e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      handleClick();
    }
  }}
  ```

- **`role="slider"`** requires `onKeyDown` handling ArrowLeft, ArrowRight (and optionally Home/End):

  ```tsx
  onKeyDown={(e) => {
    if (e.key === 'ArrowRight') { e.preventDefault(); seekForward(); }
    else if (e.key === 'ArrowLeft') { e.preventDefault(); seekBackward(); }
  }}
  ```

- If keyboard interaction is **not** needed, use a read-only role instead (e.g., `role="progressbar"` instead of `role="slider"`) and remove `tabIndex`.

### Focus-visible styles for all interactive elements

Every custom interactive element with `:hover` styles **must** also have `:focus-visible` styles so keyboard users can see focus:

```css
.my-button:hover {
  /* ... */
}
.my-button:focus-visible {
  outline: 1px solid var(--color-green-primary);
  outline-offset: 1px;
}
```

## Media Elements

### Always wrap `.play()` in try/catch

`HTMLMediaElement.play()` returns a Promise that rejects under autoplay policy or when interrupted by a new load. Never `await` it without error handling:

```tsx
try {
  await element.play();
  setIsPlaying(true);
} catch {
  // Browser blocked playback (autoplay policy / interruption)
}
```

### Sync state to new media elements on mount

When a dialog re-opens, a new `<audio>`/`<video>` element is created with default properties (volume=1.0, playbackRate=1.0), but React state retains the previous values. Apply stored state in `onLoadedMetadata`:

```tsx
const handleLoadedMetadata = useCallback(() => {
  const el = mediaRef.current;
  if (!el) return;
  el.volume = volume;
  el.playbackRate = speed;
  // ... set duration, dimensions, etc.
}, [volume, speed]);
```

## React Async Lifecycle

### Ref safety in async callbacks

Inside `async` functions that reference React refs, always re-check for null after each `await`. Never use non-null assertions (`!`) on refs in async code:

```tsx
const doc = pdfDocRef.current;
if (!doc) return;
const page = await doc.getPage(1);
// Re-check after await -- dialog may have closed
if (!canvasRef.current) return;
```

### Dialog close cleanup checklist

When a dialog/modal resets state on close, ensure **all** of these are cleaned up:

- All loading/error states
- All resolved data
- All timers (`clearTimeout`, `clearInterval`) via their refs
- All animation frames (`cancelAnimationFrame`)

### Debounce single-click when double-click exists

When an element handles both `onClick` (e.g., play/pause) and `onDoubleClick` (e.g., fullscreen), use a ~250ms timer to delay single-click and cancel it on double-click to prevent conflicting state changes.

## CSS

### Use modern color function notation

Always use the space-separated modern syntax. Never use legacy comma-separated `rgba()`:

```css
/* Bad */
background: rgba(0, 0, 0, 0.5);

/* Good */
background: rgb(0 0 0 / 50%);
```

## JSX / Biome Lint

### Wrap `//` text in JSX expressions

The terminal aesthetic uses `//` as decorative text, but Biome's `noCommentText` rule interprets it as a stray comment. Always wrap in braces:

```tsx
/* Bad */
<span>// encryption</span>

/* Good */
<span>{'// encryption'}</span>
```

## Binary Data

### Never use `.buffer` on Uint8Array for Blob construction

`Uint8Array.buffer` returns the **entire** underlying ArrayBuffer, which may be larger than the view. This causes silent data corruption, especially critical for encrypted payloads:

```tsx
/* Bad -- may include extra bytes */
new Blob([uint8array.buffer]);

/* Good -- pass the typed array directly */
new Blob([uint8array]);
```

---
phase: quick-008
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - apps/web/package.json
  - apps/web/src/hooks/useFilePreview.ts
  - apps/web/src/components/file-browser/PdfPreviewDialog.tsx
  - apps/web/src/styles/pdf-preview-dialog.css
  - apps/web/src/components/file-browser/AudioPlayerDialog.tsx
  - apps/web/src/styles/audio-player-dialog.css
  - apps/web/src/components/file-browser/VideoPlayerDialog.tsx
  - apps/web/src/styles/video-player-dialog.css
  - apps/web/src/components/file-browser/FileBrowser.tsx
  - apps/web/src/components/file-browser/ContextMenu.tsx
autonomous: false

must_haves:
  truths:
    - 'User can click a PDF file and see its pages rendered in a scrollable viewer with zoom controls'
    - 'User can click an audio file and hear it play with custom transport controls and optional frequency spectrum visualization'
    - 'User can click a video file and watch it play with custom overlay controls (no native browser chrome)'
    - 'All preview dialogs show loading/decrypting state while file is fetched from IPFS'
    - 'User can download the file from within any preview dialog'
    - 'User can close any preview dialog with [x] or Escape'
  artifacts:
    - path: 'apps/web/src/hooks/useFilePreview.ts'
      provides: 'Shared decrypt-to-blob-URL hook for all preview types'
    - path: 'apps/web/src/components/file-browser/PdfPreviewDialog.tsx'
      provides: 'PDF viewer with zoom, scroll, page navigation'
    - path: 'apps/web/src/components/file-browser/AudioPlayerDialog.tsx'
      provides: 'Custom audio player with frequency spectrum visualization'
    - path: 'apps/web/src/components/file-browser/VideoPlayerDialog.tsx'
      provides: 'Custom video player with overlay controls'
  key_links:
    - from: 'FileBrowser.tsx'
      to: 'PdfPreviewDialog / AudioPlayerDialog / VideoPlayerDialog'
      via: 'dialog state + file type detection'
      pattern: 'isPdfFile|isAudioFile|isVideoFile'
    - from: 'useFilePreview.ts'
      to: 'download.service.ts'
      via: 'downloadFile() to get decrypted Uint8Array, then Blob URL'
      pattern: 'downloadFile.*createObjectURL'
    - from: 'ContextMenu.tsx'
      to: 'FileBrowser.tsx'
      via: 'onPreview callback extended to handle PDF/audio/video'
      pattern: 'onPreview'
---

<objective>
Implement PDF, audio, and video file preview modals for the CipherBox web file browser.

Purpose: Users currently can only preview images inline. This adds support for the three remaining major media types -- PDF documents, audio files, and video files -- all rendered in custom terminal-aesthetic modal overlays that match the existing design system. Audio and video use fully custom controls (no native browser player chrome). Audio includes a toggleable frequency spectrum visualization.

Output: Three new preview dialog components, a shared preview hook, updated FileBrowser integration, and updated context menu.
</objective>

<execution_context>
@./.claude/get-shit-done/workflows/execute-plan.md
@./.claude/get-shit-done/templates/summary.md
</execution_context>

<context>
@apps/web/src/components/file-browser/ImagePreviewDialog.tsx (pattern reference -- follow same structure for download/decrypt/blob URL lifecycle)
@apps/web/src/components/file-browser/FileBrowser.tsx (integration point -- add new dialog states + file type detection)
@apps/web/src/components/file-browser/ContextMenu.tsx (add Preview option for PDF/audio/video files)
@apps/web/src/components/ui/Modal.tsx (base modal component to reuse)
@apps/web/src/services/download.service.ts (downloadFile + triggerBrowserDownload functions)
@apps/web/src/hooks/useFileDownload.ts (existing download hook -- reference pattern only, do NOT modify)
@apps/web/src/styles/image-preview-dialog.css (CSS pattern reference)
@apps/web/src/styles/text-editor-dialog.css (CSS pattern reference for wider modals)
@apps/web/src/styles/dialogs.css (button classes: dialog-button, dialog-button--secondary, dialog-button--primary)
@apps/web/src/styles/modal.css (modal-backdrop, modal-container, modal-header, modal-body)
@apps/web/src/index.css (design tokens: colors, fonts, spacing)
@apps/web/package.json (dependencies -- add pdfjs-dist here)
</context>

<tasks>

<task type="auto">
  <name>Task 1: Shared preview hook + PDF Preview Dialog</name>
  <files>
    apps/web/src/hooks/useFilePreview.ts
    apps/web/src/components/file-browser/PdfPreviewDialog.tsx
    apps/web/src/styles/pdf-preview-dialog.css
    apps/web/package.json
  </files>
  <action>
**1a. Install pdfjs-dist:**
```bash
cd apps/web && pnpm add pdfjs-dist
```

**1b. Create `apps/web/src/hooks/useFilePreview.ts`:**

A reusable hook that all three preview dialogs will share. It encapsulates the download-decrypt-blob-URL lifecycle currently duplicated in ImagePreviewDialog.

```ts
type UseFilePreviewOptions = {
  open: boolean;
  item: FileEntry | null;
  mimeType: string; // caller determines MIME from extension
};

type UseFilePreviewReturn = {
  loading: boolean;
  error: string | null;
  objectUrl: string | null;
  decryptedData: Uint8Array | null;
  handleDownload: () => void;
};
```

Implementation pattern -- follow `ImagePreviewDialog` exactly:

- When `open` becomes true and `item` is not null, call `useAuthStore.getState()` to get keypair (avoid stale closures per project memory).
- Call `downloadFile({ cid: item.cid, iv: item.fileIv, wrappedKey: item.fileKeyEncrypted, originalName: item.name }, privateKey)`.
- Create `new Blob([plaintext.buffer as ArrayBuffer], { type: mimeType })`, then `URL.createObjectURL(blob)`.
- Store `objectUrl` and `decryptedData` in state.
- On close (`open` becomes false), revoke the object URL and reset state.
- Use a `cancelled` flag in the async effect to prevent stale updates.
- Expose `handleDownload` that calls `triggerBrowserDownload(decryptedData, item.name, mimeType)`.

**1c. Create `apps/web/src/components/file-browser/PdfPreviewDialog.tsx`:**

Props: `{ open: boolean; onClose: () => void; item: FileEntry | null }`.

Structure (terminal aesthetic matching design mockup frame qmlN8):

**Header row** (custom, NOT using Modal's built-in header -- render inside Modal with `title` omitted or set to empty, so we get the modal-container without a default header; alternatively, use Modal's className to override):

- Actually, DO use the base `<Modal>` component but pass a custom `title` prop or no title. The custom header should be rendered INSIDE the modal body area. Approach: Use `<Modal open={open} onClose={onClose} className="pdf-preview-modal">` with NO title, then render the custom header as the first child. The modal-header won't render if no title and onClose is still handled by the modal.

Wait -- looking at Modal.tsx more carefully: the header renders if EITHER title OR onClose is truthy. Since we need onClose for Escape/backdrop, the default header will render with just the close button. That's fine -- we'll override styling via CSS to make the header match our design, OR we accept the default close [x] in the top-right and add our custom toolbar as a separate row below the modal-header.

**Better approach:** Use `<Modal open={open} onClose={onClose} className="pdf-preview-modal">` and render everything inside the modal body. The modal's default header will show just the [x] close button (since we pass onClose but no title). Then inside modal-body, render:

1. **Toolbar row** (`.pdf-toolbar`):
   - Left side: `[PDF]` tag (green bg `#00D084`, black text, padding 2px 6px), then filename in `--color-text-primary`.
   - Right side: Zoom controls `[-]` `100%` `[+]` `[fit]`, then `[download]`. All bracket-wrapped, styled as `dialog-button dialog-button--secondary` but smaller (font-size: 10px, padding: 2px 8px).

2. **PDF canvas area** (`.pdf-canvas-area`): Background `#0a0f0d`, flex: 1, overflow: auto (scrollable). Render each page as a `<canvas>` element stacked vertically with 16px gap between pages. Use pdfjs-dist to render.

3. **Footer row** (`.pdf-footer`):
   - `[<<]` previous page, `page N / M` text, `[>>]` next page. These scroll-to-page buttons scroll the canvas area to bring the target page into view (smooth scroll).

**PDF rendering with pdfjs-dist:**

- Configure the worker: `import * as pdfjsLib from 'pdfjs-dist'; pdfjsLib.GlobalWorkerOptions.workerSrc = new URL('pdfjs-dist/build/pdf.worker.min.mjs', import.meta.url).href;`
  - NOTE: Check the actual file path in `node_modules/pdfjs-dist/build/` after install. It may be `pdf.worker.min.mjs` or `pdf.worker.mjs`. Use whichever exists. Vite handles the `new URL(..., import.meta.url)` pattern for worker files.
- Load the document from the blob URL: `pdfjsLib.getDocument(objectUrl).promise`.
- Track `numPages` from the document.
- Render ALL pages into canvases (not just current page) so user can scroll through them. For each page:

  ```ts
  const page = await doc.getPage(pageNum); // 1-indexed
  const viewport = page.getViewport({ scale: zoom });
  canvas.width = viewport.width;
  canvas.height = viewport.height;
  await page.render({ canvasContext: ctx, viewport }).promise;
  ```

- Store zoom level in state (default: 1.0). `[-]` decreases by 0.25 (min 0.25), `[+]` increases by 0.25 (max 4.0). `[fit]` calculates scale to fit container width. When zoom changes, re-render all canvases.
- Track current visible page via IntersectionObserver on the canvas elements. Update the `page N / M` display.
- `[<<]` and `[>>]` scroll to previous/next page using `canvasRef.scrollIntoView({ behavior: 'smooth' })`.
- Use `useCallback` / `useRef` appropriately. Clean up the PDF document on unmount (`doc.destroy()`).

**1d. Create `apps/web/src/styles/pdf-preview-dialog.css`:**

```css
/* Wider modal for PDF */
.pdf-preview-modal .modal-container {
  max-width: 900px;
  width: 95vw;
}

.pdf-preview-modal .modal-body {
  display: flex;
  flex-direction: column;
  padding: 0;
  max-height: calc(90vh - 60px);
}
```

Toolbar: flex row, `justify-content: space-between`, `align-items: center`, `padding: var(--spacing-xs) var(--spacing-md)`, `border-bottom: var(--border-thickness) solid var(--color-border-dim)`, `flex-shrink: 0`.

PDF tag: `background-color: var(--color-green-primary)`, `color: var(--color-black)`, `padding: 2px 6px`, `font-size: var(--font-size-xs)`, `font-weight: var(--font-weight-semibold)`, `text-transform: uppercase`.

Zoom/nav buttons: `background: transparent`, `border: var(--border-thickness) solid var(--color-border)`, `color: var(--color-text-primary)`, `font-family: var(--font-family-mono)`, `font-size: var(--font-size-xs)`, `padding: 2px 8px`, `cursor: pointer`. Hover: `background-color: var(--color-green-darker)`.

Canvas area: `flex: 1`, `overflow-y: auto`, `background-color: #0a0f0d`, `padding: var(--spacing-md)`, display flex column, `align-items: center`, `gap: var(--spacing-md)`.

Footer: same flex row pattern as toolbar, centered content.

Loading state: same pattern as `.image-preview-loading`.
Error state: same pattern as `.image-preview-error`.
</action>
<verify>
Run `cd /Users/michael/Code/cipher-box && pnpm --filter web build` -- should compile with no TypeScript errors.
Verify pdfjs-dist is in apps/web/package.json dependencies.
Verify useFilePreview.ts exports the hook.
Verify PdfPreviewDialog.tsx imports and uses Modal, useFilePreview, and pdfjs-dist.
</verify>
<done>
PDF preview dialog renders inside a Modal, loads a PDF from a blob URL via pdfjs-dist, displays all pages on canvases with scroll, supports zoom [-]/[+]/[fit], shows page N/M footer with [<<]/[>>] navigation. Shared useFilePreview hook extracts the download-decrypt-blob lifecycle. Build passes.
</done>
</task>

<task type="auto">
  <name>Task 2: Audio Player Dialog with frequency spectrum visualization</name>
  <files>
    apps/web/src/components/file-browser/AudioPlayerDialog.tsx
    apps/web/src/styles/audio-player-dialog.css
  </files>
  <action>
**Create `apps/web/src/components/file-browser/AudioPlayerDialog.tsx`:**

Props: `{ open: boolean; onClose: () => void; item: FileEntry | null }`.

Use `useFilePreview` hook from Task 1 to handle decrypt-to-blob lifecycle.

**Layout (matching design mockup frame TzRTi):**

Use `<Modal open={open} onClose={onClose} className="audio-player-modal">`. Render custom content inside modal-body:

1. **Toolbar row** (`.audio-toolbar`):
   - Left: `[AUD]` tag (same green tag style as PDF's `[PDF]` tag), filename.
   - Right: `[download]`, `[x]` (the modal already has [x] from onClose -- so just `[download]`).

2. **Visualization area** (`.audio-viz-area`):
   - Height: ~200px, background: `#0a0f0d`.
   - When viz is ON: Render 48 vertical bars using a `<canvas>` element. Each bar has width ~8px with ~4px gap. Bars represent frequency data from Web Audio API `AnalyserNode.getByteFrequencyData()`. Bar color: the LEFT portion of bars (representing "played" time as a visual metaphor) uses `#00D084` (green primary), the RIGHT portion uses `#003322` (dark green). Actually, looking at the design more carefully: ALL bars are the same color but their HEIGHT represents the frequency amplitude. Use `#00D084` for bars with a subtle gradient to `#006644` at the bottom.
   - When viz is OFF: Show a centered waveform-style placeholder text like `// visualization disabled` in `--color-text-secondary`.
   - Animate at ~30fps using `requestAnimationFrame`. Cancel on unmount or viz toggle off.

3. **Progress bar** (`.audio-progress`):
   - Full-width clickable bar. Background: `var(--color-green-darker)`. Filled portion: `var(--color-green-primary)`. Height: 4px.
   - Left timestamp: current time `MM:SS`. Right timestamp: total duration `MM:SS`. Font: `--font-size-xs`, `--color-text-secondary`.
   - Clicking/dragging on the bar seeks the audio.

4. **Transport controls** (`.audio-controls`):
   - Center row: `|<<` (skip to start), `[PLAY]`/`[PAUSE]` (toggle), `>>|` (skip to end / next track not applicable -- skip forward 10s).
   - Volume: `vol:` label then a horizontal slider (HTML range input styled to match -- green track, green thumb, dark bg). Or render a custom mini progress bar for volume.
   - Toggle: `[viz: on]` / `[viz: off]` button.
   - All bracket-wrapped controls use same button style as PDF zoom buttons.

**Web Audio API setup:**

- Create `AudioContext` and `AnalyserNode` only when dialog opens AND viz is toggled on.
- When the blob URL is available: create `new Audio(objectUrl)` element (NOT an HTML element in DOM -- just JS Audio object). Connect to AudioContext via `createMediaElementSource()`. Connect source -> analyser -> destination.
- IMPORTANT: `createMediaElementSource()` can only be called ONCE per Audio element. Store the source node in a ref.
- AnalyserNode config: `fftSize: 128` (gives 64 frequency bins, we use 48 of them), `smoothingTimeConstant: 0.8`.
- In the animation loop: `analyser.getByteFrequencyData(dataArray)` then draw bars on canvas.
- On close: pause audio, disconnect nodes, close AudioContext if created.

**Audio element state management:**

- Use refs for Audio element, AudioContext, AnalyserNode, MediaElementSourceNode, and animation frame ID.
- Track state: `isPlaying`, `currentTime`, `duration`, `volume` (default 0.7), `vizEnabled` (default true).
- `useEffect` to sync `audio.volume` when volume state changes.
- `timeupdate` event listener on Audio to update currentTime.
- `loadedmetadata` event to set duration.
- `ended` event to set isPlaying to false.

**MIME type mapping:**

```ts
const AUDIO_MIME: Record<string, string> = {
  '.mp3': 'audio/mpeg',
  '.wav': 'audio/wav',
  '.ogg': 'audio/ogg',
  '.m4a': 'audio/mp4',
  '.flac': 'audio/flac',
};
```

Pass the resolved MIME to `useFilePreview`.

**Create `apps/web/src/styles/audio-player-dialog.css`:**

Modal width: `max-width: 600px`.

Audio tag: same green tag pattern as PDF tag.

Viz area: `height: 200px`, `background: #0a0f0d`, `display: flex`, `align-items: flex-end`, `justify-content: center`, `padding: var(--spacing-md)`. Canvas fills the area.

Progress bar wrapper: `padding: var(--spacing-xs) var(--spacing-md)`. Track: `height: 4px`, `background: var(--color-green-darker)`, `cursor: pointer`, `position: relative`. Fill: `background: var(--color-green-primary)`, absolute positioned. Timestamps: flex row, `justify-content: space-between`, `font-size: var(--font-size-xs)`, `color: var(--color-text-secondary)`, `margin-top: 4px`.

Controls row: flex, `justify-content: center`, `align-items: center`, `gap: var(--spacing-md)`, `padding: var(--spacing-sm) var(--spacing-md)`. Transport buttons same style as zoom buttons. Volume slider: styled range input with `accent-color: var(--color-green-primary)` (or use CSS for full custom -- `appearance: none`, track bg `var(--color-green-darker)`, thumb `var(--color-green-primary)`).

Viz toggle: same button style, text changes between `[viz: on]` and `[viz: off]`.
</action>
<verify>
Run `cd /Users/michael/Code/cipher-box && pnpm --filter web build` -- should compile with no TypeScript errors.
Verify AudioPlayerDialog.tsx imports useFilePreview and does NOT use a native `<audio controls>` element (no browser chrome).
Verify Web Audio API AnalyserNode is used for frequency visualization.
Verify all audio state cleanup happens on dialog close.
</verify>
<done>
Audio player dialog renders a fully custom player UI with no native browser audio controls. Frequency spectrum visualization with 48 bars toggleable via [viz: on/off]. Custom progress bar with seek, transport controls (skip/play/pause), volume slider. Loading/error states. Audio context and nodes properly cleaned up on close.
</done>
</task>

<task type="auto">
  <name>Task 3: Video Player Dialog with custom overlay controls</name>
  <files>
    apps/web/src/components/file-browser/VideoPlayerDialog.tsx
    apps/web/src/styles/video-player-dialog.css
  </files>
  <action>
**Create `apps/web/src/components/file-browser/VideoPlayerDialog.tsx`:**

Props: `{ open: boolean; onClose: () => void; item: FileEntry | null }`.

Use `useFilePreview` hook from Task 1 to handle decrypt-to-blob lifecycle.

**Layout (matching design mockup frame 5UU6I):**

Use `<Modal open={open} onClose={onClose} className="video-player-modal">`. Render custom content inside modal-body:

1. **Toolbar row** (`.video-toolbar`):
   - Left: `[VID]` tag (same green tag style), filename.
   - Right: `[download]`.

2. **Video area** (`.video-screen`):
   - Container: `background: #000`, `position: relative`, flex: 1, aspect-ratio preservation.
   - `<video>` element with `src={objectUrl}`, NO `controls` attribute (we use custom controls). Style: `width: 100%`, `max-height: calc(80vh - 200px)`, `display: block`.
   - **Play overlay**: When paused and not at beginning, show a large centered play triangle (CSS-drawn or unicode). When first loaded (before play), show the play triangle. Click anywhere on the video area to toggle play/pause.
   - Resolution info: Small text in bottom-right corner of video area showing resolution (e.g., `1920x1080`) once metadata loads. Use `video.videoWidth` / `video.videoHeight`. Styled: absolute positioned, `font-size: var(--font-size-xs)`, `color: var(--color-text-secondary)`, `background: rgba(0,0,0,0.6)`, `padding: 2px 6px`.

3. **Controls bar** (`.video-controls`):
   - **Progress bar**: Full-width, same pattern as audio player. Clickable to seek. Shows buffered ranges in slightly lighter color.
   - **Control row**:
     - Left group: Play/Pause button (`[>]` / `[||]`), current time / duration (`01:23 / 05:45`).
     - Center: (nothing -- keep it clean).
     - Right group: `vol:` + slider, speed button `[1x]` (cycles through 0.5x, 1x, 1.5x, 2x on click), `[full]` fullscreen button.
   - All bracket-wrapped controls use same button style.

**Video element state management:**

- Use ref for `<video>` element.
- Track state: `isPlaying`, `currentTime`, `duration`, `volume` (default 0.7), `playbackRate` (default 1.0), `videoWidth`/`videoHeight`.
- Event listeners: `timeupdate`, `loadedmetadata`, `ended`, `play`, `pause`.
- `[full]` button: Use `videoContainerRef.current.requestFullscreen()` (the container div, not the video element, so our custom controls show in fullscreen too). Include webkit prefix fallback: `webkitRequestFullscreen`.
- Speed cycle: `[1x]` -> `[1.5x]` -> `[2x]` -> `[0.5x]` -> `[1x]`. Update `video.playbackRate`.
- Auto-hide controls: When playing, start a 3-second idle timer. On mouse move over video area, show controls and reset timer. When timer fires, hide the control bar (fade out). Always show when paused.
- Click on video toggles play/pause. Double-click toggles fullscreen.

**MIME type mapping:**

```ts
const VIDEO_MIME: Record<string, string> = {
  '.mp4': 'video/mp4',
  '.webm': 'video/webm',
  '.mov': 'video/mp4', // browsers handle mov as mp4
  '.mkv': 'video/x-matroska',
};
```

Pass the resolved MIME to `useFilePreview`.

**Create `apps/web/src/styles/video-player-dialog.css`:**

Modal: `max-width: 960px`, `width: 95vw`.

Video tag: same green tag pattern.

Video screen: `position: relative`, `background: #000`, `overflow: hidden`. Video element: `width: 100%`, `display: block`, `max-height: calc(80vh - 200px)`.

Play overlay: `position: absolute`, `inset: 0`, `display: flex`, `align-items: center`, `justify-content: center`, `cursor: pointer`, `background: rgba(0,0,0,0.3)`. Play triangle: CSS border trick or a simple `>` character at `font-size: 48px`, `color: var(--color-green-primary)`. On hover: `background: rgba(0,0,0,0.5)`.

Resolution badge: `position: absolute`, `bottom: 8px`, `right: 8px`, styles as described above.

Controls bar: `padding: var(--spacing-xs) var(--spacing-md)`, `background: rgba(0,0,0,0.8)`. Transition: `opacity 0.3s ease` for auto-hide. When hidden class applied: `opacity: 0`, `pointer-events: none`.

Progress bar: same as audio player pattern.

Control row: flex, `justify-content: space-between`, `align-items: center`, `gap: var(--spacing-sm)`, `margin-top: 4px`.

Volume slider: same as audio player.
</action>
<verify>
Run `cd /Users/michael/Code/cipher-box && pnpm --filter web build` -- should compile with no TypeScript errors.
Verify VideoPlayerDialog.tsx uses `<video>` with NO `controls` attribute.
Verify custom controls include play/pause, seek, volume, speed, and fullscreen.
Verify auto-hide behavior is implemented (3s timeout).
</verify>
<done>
Video player dialog renders a `<video>` element with fully custom overlay controls. No native browser video chrome visible. Custom progress bar with seek, play/pause, volume slider, speed toggle [1x], fullscreen [full]. Play overlay shown when paused. Resolution badge shown. Controls auto-hide after 3s during playback. Clean state management and cleanup on close.
</done>
</task>

<task type="auto">
  <name>Task 4: Integrate all preview dialogs into FileBrowser and ContextMenu</name>
  <files>
    apps/web/src/components/file-browser/FileBrowser.tsx
    apps/web/src/components/file-browser/ContextMenu.tsx
  </files>
  <action>
**4a. Update `FileBrowser.tsx`:**

Add file type detection functions (alongside existing `isTextFile` and `isImageFile`):

```ts
const PDF_EXTENSIONS = new Set(['.pdf']);
const AUDIO_EXTENSIONS = new Set(['.mp3', '.wav', '.ogg', '.m4a', '.flac']);
const VIDEO_EXTENSIONS = new Set(['.mp4', '.webm', '.mov', '.mkv']);

function isPdfFile(name: string): boolean {
  /* same pattern as isImageFile */
}
function isAudioFile(name: string): boolean {
  /* same pattern */
}
function isVideoFile(name: string): boolean {
  /* same pattern */
}
```

Also add a combined `isPreviewableFile(name: string)` that returns true for image, PDF, audio, or video files.

Add imports for the three new dialog components:

```ts
import { PdfPreviewDialog } from './PdfPreviewDialog';
import { AudioPlayerDialog } from './AudioPlayerDialog';
import { VideoPlayerDialog } from './VideoPlayerDialog';
```

Add dialog state for each (same pattern as `imagePreviewDialog`):

```ts
const [pdfPreviewDialog, setPdfPreviewDialog] = useState<DialogState>({ open: false, item: null });
const [audioPlayerDialog, setAudioPlayerDialog] = useState<DialogState>({
  open: false,
  item: null,
});
const [videoPlayerDialog, setVideoPlayerDialog] = useState<DialogState>({
  open: false,
  item: null,
});
```

Add open/close handlers (same pattern as `handlePreviewClick` / `closeImagePreviewDialog`):

```ts
const handlePdfPreviewClick = useCallback(() => {
  if (contextMenu.item) setPdfPreviewDialog({ open: true, item: contextMenu.item });
}, [contextMenu.item]);

// ... similar for audio and video

const closePdfPreviewDialog = useCallback(
  () => setPdfPreviewDialog({ open: false, item: null }),
  []
);
// ... similar for audio and video
```

**Update the `onPreview` logic in the ContextMenu rendering.** Currently `onPreview` is only passed for image files. Change this so `onPreview` is passed for ALL previewable file types (image, PDF, audio, video). The handler should detect the type and open the appropriate dialog:

```ts
const handlePreviewClick = useCallback(() => {
  const item = contextMenu.item;
  if (!item || !isFileEntry(item)) return;
  const name = item.name;
  if (isImageFile(name)) {
    setImagePreviewDialog({ open: true, item });
  } else if (isPdfFile(name)) {
    setPdfPreviewDialog({ open: true, item });
  } else if (isAudioFile(name)) {
    setAudioPlayerDialog({ open: true, item });
  } else if (isVideoFile(name)) {
    setVideoPlayerDialog({ open: true, item });
  }
}, [contextMenu.item]);
```

Update the `onPreview` conditional in the ContextMenu JSX from:

```tsx
onPreview={isFileEntry(contextMenu.item) && isImageFile(contextMenu.item.name) ? handlePreviewClick : undefined}
```

to:

```tsx
onPreview={isFileEntry(contextMenu.item) && isPreviewableFile(contextMenu.item.name) ? handlePreviewClick : undefined}
```

**Add the three new dialog components in the JSX** (after the ImagePreviewDialog):

```tsx
<PdfPreviewDialog
  open={pdfPreviewDialog.open}
  onClose={closePdfPreviewDialog}
  item={pdfPreviewDialog.item && isFileEntry(pdfPreviewDialog.item) ? pdfPreviewDialog.item : null}
/>
<AudioPlayerDialog
  open={audioPlayerDialog.open}
  onClose={closeAudioPlayerDialog}
  item={audioPlayerDialog.item && isFileEntry(audioPlayerDialog.item) ? audioPlayerDialog.item : null}
/>
<VideoPlayerDialog
  open={videoPlayerDialog.open}
  onClose={closeVideoPlayerDialog}
  item={videoPlayerDialog.item && isFileEntry(videoPlayerDialog.item) ? videoPlayerDialog.item : null}
/>
```

**4b. Update `ContextMenu.tsx`:**

The existing `onPreview` prop and "Preview" menu item already exist and are generic enough. No structural changes needed to ContextMenu itself -- it just calls `onPreview` when clicked, and FileBrowser decides what to do. The only change: update the icon for the Preview menu item to be more generic (currently it uses a picture icon `&#128444;` which is image-specific). Change to the eye icon: `&#9673;` (or keep it -- it is a minor visual detail, the label "Preview" is clear enough). Actually, keep `&#128444;` for now -- it is fine as a generic "view" icon.

No code changes needed in ContextMenu.tsx if the existing structure is sufficient. Verify this by reading the file -- the `onPreview` callback is already generic.
</action>
<verify>
Run `cd /Users/michael/Code/cipher-box && pnpm --filter web build` -- should compile with no TypeScript errors.
Verify FileBrowser.tsx imports all three new dialog components.
Verify `isPreviewableFile` covers: .pdf, .mp3, .wav, .ogg, .m4a, .flac, .mp4, .webm, .mov, .mkv, plus existing image extensions.
Verify the context menu "Preview" option appears for PDF, audio, and video files (via the `isPreviewableFile` guard).
Verify each file type opens the correct dialog.
</verify>
<done>
FileBrowser.tsx has file type detection for PDF/audio/video, dialog states for all three, correct routing from the unified handlePreviewClick to the type-specific dialog, and all three dialog components rendered in JSX. Context menu "Preview" option shows for all previewable file types. Build passes with no errors.
</done>
</task>

<task type="checkpoint:human-verify" gate="blocking">
  <name>Task 5: Visual and functional verification</name>
  <what-built>
    Three new file preview dialogs (PDF, Audio, Video) integrated into the CipherBox file browser. All use the terminal/hacker aesthetic with custom controls -- no native browser player chrome for audio or video.
  </what-built>
  <how-to-verify>
    1. Start the dev server: `cd /Users/michael/Code/cipher-box && pnpm --filter web dev`
    2. Open http://localhost:5173 and log in
    3. Upload test files if not present: a PDF, an MP3/WAV, and an MP4/WebM
    4. **PDF test:** Right-click a PDF file -> click "Preview". Verify:
       - Modal opens with [PDF] green tag and filename in header
       - PDF pages render on dark background (#0a0f0d)
       - Scroll through pages works
       - Zoom [-] [+] [fit] controls work
       - Page N/M counter updates as you scroll
       - [<<] [>>] navigate between pages (smooth scroll)
       - [download] triggers file download
       - [x] or Escape closes the modal
    5. **Audio test:** Right-click an audio file -> "Preview". Verify:
       - Modal opens with [AUD] tag and filename
       - Frequency spectrum visualization shows animated green bars when playing
       - [viz: off] hides visualization, [viz: on] shows it again
       - Play/Pause button works
       - Progress bar shows current position, clicking seeks
       - Volume slider works
       - Timestamps show correctly (MM:SS format)
       - No native browser audio player chrome visible anywhere
    6. **Video test:** Right-click a video file -> "Preview". Verify:
       - Modal opens with [VID] tag and filename
       - Video plays with NO native browser controls
       - Custom controls: play/pause, progress seek, volume, speed [1x], fullscreen [full]
       - Play overlay (triangle) shows when paused
       - Controls auto-hide after 3s during playback, reappear on mouse move
       - Resolution badge (e.g. "1920x1080") visible in corner
       - Speed button cycles through 0.5x/1x/1.5x/2x
       - Fullscreen works
    7. Verify all dialogs show "decrypting..." loading state briefly while file is fetched
    8. Verify the terminal aesthetic is consistent: black bg, green accents, monospace font, bracket-wrapped controls
  </how-to-verify>
  <resume-signal>Type "approved" or describe any issues to fix</resume-signal>
</task>

</tasks>

<verification>
- `pnpm --filter web build` passes with zero TypeScript errors
- No native browser audio/video controls visible (no `controls` attribute on media elements)
- All three preview types accessible via right-click context menu "Preview"
- File type routing: PDF -> PdfPreviewDialog, audio -> AudioPlayerDialog, video -> VideoPlayerDialog, images -> ImagePreviewDialog (existing, unchanged)
- Object URLs are revoked on dialog close (no memory leaks)
- Audio context and nodes are cleaned up on close
- PDF document is destroyed on close
- Design system tokens used consistently (no hardcoded colors except where specified: #0a0f0d for canvas backgrounds)
</verification>

<success_criteria>

- PDF files open in a scrollable, zoomable viewer with page navigation
- Audio files play with fully custom UI and toggleable frequency spectrum visualization
- Video files play with fully custom overlay controls including auto-hide, speed, and fullscreen
- All preview dialogs match the terminal/hacker aesthetic
- Loading states shown during file download and decryption
- Download button works in all three dialogs
- No regressions to existing image preview functionality
- Build passes cleanly
  </success_criteria>

<output>
After completion, create `.planning/quick/008-file-preview/008-SUMMARY.md`
</output>

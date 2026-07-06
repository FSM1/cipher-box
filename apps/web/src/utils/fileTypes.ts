import type { SealedChildRef } from '@cipherbox/core';
import type { ResolvedChild } from '@cipherbox/sdk';

/** Extensions recognized as editable text files. */
const TEXT_EXTENSIONS = new Set([
  '.txt',
  '.md',
  '.json',
  '.yaml',
  '.yml',
  '.toml',
  '.xml',
  '.csv',
  '.log',
  '.env',
  '.sh',
  '.bash',
  '.zsh',
  '.fish',
  '.ps1',
  '.bat',
  '.cmd',
  '.ini',
  '.cfg',
  '.conf',
  '.html',
  '.htm',
  '.css',
  '.scss',
  '.less',
  '.js',
  '.mjs',
  '.cjs',
  '.ts',
  '.mts',
  '.cts',
  '.jsx',
  '.tsx',
  '.py',
  '.rb',
  '.rs',
  '.go',
  '.java',
  '.c',
  '.cpp',
  '.h',
  '.hpp',
  '.sql',
  '.graphql',
  '.gitignore',
  '.editorconfig',
]);

/** Well-known extensionless text filenames. */
const TEXT_FILENAMES = new Set([
  'dockerfile',
  'makefile',
  'rakefile',
  'gemfile',
  'procfile',
  'vagrantfile',
]);

/** Extensions recognized as previewable image files. */
const IMAGE_EXTENSIONS = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.webp',
  '.svg',
  '.bmp',
  '.ico',
  '.avif',
]);

/** Extensions recognized as PDF files. */
const PDF_EXTENSIONS = new Set(['.pdf']);

/** Extensions recognized as playable audio files. */
const AUDIO_EXTENSIONS = new Set(['.mp3', '.wav', '.ogg', '.m4a', '.flac']);

/** Extensions recognized as playable video files. */
const VIDEO_EXTENSIONS = new Set(['.mp4', '.webm', '.mov', '.mkv']);

function getExtension(name: string): string | null {
  const lower = name.toLowerCase();
  const lastDot = lower.lastIndexOf('.');
  if (lastDot === -1) return null;
  return lower.slice(lastDot);
}

/** Check if a filename has a text-editable extension. */
export function isTextFile(name: string): boolean {
  const lower = name.toLowerCase();
  if (TEXT_EXTENSIONS.has(lower)) return true;
  if (TEXT_FILENAMES.has(lower)) return true;
  const ext = getExtension(name);
  return ext !== null && TEXT_EXTENSIONS.has(ext);
}

/** Check if a filename has a previewable image extension. */
export function isImageFile(name: string): boolean {
  const ext = getExtension(name);
  return ext !== null && IMAGE_EXTENSIONS.has(ext);
}

/** Check if a filename has a PDF extension. */
export function isPdfFile(name: string): boolean {
  const ext = getExtension(name);
  return ext !== null && PDF_EXTENSIONS.has(ext);
}

/** Check if a filename has a playable audio extension. */
export function isAudioFile(name: string): boolean {
  const ext = getExtension(name);
  return ext !== null && AUDIO_EXTENSIONS.has(ext);
}

/** Check if a filename has a playable video extension. */
export function isVideoFile(name: string): boolean {
  const ext = getExtension(name);
  return ext !== null && VIDEO_EXTENSIONS.has(ext);
}

/** Check if a filename is any previewable type (image, PDF, audio, video). */
export function isPreviewableFile(name: string): boolean {
  return isImageFile(name) || isPdfFile(name) || isAudioFile(name) || isVideoFile(name);
}

/**
 * Type guard: is this child a "file-kind" ref?
 *
 * Accepts EITHER shape (D-02):
 * - `ResolvedChild` (the SDK-resolved listing, SDK-READ-02) carries `kind`
 *   pre-resolved -- read it directly, no cache/resolve needed. This is the
 *   target shape every render site converges on.
 * - `SealedChildRef` (the legacy per-child ref, still the identity/crypto
 *   carrier for call sites that only have identity -- e.g. context-menu/
 *   download/drag payloads that need `readKeySealed`/`generation` -- and no
 *   paired `ResolvedChild` lookup available at that call site) defaults to
 *   `false` (folder-safe). 68.2-11 removed the per-ipnsName kind-cache
 *   (kind-cache.ts) this branch used to fall back to: `resolveKinds` was
 *   never wired into any render path, so the cache was permanently empty in
 *   practice -- this default preserves that exact always-miss behavior.
 *
 * Synchronous by design (called in render-time list mapping across many
 * components).
 */
export function isFileRef(item: SealedChildRef | ResolvedChild): boolean {
  if ('kind' in item) return item.kind === 'file';
  return false;
}

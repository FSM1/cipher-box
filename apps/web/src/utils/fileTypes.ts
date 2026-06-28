import type { SealedChildRef } from '@cipherbox/core';

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
 * Type guard: narrows SealedChildRef to a "file-kind" ref by checking ipnsName presence.
 * In node/v3 all children are SealedChildRef — kind discrimination requires reading
 * the child Node itself (phase 63).
 * @stub phase 63 — file vs folder discrimination via Node.kind
 */
export function isFileRef(_item: SealedChildRef): boolean {
  throw new Error('not implemented — phase 63 (file/folder kind discrimination via Node.kind)');
}

/**
 * Alias for isFileRef — kept as isFilePointer for component-layer compile compatibility.
 * @stub phase 63 — file vs folder discrimination via Node.kind
 */
export function isFilePointer(_item: SealedChildRef): boolean {
  throw new Error('not implemented — phase 63 (file/folder kind discrimination via Node.kind)');
}

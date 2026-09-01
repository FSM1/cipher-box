/**
 * A member-authored name, made safe to read in the sentence a member acts on.
 * A name can arrive from another vault through a shared folder, so a bidi
 * override in one reorders the confirmation that names it, and a line break or
 * a very long run pushes the confirm control out of view.
 *
 * Display only: the engine keeps the stored bytes, and every command still
 * addresses a node by id.
 */

/** Longest name a listing or a dialog shows, in code points. */
const MAX_NAME_POINTS = 96;

const ELLIPSIS = '\u2026';

/**
 * Every control character, the format characters that render as nothing, the
 * bidi marks, embeddings, overrides and isolates, and the two separators that
 * render as a line break. A zero-width joiner stays: it carries meaning inside
 * an emoji and inside a name.
 */
const NEUTRALISED =
  /[\p{Cc}\u00AD\u061C\u200B\u200E\u200F\u202A-\u202E\u2028\u2029\u2060\u2066-\u2069\uFEFF]/gu;

export function displayName(name: string): string {
  const stripped = name.replace(NEUTRALISED, '');
  // A UTF-16 length never reads under the code-point count, so a name the
  // clamp cannot reach settles here rather than through a split.
  if (stripped.length <= MAX_NAME_POINTS) return stripped;
  const points = Array.from(stripped);
  if (points.length <= MAX_NAME_POINTS) return stripped;
  return points.slice(0, MAX_NAME_POINTS).join('') + ELLIPSIS;
}

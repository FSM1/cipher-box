/**
 * A member-authored name, held to the length a sentence a member acts on can
 * carry. A very long run pushes the confirm control out of view.
 *
 * Layout only. Which characters a name may hold is the engine's law, applied
 * before a name reaches this realm (`crates/engine/src/name.rs`): the browser
 * keeps no rule of its own, or the two sets drift with nothing to report it.
 */

/** Code points kept off a name. A clamped name shows one more: the ellipsis. */
const LONGEST_KEPT_POINTS = 96;

const ELLIPSIS = '…';

export function displayName(name: string): string {
  // A UTF-16 length never reads under the code-point count, so a name the
  // clamp cannot reach settles here rather than through a split.
  if (name.length <= LONGEST_KEPT_POINTS) return name;
  const points = Array.from(name);
  if (points.length <= LONGEST_KEPT_POINTS) return name;
  return points.slice(0, LONGEST_KEPT_POINTS).join('') + ELLIPSIS;
}

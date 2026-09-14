import { describe, expect, it } from 'vitest';
import { displayName } from './displayName';

/** The clamp the helper holds a name to, in code points. */
const LONGEST_KEPT = 96;

describe('a member-authored name shown in a sentence', () => {
  it('keeps an ordinary name exactly as it is stored', () => {
    expect(displayName('quarterly report.pdf')).toBe('quarterly report.pdf');
  });

  it('keeps text outside latin, and characters above the basic plane', () => {
    expect(displayName('ملف 📄')).toBe('ملف 📄');
  });

  it('keeps a joiner, which carries meaning inside an emoji and inside a name', () => {
    expect(displayName('crew \u{1F468}‍\u{1F4BB}')).toBe('crew \u{1F468}‍\u{1F4BB}');
  });

  // The engine neutralises a deceptive name before it reaches this realm, so a
  // second rule here would only be a second set to keep in step.
  it('holds no rule of its own about which characters a name may carry', () => {
    expect(displayName('report‮fdp.exe')).toBe('report‮fdp.exe');
  });

  it('keeps a name at the clamp whole, and marks a longer one as truncated', () => {
    const atClamp = 'a'.repeat(LONGEST_KEPT);

    expect(displayName(atClamp)).toBe(atClamp);
    expect(displayName(atClamp + 'b')).toBe(atClamp + '…');
  });

  it('clamps by code point, so a character above the basic plane is never split', () => {
    const clamped = displayName('📄'.repeat(LONGEST_KEPT + 1));

    expect(clamped).toBe('📄'.repeat(LONGEST_KEPT) + '…');
    expect([...clamped]).toHaveLength(LONGEST_KEPT + 1);
  });
});

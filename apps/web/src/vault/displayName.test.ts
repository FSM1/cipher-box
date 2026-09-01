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

  it('strips a right-to-left override, so the name reads in stored order', () => {
    expect(displayName('report\u202Efdp.exe\u202C')).toBe('reportfdp.exe');
  });

  it('strips the bidi isolates and the arabic letter mark', () => {
    expect(displayName('\u2066notes\u2069\u061C.txt')).toBe('notes.txt');
  });

  it('strips a line break, so a name cannot push a control out of view', () => {
    expect(displayName('notes\n\r\u2028.txt')).toBe('notes.txt');
  });

  it('strips a C0 control the terminal would act on', () => {
    expect(displayName('notes\u0000.txt')).toBe('notes.txt');
  });

  it('strips the format characters that pad a name invisibly', () => {
    expect(displayName('\uFEFF\u00ADnotes\u200B\u2060.txt')).toBe('notes.txt');
  });

  it('keeps a joiner, which carries meaning inside an emoji and inside a name', () => {
    expect(displayName('crew \u{1F468}\u200D\u{1F4BB}')).toBe('crew \u{1F468}\u200D\u{1F4BB}');
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

  it('counts what it strips against no part of the clamp', () => {
    expect(displayName('\u202E'.repeat(200) + 'notes.txt')).toBe('notes.txt');
  });
});

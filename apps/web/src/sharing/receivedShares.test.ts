import { describe, expect, it } from 'vitest';
import { shareName } from './receivedShares';

describe('the name a received share shows', () => {
  it('names a link-held share whose names did not verify as shared via link', () => {
    expect(shareName({ displayName: '', viaLink: true })).toBe('shared via link');
  });

  it('shows the verified name of a link-held share', () => {
    expect(shareName({ displayName: 'Docs', viaLink: true })).toBe('Docs');
  });

  it('keeps the label off a personal share', () => {
    expect(shareName({ displayName: '', viaLink: false })).toBe('');
  });

  it('clamps a long name as every other name is clamped', () => {
    const shown = shareName({ displayName: 'a'.repeat(200), viaLink: true });

    expect(shown.endsWith('…')).toBe(true);
    expect(Array.from(shown)).toHaveLength(97);
  });
});

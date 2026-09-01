import { describe, expect, it } from 'vitest';
import { isLoginSecret } from './scenario';
import { namesOf, nodeOf, type Listing } from '../../web-e2e/vault';

const listing: Listing = {
  children: [
    { id: 'aa', name: 'granted', kind: 'folder' },
    { id: 'bb', name: 'notes.txt', kind: 'file' },
  ],
};

describe('isLoginSecret', () => {
  it('takes the shape the desktop entry and the web tap both take', () => {
    expect(isLoginSecret('a'.repeat(64))).toBe(true);
  });

  it('refuses a length no 32-byte secret has', () => {
    expect(isLoginSecret('a'.repeat(63))).toBe(false);
    expect(isLoginSecret('a'.repeat(65))).toBe(false);
  });

  it('refuses uppercase hex, which the desktop entry rejects', () => {
    expect(isLoginSecret('A'.repeat(64))).toBe(false);
  });

  it('refuses a character that is not hex', () => {
    expect(isLoginSecret(`${'a'.repeat(63)}g`)).toBe(false);
  });
});

describe('nodeOf', () => {
  it('gives the node id of the named child', () => {
    expect(nodeOf(listing, 'granted')).toBe('aa');
  });

  it('names what the listing does carry when the name is absent', () => {
    expect(() => nodeOf(listing, 'absent')).toThrow(/granted, notes.txt/);
  });

  it('refuses a name two children carry', () => {
    const twice: Listing = {
      children: [...listing.children, { id: 'cc', name: 'granted', kind: 'folder' }],
    };
    expect(() => nodeOf(twice, 'granted')).toThrow(/2 children named granted/);
  });
});

describe('namesOf', () => {
  it('sorts, so a listing compares against a mount listing', () => {
    expect(namesOf({ children: [...listing.children].reverse() })).toEqual([
      'granted',
      'notes.txt',
    ]);
  });
});

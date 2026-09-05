import { describe, expect, it } from 'vitest';
import {
  isRecoveryPhraseWellFormed,
  normalizeRecoveryPhrase,
  RECOVERY_PHRASE_WORDS,
} from './phrase';

/** Not a phrase any account holds: the shape is what these rules read. */
const WORDS = Array.from({ length: RECOVERY_PHRASE_WORDS }, (_, index) => `word${String(index)}`);

describe('a typed recovery phrase', () => {
  it('reads the same however a member spaced and cased it', () => {
    const typed = `\n  ${WORDS.join('   ').toUpperCase()} \t`;

    expect(normalizeRecoveryPhrase(typed)).toBe(WORDS.join(' '));
  });

  it('carries the word count the Core Kit serializer emits', () => {
    expect(isRecoveryPhraseWellFormed(WORDS.join(' '))).toBe(true);
  });

  it('refuses a phrase with a word too many or too few', () => {
    expect(isRecoveryPhraseWellFormed([...WORDS, 'spare'].join(' '))).toBe(false);
    expect(isRecoveryPhraseWellFormed(WORDS.slice(1).join(' '))).toBe(false);
  });

  /** An empty field is a count of nothing, never a phrase to redeem. */
  it('refuses a field nobody typed in', () => {
    expect(isRecoveryPhraseWellFormed(normalizeRecoveryPhrase('   '))).toBe(false);
  });
});

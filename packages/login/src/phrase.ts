/**
 * The recovery phrase as both hosts read it. A field that counted words one way
 * and a redemption that normalized them another would refuse a phrase the
 * account holds (ADR 0009 D2).
 */

/** What the Core Kit's own serializer emits, and so what a field must collect. */
export const RECOVERY_PHRASE_WORDS = 24;

/** The one reading of a typed phrase, so a field and the redemption agree. */
export function normalizeRecoveryPhrase(typed: string): string {
  return typed.trim().toLowerCase().replace(/\s+/g, ' ');
}

/** Whether a normalized phrase carries the word count a redemption needs. */
export function isRecoveryPhraseWellFormed(normalized: string): boolean {
  return normalized.split(' ').filter(Boolean).length === RECOVERY_PHRASE_WORDS;
}

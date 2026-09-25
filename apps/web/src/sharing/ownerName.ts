/**
 * The name an owner types for the links they mint, which the fragment shows
 * the holder under the owner signature (ADR 0027 D5). A label the owner
 * chooses, never the sign-in email; empty is allowed.
 *
 * Kept per tab so the next mint pre-fills it. Session storage goes with the
 * tab, and sign-out clears it, so a later account on this browser does not
 * inherit it.
 */

const OWNER_NAME_KEY = 'cipherbox.share.ownerName';

export function storedOwnerName(): string {
  try {
    return sessionStorage.getItem(OWNER_NAME_KEY) ?? '';
  } catch {
    return '';
  }
}

export function storeOwnerName(name: string): void {
  try {
    if (name === '') sessionStorage.removeItem(OWNER_NAME_KEY);
    else sessionStorage.setItem(OWNER_NAME_KEY, name);
  } catch {
    // A browser that refuses storage still mints under the name typed now.
  }
}

export function forgetOwnerName(): void {
  storeOwnerName('');
}

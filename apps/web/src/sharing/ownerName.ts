/**
 * The name an owner types for the links they mint, which the fragment shows
 * the holder under the owner signature (ADR 0027 D5). A label the owner
 * chooses, never the sign-in email; empty is allowed.
 *
 * Kept on this device so the next mint pre-fills it, and forgotten when the
 * session ends so a later account on this browser does not inherit it.
 */

const OWNER_NAME_KEY = 'cipherbox.share.ownerName';

export function storedOwnerName(): string {
  try {
    return localStorage.getItem(OWNER_NAME_KEY) ?? '';
  } catch {
    return '';
  }
}

export function storeOwnerName(name: string): void {
  try {
    if (name === '') localStorage.removeItem(OWNER_NAME_KEY);
    else localStorage.setItem(OWNER_NAME_KEY, name);
  } catch {
    // A browser that refuses storage still mints under the name typed now.
  }
}

export function forgetOwnerName(): void {
  storeOwnerName('');
}

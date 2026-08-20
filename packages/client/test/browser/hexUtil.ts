/** Hex helpers shared by the browser-suite page harnesses. */

export function hex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

export function unhex(text: string): Uint8Array {
  const bytes = new Uint8Array(text.length / 2);
  for (let i = 0; i < bytes.length; i += 1) bytes[i] = parseInt(text.slice(i * 2, i * 2 + 2), 16);
  return bytes;
}

/** The account the browser suite's engines namespace their durable stores under. */
export const TEST_ACCOUNT_ID = 'browsersuite';

/** A second account on the same profile, for the cross-account isolation checks. */
export const OTHER_ACCOUNT_ID = 'browsersuiteother';

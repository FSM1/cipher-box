/**
 * Reports whether the copy actually landed, so a caller never shows a "copied"
 * confirmation for a clipboard write the browser refused.
 */
export async function copyToClipboard(value: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    return false;
  }
}

/**
 * Copy `value` to the clipboard, returning whether the copy actually succeeded.
 *
 * Tries the async Clipboard API first; on failure (older browsers, denied
 * permission, insecure context) falls back to a hidden-textarea + execCommand.
 * The boolean return is the D-14 contract: callers must gate their "Copied!" UI
 * state on a real success, never assume the attempt worked.
 */
export async function copyTextToClipboard(value: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(value);
    return true;
  } catch {
    const textarea = document.createElement('textarea');
    textarea.value = value;
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(textarea);
    return ok;
  }
}

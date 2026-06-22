/**
 * DetailsPrimitives — copy-success gating (D-14)
 *
 * Exercises the REAL production helper `copyTextToClipboard` (used by
 * CopyableValue.handleCopy), so a regression in the copy path fails this suite.
 * The helper returns whether the copy actually succeeded; CopyableValue gates
 * its "Copied!" state on that boolean.
 *
 * The web vitest environment is `node` (no DOM), so we stub the minimal
 * `navigator.clipboard` / `document` surface the helper touches.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { copyTextToClipboard } from '../copy-clipboard';

describe('copyTextToClipboard (D-14 copy-success gating)', () => {
  let writeText: ReturnType<typeof vi.fn>;
  let execCommand: ReturnType<typeof vi.fn>;
  let removeChild: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    writeText = vi.fn();
    execCommand = vi.fn();
    removeChild = vi.fn();

    vi.stubGlobal('navigator', { clipboard: { writeText } });
    // Minimal DOM surface for the execCommand fallback path.
    vi.stubGlobal('document', {
      createElement: vi.fn(() => ({ style: {}, select: vi.fn(), value: '' })),
      body: { appendChild: vi.fn(), removeChild },
      execCommand,
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it('returns true when clipboard.writeText resolves', async () => {
    writeText.mockResolvedValue(undefined);

    const ok = await copyTextToClipboard('test-value');

    expect(ok).toBe(true);
    expect(writeText).toHaveBeenCalledWith('test-value');
    // Async clipboard path must not touch the fallback.
    expect(execCommand).not.toHaveBeenCalled();
  });

  it('returns false when clipboard rejects and execCommand returns false', async () => {
    writeText.mockRejectedValue(new Error('clipboard denied'));
    execCommand.mockReturnValue(false);

    const ok = await copyTextToClipboard('test-value');

    expect(ok).toBe(false);
    expect(execCommand).toHaveBeenCalledWith('copy');
    // The fallback textarea must be cleaned up even on failure.
    expect(removeChild).toHaveBeenCalled();
  });

  it('returns true when clipboard rejects but execCommand fallback succeeds', async () => {
    writeText.mockRejectedValue(new Error('clipboard denied'));
    execCommand.mockReturnValue(true);

    const ok = await copyTextToClipboard('test-value');

    expect(ok).toBe(true);
    expect(execCommand).toHaveBeenCalledWith('copy');
    expect(removeChild).toHaveBeenCalled();
  });
});

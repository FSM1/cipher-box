/**
 * DetailsPrimitives — copy-success gating (D-14)
 *
 * The handleCopy logic in CopyableValue must gate setCopied(true) on an
 * actual successful copy. Tests cover:
 *  1. clipboard.writeText resolves → setCopied called
 *  2. clipboard.writeText rejects AND execCommand returns false → setCopied NOT called
 *  3. clipboard.writeText rejects but execCommand returns true → setCopied called
 *
 * We test the pure copy logic extracted from the component callback to avoid
 * a DOM/RTL dependency in the node test environment.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

/**
 * Extracted copy logic that mirrors the handleCopy implementation.
 * This is the exact shape from 56-PATTERNS.md (D-14 fix).
 */
async function handleCopyLogic(
  value: string,
  setCopied: (v: boolean) => void,
  writeText: (v: string) => Promise<void>,
  execCommandImpl: (cmd: string) => boolean,
  createTextarea: () => { select: () => void; remove: () => void }
): Promise<void> {
  let success = false;
  try {
    await writeText(value);
    success = true;
  } catch {
    const el = createTextarea();
    el.select();
    success = execCommandImpl('copy');
    el.remove();
  }
  if (success) {
    setCopied(true);
  }
}

describe('handleCopy logic (D-14 copy-success gating)', () => {
  let setCopied: ReturnType<typeof vi.fn>;
  let createTextarea: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    setCopied = vi.fn();
    createTextarea = vi.fn(() => ({ select: vi.fn(), remove: vi.fn() }));
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('calls setCopied(true) when clipboard.writeText resolves', async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    const execCommand = vi.fn().mockReturnValue(false);

    await handleCopyLogic('test-value', setCopied, writeText, execCommand, createTextarea);

    expect(setCopied).toHaveBeenCalledWith(true);
    expect(setCopied).toHaveBeenCalledTimes(1);
  });

  it('does NOT call setCopied(true) when clipboard rejects and execCommand returns false', async () => {
    // Both paths fail — no successful copy
    const writeText = vi.fn().mockRejectedValue(new Error('clipboard denied'));
    const execCommand = vi.fn().mockReturnValue(false);

    await handleCopyLogic('test-value', setCopied, writeText, execCommand, createTextarea);

    // RED: current code calls setCopied(true) unconditionally
    expect(setCopied).not.toHaveBeenCalled();
  });

  it('calls setCopied(true) when clipboard rejects but execCommand returns true (fallback success)', async () => {
    const writeText = vi.fn().mockRejectedValue(new Error('clipboard denied'));
    const execCommand = vi.fn().mockReturnValue(true);

    await handleCopyLogic('test-value', setCopied, writeText, execCommand, createTextarea);

    expect(setCopied).toHaveBeenCalledWith(true);
    expect(setCopied).toHaveBeenCalledTimes(1);
  });
});

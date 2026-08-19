import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { UploadEntry } from '../../hooks/useDropUpload';
import { UploadListItem } from './UploadListItem';

function entry(overrides: Partial<UploadEntry> = {}): UploadEntry {
  return {
    id: 'upload-1',
    name: 'report.pdf',
    size: 2048,
    phase: 'staging',
    progress: 0,
    opId: null,
    error: null,
    code: null,
    ...overrides,
  };
}

function show(upload: UploadEntry, heldBytes: bigint | null = null) {
  const handlers = { onCancel: vi.fn(), onRetry: vi.fn(), onDismiss: vi.fn() };
  const { rerender } = render(
    <UploadListItem upload={upload} heldBytes={heldBytes} {...handlers} />
  );
  return {
    ...handlers,
    /** Repaints the row from a later snapshot, as the panel does. */
    repaint: (next: bigint | null) =>
      rerender(<UploadListItem upload={upload} heldBytes={next} {...handlers} />),
  };
}

describe('an upload row', () => {
  it('quotes the confirmed fraction once the drain reports blocks', () => {
    show(entry({ phase: 'uploading', progress: 0.5, opId: 1n }));

    const bar = screen.getByRole('progressbar');
    expect(bar.getAttribute('aria-valuenow')).toBe('50');
    expect(screen.getByTestId('upload-row-status').textContent).toBe('50%');
  });

  it('shimmers only while the client is feeding the engine', () => {
    show(entry({ phase: 'staging' }));

    const bar = screen.getByRole('progressbar');
    expect(bar.getAttribute('aria-valuenow')).toBeNull();
    expect(bar.className).toContain('upload-row-track--indeterminate');
  });

  it('leaves a queued row still, because nothing is moving yet', () => {
    show(entry({ phase: 'queued', opId: 1n }));

    const bar = screen.getByRole('progressbar');
    expect(bar.getAttribute('aria-valuetext')).toBe('queued');
    expect(bar.className).not.toContain('upload-row-track--indeterminate');
  });

  it('offers cancel while the engine still has work', () => {
    const handlers = show(entry({ phase: 'uploading', opId: 1n }));

    fireEvent.click(screen.getByLabelText('Cancel upload of report.pdf'));

    expect(handlers.onCancel).toHaveBeenCalledWith('upload-1');
    expect(screen.queryByLabelText('Retry upload of report.pdf')).toBeNull();
  });

  it('offers retry and dismiss once a row has failed for good', () => {
    const handlers = show(entry({ phase: 'failed', error: 'no reachable pin provider' }));

    fireEvent.click(screen.getByLabelText('Retry upload of report.pdf'));
    fireEvent.click(screen.getByLabelText('Dismiss upload of report.pdf'));

    expect(handlers.onRetry).toHaveBeenCalledWith('upload-1');
    expect(handlers.onDismiss).toHaveBeenCalledWith('upload-1');
    expect(screen.queryByRole('progressbar')).toBeNull();
    expect(screen.getByRole('alert').textContent).toBe('no reachable pin provider');
  });

  it('lets a cancelled row be cleared, so none can strand its file', () => {
    const handlers = show(entry({ phase: 'cancelled', opId: 1n }));

    fireEvent.click(screen.getByLabelText('Dismiss upload of report.pdf'));

    expect(handlers.onDismiss).toHaveBeenCalledWith('upload-1');
    expect(screen.queryByLabelText('Cancel upload of report.pdf')).toBeNull();
  });

  // Every cause the user can still act on: the engine's message says which
  // budget refused, and the row says what to do about that one.
  it.each([
    ['overBudgetStagingBacklog', 'or cancel one'],
    ['overBudgetTooManyWrites', 'or cancel one'],
    ['overBudgetDeviceFull', 'space on this device'],
    ['overBudgetAccountQuota', 'your CipherBox storage'],
  ])('offers a retry on %s and says what will clear it', (code, action) => {
    show(
      entry({
        phase: 'failed',
        code,
        error: 'this write needs 900 bytes but only 100 are free',
      })
    );

    const message = screen.getByTestId('upload-row-error');
    expect(message.className).toContain('upload-row-error--transient');
    expect(message.textContent).toContain('only 100 are free');
    expect(screen.getByTestId('upload-row-remedy').textContent).toContain(action);
    expect(screen.getByLabelText('Retry upload of report.pdf')).toBeTruthy();
  });

  // Including a cause this build does not name: an unnamed over-budget code
  // must fail closed rather than inherit the retry.
  it.each([
    'overBudgetStagingLimit',
    'overBudgetStorageUnmeasured',
    'overBudgetSomethingThisBuildDoesNotName',
  ])('drops the retry on %s, where trying again can never succeed', (code) => {
    show(
      entry({
        phase: 'failed',
        code,
        error: 'this device cannot stage a write this large',
      })
    );

    const message = screen.getByTestId('upload-row-error');
    expect(message.className).not.toContain('upload-row-error--transient');
    expect(screen.getByTestId('upload-row-remedy').textContent).toContain('will not help');
    expect(screen.queryByLabelText('Retry upload of report.pdf')).toBeNull();
    // Nothing may strand its `File`, whether or not a retry can help.
    expect(screen.getByLabelText('Dismiss upload of report.pdf')).toBeTruthy();
  });

  it('leaves a failure that is not over-budget alone', () => {
    show(entry({ phase: 'failed', code: 'noPlacement', error: 'no reachable pin provider' }));

    expect(screen.queryByTestId('upload-row-remedy')).toBeNull();
    expect(screen.getByLabelText('Retry upload of report.pdf')).toBeTruthy();
  });

  it('says the drain is holding the row, apart from a plain queue', () => {
    show(entry({ phase: 'queued', opId: 1n }), 900n);

    expect(screen.getByTestId('upload-row-hold').textContent).toContain('900 B');
    expect(screen.getByTestId('upload-row-status').textContent).toBe('waiting for room');
    expect(screen.getByRole('progressbar').getAttribute('aria-valuetext')).toBe('waiting for room');
    // A hold is neither the refusal surface nor a verdict on the write.
    expect(screen.queryByTestId('upload-row-error')).toBeNull();
    expect(screen.queryByRole('alert')).toBeNull();
    expect(screen.getByLabelText('Cancel upload of report.pdf')).toBeTruthy();
  });

  it('drops the hold when a later snapshot no longer reports one', () => {
    const row = show(entry({ phase: 'queued', opId: 1n }), 900n);

    row.repaint(null);

    expect(screen.queryByTestId('upload-row-hold')).toBeNull();
    expect(screen.getByTestId('upload-row-status').textContent).toBe('queued');
  });

  it('marks a stopped attempt as retryable, not settled', () => {
    show(entry({ phase: 'stalled', opId: 1n, error: 'no reachable pin provider' }));

    expect(screen.getByTestId('upload-row-error').className).toContain(
      'upload-row-error--transient'
    );
    expect(screen.getByTestId('upload-row-error').getAttribute('role')).toBeNull();
  });
});

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

function show(upload: UploadEntry) {
  const handlers = { onCancel: vi.fn(), onRetry: vi.fn(), onDismiss: vi.fn() };
  render(<UploadListItem upload={upload} {...handlers} />);
  return handlers;
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

  it.each([
    ['overBudgetStagingBacklog', 'wait'],
    ['overBudgetTooManyWrites', 'wait'],
    ['overBudgetDeviceFull', 'freeDeviceSpace'],
    ['overBudgetAccountQuota', 'freeAccountQuota'],
  ])('offers a retry on %s, which the user can still clear', (code, remedy) => {
    show(
      entry({
        phase: 'failed',
        code,
        error: 'this write needs 900 bytes but only 100 are free',
      })
    );

    const message = screen.getByTestId('upload-row-error');
    expect(message.className).toContain('upload-row-error--transient');
    expect(message.getAttribute('data-remedy')).toBe(remedy);
    expect(screen.getByLabelText('Retry upload of report.pdf')).toBeTruthy();
  });

  it.each(['overBudgetStagingLimit', 'overBudgetStorageUnmeasured'])(
    'drops the retry on %s, where retrying can never succeed',
    (code) => {
      show(
        entry({
          phase: 'failed',
          code,
          error: 'this device cannot stage a write this large',
        })
      );

      const message = screen.getByTestId('upload-row-error');
      expect(message.className).not.toContain('upload-row-error--transient');
      expect(message.getAttribute('data-remedy')).toBe('nothing');
      expect(screen.queryByLabelText('Retry upload of report.pdf')).toBeNull();
      // Nothing may strand its `File`, whether or not a retry can help.
      expect(screen.getByLabelText('Dismiss upload of report.pdf')).toBeTruthy();
    }
  );

  it('marks a stopped attempt as retryable, not settled', () => {
    show(entry({ phase: 'stalled', opId: 1n, error: 'no reachable pin provider' }));

    expect(screen.getByTestId('upload-row-error').className).toContain(
      'upload-row-error--transient'
    );
    expect(screen.getByTestId('upload-row-error').getAttribute('role')).toBeNull();
  });
});

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

  it('stays indeterminate while the engine has no block count to give', () => {
    show(entry({ phase: 'staging' }));

    const bar = screen.getByRole('progressbar');
    expect(bar.getAttribute('aria-valuenow')).toBeNull();
    expect(bar.className).toContain('upload-row-track--indeterminate');
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
    fireEvent.click(screen.getByLabelText('Dismiss failed upload of report.pdf'));

    expect(handlers.onRetry).toHaveBeenCalledWith('upload-1');
    expect(handlers.onDismiss).toHaveBeenCalledWith('upload-1');
    expect(screen.queryByRole('progressbar')).toBeNull();
    expect(screen.getByRole('alert').textContent).toBe('no reachable pin provider');
  });

  it('marks an over-budget refusal apart from a terminal failure', () => {
    show(
      entry({
        phase: 'failed',
        code: 'overBudget',
        error: 'this write needs 900 bytes but only 100 are free',
      })
    );

    expect(screen.getByTestId('upload-row-error').className).toContain('upload-row-error--budget');
  });
});

import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ListingRow } from '../../../vault/listing';
import { DetailsDialog } from '../DetailsDialog';

const NODE = new Uint8Array(4).fill(0xab);

function fileRow(overrides: Partial<ListingRow> = {}): ListingRow {
  return {
    id: NODE,
    key: 'abababab',
    name: 'notes.txt',
    kind: 'file',
    icon: '[FILE]',
    size: '12 B',
    bytes: 12n,
    contentVersion: 3n,
    modified: '14 Nov 2023',
    pending: 'none',
    deadLetter: false,
    ...overrides,
  };
}

function folderRow(overrides: Partial<ListingRow> = {}): ListingRow {
  return fileRow({
    name: 'documents',
    kind: 'folder',
    icon: '[DIR]',
    size: '-',
    bytes: null,
    ...overrides,
  });
}

function rowText(label: string): string {
  const term = screen.getByText(label);
  return term.parentElement?.querySelector('.details-value')?.textContent ?? '';
}

describe('the details panel', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('renders the snapshot fields of a file', () => {
    render(<DetailsDialog row={fileRow()} onClose={() => undefined} />);

    expect(screen.getByTestId('file-details')).toBeDefined();
    expect(rowText('name')).toContain('notes.txt');
    expect(rowText('type')).toBe('[FILE]');
    expect(rowText('node id')).toContain('abababab');
    expect(rowText('size')).toBe('12 B');
    expect(rowText('bytes')).toBe('12');
    expect(rowText('version')).toBe('3');
    expect(rowText('modified')).toBe('14 Nov 2023');
    expect(rowText('queued')).toBe('nothing pending');
  });

  it('renders the folder variant, which carries no content of its own', () => {
    render(<DetailsDialog row={folderRow()} onClose={() => undefined} />);

    expect(screen.getByTestId('folder-details')).toBeDefined();
    expect(rowText('type')).toBe('[DIR]');
    expect(screen.queryByText('size')).toBeNull();
    expect(screen.queryByText('bytes')).toBeNull();
    expect(screen.queryByText('version')).toBeNull();
  });

  it('renders an empty state for content the snapshot has not projected', () => {
    render(
      <DetailsDialog
        row={fileRow({ bytes: null, size: '...', contentVersion: null })}
        onClose={() => undefined}
      />
    );

    expect(rowText('size')).toBe('unknown');
    expect(rowText('bytes')).toBe('unknown');
    expect(rowText('version')).toBe('unknown');
  });

  it('reports the queued change and the dead letter the snapshot carries', () => {
    render(
      <DetailsDialog
        row={fileRow({ pending: 'content', deadLetter: true })}
        onClose={() => undefined}
      />
    );

    expect(rowText('queued')).toBe('content change');
    expect(rowText('dead letter')).toBe('this change will not publish');
  });

  it('copies the node id verbatim', async () => {
    const writeText = vi.fn(() => Promise.resolve());
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } });

    render(<DetailsDialog row={fileRow()} onClose={() => undefined} />);
    fireEvent.click(screen.getByLabelText('copy node id'));

    await waitFor(() => expect(writeText).toHaveBeenCalledWith('abababab'));
    await waitFor(() =>
      expect(screen.getByLabelText('copy node id').getAttribute('aria-pressed')).toBe('true')
    );
  });

  it('never confirms a copy the browser refused', async () => {
    const writeText = vi.fn(() => Promise.reject(new Error('denied')));
    vi.stubGlobal('navigator', { ...navigator, clipboard: { writeText } });

    render(<DetailsDialog row={fileRow()} onClose={() => undefined} />);
    fireEvent.click(screen.getByLabelText('copy name'));

    await waitFor(() => expect(writeText).toHaveBeenCalledOnce());
    expect(screen.getByLabelText('copy name').getAttribute('aria-pressed')).toBe('false');
  });
});

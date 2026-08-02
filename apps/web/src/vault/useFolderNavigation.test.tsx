import type { SnapshotDescriptor } from '@cipherbox/client';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { FileBrowser } from '../components/file-browser/FileBrowser';
import { fakeEngine } from '../engine/testFakes';
import { folderPath } from '../lib/nodeId';
import { EngineProvider } from '../providers/EngineProvider';

const ROOT = new Uint8Array(16).fill(0);
const DOCS = new Uint8Array(16).fill(7);
const SUB = new Uint8Array(16).fill(9);
const NOTE = new Uint8Array(16).fill(3);

function folderView(overrides: Partial<SnapshotDescriptor> = {}): SnapshotDescriptor {
  return {
    root: ROOT,
    folder: ROOT,
    folderName: '',
    children: [],
    ancestors: [],
    deadLetters: [],
    blocked: null,
    retainedRecords: 0,
    staleness: 'fresh',
    ...overrides,
  };
}

function renderBrowser(engine: ReturnType<typeof fakeEngine>, path = '/files') {
  render(
    <EngineProvider createClient={() => engine.client}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path="/files/:nodeId?" element={<FileBrowser />} />
        </Routes>
      </MemoryRouter>
    </EngineProvider>
  );
}

/** Settles the pull the engine's `snapshotUpdated` event triggers. */
async function landSnapshot(
  engine: ReturnType<typeof fakeEngine>,
  view: SnapshotDescriptor
): Promise<void> {
  await act(async () => {
    engine.emit({ kind: 'snapshotUpdated' });
    engine.pulls[engine.pulls.length - 1].resolve(view);
    await Promise.resolve();
  });
}

const rowNames = () =>
  screen.getAllByTestId('file-list-item').map((row) => row.querySelector('.file-list-item-name')!);

describe('the vault browser read path', () => {
  it('renders the routed folder from the snapshot, folders first', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);

    expect(screen.getByTestId('file-browser-loading')).toBeDefined();

    await landSnapshot(
      engine,
      folderView({
        children: [
          {
            id: NOTE,
            name: 'notes.txt',
            kind: 'file',
            size: 1024n,
            mtime: 1_700_000_000_000n,
            pending: 'none',
            deadLetter: false,
            contentVersion: 1n,
          },
          {
            id: DOCS,
            name: 'documents',
            kind: 'folder',
            size: null,
            mtime: null,
            pending: 'none',
            deadLetter: false,
            contentVersion: null,
          },
        ],
      })
    );

    expect(rowNames().map((cell) => cell.textContent)).toEqual(['documents', 'notes.txt']);
    expect(screen.queryByTestId('parent-dir-row')).toBeNull();
  });

  it('shows the empty state for a folder with no children', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, folderView());

    expect(screen.getByTestId('empty-state')).toBeDefined();
  });

  it('renders name and kind before size and mtime resolve, then repaints', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);

    const unresolved = {
      id: NOTE,
      name: 'holiday.jpg',
      kind: 'file' as const,
      size: null,
      mtime: null,
      pending: 'none' as const,
      deadLetter: false,
      contentVersion: null,
    };
    await landSnapshot(engine, folderView({ children: [unresolved] }));

    const row = screen.getByTestId('file-list-item');
    expect(row.querySelector('.file-list-item-name')?.textContent).toBe('holiday.jpg');
    expect(row.querySelector('.file-list-item-size')?.textContent).toBe('...');

    await landSnapshot(
      engine,
      folderView({ children: [{ ...unresolved, size: 2048n, mtime: 1_700_000_000_000n }] })
    );

    expect(
      screen.getByTestId('file-list-item').querySelector('.file-list-item-size')?.textContent
    ).toBe('2 KB');
  });

  it('moves the engine focus window when a folder is opened', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(
      engine,
      folderView({
        children: [
          {
            id: DOCS,
            name: 'documents',
            kind: 'folder',
            size: null,
            mtime: null,
            pending: 'none',
            deadLetter: false,
            contentVersion: null,
          },
        ],
      })
    );

    await act(async () => {
      fireEvent.doubleClick(screen.getByTestId('file-list-item'));
      await Promise.resolve();
    });

    expect(engine.focus).toEqual([DOCS]);
    expect(engine.reported).toEqual([DOCS]);

    await act(async () => {
      engine.ackFocus();
      await Promise.resolve();
      engine.pulls[engine.pulls.length - 1].resolve(
        folderView({
          folder: DOCS,
          folderName: 'documents',
          ancestors: [{ id: ROOT, name: '' }],
        })
      );
      await Promise.resolve();
    });

    expect(screen.getByTestId('parent-dir-row')).toBeDefined();
  });

  it('builds the breadcrumb chain from the ancestor trail, root first', async () => {
    const engine = fakeEngine();
    renderBrowser(engine, folderPath(SUB));

    await act(async () => {
      engine.ackFocus();
      await Promise.resolve();
      engine.pulls[engine.pulls.length - 1].resolve(
        folderView({
          folder: SUB,
          folderName: 'sub',
          ancestors: [
            { id: DOCS, name: 'documents' },
            { id: ROOT, name: '' },
          ],
        })
      );
      await Promise.resolve();
    });

    const crumbs = screen.getByTestId('breadcrumbs').querySelectorAll('.breadcrumb-item');
    expect([...crumbs].map((crumb) => crumb.textContent)).toEqual(['root', 'documents', 'sub']);
    expect(crumbs[crumbs.length - 1].getAttribute('aria-current')).toBe('page');
  });

  it('does not list a folder the routed id does not match', async () => {
    const engine = fakeEngine();
    renderBrowser(engine, folderPath(SUB));

    // The folder just left answers late; it must not paint under the new route.
    await act(async () => {
      engine.ackFocus();
      await Promise.resolve();
      engine.pulls[engine.pulls.length - 1].resolve(
        folderView({
          children: [
            {
              id: NOTE,
              name: 'stale.txt',
              kind: 'file',
              size: null,
              mtime: null,
              pending: 'none',
              deadLetter: false,
              contentVersion: null,
            },
          ],
        })
      );
      await Promise.resolve();
    });

    expect(screen.queryByTestId('file-list-item')).toBeNull();
    expect(screen.getByTestId('file-browser-loading')).toBeDefined();
  });

  it('refuses a route param that is not a node id', () => {
    const engine = fakeEngine();
    renderBrowser(engine, '/files/not-a-node');

    expect(screen.getByTestId('file-browser-error').textContent).toBe('that is not a folder id');
    expect(engine.focus).toEqual([]);
  });
});

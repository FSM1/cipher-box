import type { EngineClient, EventDescriptor, SnapshotDescriptor } from '@cipherbox/client';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { EngineProvider } from '../../providers/EngineProvider';
import { FileBrowser } from './FileBrowser';

const ROOT = new Uint8Array(16).fill(0);
const DOCS = new Uint8Array(16).fill(7);
const NOTE = new Uint8Array(16).fill(3);
const PICTURE = new Uint8Array(16).fill(5);

type Child = SnapshotDescriptor['children'][number];

function file(id: Uint8Array, name: string, overrides: Partial<Child> = {}): Child {
  return {
    id,
    name,
    kind: 'file',
    size: 12n,
    mtime: 1_700_000_000_000n,
    pending: 'none',
    deadLetter: false,
    contentVersion: 1n,
    ...overrides,
  };
}

function folder(id: Uint8Array, name: string): Child {
  return { ...file(id, name), kind: 'folder', size: null, contentVersion: null };
}

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

/** An engine whose commands and reads are recorded and settled by hand. */
function fakeEngine(
  download: () => Promise<ArrayBuffer> = () => Promise.resolve(new ArrayBuffer(0))
) {
  const listeners = new Set<(event: EventDescriptor) => void>();
  const pulls: { folder: Uint8Array | null; resolve: (view: SnapshotDescriptor) => void }[] = [];
  const facade = {
    subscribe(listener: (event: EventDescriptor) => void) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    snapshot: vi.fn((folder: Uint8Array | null) => {
      return new Promise<SnapshotDescriptor>((resolve) => {
        pulls.push({ folder, resolve });
      });
    }),
    setFocus: vi.fn((_node: Uint8Array | null) => Promise.resolve()),
    create: vi.fn(() => Promise.resolve()),
    rename: vi.fn(() => Promise.resolve()),
    relink: vi.fn(() => Promise.resolve()),
    delete: vi.fn(() => Promise.resolve()),
    download: vi.fn(download),
  };
  const client = {
    facade,
    reportFocus: () => undefined,
    dispose: () => Promise.resolve(),
  } as unknown as EngineClient;

  return {
    client,
    facade,
    pulls,
    emit: (event: EventDescriptor) => {
      for (const listener of listeners) listener(event);
    },
  };
}

type Engine = ReturnType<typeof fakeEngine>;

function renderBrowser(engine: Engine, path = '/files') {
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

async function landSnapshot(engine: Engine, view: SnapshotDescriptor): Promise<void> {
  await act(async () => {
    engine.emit({ kind: 'snapshotUpdated' });
    engine.pulls[engine.pulls.length - 1].resolve(view);
    await Promise.resolve();
  });
}

/** Settles the read the picker issues for a candidate parent. */
async function settlePickerRead(engine: Engine, view: SnapshotDescriptor): Promise<void> {
  await act(async () => {
    for (let hop = 0; hop < 5; hop += 1) await Promise.resolve();
    engine.pulls[engine.pulls.length - 1].resolve(view);
    for (let hop = 0; hop < 5; hop += 1) await Promise.resolve();
  });
}

function openRowMenu(name: string): void {
  fireEvent.click(screen.getByLabelText(`actions for ${name}`));
}

function chooseMenuItem(label: string): void {
  fireEvent.click(screen.getByRole('menuitem', { name: label }));
}

const listing = () =>
  folderView({ children: [folder(DOCS, 'documents'), file(NOTE, 'notes.txt')] });

describe('the vault browser write path', () => {
  it('dispatches create for a new folder under the folder on screen', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    fireEvent.click(screen.getByTestId('new-folder-button'));
    fireEvent.change(screen.getByLabelText('folder name'), { target: { value: '  plans  ' } });
    fireEvent.click(screen.getByTestId('create-folder-confirm'));

    await waitFor(() => expect(engine.facade.create).toHaveBeenCalledWith(ROOT, 'plans', 'folder'));
    await waitFor(() => expect(screen.queryByTestId('create-folder-dialog')).toBeNull());
  });

  it('keeps the dialog up and reports the failure inside it when the engine rejects', async () => {
    const engine = fakeEngine();
    engine.facade.create.mockRejectedValueOnce(new Error('name already taken'));
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    fireEvent.click(screen.getByTestId('new-folder-button'));
    fireEvent.change(screen.getByLabelText('folder name'), { target: { value: 'plans' } });
    fireEvent.click(screen.getByTestId('create-folder-confirm'));

    // Behind the backdrop the browser's own banner is unreadable, so the
    // failure has to reach the dialog that refused to close.
    await waitFor(() =>
      expect(screen.getByTestId('dialog-error').textContent).toBe('name already taken')
    );
    const dialog = screen.getByTestId('create-folder-dialog');
    expect(dialog.closest('.modal-container')?.contains(screen.getByTestId('dialog-error'))).toBe(
      true
    );
  });

  it('dispatches rename for the row the menu was raised on', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    openRowMenu('notes.txt');
    chooseMenuItem('rename');
    fireEvent.change(screen.getByLabelText('new name'), { target: { value: 'todo.txt' } });
    fireEvent.click(screen.getByTestId('rename-confirm'));

    await waitFor(() => expect(engine.facade.rename).toHaveBeenCalledWith(NOTE, 'todo.txt'));
  });

  it('dispatches delete only after the prompt is confirmed', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    openRowMenu('documents');
    chooseMenuItem('delete');
    expect(screen.getByTestId('delete-dialog').textContent).toContain('everything inside it');
    expect(engine.facade.delete).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId('delete-confirm'));
    await waitFor(() => expect(engine.facade.delete).toHaveBeenCalledWith(DOCS));
  });

  it('dispatches relink to the folder the picker walked into', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    openRowMenu('notes.txt');
    chooseMenuItem('move to...');
    await settlePickerRead(engine, listing());

    // The destination is the folder it opened on until the picker moves.
    expect(screen.getByTestId('move-confirm').getAttribute('disabled')).not.toBeNull();

    fireEvent.click(screen.getByTestId('move-dialog-folder'));
    await settlePickerRead(
      engine,
      folderView({
        folder: DOCS,
        folderName: 'documents',
        ancestors: [{ id: ROOT, name: '' }],
      })
    );

    fireEvent.click(screen.getByTestId('move-confirm'));
    await waitFor(() => expect(engine.facade.relink).toHaveBeenCalledWith(NOTE, DOCS));
  });

  it('never offers the moved folder as its own destination', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    openRowMenu('documents');
    chooseMenuItem('move to...');
    await settlePickerRead(engine, listing());

    expect(screen.queryAllByTestId('move-dialog-folder')).toHaveLength(0);
  });

  it('hands the focus window back when the picker closes', async () => {
    const engine = fakeEngine();
    renderBrowser(engine, `/files/${'07'.repeat(16)}`);
    await landSnapshot(
      engine,
      folderView({
        folder: DOCS,
        folderName: 'documents',
        ancestors: [{ id: ROOT, name: '' }],
        children: [file(NOTE, 'notes.txt')],
      })
    );
    engine.facade.setFocus.mockClear();

    openRowMenu('notes.txt');
    chooseMenuItem('move to...');
    fireEvent.click(screen.getByTestId('move-dialog-up'));
    await act(async () => {
      await Promise.resolve();
    });
    fireEvent.click(screen.getByRole('button', { name: 'cancel' }));

    await waitFor(() => expect(engine.facade.setFocus).toHaveBeenLastCalledWith(DOCS));
  });
});

describe('the vault browser read path over the facade', () => {
  const originalCreate = URL.createObjectURL;
  const originalRevoke = URL.revokeObjectURL;
  let created: Blob[] = [];
  let revoked: string[] = [];

  beforeEach(() => {
    created = [];
    revoked = [];
    URL.createObjectURL = vi.fn((blob: Blob) => {
      created.push(blob);
      return `blob:fake/${created.length}`;
    });
    URL.revokeObjectURL = vi.fn((url: string) => revoked.push(url));
  });

  afterEach(() => {
    URL.createObjectURL = originalCreate;
    URL.revokeObjectURL = originalRevoke;
  });

  const bytes = (text: string) => new TextEncoder().encode(text).buffer as ArrayBuffer;

  it('object-URLs a blob of the downloaded plaintext and revokes it', async () => {
    const engine = fakeEngine(() => Promise.resolve(bytes('hello')));
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    openRowMenu('notes.txt');
    chooseMenuItem('download');

    await waitFor(() => expect(engine.facade.download).toHaveBeenCalledWith(NOTE));
    await waitFor(() => expect(created).toHaveLength(1));
    expect(created[0].type).toBe('application/octet-stream');
    expect(created[0].size).toBe(5);
    await waitFor(() => expect(revoked).toEqual(['blob:fake/1']));
  });

  it('renders a text file as text, without an object URL', async () => {
    const engine = fakeEngine(() => Promise.resolve(bytes('to do: nothing')));
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    openRowMenu('notes.txt');
    chooseMenuItem('preview');

    await waitFor(() =>
      expect(screen.getByTestId('preview-text').textContent).toBe('to do: nothing')
    );
    expect(created).toHaveLength(0);
  });

  it('renders an image from a blob URL typed by its name, and revokes it on close', async () => {
    const engine = fakeEngine(() => Promise.resolve(bytes('PNG')));
    renderBrowser(engine);
    await landSnapshot(
      engine,
      folderView({ children: [file(PICTURE, 'cat.png'), file(NOTE, 'notes.txt')] })
    );

    openRowMenu('cat.png');
    chooseMenuItem('preview');

    await waitFor(() =>
      expect(screen.getByTestId('preview-image').getAttribute('src')).toBe('blob:fake/1')
    );
    expect(created[0].type).toBe('image/png');

    fireEvent.click(screen.getByLabelText('close'));
    await waitFor(() => expect(revoked).toEqual(['blob:fake/1']));
  });

  it('embeds a pdf under a sandbox that grants it nothing', async () => {
    const engine = fakeEngine(() => Promise.resolve(bytes('%PDF-')));
    renderBrowser(engine);
    await landSnapshot(engine, folderView({ children: [file(PICTURE, 'deed.pdf')] }));

    openRowMenu('deed.pdf');
    chooseMenuItem('preview');

    const frame = await screen.findByTestId('preview-pdf');
    expect(frame.getAttribute('sandbox')).toBe('');
    expect(created[0].type).toBe('application/pdf');
  });

  it('offers no preview for a type the browser must not render', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, folderView({ children: [file(PICTURE, 'logo.svg')] }));

    openRowMenu('logo.svg');
    expect(screen.queryByRole('menuitem', { name: 'preview' })).toBeNull();
    expect(screen.getByRole('menuitem', { name: 'download' })).toBeDefined();
  });

  it('refuses to decrypt a file the engine already reports as too large', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(
      engine,
      folderView({ children: [file(NOTE, 'huge.txt', { size: 64n * 1024n * 1024n })] })
    );

    openRowMenu('huge.txt');
    chooseMenuItem('preview');

    await waitFor(() =>
      expect(screen.getByRole('alert').textContent).toBe(
        'too large to preview - download it instead'
      )
    );
    expect(engine.facade.download).not.toHaveBeenCalled();
  });

  it('reports a failed read instead of rendering it', async () => {
    const engine = fakeEngine(() => Promise.reject(new Error('adoption gate refused the record')));
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    openRowMenu('notes.txt');
    chooseMenuItem('preview');

    await waitFor(() =>
      expect(screen.getByRole('alert').textContent).toBe('adoption gate refused the record')
    );
  });
});

describe('the row action menu', () => {
  it('anchors to the control when opened without a pointer position', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    const control = screen.getByLabelText('actions for notes.txt');
    control.getBoundingClientRect = () => ({ left: 120, bottom: 48 }) as DOMRect;
    fireEvent.click(control, { detail: 0, clientX: 0, clientY: 0 });

    const menu = screen.getByTestId('context-menu');
    expect(menu.style.left).toBe('120px');
    expect(menu.style.top).toBe('48px');
  });

  it('anchors to the pointer on a right-click', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    const row = screen.getAllByTestId('file-list-item')[1];
    fireEvent.contextMenu(row, { detail: 1, clientX: 200, clientY: 90 });

    const menu = screen.getByTestId('context-menu');
    expect(menu.style.left).toBe('200px');
    expect(menu.style.top).toBe('90px');
  });
});

describe('the queue overlay', () => {
  it('marks a node the engine reports as pending', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(
      engine,
      folderView({ children: [file(NOTE, 'notes.txt', { pending: 'content' })] })
    );

    expect(screen.getByTitle('content change not published yet')).toBeDefined();
  });

  it('keeps a dead-letter notice up for as long as the engine reports it', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(
      engine,
      folderView({
        children: [file(NOTE, 'notes.txt', { deadLetter: true })],
        deadLetters: [{ opId: 4n, reason: 'targetGone' }],
      })
    );

    expect(screen.getByTestId('dead-letter-notice').textContent).toContain(
      'its target no longer exists'
    );

    await landSnapshot(
      engine,
      folderView({
        children: [file(NOTE, 'notes.txt', { deadLetter: true })],
        deadLetters: [{ opId: 4n, reason: 'targetGone' }],
      })
    );

    expect(screen.getByTestId('dead-letter-notice')).toBeDefined();
  });
});

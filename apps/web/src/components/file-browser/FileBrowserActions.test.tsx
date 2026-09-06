import {
  toHex,
  type EngineClient,
  type EventDescriptor,
  type MediaService,
  type MediaStreamFailure,
  type SnapshotDescriptor,
} from '@cipherbox/client';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { useFolderPicker } from '../../hooks/useFolderPicker';
import { EngineProvider } from '../../providers/EngineProvider';
import { VaultStorageProvider } from '../../providers/VaultStorageProvider';
import { FAKE_VAULT_STORAGE } from '../../test/authFakes';
import { trackSaves } from '../../test/saveSpy';
import { FileBrowser } from './FileBrowser';

/** The pipe this tab gets; `null` is the browser without a Service Worker. */
const mediaControl = { create: (): MediaService | null => null };
vi.mock('../../engine/createMediaService', () => ({
  createMediaService: () => mediaControl.create(),
}));

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
    contentCid: null,
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
    settingsHold: null,
    binIndexHold: null,
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
    beginWrite: vi.fn((_target: { node: Uint8Array }, _size: number) => Promise.resolve(9n)),
    pushChunk: vi.fn((_handle: bigint, _chunk: ArrayBuffer) => Promise.resolve()),
    commitWrite: vi.fn(() => Promise.resolve(1n)),
    abortWrite: vi.fn(() => Promise.resolve()),
    vaultStorage: vi.fn(() => Promise.resolve(FAKE_VAULT_STORAGE)),
  };
  const client = {
    facade,
    subscribeSession: () => () => undefined,
    signedInAccount: () => null,
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
      <VaultStorageProvider>
        <MemoryRouter initialEntries={[path]}>
          <Routes>
            <Route path="/files/:nodeId?" element={<FileBrowser />} />
          </Routes>
        </MemoryRouter>
      </VaultStorageProvider>
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

  it('names a row the confirmation destroys in the order the vault stores it', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, folderView({ children: [file(NOTE, 'report\u202Efdp.exe')] }));

    openRowMenu('reportfdp.exe');
    chooseMenuItem('delete');

    expect(screen.getByTestId('delete-dialog').textContent).toContain('"reportfdp.exe"');
  });

  it('prefills a rename with the name the engine holds, not the shown one', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, folderView({ children: [file(NOTE, 'report\u202Efdp.exe')] }));

    openRowMenu('reportfdp.exe');
    chooseMenuItem('rename');

    expect((screen.getByLabelText('new name') as HTMLInputElement).value).toBe(
      'report\u202Efdp.exe'
    );
    expect((screen.getByTestId('rename-confirm') as HTMLButtonElement).disabled).toBe(true);
  });

  it('saves a file under the name the engine holds, not the shown one', async () => {
    const engine = fakeEngine();
    const saves = trackSaves();
    try {
      renderBrowser(engine);
      await landSnapshot(engine, folderView({ children: [file(NOTE, 'report\u202Efdp.exe')] }));

      openRowMenu('reportfdp.exe');
      chooseMenuItem('download');

      await waitFor(() =>
        expect(saves.clicked.map((save) => save.download)).toEqual(['report\u202Efdp.exe'])
      );
    } finally {
      saves.restore();
    }
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

    fireEvent.click(screen.getByTestId('folder-picker-entry'));
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

    expect(screen.queryAllByTestId('folder-picker-entry')).toHaveLength(0);
  });

  it('never names the folder it is walking out of as the destination', async () => {
    const engine = fakeEngine();
    const frames: { atHome: boolean; destination: string | null }[] = [];

    function Probe() {
      const picker = useFolderPicker(DOCS, new Set([toHex(NOTE)]));
      frames.push({
        atHome: picker.atHome,
        destination: picker.destination === null ? null : toHex(picker.destination),
      });
      return (
        <button type="button" onClick={() => picker.enter(PICTURE)}>
          descend
        </button>
      );
    }

    render(
      <EngineProvider createClient={() => engine.client}>
        <Probe />
      </EngineProvider>
    );
    await settlePickerRead(engine, folderView({ folder: DOCS, folderName: 'documents' }));
    frames.length = 0;

    fireEvent.click(screen.getByRole('button', { name: 'descend' }));
    await act(async () => {
      for (let hop = 0; hop < 5; hop += 1) await Promise.resolve();
    });

    // Descending renders before the read effect lands, so no frame may still
    // name the folder left behind: a move confirmed from one of those would
    // relink the row straight back to where it started.
    expect(frames.some((frame) => !frame.atHome)).toBe(true);
    expect(frames.filter((frame) => !frame.atHome && frame.destination === toHex(DOCS))).toEqual(
      []
    );
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
    await settlePickerRead(
      engine,
      folderView({ folder: DOCS, folderName: 'documents', ancestors: [{ id: ROOT, name: '' }] })
    );
    fireEvent.click(screen.getByTestId('folder-picker-up'));
    await act(async () => {
      await Promise.resolve();
    });
    fireEvent.click(screen.getByRole('button', { name: 'cancel' }));

    await waitFor(() => expect(engine.facade.setFocus).toHaveBeenLastCalledWith(DOCS));
  });

  it('walks [..] back to the folder it descended from, not the vault root', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    openRowMenu('notes.txt');
    chooseMenuItem('move to...');
    await settlePickerRead(engine, listing());
    engine.facade.snapshot.mockClear();

    // Leaving before the child's listing lands has no ancestry to read, and
    // reading none as "the vault root" would strand the walk at the top.
    fireEvent.click(screen.getByTestId('folder-picker-entry'));
    fireEvent.click(screen.getByTestId('folder-picker-up'));
    await act(async () => {
      for (let hop = 0; hop < 5; hop += 1) await Promise.resolve();
    });

    expect(engine.facade.snapshot).toHaveBeenLastCalledWith(ROOT);
    expect(engine.facade.snapshot).not.toHaveBeenCalledWith(null);
  });

  it('refuses to dismiss a dialog while its command is in flight', async () => {
    const engine = fakeEngine();
    let release: () => void = () => undefined;
    engine.facade.create.mockImplementationOnce(
      () =>
        new Promise<void>((resolve) => {
          release = resolve;
        })
    );
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    fireEvent.click(screen.getByTestId('new-folder-button'));
    fireEvent.change(screen.getByLabelText('folder name'), { target: { value: 'plans' } });
    fireEvent.click(screen.getByTestId('create-folder-confirm'));
    await act(async () => {
      await Promise.resolve();
    });

    fireEvent.keyDown(document, { key: 'Escape' });
    fireEvent.mouseDown(screen.getByTestId('modal-backdrop'));
    expect(screen.getByTestId('create-folder-dialog')).toBeDefined();

    await act(async () => {
      release();
      await Promise.resolve();
    });
    await waitFor(() => expect(screen.queryByTestId('create-folder-dialog')).toBeNull());
  });
});

describe('the vault browser selection', () => {
  const select = (name: string) => fireEvent.click(screen.getByLabelText(`select ${name}`));
  const count = () => screen.queryByTestId('selection-count')?.textContent ?? null;

  it('counts the rows toggled on, and empties on clear', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    expect(screen.queryByTestId('selection-action-bar')).toBeNull();

    select('notes.txt');
    expect(count()).toBe('notes.txt selected');
    select('documents');
    expect(count()).toBe('1 file, 1 folder selected');
    select('notes.txt');
    expect(count()).toBe('documents selected');

    fireEvent.click(screen.getByTestId('selection-clear'));
    expect(screen.queryByTestId('selection-action-bar')).toBeNull();
  });

  it('takes the whole listing from the header, and gives it back', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    fireEvent.click(screen.getByTestId('select-all'));
    expect(count()).toBe('1 file, 1 folder selected');

    fireEvent.click(screen.getByTestId('select-all'));
    expect(screen.queryByTestId('selection-action-bar')).toBeNull();
  });

  it('dispatches one delete per selected node', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    fireEvent.click(screen.getByTestId('select-all'));
    fireEvent.click(screen.getByTestId('selection-delete'));
    fireEvent.click(screen.getByTestId('delete-confirm'));

    await waitFor(() => expect(engine.facade.delete).toHaveBeenCalledTimes(2));
    expect(engine.facade.delete.mock.calls).toEqual([[DOCS], [NOTE]]);
    await waitFor(() => expect(screen.queryByTestId('selection-action-bar')).toBeNull());
  });

  it('dispatches one relink per selected node, all to the picked destination', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(
      engine,
      folderView({ children: [file(NOTE, 'notes.txt'), file(PICTURE, 'shot.png')] })
    );

    fireEvent.click(screen.getByTestId('select-all'));
    fireEvent.click(screen.getByTestId('selection-move'));
    await settlePickerRead(engine, listing());

    fireEvent.click(screen.getByTestId('folder-picker-entry'));
    await settlePickerRead(
      engine,
      folderView({ folder: DOCS, folderName: 'documents', ancestors: [{ id: ROOT, name: '' }] })
    );
    fireEvent.click(screen.getByTestId('move-confirm'));

    await waitFor(() => expect(engine.facade.relink).toHaveBeenCalledTimes(2));
    expect(engine.facade.relink.mock.calls).toEqual([
      [NOTE, DOCS],
      [PICTURE, DOCS],
    ]);
  });

  it('reads every selected file and leaves the folders alone', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(
      engine,
      folderView({
        children: [folder(DOCS, 'documents'), file(NOTE, 'notes.txt'), file(PICTURE, 'shot.png')],
      })
    );

    fireEvent.click(screen.getByTestId('select-all'));
    fireEvent.click(screen.getByTestId('selection-download'));

    await waitFor(() => expect(engine.facade.download).toHaveBeenCalledTimes(2));
    expect(engine.facade.download.mock.calls).toEqual([[NOTE], [PICTURE]]);
  });

  it('runs one batch download at a time, however often the button is clicked', async () => {
    const pending: ((bytes: ArrayBuffer) => void)[] = [];
    const engine = fakeEngine(() => new Promise<ArrayBuffer>((resolve) => pending.push(resolve)));
    renderBrowser(engine);
    await landSnapshot(
      engine,
      folderView({ children: [file(NOTE, 'notes.txt'), file(PICTURE, 'shot.png')] })
    );

    fireEvent.click(screen.getByTestId('select-all'));
    fireEvent.click(screen.getByTestId('selection-download'));
    await act(async () => {
      await Promise.resolve();
    });

    // A second loop would hand the user a duplicate of every file, and would
    // let a move or delete land between two reads of the same batch.
    const bar = screen.getByTestId('selection-action-bar');
    for (const action of ['download', 'move', 'delete']) {
      expect((screen.getByTestId(`selection-${action}`) as HTMLButtonElement).disabled).toBe(true);
    }
    fireEvent.click(screen.getByTestId('selection-download'));
    expect(engine.facade.download.mock.calls).toEqual([[NOTE]]);
    expect(bar).toBeDefined();

    await act(async () => {
      pending[0](new ArrayBuffer(0));
      await Promise.resolve();
    });
    await waitFor(() => expect(pending).toHaveLength(2));
    await act(async () => {
      pending[1](new ArrayBuffer(0));
      await Promise.resolve();
    });

    await waitFor(() =>
      expect((screen.getByTestId('selection-download') as HTMLButtonElement).disabled).toBe(false)
    );
    expect(engine.facade.download.mock.calls).toEqual([[NOTE], [PICTURE]]);
  });

  it('retires only the nodes a partly refused batch was accepted for', async () => {
    const engine = fakeEngine();
    engine.facade.delete
      .mockImplementationOnce(() => Promise.resolve())
      .mockImplementationOnce(() => Promise.reject(new Error('the op queue is full')));
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    fireEvent.click(screen.getByTestId('select-all'));
    fireEvent.click(screen.getByTestId('selection-delete'));
    fireEvent.click(screen.getByTestId('delete-confirm'));

    await waitFor(() =>
      expect(screen.getByTestId('dialog-error').textContent).toBe('the op queue is full')
    );
    // The dialog stays up over what was refused only: retrying it must not
    // journal a second delete for the node the engine already took.
    expect(count()).toBe('notes.txt selected');
    expect(screen.getByTestId('delete-dialog').textContent).toContain('"notes.txt"');

    fireEvent.click(screen.getByTestId('delete-confirm'));
    await waitFor(() => expect(engine.facade.delete.mock.calls).toEqual([[DOCS], [NOTE], [NOTE]]));
    await waitFor(() => expect(screen.queryByTestId('delete-dialog')).toBeNull());
    expect(screen.queryByTestId('selection-action-bar')).toBeNull();
  });

  it('retires only the rows a command acted on, not the whole selection', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    fireEvent.click(screen.getByTestId('select-all'));
    // A command raised from one row's own menu is about that row, not the batch.
    openRowMenu('notes.txt');
    chooseMenuItem('delete');
    fireEvent.click(screen.getByTestId('delete-confirm'));

    await waitFor(() => expect(engine.facade.delete.mock.calls).toEqual([[NOTE]]));
    await waitFor(() => expect(count()).toBe('documents selected'));
  });

  it('starts over when the route moves to another folder', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    fireEvent.click(screen.getByTestId('select-all'));
    expect(count()).toBe('1 file, 1 folder selected');

    fireEvent.doubleClick(screen.getByText('documents'));
    await landSnapshot(
      engine,
      folderView({
        folder: DOCS,
        folderName: 'documents',
        children: [file(PICTURE, 'shot.png')],
        ancestors: [{ id: ROOT, name: '' }],
      })
    );

    expect(screen.getByText('shot.png')).toBeDefined();
    expect(screen.queryByTestId('selection-action-bar')).toBeNull();
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

  it('object-URLs a blob of the downloaded plaintext and revokes it once saved', async () => {
    const engine = fakeEngine(() => Promise.resolve(bytes('hello')));
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    openRowMenu('notes.txt');
    vi.useFakeTimers();
    try {
      chooseMenuItem('download');
      await act(async () => {
        await vi.advanceTimersByTimeAsync(0);
      });

      expect(engine.facade.download).toHaveBeenCalledWith(NOTE);
      expect(created).toHaveLength(1);
      expect(created[0].type).toBe('application/octet-stream');
      expect(created[0].size).toBe(5);
      // Revoking inside the click's own task cancels the save in some browsers.
      expect(revoked).toEqual([]);

      await act(async () => {
        await vi.advanceTimersByTimeAsync(60_000);
      });
      expect(revoked).toEqual(['blob:fake/1']);
    } finally {
      vi.useRealTimers();
    }
  });

  it('refuses to decrypt a file whose size the engine has not projected', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, folderView({ children: [file(NOTE, 'notes.txt', { size: null })] }));

    openRowMenu('notes.txt');
    chooseMenuItem('preview');

    await waitFor(() =>
      expect(screen.getByRole('alert').textContent).toBe(
        'size not known yet - preview it again in a moment'
      )
    );
    expect(engine.facade.download).not.toHaveBeenCalled();
  });

  it('retires a failed download from the banner once an action dispatches', async () => {
    const engine = fakeEngine(() => Promise.reject(new Error('the record is gone')));
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    openRowMenu('notes.txt');
    chooseMenuItem('download');
    await waitFor(() =>
      expect(screen.getByTestId('vault-action-error').textContent).toBe('the record is gone')
    );

    fireEvent.click(screen.getByTestId('new-folder-button'));
    fireEvent.change(screen.getByLabelText('folder name'), { target: { value: 'plans' } });
    fireEvent.click(screen.getByTestId('create-folder-confirm'));

    await waitFor(() => expect(screen.queryByTestId('vault-action-error')).toBeNull());
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

  it('embeds a pdf in a frame that carries no sandbox', async () => {
    const engine = fakeEngine(() => Promise.resolve(bytes('%PDF-')));
    renderBrowser(engine);
    await landSnapshot(engine, folderView({ children: [file(PICTURE, 'deed.pdf')] }));

    openRowMenu('deed.pdf');
    chooseMenuItem('preview');

    const frame = await screen.findByTestId('preview-pdf');
    expect(frame.hasAttribute('sandbox')).toBe(false);
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

describe('the vault browser read path over the streaming pipe', () => {
  const minted: Parameters<MediaService['createStreamUrl']>[0][] = [];
  const revoked: string[] = [];
  let saves = trackSaves();
  /** Whether the browser opens the save the ticket was minted for. */
  let fetched = true;
  /** Set by a test that drives the transfers itself, keyed by ticket url. */
  let transfers: Map<string, (outcome: { read: boolean; failure: string | null }) => void> | null =
    null;
  const streamListeners = new Set<(failure: MediaStreamFailure) => void>();

  /** The browser finished reading this ticket. */
  const endTransfer = async (url: string): Promise<void> => {
    await act(async () => {
      transfers?.get(url)?.({ read: fetched, failure: null });
      await Promise.resolve();
    });
  };

  /** Stands in for the broker giving up on a read. */
  const reportStreamError = (failure: MediaStreamFailure): void => {
    act(() => {
      for (const listener of streamListeners) listener(failure);
    });
  };

  /** Opens the preview of one audio file and waits for the player. */
  async function playAudio(): Promise<void> {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, folderView({ children: [file(NOTE, 'song.mp3')] }));

    openRowMenu('song.mp3');
    chooseMenuItem('preview');
    await screen.findByTestId('media-player-audio');
  }

  beforeEach(() => {
    minted.length = 0;
    revoked.length = 0;
    saves.restore();
    saves = trackSaves();
    fetched = true;
    transfers = null;
    streamListeners.clear();
    mediaControl.create = () =>
      ({
        streaming: true,
        start: () => Promise.resolve(),
        dispose: () => Promise.resolve(),
        createStreamUrl: (source: Parameters<MediaService['createStreamUrl']>[0]) => {
          minted.push(source);
          return `/stream/ticket-${minted.length}`;
        },
        whenStreamIdle: (url: string) => {
          const held = transfers;
          if (held === null) return Promise.resolve({ read: fetched, failure: null });
          return new Promise<{ read: boolean; failure: string | null }>((resolve) =>
            held.set(url, resolve)
          );
        },
        onStreamError: (listener: (failure: MediaStreamFailure) => void) => {
          streamListeners.add(listener);
          return () => streamListeners.delete(listener);
        },
        revokeStreamUrl: (url: string) => {
          revoked.push(url);
          return true;
        },
      }) as unknown as MediaService;
  });

  afterEach(() => {
    mediaControl.create = () => null;
    saves.restore();
  });

  it('hands a save to the browser as a ticket instead of buffering the plaintext', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    openRowMenu('notes.txt');
    chooseMenuItem('download');
    await act(async () => {
      await Promise.resolve();
    });

    expect(engine.facade.download).not.toHaveBeenCalled();
    // No length: the pipe frames the head from the version its engine stream
    // pins, so a size recorded when the ticket was minted travels nowhere.
    expect(minted).toEqual([
      { node: NOTE, mimeType: 'application/octet-stream', downloadName: 'notes.txt' },
    ]);
    // The name rides the pipe's `content-disposition`, not the link's attribute.
    expect(saves.navigated).toEqual(['/stream/ticket-1']);
    expect(saves.clicked).toEqual([]);
    // The ticket serves plaintext to anything same-origin that can name it, so
    // it dies with the transfer rather than with the view.
    await waitFor(() => expect(revoked).toEqual(['/stream/ticket-1']));
  });

  const twoFiles = () =>
    folderView({ children: [file(NOTE, 'notes.txt'), file(PICTURE, 'shot.png')] });

  it('saves a selection one ticket at a time', async () => {
    const engine = fakeEngine();
    transfers = new Map();
    renderBrowser(engine);
    await landSnapshot(engine, twoFiles());

    fireEvent.click(screen.getByTestId('select-all'));
    fireEvent.click(screen.getByTestId('selection-download'));

    await waitFor(() => expect(minted).toHaveLength(1));
    expect(revoked).toEqual([]);

    await endTransfer('/stream/ticket-1');

    await waitFor(() => expect(minted).toHaveLength(2));
    expect(revoked).toEqual(['/stream/ticket-1']);

    await endTransfer('/stream/ticket-2');

    await waitFor(() => expect(revoked).toEqual(['/stream/ticket-1', '/stream/ticket-2']));
  });

  it('stops a batch at the first save the browser refuses', async () => {
    const engine = fakeEngine();
    fetched = false;
    renderBrowser(engine);
    await landSnapshot(engine, twoFiles());

    fireEvent.click(screen.getByTestId('select-all'));
    fireEvent.click(screen.getByTestId('selection-download'));

    await waitFor(() =>
      expect(screen.getByTestId('vault-action-error').textContent).toBe(
        'the browser did not start the download'
      )
    );
    // Grinding through the rest would burn the start deadline once per file.
    expect(minted).toHaveLength(1);
  });

  it('buffers a save whose size the engine has not projected', async () => {
    const engine = fakeEngine(() => Promise.resolve(new ArrayBuffer(3)));
    renderBrowser(engine);
    await landSnapshot(engine, folderView({ children: [file(NOTE, 'notes.txt', { size: null })] }));

    openRowMenu('notes.txt');
    chooseMenuItem('download');

    await waitFor(() => expect(engine.facade.download).toHaveBeenCalledWith(NOTE));
    expect(minted).toEqual([]);
  });

  it('streams an image preview and revokes its ticket on close', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, folderView({ children: [file(PICTURE, 'cat.png')] }));

    openRowMenu('cat.png');
    chooseMenuItem('preview');

    await waitFor(() =>
      expect(screen.getByTestId('preview-image').getAttribute('src')).toBe('/stream/ticket-1')
    );
    expect(engine.facade.download).not.toHaveBeenCalled();
    expect(minted[0].mimeType).toBe('image/png');

    fireEvent.click(screen.getByLabelText('close'));
    await waitFor(() => expect(revoked).toEqual(['/stream/ticket-1']));
  });

  it('shows an image the byte budget would have refused', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(
      engine,
      folderView({ children: [file(PICTURE, 'cat.png', { size: 64n * 1024n * 1024n })] })
    );

    openRowMenu('cat.png');
    chooseMenuItem('preview');

    await waitFor(() => expect(screen.getByTestId('preview-image')).toBeDefined());
    expect(engine.facade.download).not.toHaveBeenCalled();
  });

  it('plays a video off a ticket and never buffers it', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(
      engine,
      folderView({ children: [file(PICTURE, 'clip.mp4', { size: 64n * 1024n * 1024n })] })
    );

    openRowMenu('clip.mp4');
    chooseMenuItem('preview');

    const player = await screen.findByTestId('media-player-video');
    expect(player.getAttribute('src')).toBe('/stream/ticket-1');
    expect(minted[0].mimeType).toBe('video/mp4');
    expect(engine.facade.download).not.toHaveBeenCalled();

    fireEvent.click(screen.getByLabelText('close'));
    await waitFor(() => expect(revoked).toEqual(['/stream/ticket-1']));
  });

  it('offers a retry for a ceiling refusal and a bare failure for a fault', async () => {
    await playAudio();

    reportStreamError({
      url: '/stream/ticket-1',
      message: 'too many read streams are already open',
      recoverable: true,
    });
    expect(screen.getByTestId('media-player-error').textContent).toContain(
      'too many streams are open right now'
    );

    fireEvent.click(screen.getByTestId('media-player-retry'));
    expect(screen.queryByTestId('media-player-error')).toBeNull();
    // The pipe refused a read; it did not withdraw the capability.
    expect(revoked).toEqual([]);
    expect(screen.getByTestId('media-player-audio').getAttribute('src')).toBe('/stream/ticket-1');

    reportStreamError({
      url: '/stream/ticket-1',
      message: 'the adoption gate refused the record',
      recoverable: false,
    });
    expect(screen.getByTestId('media-player-error').textContent).toBe(
      'the adoption gate refused the record'
    );
    expect(screen.queryByTestId('media-player-retry')).toBeNull();
  });

  it('ignores a refusal reported for another stream', async () => {
    await playAudio();

    reportStreamError({ url: '/stream/ticket-9', message: 'not mine', recoverable: true });

    expect(screen.queryByTestId('media-player-error')).toBeNull();
  });

  it('reports a playback failure the pipe never named', async () => {
    await playAudio();

    fireEvent.error(screen.getByTestId('media-player-audio'));

    expect(screen.getByTestId('media-player-error').textContent).toBe('playback failed');
    expect(screen.queryByTestId('media-player-retry')).toBeNull();
  });

  it('keeps the retry when the element reports the refusal it was already told about', async () => {
    await playAudio();

    reportStreamError({
      url: '/stream/ticket-1',
      message: 'too many read streams are already open',
      recoverable: true,
    });
    // Ending the body is what the element sees, and it cannot classify it.
    fireEvent.error(screen.getByTestId('media-player-audio'));

    expect(screen.getByTestId('media-player-error').textContent).toContain(
      'too many streams are open right now'
    );
    expect(screen.getByTestId('media-player-retry')).toBeDefined();
  });

  it('buffers a pdf, which the pipe would serve under an opaque type', async () => {
    const engine = fakeEngine(() => Promise.resolve(new ArrayBuffer(5)));
    renderBrowser(engine);
    await landSnapshot(engine, folderView({ children: [file(PICTURE, 'deed.pdf')] }));

    openRowMenu('deed.pdf');
    chooseMenuItem('preview');

    await waitFor(() => expect(screen.getByTestId('preview-pdf')).toBeDefined());
    expect(minted).toEqual([]);
  });
});

describe('the text editor', () => {
  const text = (value: string) => () =>
    Promise.resolve(new TextEncoder().encode(value).buffer as ArrayBuffer);

  it('offers an editor only for a type the preview allow-list calls text', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(
      engine,
      folderView({ children: [file(NOTE, 'notes.txt'), file(PICTURE, 'cat.png')] })
    );

    openRowMenu('cat.png');
    expect(screen.queryByRole('menuitem', { name: 'edit' })).toBeNull();
    fireEvent.keyDown(document, { key: 'Escape' });

    openRowMenu('notes.txt');
    expect(screen.getByRole('menuitem', { name: 'edit' })).toBeDefined();
  });

  it('writes the edited bytes through one facade write', async () => {
    const engine = fakeEngine(text('to do: nothing'));
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    openRowMenu('notes.txt');
    chooseMenuItem('edit');
    const field = await screen.findByTestId('text-editor-field');
    fireEvent.change(field, { target: { value: 'to do: everything' } });
    fireEvent.click(screen.getByTestId('text-editor-save'));

    await waitFor(() => expect(engine.facade.commitWrite).toHaveBeenCalledWith(9n));
    expect(engine.facade.beginWrite).toHaveBeenCalledWith({ node: NOTE }, 17);
    const [, chunk] = engine.facade.pushChunk.mock.calls[0];
    expect(new TextDecoder().decode(chunk)).toBe('to do: everything');
    await waitFor(() => expect(screen.queryByTestId('text-editor-dialog')).toBeNull());
  });

  it('refuses to dismiss while the save is in flight', async () => {
    const engine = fakeEngine(text('to do: nothing'));
    let release: () => void = () => undefined;
    engine.facade.commitWrite.mockImplementationOnce(
      () =>
        new Promise<bigint>((resolve) => {
          release = () => resolve(1n);
        })
    );
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    openRowMenu('notes.txt');
    chooseMenuItem('edit');
    fireEvent.change(await screen.findByTestId('text-editor-field'), {
      target: { value: 'changed' },
    });
    fireEvent.click(screen.getByTestId('text-editor-save'));
    await act(async () => {
      await Promise.resolve();
    });

    fireEvent.keyDown(document, { key: 'Escape' });
    fireEvent.mouseDown(screen.getByTestId('modal-backdrop'));
    expect(screen.getByTestId('text-editor-dialog')).toBeDefined();

    await act(async () => {
      release();
      await Promise.resolve();
    });
    await waitFor(() => expect(screen.queryByTestId('text-editor-dialog')).toBeNull());
  });

  it('releases the write when the engine refuses it, and keeps the draft up', async () => {
    const engine = fakeEngine(text('to do: nothing'));
    engine.facade.commitWrite.mockRejectedValueOnce(new Error('the op queue is full'));
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    openRowMenu('notes.txt');
    chooseMenuItem('edit');
    fireEvent.change(await screen.findByTestId('text-editor-field'), {
      target: { value: 'changed' },
    });
    fireEvent.click(screen.getByTestId('text-editor-save'));

    await waitFor(() =>
      expect(screen.getByTestId('dialog-error').textContent).toBe('the op queue is full')
    );
    expect(engine.facade.abortWrite).toHaveBeenCalledWith(9n);
    expect(screen.getByTestId('text-editor-field')).toBeDefined();
  });

  it('refuses a file over the byte budget before it decrypts anything', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(
      engine,
      folderView({ children: [file(NOTE, 'huge.txt', { size: 64n * 1024n * 1024n })] })
    );

    openRowMenu('huge.txt');
    chooseMenuItem('edit');

    await waitFor(() =>
      expect(screen.getByTestId('dialog-error').textContent).toBe(
        'too large to preview - download it instead'
      )
    );
    expect(engine.facade.download).not.toHaveBeenCalled();
    expect(screen.queryByTestId('text-editor-field')).toBeNull();
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

  it('leaves the action button its own keyboard activation', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, listing());
    engine.facade.snapshot.mockClear();

    const control = screen.getByLabelText('actions for documents');
    control.focus();
    fireEvent.keyDown(control, { key: 'Enter' });
    await act(async () => {
      await Promise.resolve();
    });
    expect(engine.facade.snapshot).not.toHaveBeenCalled();

    fireEvent.keyDown(screen.getAllByTestId('file-list-item')[0], { key: 'Enter' });
    await act(async () => {
      await Promise.resolve();
    });
    expect(engine.facade.snapshot).toHaveBeenLastCalledWith(DOCS);
  });

  it('takes focus into the menu and hands it back to the trigger', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(engine, listing());

    const control = screen.getByLabelText('actions for notes.txt');
    control.focus();
    fireEvent.click(control, { detail: 0, clientX: 0, clientY: 0 });

    const items = screen.getAllByRole('menuitem');
    expect(document.activeElement).toBe(items[0]);

    const menu = screen.getByTestId('context-menu');
    fireEvent.keyDown(menu, { key: 'ArrowDown' });
    expect(document.activeElement).toBe(items[1]);
    fireEvent.keyDown(menu, { key: 'End' });
    expect(document.activeElement).toBe(items[items.length - 1]);
    fireEvent.keyDown(menu, { key: 'ArrowDown' });
    expect(document.activeElement).toBe(items[0]);

    fireEvent.keyDown(document, { key: 'Escape' });
    await waitFor(() => expect(screen.queryByTestId('context-menu')).toBeNull());
    expect(document.activeElement).toBe(control);
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

  it('shows a held queue head beside the listing, and drops it when the hold clears', async () => {
    const engine = fakeEngine();
    renderBrowser(engine);
    await landSnapshot(
      engine,
      folderView({
        children: [file(NOTE, 'notes.txt')],
        binIndexHold: { opId: 8n, node: NOTE, check: 'timed-out' },
      })
    );

    expect(screen.getByTestId('queue-hold-notice').textContent).toContain(
      '"notes.txt" waits on your bin'
    );

    await landSnapshot(engine, folderView({ children: [file(NOTE, 'notes.txt')] }));

    expect(screen.queryByTestId('queue-hold-notice')).toBeNull();
  });
});

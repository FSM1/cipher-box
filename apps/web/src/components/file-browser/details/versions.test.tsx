import { toHex, type CommandOutcomeDescriptor } from '@cipherbox/client';
import { act, fireEvent, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  renderWithEngine,
  versionEngine,
  versionEntry,
  type VersionEngineOptions,
} from '../../../test/versionFakes';
import { trackSaves } from '../../../test/saveSpy';
import type { ListingRow } from '../../../vault/listing';
import { DetailsDialog } from '../DetailsDialog';

const NODE = new Uint8Array(4).fill(0xab);
const OTHER_NODE = new Uint8Array(4).fill(0xcd);
const OLDER = versionEntry(0x11, { size: 2048n });
const OLDEST = versionEntry(0x22);
const OLDER_CID = toHex(OLDER.contentCid);
const OLDEST_CID = toHex(OLDEST.contentCid);

function fileRow(overrides: Partial<ListingRow> = {}): ListingRow {
  return {
    id: NODE,
    key: 'abababab',
    name: 'notes.txt',
    storedName: 'notes.txt',
    kind: 'file',
    icon: '[FILE]',
    size: '12 B',
    bytes: 12n,
    contentVersion: 3n,
    contentCid: null,
    modified: '14 Nov 2023',
    pending: 'none',
    deadLetter: false,
    pendingInviteClaims: 0,
    ...overrides,
  };
}

function openDetails(options: VersionEngineOptions = {}, onClose = () => undefined) {
  const engine = versionEngine(options);
  const view = renderWithEngine(
    <DetailsDialog row={fileRow()} access="owner" onClose={onClose} />,
    engine.client
  );
  return { ...engine, view };
}

/** The label a version's controls carry, which is its clamped content root CID. */
function clamped(cid: string): string {
  return `${cid.slice(0, 8)}…${cid.slice(-6)}`;
}

function control(action: string, cid: string): HTMLElement {
  return screen.getByLabelText(`${action} version ${clamped(cid)}`);
}

afterEach(() => vi.restoreAllMocks());

describe('the version history', () => {
  it('lists the prior versions the engine answers with, for the node on screen', async () => {
    const engine = openDetails({ entries: [OLDER, OLDEST] });

    await waitFor(() => expect(screen.getByTestId('version-history')).toBeDefined());
    expect(engine.facade.fileVersions).toHaveBeenCalledWith(NODE);
    expect(screen.getByTestId(`version-${OLDER_CID}`)).toBeDefined();
    expect(screen.getByTestId(`version-${OLDEST_CID}`)).toBeDefined();
    expect(screen.getByTestId(`version-${OLDER_CID}`).textContent).toContain('2 KB');
  });

  it('renders no history section for a file the engine holds no prior version of', async () => {
    const engine = openDetails();

    await waitFor(() => expect(engine.facade.fileVersions).toHaveBeenCalledOnce());
    expect(screen.queryByTestId('version-history')).toBeNull();
  });

  it('downloads the version the control names, and saves it under the file name', async () => {
    const saves = trackSaves();
    try {
      const engine = openDetails({ entries: [OLDER, OLDEST] });
      await waitFor(() => expect(screen.getByTestId('version-history')).toBeDefined());

      fireEvent.click(control('download', OLDEST_CID));

      await waitFor(() =>
        expect(engine.facade.downloadVersion).toHaveBeenCalledWith(NODE, OLDEST.contentCid)
      );
      await waitFor(() => expect(saves.clicked).toHaveLength(1));
      expect(saves.clicked[0].download).toBe('notes.txt');
    } finally {
      saves.restore();
    }
  });

  it('restores nothing until the confirmation is answered', async () => {
    const engine = openDetails({ entries: [OLDER, OLDEST] });
    await waitFor(() => expect(screen.getByTestId('version-history')).toBeDefined());

    fireEvent.click(control('restore', OLDER_CID));

    expect(screen.getByTestId('version-restore-dialog')).toBeDefined();
    expect(engine.facade.restoreVersion).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId('version-restore-confirm'));

    await waitFor(() =>
      expect(engine.facade.restoreVersion).toHaveBeenCalledWith(NODE, OLDER.contentCid)
    );
  });

  it('re-reads the list once a restore is accepted', async () => {
    const engine = openDetails({ entries: [OLDER, OLDEST] });
    await waitFor(() => expect(screen.getByTestId('version-history')).toBeDefined());

    fireEvent.click(control('restore', OLDER_CID));
    fireEvent.click(screen.getByTestId('version-restore-confirm'));

    await waitFor(() => expect(screen.queryByTestId(`version-${OLDER_CID}`)).toBeNull());
    expect(engine.facade.fileVersions).toHaveBeenCalledTimes(2);
    expect(screen.queryByTestId('version-restore-dialog')).toBeNull();
    expect(screen.getByTestId(`version-${OLDEST_CID}`)).toBeDefined();
  });

  it('deletes nothing until the confirmation is answered', async () => {
    const engine = openDetails({ entries: [OLDER, OLDEST] });
    await waitFor(() => expect(screen.getByTestId('version-history')).toBeDefined());

    fireEvent.click(control('delete', OLDEST_CID));

    expect(screen.getByTestId('version-delete-dialog')).toBeDefined();
    expect(engine.facade.deleteVersion).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId('version-delete-confirm'));

    await waitFor(() =>
      expect(engine.facade.deleteVersion).toHaveBeenCalledWith(NODE, OLDEST.contentCid)
    );
    await waitFor(() => expect(engine.facade.fileVersions).toHaveBeenCalledTimes(2));
  });

  it('holds the confirmation up and reports the refusal the engine answered with', async () => {
    const engine = openDetails({
      entries: [OLDER],
      refusals: { deleteVersion: new Error('the current version cannot be deleted') },
    });
    await waitFor(() => expect(screen.getByTestId('version-history')).toBeDefined());

    fireEvent.click(control('delete', OLDER_CID));
    fireEvent.click(screen.getByTestId('version-delete-confirm'));

    await waitFor(() =>
      expect(screen.getByTestId('dialog-error').textContent).toContain(
        'the current version cannot be deleted'
      )
    );
    expect(screen.getByTestId('version-delete-dialog')).toBeDefined();
    expect(engine.facade.fileVersions).toHaveBeenCalledOnce();
  });

  it('refuses to dismiss the details dialog while a version command is in flight', async () => {
    const onClose = vi.fn();
    openDetails({ entries: [OLDER], hold: ['downloadVersion'] }, onClose);
    await waitFor(() => expect(screen.getByTestId('version-history')).toBeDefined());

    fireEvent.click(control('download', OLDER_CID));

    await waitFor(() => expect(screen.getByLabelText('close').hasAttribute('disabled')).toBe(true));
    fireEvent.keyDown(document, { key: 'Escape' });
    fireEvent.mouseDown(screen.getByTestId('modal-backdrop'));

    expect(onClose).not.toHaveBeenCalled();
  });

  it('stays dismissible while the versions read is still in flight', async () => {
    const onClose = vi.fn();
    openDetails({ entries: [OLDER], hold: ['fileVersions'] }, onClose);

    await waitFor(() =>
      expect(screen.getByLabelText('close').hasAttribute('disabled')).toBe(false)
    );
    fireEvent.click(screen.getByLabelText('close'));

    expect(onClose).toHaveBeenCalledOnce();
  });

  it('reports a failed read of the list, which leaves no entry to report it against', async () => {
    openDetails({ refusals: { fileVersions: new Error('the versions could not be read') } });

    await waitFor(() =>
      expect(screen.getByTestId('version-error').textContent).toContain(
        'the versions could not be read'
      )
    );
  });

  it('holds the confirmation locked until the re-read after the write lands', async () => {
    const engine = openDetails({ entries: [OLDER, OLDEST] });
    await waitFor(() => expect(screen.getByTestId('version-history')).toBeDefined());

    fireEvent.click(control('delete', OLDEST_CID));
    // The re-read never settles, so the write is still the dialog's to own.
    engine.facade.fileVersions.mockImplementation(() => new Promise<never>(() => undefined));
    fireEvent.click(screen.getByTestId('version-delete-confirm'));

    await waitFor(() => expect(engine.facade.fileVersions).toHaveBeenCalledTimes(2));
    expect(screen.getByTestId('version-delete-confirm').hasAttribute('disabled')).toBe(true);

    fireEvent.click(screen.getByTestId('version-delete-confirm'));
    expect(engine.facade.deleteVersion).toHaveBeenCalledOnce();
  });

  it('drops the list of the node it left when the dialog is shown another node', async () => {
    const engine = openDetails({ entries: [OLDER, OLDEST] });
    await waitFor(() => expect(screen.getByTestId('version-history')).toBeDefined());

    // The next node's read never settles, so only a cleared list can hide the
    // entries the previous node answered with.
    engine.facade.fileVersions.mockImplementation(() => new Promise<never>(() => undefined));
    engine.view.rerender(
      <DetailsDialog row={fileRow({ id: OTHER_NODE })} access="owner" onClose={() => undefined} />
    );

    await waitFor(() => expect(screen.queryByTestId('version-history')).toBeNull());
  });

  it('retires an unanswered confirmation when the dialog is shown another node', async () => {
    const engine = openDetails({ entries: [OLDER, OLDEST] });
    await waitFor(() => expect(screen.getByTestId('version-history')).toBeDefined());

    fireEvent.click(control('restore', OLDER_CID));
    expect(screen.getByTestId('version-restore-dialog')).toBeDefined();

    engine.view.rerender(
      <DetailsDialog row={fileRow({ id: OTHER_NODE })} access="owner" onClose={() => undefined} />
    );

    expect(screen.queryByTestId('version-restore-dialog')).toBeNull();
  });

  it('offers no version write in a scope this vault only reads', async () => {
    const engine = versionEngine({ entries: [OLDER, OLDEST] });
    renderWithEngine(
      <DetailsDialog row={fileRow()} access="read-only" onClose={() => undefined} />,
      engine.client
    );

    await waitFor(() => expect(screen.getByTestId('version-history')).toBeDefined());
    // The read affordance stays: a read grant carries the seed the download needs.
    expect(control('download', OLDER_CID)).toBeDefined();
    expect(screen.queryByLabelText(`restore version ${clamped(OLDER_CID)}`)).toBeNull();
    expect(screen.queryByLabelText(`delete version ${clamped(OLDEST_CID)}`)).toBeNull();
  });

  it('offers a restore and no delete in a share granted for writing', async () => {
    const engine = versionEngine({ entries: [OLDER, OLDEST] });
    renderWithEngine(
      <DetailsDialog row={fileRow()} access="write-grant" onClose={() => undefined} />,
      engine.client
    );

    await waitFor(() => expect(screen.getByTestId('version-history')).toBeDefined());
    expect(control('download', OLDER_CID)).toBeDefined();
    fireEvent.click(control('restore', OLDER_CID));
    fireEvent.click(screen.getByTestId('version-restore-confirm'));
    await waitFor(() =>
      expect(engine.facade.restoreVersion).toHaveBeenCalledWith(NODE, OLDER.contentCid)
    );
    expect(screen.queryByLabelText(`delete version ${clamped(OLDEST_CID)}`)).toBeNull();
  });

  it('retires an unanswered confirmation when the scope turns read-only', async () => {
    const engine = openDetails({ entries: [OLDER, OLDEST] });
    await waitFor(() => expect(screen.getByTestId('version-history')).toBeDefined());

    fireEvent.click(control('delete', OLDEST_CID));
    expect(screen.getByTestId('version-delete-dialog')).toBeDefined();

    engine.view.rerender(
      <DetailsDialog row={fileRow()} access="read-only" onClose={() => undefined} />
    );

    expect(screen.queryByTestId('version-delete-dialog')).toBeNull();
    expect(engine.facade.deleteVersion).not.toHaveBeenCalled();
  });

  it('retires a delete confirmation and keeps a restore one when the access drops to a write grant', async () => {
    const engine = openDetails({ entries: [OLDER, OLDEST] });
    await waitFor(() => expect(screen.getByTestId('version-history')).toBeDefined());

    fireEvent.click(control('delete', OLDEST_CID));
    engine.view.rerender(
      <DetailsDialog row={fileRow()} access="write-grant" onClose={() => undefined} />
    );
    expect(screen.queryByTestId('version-delete-dialog')).toBeNull();
    expect(engine.facade.deleteVersion).not.toHaveBeenCalled();

    engine.view.rerender(
      <DetailsDialog row={fileRow()} access="owner" onClose={() => undefined} />
    );
    fireEvent.click(control('restore', OLDER_CID));
    engine.view.rerender(
      <DetailsDialog row={fileRow()} access="write-grant" onClose={() => undefined} />
    );
    expect(screen.getByTestId('version-restore-dialog')).toBeDefined();
  });

  it('does not re-read for a node the dialog left while its write was in flight', async () => {
    const engine = openDetails({ entries: [OLDER, OLDEST] });
    await waitFor(() => expect(screen.getByTestId('version-history')).toBeDefined());

    let land = (): void => undefined;
    engine.facade.deleteVersion.mockImplementation(
      () =>
        new Promise<CommandOutcomeDescriptor>((resolve) => {
          land = () => resolve({ kind: 'done' });
        })
    );
    fireEvent.click(control('delete', OLDEST_CID));
    fireEvent.click(screen.getByTestId('version-delete-confirm'));
    await waitFor(() => expect(engine.facade.deleteVersion).toHaveBeenCalledOnce());

    engine.view.rerender(
      <DetailsDialog row={fileRow({ id: OTHER_NODE })} access="owner" onClose={() => undefined} />
    );
    await waitFor(() => expect(engine.facade.fileVersions).toHaveBeenCalledTimes(2));
    expect(engine.facade.fileVersions).toHaveBeenLastCalledWith(OTHER_NODE);

    // The read the new node asked for stays the last one. A re-read for the node
    // the write named would land the previous node's list on this one.
    await act(async () => {
      land();
      await new Promise((resolve) => setTimeout(resolve, 0));
    });

    expect(engine.facade.fileVersions).toHaveBeenCalledTimes(2);
  });

  it('keeps a new confirmation when a write from an earlier display of the node lands', async () => {
    const engine = openDetails({ entries: [OLDER, OLDEST] });
    await waitFor(() => expect(screen.getByTestId('version-history')).toBeDefined());

    let land = (): void => undefined;
    engine.facade.deleteVersion.mockImplementation(
      () =>
        new Promise<CommandOutcomeDescriptor>((resolve) => {
          land = () => resolve({ kind: 'done' });
        })
    );
    fireEvent.click(control('delete', OLDEST_CID));
    fireEvent.click(screen.getByTestId('version-delete-confirm'));
    await waitFor(() => expect(engine.facade.deleteVersion).toHaveBeenCalledOnce());

    // The dialog leaves the node and is shown it again, while the write is still
    // in flight. Each display reads the list, so the entries come back.
    engine.view.rerender(
      <DetailsDialog row={fileRow({ id: OTHER_NODE })} access="owner" onClose={() => undefined} />
    );
    await waitFor(() => expect(engine.facade.fileVersions).toHaveBeenLastCalledWith(OTHER_NODE));
    engine.view.rerender(
      <DetailsDialog row={fileRow()} access="owner" onClose={() => undefined} />
    );
    await waitFor(() => expect(control('restore', OLDER_CID).hasAttribute('disabled')).toBe(false));

    fireEvent.click(control('restore', OLDER_CID));
    expect(screen.getByTestId('version-restore-dialog')).toBeDefined();

    await act(async () => {
      land();
      await new Promise((resolve) => setTimeout(resolve, 0));
    });

    // The write named the earlier display, so it may not answer this one.
    expect(screen.getByTestId('version-restore-dialog')).toBeDefined();
  });

  it('refuses to dismiss the details dialog under an unanswered confirmation', async () => {
    const onClose = vi.fn();
    openDetails({ entries: [OLDER] }, onClose);
    await waitFor(() => expect(screen.getByTestId('version-history')).toBeDefined());

    fireEvent.click(control('restore', OLDER_CID));
    fireEvent.mouseDown(screen.getAllByTestId('modal-backdrop')[0]);

    expect(onClose).not.toHaveBeenCalled();
  });
});

import { toHex } from '@cipherbox/client';
import { fireEvent, screen, waitFor } from '@testing-library/react';
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
    ...overrides,
  };
}

function openDetails(options: VersionEngineOptions = {}, onClose = () => undefined) {
  const engine = versionEngine(options);
  renderWithEngine(<DetailsDialog row={fileRow()} onClose={onClose} />, engine.client);
  return engine;
}

/** The label a version's controls carry, which is its clamped content root CID. */
function control(action: string, cid: string): HTMLElement {
  const named = `${cid.slice(0, 8)}…${cid.slice(-6)}`;
  return screen.getByLabelText(`${action} version ${named}`);
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

  it('refuses to dismiss the details dialog under an unanswered confirmation', async () => {
    const onClose = vi.fn();
    openDetails({ entries: [OLDER] }, onClose);
    await waitFor(() => expect(screen.getByTestId('version-history')).toBeDefined());

    fireEvent.click(control('restore', OLDER_CID));
    fireEvent.mouseDown(screen.getAllByTestId('modal-backdrop')[0]);

    expect(onClose).not.toHaveBeenCalled();
  });
});

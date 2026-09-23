import { EngineRequestError } from '@cipherbox/client';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { EngineProvider } from '../../providers/EngineProvider';
import { VaultStorageProvider } from '../../providers/VaultStorageProvider';
import { ROOT_ID, fakeEngine, view } from '../../engine/testFakes';
import { FileBrowser } from './FileBrowser';

function draw(client: ReturnType<typeof fakeEngine>['client']) {
  return render(
    <MemoryRouter initialEntries={['/files']}>
      <EngineProvider createClient={() => client}>
        <VaultStorageProvider>
          <Routes>
            <Route path="/files/:nodeId?" element={<FileBrowser />} />
          </Routes>
        </VaultStorageProvider>
      </EngineProvider>
    </MemoryRouter>
  );
}

/** Renders the browser with two rows on screen, then fails its next pull. */
async function listedThenFailed(failure: Error) {
  const engine = fakeEngine();
  draw(engine.client);

  await act(async () => {
    engine.emit({ kind: 'snapshotUpdated' });
  });
  await act(async () => {
    engine.pulls[0].resolve(view(ROOT_ID, 'fresh', 2));
  });
  await waitFor(() => expect(screen.getAllByTestId('file-list-item')).toHaveLength(2));

  await act(async () => {
    engine.emit({ kind: 'snapshotUpdated' });
  });
  await act(async () => {
    engine.pulls[1].reject(failure);
  });
  return engine;
}

describe('the vault browser', () => {
  it('keeps the listing on screen when a refusal is recoverable', async () => {
    await listedThenFailed(
      new EngineRequestError('too many read streams are already open', 'tooManyStreams')
    );

    const notice = await screen.findByTestId('file-browser-notice');
    expect(notice.textContent).toContain('too many read streams are already open');
    // The gate is the rows, not the notice: a blanked listing must not pass.
    expect(screen.getAllByTestId('file-list-item')).toHaveLength(2);
    expect(screen.queryByTestId('file-browser-error')).toBeNull();
  });

  it('blanks the listing on a failure that will not clear', async () => {
    await listedThenFailed(new EngineRequestError('no such node', 'unknownNode'));

    const error = await screen.findByTestId('file-browser-error');
    expect(error.textContent).toBe('no such node');
    expect(screen.queryAllByTestId('file-list-item')).toHaveLength(0);
    expect(screen.queryByTestId('file-browser-notice')).toBeNull();
  });

  it('treats an engine code it does not recognise as fatal', async () => {
    await listedThenFailed(new EngineRequestError('something new', 'someFutureCeiling'));

    expect(await screen.findByTestId('file-browser-error')).toBeTruthy();
    expect(screen.queryAllByTestId('file-list-item')).toHaveLength(0);
  });

  /**
   * The engine refuses a write in a read-granted share at the journal call. The
   * browser must refuse at the gesture instead of offering one the engine will
   * not take.
   */
  it('offers no write affordance in a scope another vault shared for reading', async () => {
    const engine = fakeEngine();
    draw(engine.client);

    await act(async () => {
      engine.emit({ kind: 'snapshotUpdated' });
    });
    await act(async () => {
      engine.pulls[0].resolve({
        ...view(ROOT_ID, 'fresh', 2),
        permission: 'read',
        receivedShare: true,
      });
    });
    await screen.findByTestId('read-only-scope');

    expect(screen.getAllByTestId('file-list-item')).toHaveLength(2);
    expect(screen.queryByTestId('new-folder-button')).toBeNull();
    expect(screen.queryByTestId('upload-zone')).toBeNull();

    await act(async () => {
      fireEvent.click(screen.getAllByTestId('file-list-item-menu')[0]);
    });
    const labels = screen.getAllByRole('menuitem').map((item) => item.textContent);
    expect(labels).toEqual(['download', 'details']);
  });

  /**
   * The engine reports `write` in a share only once it holds the write pass, so
   * a write grant gets the writes that stay inside the share and none of the
   * owner's actions.
   */
  it('offers the in-share writes in a share granted for writing', async () => {
    const engine = fakeEngine();
    draw(engine.client);

    await act(async () => {
      engine.emit({ kind: 'snapshotUpdated' });
    });
    const listed = view(ROOT_ID, 'fresh', 1);
    await act(async () => {
      engine.pulls[0].resolve({
        ...listed,
        permission: 'write',
        receivedShare: true,
        children: listed.children.map((child) => ({ ...child, kind: 'folder' })),
      });
    });
    await screen.findByTestId('new-folder-button');

    expect(screen.queryByTestId('read-only-scope')).toBeNull();
    expect(screen.getByTestId('upload-zone')).toBeTruthy();
    await act(async () => {
      fireEvent.click(screen.getAllByTestId('file-list-item-menu')[0]);
    });
    const labels = screen.getAllByRole('menuitem').map((item) => item.textContent);
    expect(labels).toEqual(['rename', 'move to...', 'details', 'delete']);
  });

  it('offers the write affordances in a scope this vault writes', async () => {
    const engine = fakeEngine();
    draw(engine.client);

    await act(async () => {
      engine.emit({ kind: 'snapshotUpdated' });
    });
    await act(async () => {
      engine.pulls[0].resolve(view(ROOT_ID, 'fresh', 2));
    });
    await screen.findByTestId('new-folder-button');

    expect(screen.queryByTestId('read-only-scope')).toBeNull();
    expect(screen.getByTestId('upload-zone')).toBeTruthy();
  });

  /**
   * A gated menu entry does not reach a dialog the user opened while the scope
   * was still writable, and that dialog's confirm is a write.
   */
  it('takes an open write dialog down when the browse enters a shared scope', async () => {
    const engine = fakeEngine();
    draw(engine.client);

    await act(async () => {
      engine.emit({ kind: 'snapshotUpdated' });
    });
    await act(async () => {
      engine.pulls[0].resolve(view(ROOT_ID, 'fresh', 2));
    });
    await screen.findByTestId('new-folder-button');

    await act(async () => {
      fireEvent.click(screen.getAllByTestId('file-list-item-menu')[0]);
    });
    await act(async () => {
      fireEvent.click(screen.getByText('rename'));
    });
    expect(screen.getByTestId('rename-dialog')).toBeTruthy();

    await act(async () => {
      engine.emit({ kind: 'snapshotUpdated' });
    });
    await act(async () => {
      engine.pulls[1].resolve({
        ...view(ROOT_ID, 'fresh', 2),
        permission: 'read',
        receivedShare: true,
      });
    });
    await screen.findByTestId('read-only-scope');

    expect(screen.queryByTestId('rename-dialog')).toBeNull();

    // The dialog state goes with the dialog, so a scope the engine reports
    // writable again raises nothing the member did not ask for.
    await act(async () => {
      engine.emit({ kind: 'snapshotUpdated' });
    });
    await act(async () => {
      engine.pulls[2].resolve(view(ROOT_ID, 'fresh', 2));
    });
    await screen.findByTestId('new-folder-button');

    expect(screen.queryByTestId('rename-dialog')).toBeNull();
  });

  it('re-drives the pull from the recoverable notice', async () => {
    const engine = await listedThenFailed(
      new EngineRequestError('too many read streams are already open', 'tooManyStreams')
    );
    await screen.findByTestId('file-browser-notice');
    expect(engine.refreshes()).toBe(0);

    await act(async () => {
      fireEvent.click(screen.getByText('[retry]'));
    });

    expect(engine.refreshes()).toBe(1);
    await act(async () => {
      engine.pulls[2].resolve(view(ROOT_ID, 'fresh', 2));
    });
    await waitFor(() => expect(screen.queryByTestId('file-browser-notice')).toBeNull());
    expect(screen.getAllByTestId('file-list-item')).toHaveLength(2);
  });

  it('marks a row whose invite claims wait, until the engine counts none', async () => {
    const engine = fakeEngine();
    draw(engine.client);
    const waiting = (claims: number) => {
      const listed = view(ROOT_ID, 'fresh', 2);
      listed.children[0] = { ...listed.children[0], kind: 'folder', pendingInviteClaims: claims };
      return listed;
    };

    await act(async () => {
      engine.emit({ kind: 'snapshotUpdated' });
    });
    await act(async () => {
      engine.pulls[0].resolve(waiting(2));
    });
    const badge = await screen.findByTestId('file-list-item-claims');
    expect(badge.textContent).toBe('[2 claims]');
    expect(screen.getAllByTestId('file-list-item-claims')).toHaveLength(1);

    await act(async () => {
      engine.emit({ kind: 'snapshotUpdated' });
    });
    await act(async () => {
      engine.pulls[1].resolve(waiting(0));
    });
    await waitFor(() => expect(screen.queryByTestId('file-list-item-claims')).toBeNull());
  });
});

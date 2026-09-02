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
});

import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { RequireAuth } from '../auth/RequireAuth';
import { authWrapper, fakeCoreKitSession, fakeEngineClient } from '../test/authFakes';
import { FilesPage } from './FilesPage';

/** Longer than the provider's restore deadline, so the wait is over. */
const PAST_DEADLINE_MS = 30_000;

function renderDeepLink(coreKit: ReturnType<typeof fakeCoreKitSession>) {
  const Wrapper = authWrapper(fakeEngineClient().client, coreKit.session);
  render(
    <Wrapper>
      <MemoryRouter initialEntries={['/files']}>
        <Routes>
          <Route path="/" element={<p>FRONT DOOR</p>} />
          <Route
            path="/files/:nodeId?"
            element={
              <RequireAuth>
                <FilesPage />
              </RequireAuth>
            }
          />
        </Routes>
      </MemoryRouter>
    </Wrapper>
  );
}

const frontDoor = () => screen.queryByText('FRONT DOOR');

describe('the vault route with no session', () => {
  afterEach(() => vi.useRealTimers());

  it('returns an unauthenticated deep link to the front door', async () => {
    renderDeepLink(fakeCoreKitSession());

    await waitFor(() => expect(frontDoor()).not.toBeNull());
  });

  it('returns the deep link to the front door when the session provider never resolves', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    renderDeepLink(fakeCoreKitSession({ restore: () => new Promise<void>(() => undefined) }));

    // The redirect must not depend on the provider ever answering.
    expect(frontDoor()).toBeNull();
    await vi.advanceTimersByTimeAsync(PAST_DEADLINE_MS);

    await waitFor(() => expect(frontDoor()).not.toBeNull());
  });

  it('keeps showing progress while the check is genuinely still in flight', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    let land!: () => void;
    renderDeepLink(
      fakeCoreKitSession({ restore: () => new Promise<void>((resolve) => (land = resolve)) })
    );

    await waitFor(() => expect(screen.queryByTestId('files-signing-in')).not.toBeNull());
    await vi.advanceTimersByTimeAsync(1_000);

    expect(frontDoor()).toBeNull();
    expect(screen.queryByTestId('files-signing-in')).not.toBeNull();
    land();
  });
});

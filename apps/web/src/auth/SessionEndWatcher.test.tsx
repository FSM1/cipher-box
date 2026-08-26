import { act, renderHook, waitFor } from '@testing-library/react';
import type { ReactNode } from 'react';
import { beforeEach, describe, expect, it } from 'vitest';
import { authStore } from '../stores/auth.store';
import { authWrapper, fakeCoreKitSession, fakeEngineClient } from '../test/authFakes';
import { SessionEndWatcher } from './SessionEndWatcher';
import { useAuth } from './useAuth';

/**
 * Mounts the watcher where both seams it reads resolve, as the app does, and
 * signs in deliberately: the flow latches a session end until the next login, so
 * a restored session would read whatever the previous test left latched.
 */
async function signedInTab(
  engine: ReturnType<typeof fakeEngineClient>,
  coreKit: ReturnType<typeof fakeCoreKitSession>
) {
  const Auth = authWrapper(engine.client, coreKit.session);
  const { result } = renderHook(() => useAuth(), {
    wrapper: ({ children }: { children: ReactNode }) => (
      <Auth>
        <SessionEndWatcher />
        {children}
      </Auth>
    ),
  });
  await waitFor(() => expect(result.current.isReady).toBe(true));
  await act(() => result.current.loginWithGoogle('google.id.token'));
  return result;
}

describe('the session end another tab announced', () => {
  beforeEach(() => authStore.signedOut());

  it('tears this tab down rather than leaving its chrome signed in', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession();
    const result = await signedInTab(engine, coreKit);

    act(() => engine.endSessionElsewhere());

    await waitFor(() => expect(engine.calls.logouts).toBe(1));
    expect(coreKit.calls.logouts).toBe(1);
    await waitFor(() => expect(result.current.isSignedOut).toBe(true));
  });

  it('swallows a refused teardown, which the front door can offer nothing for', async () => {
    const engine = fakeEngineClient({ logout: () => Promise.reject(new Error('engine gone')) });
    const coreKit = fakeCoreKitSession();
    const result = await signedInTab(engine, coreKit);

    const unhandled: unknown[] = [];
    const record = (event: PromiseRejectionEvent) => unhandled.push(event.reason);
    window.addEventListener('unhandledrejection', record);
    try {
      act(() => engine.endSessionElsewhere());
      await waitFor(() => expect(engine.calls.logouts).toBe(1));
      // A turn past the rejection, so an unhandled one would have fired by now.
      await act(() => Promise.resolve());
    } finally {
      window.removeEventListener('unhandledrejection', record);
    }

    expect(unhandled).toEqual([]);
    expect(coreKit.calls.logouts).toBe(1);
    await waitFor(() => expect(result.current.isSignedOut).toBe(true));
  });
});

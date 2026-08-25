import { StrictMode, type ReactNode } from 'react';
import { EngineRequestError } from '@cipherbox/client';
import type { EngineClient } from '@cipherbox/client';
import { act, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { EngineProvider } from '../providers/EngineProvider';
import { InvitePage } from './InvitePage';

/** Stands in for the engine's opaque capability; the page reads none of it. */
const FRAGMENT = 'a-link-fragment';

/**
 * The engine as the claim route sees it, with the address bar sampled at the
 * moment the claim is dispatched — the ordering the capability's exposure window
 * depends on.
 */
function claimEngine(refusal: Error | null = null, signedIn = true) {
  const hashAtDispatch: string[] = [];
  const claimInviteLink = vi.fn((_fragment: string) => {
    hashAtDispatch.push(window.location.hash);
    return refusal === null ? Promise.resolve({ kind: 'done' as const }) : Promise.reject(refusal);
  });
  const client = {
    subscribeSession: () => () => undefined,
    signedInAccount: () => (signedIn ? 'acct01' : null),
    facade: {
      subscribe: () => () => undefined,
      snapshot: () => new Promise<never>(() => undefined),
      setFocus: () => Promise.resolve(),
      claimInviteLink,
    },
    reportFocus: () => undefined,
    dispose: () => Promise.resolve(),
  } as unknown as EngineClient;
  return { client, claimInviteLink, hashAtDispatch };
}

/**
 * Mounts the route under `StrictMode`, so its double-invoked effect stands for
 * the remount a real tab can make: a link is spent once or not at all.
 */
async function claimAt(hash: string, engine = claimEngine()) {
  window.location.hash = hash;
  const wrapper = ({ children }: { children: ReactNode }) => (
    <StrictMode>
      <MemoryRouter>
        <EngineProvider createClient={() => engine.client}>{children}</EngineProvider>
      </MemoryRouter>
    </StrictMode>
  );
  await act(async () => {
    render(wrapper({ children: <InvitePage /> }));
  });
  return engine;
}

afterEach(() => window.history.replaceState(null, '', '/'));

describe('the invite claim route', () => {
  it('hands the fragment to the facade verbatim, once, and holds none of it', async () => {
    const { claimInviteLink } = await claimAt(`#${FRAGMENT}`);

    expect(claimInviteLink.mock.calls).toEqual([[FRAGMENT]]);
    // Nothing rendered it, so nothing screenshots, logs, or restores it.
    expect(document.body.innerHTML).not.toContain(FRAGMENT);
    expect(screen.getByTestId('invite-claim').dataset.state).toBe('claimed');
  });

  it('clears the address bar before the claim is awaited', async () => {
    const { hashAtDispatch } = await claimAt(`#${FRAGMENT}`);

    expect(hashAtDispatch).toEqual(['']);
    expect(window.location.hash).toBe('');
  });

  it('claims nothing at an address that carries no link', async () => {
    const { claimInviteLink } = await claimAt('');

    expect(claimInviteLink).not.toHaveBeenCalled();
    expect(screen.getByTestId('invite-claim').dataset.state).toBe('noLink');
  });

  it("renders the engine's refusal in its own words", async () => {
    const refusal = new EngineRequestError('malformed-invite-fragment', 'malformedInput');
    await claimAt(`#${FRAGMENT}`, claimEngine(refusal));

    expect(screen.getByTestId('invite-error').textContent).toBe('malformed-invite-fragment');
    expect(screen.getByTestId('invite-claim').dataset.state).toBe('refused');
  });

  it('leaves the link in the address bar until there is a session to claim with', async () => {
    const { claimInviteLink } = await claimAt(`#${FRAGMENT}`, claimEngine(null, false));

    expect(claimInviteLink).not.toHaveBeenCalled();
    expect(window.location.hash).toBe(`#${FRAGMENT}`);
    expect(screen.getByTestId('invite-claim').dataset.state).toBe('waiting');
  });
});

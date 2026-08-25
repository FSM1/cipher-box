import { StrictMode, type ReactNode } from 'react';
import { EngineRequestError } from '@cipherbox/client';
import type { EngineClient } from '@cipherbox/client';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { BrowserRouter, useLocation } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { WebCoreKitSession } from '../auth/coreKit';
import { authWrapper, fakeCoreKitSession } from '../test/authFakes';
import { InvitePage } from './InvitePage';

/** Stands in for the engine's opaque capability; the page reads none of it. */
const FRAGMENT = 'a-link-fragment';

/**
 * The engine as the claim route sees it, with the address bar sampled at the
 * moment the claim is dispatched — the ordering the capability's exposure
 * window depends on — and react-router's own location readable after it.
 */
function claimEngine(refusal: Error | null = null, signedIn = true) {
  const addressAtDispatch: string[] = [];
  let routerHash = '';
  const listeners = new Set<() => void>();
  let account: string | null = signedIn ? 'acct01' : null;
  const claimInviteLink = vi.fn((_fragment: string) => {
    addressAtDispatch.push(window.location.hash);
    return refusal === null ? Promise.resolve({ kind: 'done' as const }) : Promise.reject(refusal);
  });
  const client = {
    subscribeSession(listener: () => void) {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    signedInAccount: () => account,
    facade: {
      subscribe: () => () => undefined,
      snapshot: () => new Promise<never>(() => undefined),
      setFocus: () => Promise.resolve(),
      // The hand-off a restored Core Kit session owes the engine; it is what
      // gives this tab an account to claim with.
      start(_secret: ArrayBuffer, accountId: string) {
        account = accountId;
        for (const listener of [...listeners]) listener();
        return Promise.resolve();
      },
      claimInviteLink,
    },
    reportFocus: () => undefined,
    dispose: () => Promise.resolve(),
  } as unknown as EngineClient;
  /** Reports what react-router's own location still carries. */
  function RouterHash() {
    routerHash = useLocation().hash;
    return null;
  }
  return { client, claimInviteLink, addressAtDispatch, RouterHash, routerHash: () => routerHash };
}

/**
 * Mounts the route under `StrictMode`, so its double-invoked lifecycle stands
 * for the remount a real tab can make: a link is spent once or not at all.
 */
async function openAt(
  hash: string,
  engine = claimEngine(),
  session: WebCoreKitSession = fakeCoreKitSession().session
) {
  window.history.replaceState(null, '', `/invite${hash}`);
  const Providers = authWrapper(engine.client, session);
  const wrapper = ({ children }: { children: ReactNode }) => (
    <StrictMode>
      <Providers>
        <BrowserRouter>
          <engine.RouterHash />
          {children}
        </BrowserRouter>
      </Providers>
    </StrictMode>
  );
  await act(async () => {
    render(wrapper({ children: <InvitePage /> }));
  });
  return engine;
}

/** Presses the claim control and lets the command settle. */
async function claim() {
  await act(async () => {
    fireEvent.click(screen.getByTestId('invite-claim-confirm'));
  });
}

afterEach(() => window.history.replaceState(null, '', '/'));

describe('the invite claim route', () => {
  it('spends nothing until the member asks for it', async () => {
    // A page that claimed on mount would spend a link for any site that can
    // navigate a signed-in tab here.
    const { claimInviteLink } = await openAt(`#${FRAGMENT}`);

    expect(claimInviteLink).not.toHaveBeenCalled();
    expect(screen.getByTestId('invite-claim').dataset.state).toBe('ready');
    expect(screen.getByTestId('invite-account').textContent).toContain('acct01');
  });

  it('hands the fragment to the facade verbatim, once, and holds none of it', async () => {
    const { claimInviteLink } = await openAt(`#${FRAGMENT}`);

    await claim();

    expect(claimInviteLink.mock.calls).toEqual([[FRAGMENT]]);
    // Nothing rendered it, so nothing screenshots, logs, or restores it.
    expect(document.body.innerHTML).not.toContain(FRAGMENT);
    expect(screen.getByTestId('invite-claim').dataset.state).toBe('claimed');
  });

  it('clears the address bar before the await, and the router location with it', async () => {
    const engine = await openAt(`#${FRAGMENT}`);

    await claim();

    expect(engine.addressAtDispatch).toEqual(['']);
    expect(window.location.hash).toBe('');
    // Cleared through the router, so its in-memory location drops it too — a
    // raw `history.replaceState` would leave the capability there for the tab's
    // life.
    expect(engine.routerHash()).toBe('');
  });

  it('offers no claim at an address that carries no link', async () => {
    const { claimInviteLink } = await openAt('');

    expect(claimInviteLink).not.toHaveBeenCalled();
    expect(screen.getByTestId('invite-claim').dataset.state).toBe('noLink');
    expect(screen.queryByTestId('invite-claim-confirm')).toBeNull();
  });

  it("renders the engine's refusal in its own words", async () => {
    const refusal = new EngineRequestError('malformed-invite-fragment', 'malformedInput');
    await openAt(`#${FRAGMENT}`, claimEngine(refusal));

    await claim();

    expect(screen.getByRole('alert').textContent).toBe('malformed-invite-fragment');
    expect(screen.getByTestId('invite-claim').dataset.state).toBe('refused');
  });

  it('leaves the link in the address bar until there is a session to claim with', async () => {
    const { claimInviteLink } = await openAt(`#${FRAGMENT}`, claimEngine(null, false));

    expect(claimInviteLink).not.toHaveBeenCalled();
    expect(window.location.hash).toBe(`#${FRAGMENT}`);
    expect(screen.getByTestId('invite-claim').dataset.state).toBe('waiting');
    // A new tab, so signing in does not navigate this one off the capability.
    expect(screen.getByRole('link', { name: 'sign in' }).getAttribute('target')).toBe('_blank');
    // A session is the tab's own, so the sign-in that happens in that new tab
    // reaches this one only across a load.
    expect(screen.getByTestId('invite-recheck')).toBeTruthy();
  });

  it('hands the engine a restored session, so an open link needs no second sign-in', async () => {
    // The route sits outside `RequireAuth`, and nothing else on it would make
    // the hand-off a signed-in browser still owes the engine.
    const engine = claimEngine(null, false);
    const { session } = fakeCoreKitSession({ loggedIn: true });

    await openAt(`#${FRAGMENT}`, engine, session);

    expect(screen.getByTestId('invite-claim').dataset.state).toBe('ready');
    expect(screen.getByTestId('invite-account').textContent).toContain('acct01');
    expect(engine.claimInviteLink).not.toHaveBeenCalled();
  });
});

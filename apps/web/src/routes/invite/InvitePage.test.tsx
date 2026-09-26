import { StrictMode, type ReactNode } from 'react';
import { EngineRequestError, toHex } from '@cipherbox/client';
import type { EngineClient, InvitePreviewDescriptor } from '@cipherbox/client';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { BrowserRouter, Route, Routes, useLocation } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { WebCoreKitSession } from '../../auth/coreKit';
import { authStore } from '../../stores/auth.store';
import { FAKE_PHRASE, fakeCoreKitSession, pageWrapper, signInByEmail } from '../../test/authFakes';
import { InvitePage } from './InvitePage';

/** Stands in for the engine's opaque capability; the page reads none of it. */
const FRAGMENT = 'a-link-fragment';

const SCOPE = new Uint8Array(16).fill(0xab);

function livePreview(overrides: Partial<InvitePreviewDescriptor> = {}): InvitePreviewDescriptor {
  return {
    scope: SCOPE,
    names: { ownerName: 'Ada', folderName: 'trips' },
    permission: 'read',
    state: 'live',
    joined: false,
    listing: [
      { name: 'drafts', kind: 'folder' },
      { name: 'notes.txt', kind: 'file' },
    ],
    ...overrides,
  };
}

interface EngineOptions {
  preview?: (fragment: string) => Promise<InvitePreviewDescriptor>;
  refusal?: Error | null;
  claim?: () => Promise<unknown>;
  signedIn?: boolean;
  started?: Promise<void>;
}

/**
 * The engine as the invite route sees it, with the address bar sampled at the
 * moment the join is dispatched — the ordering the capability's exposure
 * window depends on — and react-router's own location readable after it.
 */
function inviteEngine({
  preview = () => Promise.resolve(livePreview()),
  refusal = null,
  claim = () =>
    refusal === null ? Promise.resolve({ kind: 'done' as const }) : Promise.reject(refusal),
  signedIn = true,
  started = Promise.resolve(),
}: EngineOptions = {}) {
  const addressAtDispatch: string[] = [];
  let routerHash = '';
  const listeners = new Set<() => void>();
  let account: string | null = signedIn ? 'acct01' : null;
  const previewInviteLink = vi.fn((fragment: string) => preview(fragment));
  const claimInviteLink = vi.fn((_fragment: string, _name: string) => {
    addressAtDispatch.push(window.location.hash);
    return claim();
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
      // gives this tab an account to join with.
      async start(_secret: ArrayBuffer, accountId: string) {
        await started;
        account = accountId;
        for (const listener of [...listeners]) listener();
      },
      previewInviteLink,
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
  /** The engine session moving to another account, or signing out. */
  function switchAccount(next: string | null) {
    account = next;
    for (const listener of [...listeners]) listener();
  }
  return {
    client,
    switchAccount,
    previewInviteLink,
    claimInviteLink,
    addressAtDispatch,
    RouterHash,
    routerHash: () => routerHash,
  };
}

/**
 * Mounts the route under `StrictMode`, so its double-invoked lifecycle stands
 * for the remount a real tab can make: a link is spent once or not at all.
 */
async function openAt(
  hash: string,
  engine = inviteEngine(),
  session: WebCoreKitSession = fakeCoreKitSession().session,
  page: ReactNode = <InvitePage />
) {
  window.history.replaceState(null, '', `/invite${hash}`);
  const Providers = pageWrapper(engine.client, session);
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
    render(wrapper({ children: page }));
  });
  return engine;
}

const pageState = () => screen.getByTestId('invite-claim').dataset.state;

/** A preview read the test lands by hand. */
function deferred() {
  let land!: (read: InvitePreviewDescriptor) => void;
  const promise = new Promise<InvitePreviewDescriptor>((resolve) => (land = resolve));
  return { promise, land };
}

/** Claims the test settles by hand, in the order the page made them. */
function heldClaims() {
  const pending: { accept(): void; refuse(words: string): void }[] = [];
  const claim = () =>
    new Promise((resolve, reject) => {
      pending.push({
        accept: () => resolve({ kind: 'done' }),
        refuse: (words) => reject(new Error(words)),
      });
    });
  return { claim, pending };
}

/** The address moving to another link inside the tab, as a pasted link does. */
async function moveTo(hash: string) {
  await act(async () => {
    window.history.pushState(null, '', `/invite${hash}`);
    window.dispatchEvent(new PopStateEvent('popstate'));
  });
}

/** Presses "join" and lets the command settle. */
async function join() {
  await act(async () => {
    fireEvent.click(screen.getByTestId('invite-join'));
  });
}

beforeEach(() => authStore.signedOut());
afterEach(() => window.history.replaceState(null, '', '/'));

describe('the invite preview', () => {
  it('reads the preview with the fragment verbatim and spends nothing', async () => {
    const { previewInviteLink, claimInviteLink } = await openAt(`#${FRAGMENT}`);

    expect(previewInviteLink).toHaveBeenCalledWith(FRAGMENT);
    expect(claimInviteLink).not.toHaveBeenCalled();
    expect(pageState()).toBe('joinable');
    expect(window.location.hash).toBe(`#${FRAGMENT}`);
    expect(document.body.innerHTML).not.toContain(FRAGMENT);
  });

  it('leads with the owner and folder names when the signature verifies', async () => {
    await openAt(`#${FRAGMENT}`);

    expect(screen.getByTestId('invite-headline').textContent).toBe('Ada shared trips with you');
    expect(screen.getByTestId('invite-permission').textContent).toBe('can view');
    expect(screen.getByTestId('invite-account').textContent).toContain('acct01');
  });

  it('shows no owner name and no folder name when the signature does not verify', async () => {
    await openAt(
      `#${FRAGMENT}`,
      inviteEngine({ preview: async () => livePreview({ names: null }) })
    );

    expect(screen.getByTestId('invite-headline').textContent).toBe('a folder was shared with you');
    expect(screen.getAllByTestId('invite-entry')).toHaveLength(2);
    expect(document.body.textContent).not.toContain('Ada');
    expect(document.body.textContent).not.toContain('trips');
  });

  it('lists the direct children by name and kind', async () => {
    await openAt(`#${FRAGMENT}`);

    const entries = screen.getAllByTestId('invite-entry');
    expect(entries.map((entry) => [entry.dataset.kind, entry.textContent])).toEqual([
      ['folder', '[DIR]drafts'],
      ['file', '[FILE]notes.txt'],
    ]);
  });

  it('marks a write link as one that edits', async () => {
    await openAt(
      `#${FRAGMENT}`,
      inviteEngine({ preview: async () => livePreview({ permission: 'write' }) })
    );

    expect(screen.getByTestId('invite-permission').textContent).toBe('can edit');
  });

  it('starts the name field empty and takes an edit', async () => {
    await openAt(`#${FRAGMENT}`);

    const field = screen.getByTestId<HTMLInputElement>('invite-name');
    expect(field.value).toBe('');
    fireEvent.change(field, { target: { value: 'Grace' } });
    expect(field.value).toBe('Grace');
  });

  it.each([
    ['expired', 'this link has expired'],
    ['revoked', 'the owner turned this link off'],
    ['unresolvable', 'the shared folder could not be reached'],
  ] as const)('shows a %s link in its own words, with no join', async (state, words) => {
    const { claimInviteLink } = await openAt(
      `#${FRAGMENT}`,
      inviteEngine({ preview: async () => livePreview({ state, listing: [] }) })
    );

    expect(pageState()).toBe(state);
    expect(screen.getByTestId('invite-status').textContent).toContain(words);
    expect(screen.queryByTestId('invite-join')).toBeNull();
    expect(claimInviteLink).not.toHaveBeenCalled();
  });

  it('shows nothing a previous account read, and no action until the read for this one lands', async () => {
    const reads = [Promise.resolve(livePreview({ joined: true }))];
    const engine = await openAt(`#${FRAGMENT}`, inviteEngine({ preview: () => reads.shift()! }));
    expect(pageState()).toBe('joined');

    const second = deferred();
    reads.push(second.promise);
    await act(async () => engine.switchAccount('acct02'));

    expect(pageState()).toBe('previewing');
    expect(screen.queryByTestId('invite-open-folder')).toBeNull();
    expect(screen.queryByTestId('invite-join')).toBeNull();

    await act(async () => second.land(livePreview()));
    expect(pageState()).toBe('joinable');
    expect(screen.getByTestId('invite-account').textContent).toContain('acct02');

    await act(async () => engine.switchAccount(null));
    reads.push(new Promise(() => undefined));
    await act(async () => engine.switchAccount('acct02'));

    expect(pageState()).toBe('previewing');
    expect(screen.queryByTestId('invite-join')).toBeNull();
  });

  it('offers "open folder" and no join on a link this account already joined', async () => {
    const { claimInviteLink } = await openAt(
      `#${FRAGMENT}`,
      inviteEngine({ preview: async () => livePreview({ joined: true }) })
    );

    expect(pageState()).toBe('joined');
    expect(screen.queryByTestId('invite-join')).toBeNull();

    await act(async () => {
      fireEvent.click(screen.getByTestId('invite-open-folder'));
    });

    expect(window.location.pathname).toBe(`/files/${toHex(SCOPE)}`);
    expect(window.location.hash).toBe('');
    expect(claimInviteLink).not.toHaveBeenCalled();
  });

  it('shows a gate refusal as a trust refusal, not as an outage', async () => {
    const refusal = new EngineRequestError('the scope root did not verify', 'trustViolation');
    await openAt(`#${FRAGMENT}`, inviteEngine({ preview: () => Promise.reject(refusal) }));

    expect(pageState()).toBe('untrusted');
    expect(screen.getByTestId('invite-status').textContent).toContain('trust');
    expect(screen.queryByTestId('invite-join')).toBeNull();
  });

  it('shows a read that did not complete as unreadable', async () => {
    const refusal = new EngineRequestError('the routing did not answer', 'seam');
    await openAt(`#${FRAGMENT}`, inviteEngine({ preview: () => Promise.reject(refusal) }));

    expect(pageState()).toBe('unreadable');
    expect(screen.queryByTestId('invite-join')).toBeNull();
  });

  it('reads no preview and offers no join at an address that carries no link', async () => {
    const { previewInviteLink, claimInviteLink } = await openAt('');

    expect(previewInviteLink).not.toHaveBeenCalled();
    expect(claimInviteLink).not.toHaveBeenCalled();
    expect(pageState()).toBe('noLink');
    expect(screen.queryByTestId('invite-join')).toBeNull();
  });
});

describe('the join', () => {
  it('hands the fragment to the facade verbatim, once, then opens the folder', async () => {
    const { claimInviteLink } = await openAt(`#${FRAGMENT}`);

    await join();

    expect(claimInviteLink.mock.calls).toEqual([[FRAGMENT, '']]);
    expect(window.location.pathname).toBe(`/files/${toHex(SCOPE)}`);
    expect(document.body.innerHTML).not.toContain(FRAGMENT);
  });

  it('carries the name the member typed with the join', async () => {
    const { claimInviteLink } = await openAt(`#${FRAGMENT}`);

    fireEvent.change(screen.getByTestId('invite-name'), { target: { value: 'Grace' } });
    await join();

    expect(claimInviteLink.mock.calls).toEqual([[FRAGMENT, 'Grace']]);
  });

  it('clears the address bar before the await, and the router location with it', async () => {
    const engine = await openAt(`#${FRAGMENT}`);

    await join();

    expect(engine.addressAtDispatch).toEqual(['']);
    expect(window.location.hash).toBe('');
    // Cleared through the router, so its in-memory location drops it too — a
    // raw `history.replaceState` would leave the capability there for the tab's
    // life.
    expect(engine.routerHash()).toBe('');
  });

  it('claims the link on screen: a new link shows no join until its own preview lands', async () => {
    const second = deferred();
    const engine = await openAt(
      `#${FRAGMENT}`,
      inviteEngine({
        preview: (fragment) =>
          fragment === FRAGMENT ? Promise.resolve(livePreview()) : second.promise,
      })
    );
    expect(pageState()).toBe('joinable');

    await moveTo('#another-link-fragment');

    expect(pageState()).toBe('previewing');
    expect(screen.queryByTestId('invite-join')).toBeNull();

    await act(async () => second.land(livePreview({ names: null })));
    expect(screen.getByTestId('invite-headline').textContent).toBe('a folder was shared with you');
    await join();

    expect(engine.previewInviteLink.mock.calls).toEqual([[FRAGMENT], ['another-link-fragment']]);
    expect(engine.claimInviteLink.mock.calls).toEqual([['another-link-fragment', '']]);
  });

  it.each(['accepted', 'refused'] as const)(
    'lets a new link take over from a join still in flight that is then %s',
    async (outcome) => {
      const { claim, pending } = heldClaims();
      await openAt(`#${FRAGMENT}`, inviteEngine({ claim }));
      await join();
      expect(pageState()).toBe('joining');

      await moveTo('#another-link-fragment');
      await waitFor(() => expect(pageState()).toBe('joinable'));
      await act(async () =>
        outcome === 'accepted' ? pending[0].accept() : pending[0].refuse('link-expired')
      );

      expect(pageState()).toBe('joinable');
      expect(window.location.pathname).toBe('/invite');
      expect(screen.queryByRole('alert')).toBeNull();
    }
  );

  it.each(['accepted', 'refused'] as const)(
    'keeps an earlier press of the same link, then %s, off a later press',
    async (outcome) => {
      const { claim, pending } = heldClaims();
      const engine = await openAt(`#${FRAGMENT}`, inviteEngine({ claim }));
      await join();
      await moveTo('#another-link-fragment');
      await moveTo(`#${FRAGMENT}`);
      await waitFor(() => expect(pageState()).toBe('joinable'));
      await join();

      await act(async () =>
        outcome === 'accepted' ? pending[0].accept() : pending[0].refuse('link-expired')
      );

      expect(pageState()).toBe('joining');
      expect(window.location.pathname).toBe('/invite');

      await act(async () => pending[1].accept());

      expect(engine.claimInviteLink.mock.calls).toEqual([
        [FRAGMENT, ''],
        [FRAGMENT, ''],
      ]);
      expect(window.location.pathname).toBe(`/files/${toHex(SCOPE)}`);
    }
  );

  it('shows the refusal of the join on screen, not of an earlier one that settles later', async () => {
    const { claim, pending } = heldClaims();
    await openAt(`#${FRAGMENT}`, inviteEngine({ claim }));
    await join();
    await moveTo('#another-link-fragment');
    await waitFor(() => expect(pageState()).toBe('joinable'));
    await join();

    await act(async () => pending[1].refuse('the second refusal'));
    await act(async () => pending[0].refuse('the first refusal'));

    expect(pageState()).toBe('refused');
    expect(screen.getByRole('alert').textContent).toBe('the second refusal');
  });

  it('opens no folder for a join that settles after the member left the invite route', async () => {
    const { claim, pending } = heldClaims();
    await openAt(
      `#${FRAGMENT}`,
      inviteEngine({ claim }),
      fakeCoreKitSession().session,
      <Routes>
        <Route path="/invite" element={<InvitePage />} />
        <Route path="*" element={null} />
      </Routes>
    );
    await join();

    await act(async () => {
      window.history.pushState(null, '', '/files');
      window.dispatchEvent(new PopStateEvent('popstate'));
    });
    await act(async () => pending[0].accept());

    expect(window.location.pathname).toBe('/files');
  });

  it('opens no folder for a join the previous account started', async () => {
    const { claim, pending } = heldClaims();
    const engine = await openAt(`#${FRAGMENT}`, inviteEngine({ claim }));
    await join();

    await act(async () => engine.switchAccount('acct02'));
    await act(async () => pending[0].accept());

    expect(pageState()).not.toBe('joining');
    expect(window.location.pathname).toBe('/invite');
  });

  it("renders the engine's refusal in its own words and stays on the page", async () => {
    const refusal = new EngineRequestError('link-expired', 'malformedInput');
    await openAt(`#${FRAGMENT}`, inviteEngine({ refusal }));

    await join();

    expect(screen.getByRole('alert').textContent).toBe('link-expired');
    expect(pageState()).toBe('refused');
    expect(window.location.pathname).toBe('/invite');
  });
});

describe('the sign-in on the invite page', () => {
  it('offers the sign-in methods in place, reads no preview, and leaves the link', async () => {
    const { previewInviteLink, claimInviteLink } = await openAt(
      `#${FRAGMENT}`,
      inviteEngine({ signedIn: false })
    );

    expect(previewInviteLink).not.toHaveBeenCalled();
    expect(claimInviteLink).not.toHaveBeenCalled();
    expect(window.location.hash).toBe(`#${FRAGMENT}`);
    expect(pageState()).toBe('waiting');
    expect(screen.getByTestId('sign-in-methods')).toBeTruthy();
    expect(screen.queryByTestId('invite-join')).toBeNull();
  });

  it('turns a sign-in on this page into a preview, with the link still in place', async () => {
    const engine = await openAt(`#${FRAGMENT}`, inviteEngine({ signedIn: false }));

    await signInByEmail();

    await waitFor(() => expect(pageState()).toBe('joinable'));
    expect(window.location.pathname).toBe('/invite');
    expect(window.location.hash).toBe(`#${FRAGMENT}`);
    expect(screen.getByTestId('invite-account').textContent).toContain('acct01');
    // The sign-in is not the gesture: the link waits for its own.
    expect(engine.claimInviteLink).not.toHaveBeenCalled();

    await join();

    expect(engine.claimInviteLink.mock.calls).toEqual([[FRAGMENT, '']]);
    expect(window.location.pathname).toBe(`/files/${toHex(SCOPE)}`);
  });

  it('moves focus to "join" once a sign-in on this page lands', async () => {
    await openAt(`#${FRAGMENT}`, inviteEngine({ signedIn: false }));

    await signInByEmail();

    await waitFor(() => expect(document.activeElement).toBe(screen.getByTestId('invite-join')));
  });

  it('keeps the sign-in panel through a sign-in still in flight', async () => {
    // Core Kit holds the login while the engine has yet to start: the tab is
    // neither signed in nor signed out, and the panel must not unmount.
    let release!: () => void;
    const started = new Promise<void>((resolve) => (release = resolve));
    await openAt(`#${FRAGMENT}`, inviteEngine({ signedIn: false, started }));

    await signInByEmail();

    expect(pageState()).toBe('waiting');
    expect(screen.getByTestId('sign-in-methods')).toBeTruthy();

    await act(async () => release());
    await waitFor(() => expect(pageState()).toBe('joinable'));
  });

  it('finishes a login held at the factor policy on this page too', async () => {
    const engine = inviteEngine({ signedIn: false });
    const { session } = fakeCoreKitSession({ needsRecovery: true });
    await openAt(`#${FRAGMENT}`, engine, session);

    await signInByEmail();
    await act(async () => {
      fireEvent.click(screen.getByTestId('recovery-choose-phrase'));
    });
    fireEvent.change(screen.getByTestId('recovery-phrase-input'), {
      target: { value: FAKE_PHRASE },
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId('recovery-submit'));
    });

    await waitFor(() => expect(pageState()).toBe('joinable'));
    expect(window.location.hash).toBe(`#${FRAGMENT}`);
    expect(engine.claimInviteLink).not.toHaveBeenCalled();
  });

  it('hands the engine a restored session, so an open link needs no second sign-in', async () => {
    // The route sits outside `RequireAuth`, and nothing else on it would make
    // the hand-off a signed-in browser still owes the engine.
    const engine = inviteEngine({ signedIn: false });
    const { session } = fakeCoreKitSession({ loggedIn: true });

    await openAt(`#${FRAGMENT}`, engine, session);

    expect(pageState()).toBe('joinable');
    expect(screen.getByTestId('invite-account').textContent).toContain('acct01');
    expect(engine.claimInviteLink).not.toHaveBeenCalled();
  });
});

import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { authStore } from '../../stores/auth.store';
import {
  authWrapper,
  FAKE_PHRASE,
  fakeCoreKitSession,
  fakeEngineClient,
  type CoreKitCalls,
} from '../../test/authFakes';
import { RecoveryPhraseLogin } from './RecoveryPhraseLogin';
import { RecoveryPhraseSetup } from './RecoveryPhraseSetup';

/**
 * Mounts a recovery surface over a Core Kit session already held at the factor
 * policy, which is the only state either of them renders in.
 */
async function held(node: React.ReactElement): Promise<{ coreKit: CoreKitCalls }> {
  const engine = fakeEngineClient();
  const coreKit = fakeCoreKitSession({ needsRecovery: true });
  authStore.recoveryRequired();
  render(node, { wrapper: authWrapper(engine.client, coreKit.session) });
  await act(async () => undefined);
  return { coreKit: coreKit.calls };
}

describe('the recovery phrase login', () => {
  beforeEach(() => authStore.signedOut());

  const field = () => screen.getByTestId('recovery-phrase-input') as HTMLTextAreaElement;
  const submit = () => fireEvent.click(screen.getByTestId('recovery-submit'));

  it('refuses a phrase of the wrong length without asking the Core Kit', async () => {
    const { coreKit } = await held(<RecoveryPhraseLogin />);

    fireEvent.change(field(), { target: { value: 'word word word' } });
    submit();

    expect((await screen.findByRole('alert')).textContent).toContain('24 words');
    expect(coreKit.phrases).toEqual([]);
  });

  it('clears a phrase of the wrong length too, rather than leaving one in the field', async () => {
    await held(<RecoveryPhraseLogin />);
    // The count is wrong because it is a phrase half-typed or pasted with a
    // stray word, not because it is harmless: a browser's crash-recovery
    // snapshot would carry it to disk either way.
    fireEvent.change(field(), { target: { value: `${FAKE_PHRASE} spare` } });

    submit();

    await waitFor(() => expect(field().value).toBe(''));
  });

  it('puts focus in the field, which the panel replaced the login methods to offer', async () => {
    await held(<RecoveryPhraseLogin />);

    // The control that had focus unmounted with the methods; without this the
    // field is only reachable by tabbing from the top of the page.
    await waitFor(() => expect(document.activeElement).toBe(field()));
  });

  it('ends the partial session when the member abandons the prompt', async () => {
    const { coreKit } = await held(<RecoveryPhraseLogin />);

    await act(async () => {
      fireEvent.click(screen.getByTestId('recovery-cancel'));
    });

    // What the login page reads to put the ordinary methods back.
    await waitFor(() => expect(authStore.getState().recoveryRequired).toBe(false));
    expect(coreKit.logouts).toBe(1);
  });

  it('normalises the typed phrase and clears the field once it is redeemed', async () => {
    const { coreKit } = await held(<RecoveryPhraseLogin />);

    fireEvent.change(field(), { target: { value: `\n  ${FAKE_PHRASE.replace(/ /g, '   ')} ` } });
    await act(async () => {
      submit();
    });

    // Held only for the attempt: a phrase left in the tree outlives the screen
    // the member can see.
    await waitFor(() => expect(field().value).toBe(''));
    expect(coreKit.phrases).toEqual([FAKE_PHRASE]);
  });

  it('clears the field on a refusal too, rather than leaving a phrase in the DOM', async () => {
    const { coreKit } = await held(<RecoveryPhraseLogin />);
    const wrong = `${'other '.repeat(23)}words`;

    fireEvent.change(field(), { target: { value: wrong } });
    await act(async () => {
      submit();
    });

    // A browser's crash-recovery snapshot persists form-field values to the
    // profile directory, so a refused phrase must not sit there waiting.
    expect(coreKit.phrases).toEqual([wrong]);
    await waitFor(() => expect(field().value).toBe(''));
  });
});

describe('the recovery phrase setup', () => {
  beforeEach(() => authStore.signedOut());

  /** Mounts the dialog and enrolls, so it is sitting on the one-time phrase. */
  async function revealed(onClose: () => void, enrollWarning?: string): Promise<void> {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession({ loggedIn: true, enrollWarning });
    render(<RecoveryPhraseSetup onClose={onClose} />, {
      wrapper: authWrapper(engine.client, coreKit.session),
    });
    await act(async () => undefined);
    await act(async () => {
      fireEvent.click(screen.getByTestId('recovery-setup-start'));
    });
  }

  it('shows the phrase once and drops it when the member confirms they hold it', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession({ loggedIn: true });
    render(<RecoveryPhraseSetup onClose={() => undefined} />, {
      wrapper: authWrapper(engine.client, coreKit.session),
    });
    await act(async () => undefined);

    await act(async () => {
      fireEvent.click(screen.getByTestId('recovery-setup-start'));
    });
    expect(coreKit.calls.enrollments).toBe(1);
    expect(screen.getAllByRole('listitem')).toHaveLength(24);

    // Gated on the acknowledgement, so the words cannot be dismissed unread.
    const confirm = screen.getByTestId('recovery-setup-confirm');
    expect((confirm as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByTestId('recovery-setup-acknowledge'));
    fireEvent.click(confirm);

    expect(screen.queryByTestId('recovery-phrase-grid')).toBeNull();
    expect(screen.getByTestId('recovery-setup-done')).not.toBeNull();
  });

  it('refuses every dismissal while the phrase is up unacknowledged', async () => {
    let closes = 0;
    await revealed(() => (closes += 1));

    fireEvent.keyDown(document, { key: 'Escape' });
    fireEvent.mouseDown(screen.getByTestId('modal-backdrop'));
    fireEvent.click(screen.getByRole('button', { name: 'close' }));

    // The cut deleted the hashed cloud share, so a dismissal here discards the
    // account's only spare key while leaving it enrolled.
    expect(closes).toBe(0);
    expect(screen.getByTestId('recovery-phrase-grid')).not.toBeNull();

    fireEvent.click(screen.getByTestId('recovery-setup-acknowledge'));
    fireEvent.keyDown(document, { key: 'Escape' });
    expect(closes).toBe(1);
  });

  it('shows the phrase beside a warning when the cut could not be confirmed', async () => {
    await revealed(() => undefined, 'the enrollment could not be synced');

    // Policy cut, sync unconfirmed: the words are still the account's only spare
    // key, so they are shown with the caveat rather than withheld.
    expect(screen.getByTestId('recovery-setup-warning').textContent).toContain(
      'could not be synced'
    );
    expect(screen.getAllByRole('listitem')).toHaveLength(24);
  });
});

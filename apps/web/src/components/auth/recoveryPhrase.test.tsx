import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { authStore } from '../../stores/auth.store';
import {
  authWrapper,
  fakeCoreKitSession,
  fakeEngineClient,
  type CoreKitCalls,
} from '../../test/authFakes';
import { RecoveryPhraseLogin } from './RecoveryPhraseLogin';
import { RecoveryPhraseSetup } from './RecoveryPhraseSetup';

const PHRASE = `${'word '.repeat(23)}last`;

/**
 * Mounts a recovery surface over a Core Kit session already held at the factor
 * policy, which is the only state either of them renders in.
 */
async function held(node: React.ReactElement): Promise<CoreKitCalls> {
  const engine = fakeEngineClient();
  const coreKit = fakeCoreKitSession({ needsRecovery: true, phrase: PHRASE });
  render(node, { wrapper: authWrapper(engine.client, coreKit.session) });
  await act(async () => undefined);
  return coreKit.calls;
}

describe('the recovery phrase login', () => {
  beforeEach(() => authStore.signedOut());

  const field = () => screen.getByTestId('recovery-phrase-input') as HTMLTextAreaElement;
  const submit = () => fireEvent.click(screen.getByTestId('recovery-submit'));

  it('refuses a phrase of the wrong length without asking the Core Kit', async () => {
    const calls = await held(<RecoveryPhraseLogin />);

    fireEvent.change(field(), { target: { value: 'word word word' } });
    submit();

    expect((await screen.findByRole('alert')).textContent).toContain('24 words');
    expect(calls.phrases).toEqual([]);
  });

  it('normalises the typed phrase and clears the field once it is redeemed', async () => {
    const calls = await held(<RecoveryPhraseLogin />);

    fireEvent.change(field(), { target: { value: `\n  ${PHRASE.replace(/ /g, '   ')} ` } });
    await act(async () => {
      submit();
    });

    // Held only for the attempt: a phrase left in the tree outlives the screen
    // the member can see.
    await waitFor(() => expect(field().value).toBe(''));
    expect(calls.phrases).toEqual([PHRASE]);
  });

  it('keeps what was typed when the phrase is refused, so a typo can be fixed', async () => {
    const calls = await held(<RecoveryPhraseLogin />);
    const wrong = `${'other '.repeat(23)}words`;

    fireEvent.change(field(), { target: { value: wrong } });
    await act(async () => {
      submit();
    });

    expect(field().value).toBe(wrong);
    expect(calls.phrases).toEqual([wrong]);
  });
});

describe('the recovery phrase setup', () => {
  beforeEach(() => authStore.signedOut());

  it('shows the phrase once and drops it when the member confirms they hold it', async () => {
    const engine = fakeEngineClient();
    const coreKit = fakeCoreKitSession({ loggedIn: true, phrase: PHRASE });
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
});

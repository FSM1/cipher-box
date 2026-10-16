import { resetLoginFlowLatches } from '@cipherbox/login';
import { act, fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { useAuth } from '../../auth/useAuth';
import { authStore } from '../../stores/auth.store';
import { KeyAssignmentTimedOutError } from '../../auth/coreKit';
import {
  fakeCoreKitSession,
  fakeEngineClient,
  pageWrapper,
  signInByEmail,
} from '../../test/authFakes';
import { SignInPanel } from './SignInPanel';

async function panel(): Promise<HTMLInputElement> {
  const Providers = pageWrapper(fakeEngineClient().client, fakeCoreKitSession().session);
  render(
    <Providers>
      <SignInPanel />
    </Providers>
  );
  await act(async () => undefined);
  return screen.getByTestId('save-device-checkbox') as HTMLInputElement;
}

describe('the "save this device" checkbox', () => {
  beforeEach(() => authStore.signedOut());

  // A registered key is a capability to approve a sign-in, so it is opt-in.
  it('starts unchecked', async () => {
    const box = await panel();

    expect(box.checked).toBe(false);
    expect(authStore.getState().saveDevice).toBe(false);
  });

  it('carries the choice to the store every login method reads', async () => {
    const box = await panel();

    fireEvent.click(box);
    expect(authStore.getState().saveDevice).toBe(true);
    expect(box.checked).toBe(true);

    fireEvent.click(box);
    expect(authStore.getState().saveDevice).toBe(false);
  });
});

/** Another surface that reads the session, as a route guard does. */
function OtherConsumer() {
  useAuth();
  return null;
}

const disabled = (testId: string): boolean =>
  (screen.getByTestId(testId) as HTMLButtonElement | HTMLInputElement).disabled;

/** The panel over a Core Kit session that survived the reload. */
async function resumingPanel(start: () => Promise<void>): Promise<void> {
  const Providers = pageWrapper(
    fakeEngineClient({ start }).client,
    fakeCoreKitSession({ loggedIn: true }).session
  );
  render(
    <Providers>
      <OtherConsumer />
      <SignInPanel />
    </Providers>
  );
  await act(async () => undefined);
}

describe('the login methods while a saved session resumes', () => {
  beforeEach(() => {
    resetLoginFlowLatches();
    authStore.signedOut();
  });

  it('stay disabled until the resume settles', async () => {
    await resumingPanel(() => new Promise<void>(() => undefined));

    expect(disabled('wallet-login-button')).toBe(true);
    expect(disabled('email-input')).toBe(true);
  });

  it('come back once a resume the engine refused leaves the tab signed out', async () => {
    await resumingPanel(() => Promise.reject(new Error('the engine refused the secret')));

    expect(disabled('wallet-login-button')).toBe(false);
  });
});

describe('a key assignment the login provider refused', () => {
  beforeEach(() => {
    resetLoginFlowLatches();
    authStore.signedOut();
  });

  /** Signs in by email over a Core Kit session whose login rejects with `refusal`. */
  async function refusedSignIn(refusal: Error): Promise<string | null> {
    const coreKit = fakeCoreKitSession();
    coreKit.session.login = () => Promise.reject(refusal);
    const Providers = pageWrapper(fakeEngineClient().client, coreKit.session);
    render(
      <Providers>
        <SignInPanel />
      </Providers>
    );
    await act(async () => undefined);
    await signInByEmail();
    return screen.getByTestId('login-error').textContent;
  }

  it('shows the timeout in the banner', async () => {
    const refusal = new KeyAssignmentTimedOutError();

    expect(await refusedSignIn(refusal)).toBe(refusal.message);
    expect(disabled('wallet-login-button')).toBe(false);
  });

  it('shows the refusal of the SDK in its own words', async () => {
    const refusal = new Error('unable to assign key, All auth network nodes are currently busy');

    expect(await refusedSignIn(refusal)).toBe(refusal.message);
  });
});

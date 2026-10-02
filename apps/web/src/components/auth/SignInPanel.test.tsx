import { act, fireEvent, render, screen } from '@testing-library/react';
import { beforeEach, describe, expect, it } from 'vitest';
import { authStore } from '../../stores/auth.store';
import { fakeCoreKitSession, fakeEngineClient, pageWrapper } from '../../test/authFakes';
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

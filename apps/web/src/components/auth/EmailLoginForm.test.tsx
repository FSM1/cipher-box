import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { EmailLoginForm } from './EmailLoginForm';

/**
 * A promise the test refuses on demand. Asserting the step before the refusal
 * settles passes whatever the component does with it, so a guard written that
 * way cannot fail.
 */
function deferred(): { promise: Promise<void>; reject: (reason: Error) => Promise<void> } {
  let refuse!: (reason: Error) => void;
  const promise = new Promise<void>((_, rejectPromise) => {
    refuse = rejectPromise;
  });
  // The component swallows the rejection; awaiting it here would fail the test.
  promise.catch(() => undefined);
  return {
    promise,
    reject: async (reason: Error) => {
      refuse(reason);
      await act(async () => undefined);
    },
  };
}

function renderForm(
  overrides: Partial<{
    onSendCode: (email: string) => Promise<void>;
    onVerify: (email: string, code: string) => Promise<void>;
    disabled: boolean;
    busy: boolean;
  }> = {}
) {
  const onSendCode = vi.fn(overrides.onSendCode ?? (() => Promise.resolve()));
  const onVerify = vi.fn(overrides.onVerify ?? (() => Promise.resolve()));
  render(
    <EmailLoginForm
      onSendCode={onSendCode}
      onVerify={onVerify}
      disabled={overrides.disabled}
      busy={overrides.busy}
    />
  );
  return { onSendCode, onVerify };
}

function typeAddress(value: string) {
  fireEvent.change(screen.getByTestId('email-input'), { target: { value } });
  fireEvent.click(screen.getByTestId('email-login-button'));
}

describe('EmailLoginForm', () => {
  it('normalizes the address before asking CipherBox to send a code', async () => {
    const { onSendCode } = renderForm();

    typeAddress('  Member@Example.TEST ');

    await waitFor(() => expect(onSendCode).toHaveBeenCalledWith('member@example.test'));
  });

  it('collects the code in the app, not in a provider window', async () => {
    const { onVerify } = renderForm();

    typeAddress('member@example.test');
    const code = await screen.findByTestId('email-code-input');
    fireEvent.change(code, { target: { value: '123456' } });
    fireEvent.click(screen.getByTestId('email-verify-button'));

    await waitFor(() => expect(onVerify).toHaveBeenCalledWith('member@example.test', '123456'));
  });

  // Advancing on a send that never happened would ask for a code that is not coming.
  it('stays on the address step when the send is refused', async () => {
    const send = deferred();
    const { onSendCode } = renderForm({ onSendCode: () => send.promise });

    typeAddress('member@example.test');
    await waitFor(() => expect(onSendCode).toHaveBeenCalledWith('member@example.test'));
    await send.reject(new Error('too many requests'));

    expect(screen.getByTestId('email-input')).toBeDefined();
    expect(screen.queryByTestId('email-code-input')).toBeNull();
  });

  // The button the member pressed is gone; without this they must hunt for the
  // field that replaced it.
  it('puts the cursor in the code field once the code is on its way', async () => {
    renderForm();

    typeAddress('member@example.test');
    const code = await screen.findByTestId('email-code-input');

    expect(document.activeElement).toBe(code);
  });

  // A refused code is the member's most likely mistyping, not a dead end.
  it('stays on the code step when the code is refused, and takes another', async () => {
    const firstAttempt = deferred();
    const { onVerify } = renderForm({ onVerify: () => firstAttempt.promise });

    typeAddress('member@example.test');
    const code = await screen.findByTestId('email-code-input');
    fireEvent.change(code, { target: { value: '111111' } });
    fireEvent.click(screen.getByTestId('email-verify-button'));

    await waitFor(() => expect(onVerify).toHaveBeenCalledWith('member@example.test', '111111'));
    await firstAttempt.reject(new Error('that code is not right'));
    expect(screen.getByTestId('email-code-input')).toBeDefined();

    fireEvent.change(screen.getByTestId('email-code-input'), { target: { value: '222222' } });
    fireEvent.click(screen.getByTestId('email-verify-button'));

    await waitFor(() => expect(onVerify).toHaveBeenLastCalledWith('member@example.test', '222222'));
  });

  it('holds the code step until six digits are in hand', async () => {
    renderForm();

    typeAddress('member@example.test');
    const code = await screen.findByTestId('email-code-input');

    fireEvent.change(code, { target: { value: '12345' } });
    expect(screen.getByTestId('email-verify-button').hasAttribute('disabled')).toBe(true);

    fireEvent.change(code, { target: { value: '123456' } });
    expect(screen.getByTestId('email-verify-button').hasAttribute('disabled')).toBe(false);
  });

  it('keeps non-digits out of the code field', async () => {
    renderForm();

    typeAddress('member@example.test');
    const code = await screen.findByTestId('email-code-input');
    fireEvent.change(code, { target: { value: '1a2b3c4d5e6f7' } });

    expect((code as HTMLInputElement).value).toBe('123456');
  });

  it('lets a member go back to a different address', async () => {
    const { onSendCode } = renderForm();

    typeAddress('typo@example.test');
    await screen.findByTestId('email-code-input');
    fireEvent.click(screen.getByTestId('email-restart-button'));

    typeAddress('member@example.test');
    await waitFor(() => expect(onSendCode).toHaveBeenLastCalledWith('member@example.test'));
  });

  it('sends nothing while the tab cannot accept a login', () => {
    const { onSendCode } = renderForm({ disabled: true });

    typeAddress('member@example.test');

    expect(onSendCode).not.toHaveBeenCalled();
  });
});

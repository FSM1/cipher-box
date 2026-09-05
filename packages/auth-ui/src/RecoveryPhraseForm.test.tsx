import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { RecoveryPhraseForm } from './RecoveryPhraseForm';

const PHRASE = Array.from({ length: 24 }, (_, index) => `word${String(index)}`).join(' ');

function renderForm(
  overrides: Partial<{
    onSubmit: (phrase: string) => Promise<void>;
    onCancel: () => void;
    busy: boolean;
    error: string | null;
  }> = {}
) {
  const props = {
    onSubmit: vi.fn(() => Promise.resolve()),
    onCancel: vi.fn(),
    busy: false,
    error: null,
    ...overrides,
  };
  render(
    <RecoveryPhraseForm
      onSubmit={props.onSubmit}
      onCancel={props.onCancel}
      busy={props.busy}
      error={props.error}
    />
  );
  return props;
}

const field = () => screen.getByTestId('recovery-phrase-input') as HTMLTextAreaElement;
const submit = () => fireEvent.click(screen.getByTestId('recovery-submit'));

describe('the recovery phrase form', () => {
  it('refuses a phrase of the wrong length without redeeming it', async () => {
    const { onSubmit } = renderForm();

    fireEvent.change(field(), { target: { value: 'word word word' } });
    submit();

    expect((await screen.findByRole('alert')).textContent).toContain('24 words');
    expect(onSubmit).not.toHaveBeenCalled();
  });

  it('clears a phrase of the wrong length too, rather than leaving one in the field', async () => {
    renderForm();
    // Wrong because it is half-typed or pasted with a stray word, not because
    // it is harmless: a crash-recovery snapshot would carry it to disk either
    // way.
    fireEvent.change(field(), { target: { value: `${PHRASE} spare` } });

    submit();

    await waitFor(() => expect(field().value).toBe(''));
  });

  it('normalises the typed phrase and clears the field once it is redeemed', async () => {
    const { onSubmit } = renderForm();

    fireEvent.change(field(), { target: { value: `\n  ${PHRASE.replace(/ /g, '   ')} ` } });
    await act(async () => {
      submit();
    });

    expect(onSubmit).toHaveBeenCalledWith(PHRASE);
    await waitFor(() => expect(field().value).toBe(''));
  });

  it('clears the field on a refusal too, rather than leaving a phrase in the DOM', async () => {
    const onSubmit = vi.fn(() => Promise.reject(new Error('that phrase did not open it')));
    renderForm({ onSubmit });

    fireEvent.change(field(), { target: { value: PHRASE } });
    await act(async () => {
      submit();
    });

    expect(onSubmit).toHaveBeenCalledWith(PHRASE);
    await waitFor(() => expect(field().value).toBe(''));
  });

  it('puts focus in the field, which the panel replaced the login methods to offer', async () => {
    renderForm();

    await waitFor(() => expect(document.activeElement).toBe(field()));
  });

  it('ends the held login when the member abandons the prompt', () => {
    const { onCancel } = renderForm();

    fireEvent.click(screen.getByTestId('recovery-cancel'));

    expect(onCancel).toHaveBeenCalled();
  });

  it('shows what the host reported, and its own count first', async () => {
    renderForm({ error: 'that phrase did not open this account' });

    expect((await screen.findByRole('alert')).textContent).toContain('did not open this account');

    fireEvent.change(field(), { target: { value: 'too few' } });
    submit();

    // The member's own last action is the one they can act on.
    expect((await screen.findByRole('alert')).textContent).toContain('24 words');
  });

  it('takes no input while the host has a transition in flight', () => {
    renderForm({ busy: true });

    expect(field().disabled).toBe(true);
    expect((screen.getByTestId('recovery-submit') as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByTestId('recovery-cancel') as HTMLButtonElement).disabled).toBe(true);
  });
});

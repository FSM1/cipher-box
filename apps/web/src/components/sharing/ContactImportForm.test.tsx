import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { ContactScanner } from '../../sharing/contactScanner';
import { ContactImportForm } from './ContactImportForm';

const CODE_HEX = '00ff10';
const OTHER_HEX = 'aabbcc';
const CODE_BYTES = new Uint8Array([0x00, 0xff, 0x10]);

/** A scanner that answers one fixture instead of holding a camera. */
function fakeScanner(
  answer: () => Promise<string | null>,
  supported = true
): ContactScanner & { aborted: () => boolean } {
  let signal: AbortSignal | null = null;
  return {
    supported: () => Promise.resolve(supported),
    scan: (target) => {
      signal = target.signal;
      return answer();
    },
    aborted: () => signal?.aborted === true,
  };
}

/** Renders the form and lets the capability read land before anything else. */
async function importForm(scanner: ContactScanner, onConfirm = vi.fn()) {
  let view!: ReturnType<typeof render>;
  await act(async () => {
    view = render(
      <ContactImportForm
        busy={false}
        ownContactCode={null}
        scanner={scanner}
        onCancel={() => undefined}
        onConfirm={onConfirm}
      />
    );
  });
  return { view, onConfirm };
}

async function click(testId: string) {
  await act(async () => {
    fireEvent.click(screen.getByTestId(testId));
  });
}

function paste(value: string) {
  fireEvent.change(screen.getByLabelText('their contact code'), { target: { value } });
}

describe('scanning a contact code', () => {
  it('hands on the same bytes a paste of that code hands on', async () => {
    const scanned = await importForm(fakeScanner(() => Promise.resolve(CODE_HEX)));
    await click('import-contact-scan');
    await waitFor(() => expect(scanned.onConfirm).toHaveBeenCalledTimes(1));
    scanned.view.unmount();

    const pasted = await importForm(fakeScanner(() => Promise.resolve(null), false));
    paste(CODE_HEX);
    await click('import-contact-confirm');

    expect(scanned.onConfirm.mock.calls[0][0]).toEqual(pasted.onConfirm.mock.calls[0][0]);
    expect(scanned.onConfirm).toHaveBeenCalledWith(CODE_BYTES);
  });

  it('says a frame carried no code, and claims no verdict the engine did not give', async () => {
    const { onConfirm } = await importForm(fakeScanner(() => Promise.resolve(null)));

    await click('import-contact-scan');

    await waitFor(() => expect(screen.getByTestId('import-contact-nothing-read')).toBeTruthy());
    expect(screen.getByTestId('import-contact-nothing-read').textContent).toBe(
      '// no code found — try again or paste it'
    );
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it('treats a frame that carries something other than a code the same way', async () => {
    const { onConfirm } = await importForm(
      fakeScanner(() => Promise.resolve('https://example.test'))
    );

    await click('import-contact-scan');

    await waitFor(() => expect(screen.getByTestId('import-contact-nothing-read')).toBeTruthy());
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it('says the camera is unavailable when the member refuses it', async () => {
    const { onConfirm } = await importForm(fakeScanner(() => Promise.reject(new Error('denied'))));

    await click('import-contact-scan');

    await waitFor(() => expect(screen.getByTestId('import-contact-no-camera')).toBeTruthy());
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it('offers no scan control at all where the browser cannot read a QR code', async () => {
    await importForm(fakeScanner(() => Promise.resolve(CODE_HEX), false));

    expect(screen.queryByTestId('import-contact-scan')).toBeNull();
    expect(screen.queryByTestId('import-contact-scan-section')).toBeNull();
  });

  it('holds the camera only while the scan is on screen', async () => {
    const scanner = fakeScanner(() => new Promise(() => undefined));
    const { view } = await importForm(scanner);

    await click('import-contact-scan');
    expect(screen.getByTestId('import-contact-preview')).toBeTruthy();
    await act(async () => {
      view.unmount();
    });

    expect(scanner.aborted()).toBe(true);
  });

  it('ends the scan when the member stops it', async () => {
    const scanner = fakeScanner(() => new Promise(() => undefined));
    await importForm(scanner);

    await click('import-contact-scan');
    await click('import-contact-scan-stop');

    expect(scanner.aborted()).toBe(true);
    expect(screen.queryByTestId('import-contact-preview')).toBeNull();
    expect(screen.getByTestId('import-contact-scan')).toBeTruthy();
  });

  it('hands on one code only, when a scan lands after a paste went out', async () => {
    let answer: (text: string) => void = () => undefined;
    const scanner = fakeScanner(() => new Promise<string>((resolve) => (answer = resolve)));
    const { onConfirm } = await importForm(scanner);

    await click('import-contact-scan');
    paste(OTHER_HEX);
    await click('import-contact-confirm');
    await act(async () => {
      answer(CODE_HEX);
    });

    expect(scanner.aborted()).toBe(true);
    expect(onConfirm).toHaveBeenCalledTimes(1);
    expect(onConfirm).toHaveBeenCalledWith(new Uint8Array([0xaa, 0xbb, 0xcc]));
  });
});

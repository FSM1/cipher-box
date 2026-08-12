import { render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

interface InitConfig {
  client_id: string;
  callback: (response: { credential: string }) => void;
}

/** What GIS injects into the target, standing in for the real button markup. */
const GIS_BUTTON = 'gis-rendered-button';

const gis = {
  initialized: [] as InitConfig[],
  rendered: 0,
  /** Fires the callback GIS was handed, as a completed Google sign-in does. */
  deliver(credential: string) {
    this.initialized[this.initialized.length - 1].callback({ credential });
  },
};

/**
 * The component loads the GIS script once per document, so each test takes a
 * fresh module rather than inheriting the previous test's resolved load.
 */
async function freshButton() {
  vi.resetModules();
  return (await import('./GoogleLoginButton')).GoogleLoginButton;
}

/**
 * Installs the global the GIS script would, and drives the script element's
 * own load event so the component's loader resolves without a network.
 */
function installGoogleIdentityServices(): void {
  vi.spyOn(document.head, 'appendChild').mockImplementation((node) => {
    const script = node as HTMLScriptElement;
    (globalThis as Record<string, unknown>).google = {
      accounts: {
        id: {
          initialize: (config: InitConfig) => gis.initialized.push(config),
          // GIS builds the button's markup inside the target it is handed, so
          // a test can tell a live button from an empty div left behind.
          renderButton: (parent: HTMLElement) => {
            gis.rendered += 1;
            const button = document.createElement('div');
            button.dataset.testid = GIS_BUTTON;
            parent.appendChild(button);
          },
        },
      },
    };
    queueMicrotask(() => script.onload?.(new Event('load')));
    return node;
  });
}

function failGoogleIdentityServices(): void {
  vi.spyOn(document.head, 'appendChild').mockImplementation((node) => {
    queueMicrotask(() => (node as HTMLScriptElement).onerror?.(new Event('error')));
    return node;
  });
}

beforeEach(() => {
  gis.initialized = [];
  gis.rendered = 0;
  delete (globalThis as Record<string, unknown>).google;
});

afterEach(() => vi.restoreAllMocks());

describe('GoogleLoginButton', () => {
  it('presents a Google-rendered button and forwards the credential it yields', async () => {
    installGoogleIdentityServices();
    const GoogleLoginButton = await freshButton();
    const onCredential = vi.fn();
    render(<GoogleLoginButton clientId="google-client-id" onCredential={onCredential} />);

    await waitFor(() => expect(gis.rendered).toBeGreaterThan(0));
    expect(gis.initialized[0].client_id).toBe('google-client-id');

    gis.deliver('google.id.token');
    expect(onCredential).toHaveBeenCalledWith('google.id.token');
  });

  it('says so when Google sign-in cannot be loaded, rather than sitting inert', async () => {
    failGoogleIdentityServices();
    const GoogleLoginButton = await freshButton();

    render(<GoogleLoginButton clientId="google-client-id" onCredential={vi.fn()} />);

    expect(await screen.findByText(/could not be loaded/)).toBeDefined();
  });

  it('names the missing variable instead of offering a method it cannot serve', async () => {
    installGoogleIdentityServices();
    const GoogleLoginButton = await freshButton();

    render(<GoogleLoginButton clientId={undefined} onCredential={vi.fn()} />);

    expect(screen.getByTestId('google-login-unavailable').textContent).toContain(
      'VITE_GOOGLE_CLIENT_ID'
    );
    expect(screen.queryByTestId('google-login-button')).toBeNull();
    // No script, so nothing renders an affordance into the absent target.
    expect(vi.mocked(document.head.appendChild)).not.toHaveBeenCalled();
  });

  it('reports the transition over the button while a sign-in is in flight', async () => {
    installGoogleIdentityServices();
    const GoogleLoginButton = await freshButton();

    render(<GoogleLoginButton clientId="google-client-id" onCredential={vi.fn()} busy />);

    expect(screen.getByText(/authenticating with google/)).toBeDefined();
    // Covered and taken out of the a11y tree, not unmounted.
    expect(screen.getByTestId('google-login-button').getAttribute('aria-hidden')).toBe('true');
  });

  it('still offers the button after a sign-in that came back', async () => {
    installGoogleIdentityServices();
    const GoogleLoginButton = await freshButton();
    const onCredential = vi.fn();
    const { rerender } = render(
      <GoogleLoginButton clientId="google-client-id" onCredential={onCredential} />
    );
    await waitFor(() => expect(gis.rendered).toBe(1));

    rerender(<GoogleLoginButton clientId="google-client-id" onCredential={onCredential} busy />);
    rerender(<GoogleLoginButton clientId="google-client-id" onCredential={onCredential} />);

    // The markup GIS injected, not merely a div at the same place: the one-shot
    // mount effect never renders a second time, so a target React emptied out
    // leaves the member with nothing to click until a reload.
    expect(screen.getByTestId(GIS_BUTTON)).toBeDefined();
    expect(gis.rendered).toBe(1);
    gis.deliver('google.id.token');
    expect(onCredential).toHaveBeenCalledWith('google.id.token');
  });

  it('delivers to the callback of the render that committed', async () => {
    installGoogleIdentityServices();
    const GoogleLoginButton = await freshButton();
    const stale = vi.fn();
    const current = vi.fn();
    const { rerender } = render(
      <GoogleLoginButton clientId="google-client-id" onCredential={stale} />
    );
    await waitFor(() => expect(gis.rendered).toBe(1));

    rerender(<GoogleLoginButton clientId="google-client-id" onCredential={current} />);
    gis.deliver('google.id.token');

    expect(current).toHaveBeenCalledWith('google.id.token');
    expect(stale).not.toHaveBeenCalled();
  });
});

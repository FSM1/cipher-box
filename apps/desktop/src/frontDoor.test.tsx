import { act, fireEvent, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { IdentityMethod } from '@cipherbox/login';
import { renderShell, type ShellActions, type ShellModel } from './frontDoor';
import type { VaultStatus, VaultWarningKind } from './vault';

function model(over: Partial<ShellModel> = {}): ShellModel {
  return {
    phase: 'signedOut',
    busy: false,
    step: null,
    methods: ['google', 'email'],
    email: null,
    error: null,
    vault: null,
    vaultError: null,
    ...over,
  };
}

function vaultStatus(over: Partial<VaultStatus> = {}): VaultStatus {
  return {
    items: 0,
    staleness: 'fresh',
    deadLetters: 0,
    provisioned: true,
    warnings: [],
    mount: { state: 'mounted', path: '/home/member/CipherBox' },
    ...over,
  };
}

function actions(): ShellActions {
  return {
    google: vi.fn(),
    sendEmailCode: vi.fn(() => Promise.resolve()),
    submitEmailCode: vi.fn(() => Promise.resolve()),
    submitRecoveryPhrase: vi.fn(() => Promise.resolve()),
    logout: vi.fn(),
  };
}

let root: HTMLElement;

beforeEach(() => {
  root = document.createElement('main');
  document.body.replaceChildren(root);
});

/** The bootstrap's own call, flushed the way React's suite expects it. */
function draw(shown: ShellModel, acted: ShellActions): void {
  act(() => renderShell(root, shown, acted));
}

const find = <T extends HTMLElement>(selector: string): T => {
  const node = root.querySelector<T>(selector);
  if (node === null) throw new Error(`the window rendered no ${selector}`);
  return node;
};

/** Drives the email method as far as the code step. */
async function codeSent(address = 'member@example.com'): Promise<void> {
  fireEvent.change(find('[data-testid="email-input"]'), { target: { value: address } });
  await act(async () => {
    fireEvent.click(find('[data-testid="email-login-button"]'));
  });
}

describe('the front door', () => {
  it('renders an affordance for each offered method', () => {
    draw(model(), actions());
    expect(root.querySelector('[data-method="google"]')).not.toBeNull();
    expect(root.querySelector('[data-method="email"]')).not.toBeNull();
  });

  it('says so when this build offers nothing to sign in with', () => {
    draw(model({ methods: [] }), actions());
    expect(root.textContent).toContain('no sign-in method configured');
  });

  it('says the shell is still starting', () => {
    draw(model({ phase: 'starting' }), actions());
    expect(root.textContent).toContain('Starting…');
  });

  it('starts the Google consent flow when its affordance is clicked', () => {
    const acted = actions();
    draw(model(), acted);
    fireEvent.click(find('[data-method="google"]'));
    expect(acted.google).toHaveBeenCalled();
  });

  it('signs out when the signed-in affordance is clicked', () => {
    const acted = actions();
    draw(model({ phase: 'signedIn', email: 'member@example.com' }), acted);
    fireEvent.click(find('[data-action="logout"]'));
    expect(acted.logout).toHaveBeenCalled();
  });

  it('renders no wallet affordance, even when a method list names one', () => {
    const methods = ['google', 'email', 'wallet'] as readonly IdentityMethod[];
    draw(model({ methods }), actions());
    expect(root.querySelector('[data-method="wallet"]')).toBeNull();
  });

  it('asks for a code only once one has been sent', async () => {
    const acted = actions();
    draw(model(), acted);
    expect(root.querySelector('[data-testid="email-code-input"]')).toBeNull();

    await codeSent();

    expect(acted.sendEmailCode).toHaveBeenCalledWith('member@example.com');
    expect(root.querySelector('[data-testid="email-code-input"]')).not.toBeNull();
  });

  /**
   * The step is the surface's, so a refused request must not advance it: a form
   * that asked for a code CipherBox never sent collects an answer to nothing.
   */
  it('stays on the address when CipherBox did not take the request', async () => {
    const acted = actions();
    acted.sendEmailCode = vi.fn(() => Promise.reject(new Error('that address was refused')));
    draw(model(), acted);

    await codeSent();

    expect(root.querySelector('[data-testid="email-code-input"]')).toBeNull();
  });

  it('submits the collected email answer', async () => {
    const acted = actions();
    draw(model(), acted);
    await codeSent();

    fireEvent.change(find('[data-testid="email-code-input"]'), { target: { value: '123456' } });
    await act(async () => {
      fireEvent.click(find('[data-testid="email-verify-button"]'));
    });

    expect(acted.submitEmailCode).toHaveBeenCalledWith('member@example.com', '123456');
  });

  it('keeps a half-typed code out of the sign-in, rather than sending a short one', async () => {
    const acted = actions();
    draw(model(), acted);
    await codeSent();

    fireEvent.change(find('[data-testid="email-code-input"]'), { target: { value: '123' } });
    await act(async () => {
      fireEvent.click(find('[data-testid="email-verify-button"]'));
    });

    expect(acted.submitEmailCode).not.toHaveBeenCalled();
  });

  it('keeps what a member was typing across a redraw', () => {
    const acted = actions();
    draw(model(), acted);
    const address = find<HTMLInputElement>('[data-testid="email-input"]');
    fireEvent.change(address, { target: { value: 'member@example.com' } });
    address.focus();

    draw(model({ error: 'that address was refused' }), acted);

    const redrawn = find<HTMLInputElement>('[data-testid="email-input"]');
    expect(redrawn).toBe(address);
    expect(redrawn.value).toBe('member@example.com');
    expect(document.activeElement).toBe(redrawn);
  });

  it('disables every control while a transition is in flight', () => {
    draw(model({ busy: true, step: 'signIn' }), actions());
    const controls = root.querySelectorAll<HTMLButtonElement | HTMLInputElement>('button, input');
    expect(controls.length).toBeGreaterThan(0);
    for (const control of controls) expect(control.disabled).toBe(true);
  });

  it('says a submitted code is being signed in', () => {
    draw(model({ busy: true, step: 'signIn' }), actions());
    expect(root.querySelector('[role="status"]')?.textContent).toBe('Signing in…');
  });

  it('names the step in flight, so one wait is not read as another', () => {
    const acted = actions();
    draw(model({ busy: true, step: 'emailCode' }), acted);
    expect(root.querySelector('[role="status"]')?.textContent).toBe('Sending a code…');

    draw(model({ busy: true, step: 'google' }), acted);
    expect(root.querySelector('[role="status"]')?.textContent).toBe('Waiting for Google…');
  });

  it('shows no wait while the shell is idle', () => {
    draw(model(), actions());
    expect(root.querySelector('[role="status"]')).toBeNull();
  });

  it('waits for the first vault read rather than reporting an empty vault', () => {
    draw(model({ phase: 'signedIn', email: 'member@example.com' }), actions());
    expect(root.textContent).toContain('member@example.com');
    expect(root.textContent).toContain('Opening your vault…');
    expect(root.querySelector('[data-vault="items"]')).toBeNull();
    expect(root.querySelector('[data-action="logout"]')).not.toBeNull();
  });

  it('renders the vault the engine reports', () => {
    const vault = vaultStatus({ items: 3, staleness: 'reconciling' });
    draw(model({ phase: 'signedIn', vault }), actions());
    expect(root.querySelector('[data-vault="items"]')?.textContent).toBe('3 items in your vault');
    expect(root.querySelector('[data-vault="staleness"]')?.textContent).toBe('Reconciling');
  });

  it('says which rung the engine is on, so one state is not read as another', () => {
    const acted = actions();
    for (const [staleness, label] of [
      ['fresh', 'Synced'],
      ['stale', 'Stale'],
      ['offline', 'Offline'],
    ] as const) {
      draw(model({ phase: 'signedIn', vault: vaultStatus({ staleness }) }), acted);
      expect(root.querySelector('[data-vault="staleness"]')?.textContent).toBe(label);
    }
  });

  /**
   * A parked write is not an old view: it gets its own line, and never
   * disappears into the staleness one.
   */
  it('surfaces dead-lettered work apart from staleness', () => {
    const vault = vaultStatus({ items: 1, deadLetters: 2, staleness: 'fresh' });
    draw(model({ phase: 'signedIn', vault }), actions());
    const parked = root.querySelector('[data-vault="dead-letters"]');
    expect(parked?.textContent).toContain('2 changes cannot publish');
    expect(root.querySelector('[data-vault="staleness"]')?.textContent).toBe('Synced');
  });

  it('says nothing about parked work when there is none', () => {
    draw(model({ phase: 'signedIn', vault: vaultStatus({ items: 1 }) }), actions());
    expect(root.querySelector('[data-vault="dead-letters"]')).toBeNull();
    expect(root.querySelector('[data-vault="items"]')?.textContent).toBe('1 item in your vault');
  });

  /**
   * A withheld update and an old view call for different reactions, so the
   * warning is its own line and the rung still reads as the rung.
   */
  it('renders an engine warning apart from the staleness rung', () => {
    const vault = vaultStatus({
      staleness: 'fresh',
      warnings: [{ kind: 'withheldUpdateEscalation', detail: null }],
    });
    draw(model({ phase: 'signedIn', vault }), actions());

    const raised = root.querySelector('[data-warning="withheldUpdateEscalation"]');
    expect(raised?.getAttribute('role')).toBe('alert');
    expect(raised?.textContent).toContain('kept from its latest update');
    expect(root.querySelector('[data-vault="staleness"]')?.textContent).toBe('Synced');
  });

  it("says the engine's own words for a warning that carried any", () => {
    const vault = vaultStatus({
      warnings: [{ kind: 'renewalFailed', detail: 'the CAS race was lost' }],
    });
    draw(model({ phase: 'signedIn', vault }), actions());
    expect(root.querySelector('[data-warning="renewalFailed"]')?.textContent).toContain(
      'the CAS race was lost'
    );
  });

  /** A class this table has not learned yet must still raise a readable line. */
  it('names a warning it has no label for, rather than rendering nothing', () => {
    const vault = vaultStatus({
      warnings: [{ kind: 'somethingNewer' as VaultWarningKind, detail: null }],
    });
    draw(model({ phase: 'signedIn', vault }), actions());
    const raised = root.querySelector('[data-vault="warning"]');
    expect(raised?.textContent).toBe('CipherBox raised a condition it could not name');
  });

  it('says a vault that was never minted is not an empty one', () => {
    draw(model({ phase: 'signedIn', vault: vaultStatus({ provisioned: false }) }), actions());
    const unminted = root.querySelector('[data-vault="unprovisioned"]');
    expect(unminted?.getAttribute('role')).toBe('alert');
    expect(unminted?.textContent).toContain('nothing will publish');
  });

  it('says nothing about provisioning once the vault is minted', () => {
    draw(model({ phase: 'signedIn', vault: vaultStatus() }), actions());
    expect(root.querySelector('[data-vault="unprovisioned"]')).toBeNull();
  });

  it('says where the vault is, so a member knows which folder is watched', () => {
    draw(model({ phase: 'signedIn', vault: vaultStatus() }), actions());
    expect(root.querySelector('[data-vault="mount"]')?.textContent).toBe(
      'Mounted at /home/member/CipherBox'
    );
    expect(root.querySelector('[data-vault="mount-refused"]')).toBeNull();
  });

  it('raises a session that is signed in with no mount, rather than staying silent', () => {
    draw(
      model({
        phase: 'signedIn',
        vault: vaultStatus({
          items: 4,
          mount: { state: 'refused', reason: '/home/member/CipherBox cannot be mounted on' },
        }),
      }),
      actions()
    );
    const refused = root.querySelector('[data-vault="mount-refused"]');
    expect(refused?.getAttribute('role')).toBe('alert');
    expect(refused?.textContent).toBe('/home/member/CipherBox cannot be mounted on');
    // A mount failure is not a sign-in failure: the vault still reads.
    expect(root.querySelector('[data-vault="items"]')?.textContent).toBe('4 items in your vault');
  });

  it('says the vault is still being mounted rather than that it is missing', () => {
    draw(
      model({ phase: 'signedIn', vault: vaultStatus({ mount: { state: 'opening' } }) }),
      actions()
    );
    expect(root.querySelector('[data-vault="mount-opening"]')).not.toBeNull();
    expect(root.querySelector('[data-vault="mount-refused"]')).toBeNull();
  });

  it('raises nothing when the engine raised nothing', () => {
    draw(model({ phase: 'signedIn', vault: vaultStatus() }), actions());
    expect(root.querySelector('[data-vault="warning"]')).toBeNull();
  });

  it('reports a vault that could not be read instead of an empty one', () => {
    draw(model({ phase: 'signedIn', vaultError: 'no session is live' }), actions());
    expect(root.querySelector('[data-vault="status"] .error')?.textContent).toBe(
      'no session is live'
    );
    expect(root.querySelector('[data-vault="items"]')).toBeNull();
  });

  it('says where factors are managed and that the recovery phrase always works', () => {
    draw(model({ phase: 'signedIn', vault: vaultStatus() }), actions());
    const security = root.querySelector('[data-security="panel"]');
    expect(security?.textContent).toContain('on the web');
    expect(security?.textContent).toContain('recovery phrase');
    expect(security?.textContent).toContain('no second device');
  });

  it('offers no factor or approval affordance of its own', () => {
    draw(model({ phase: 'signedIn', vault: vaultStatus() }), actions());
    const security = root.querySelector('[data-security="panel"]');
    expect(security?.querySelector('button')).toBeNull();
    expect(security?.querySelector('a')).toBeNull();
  });

  // A screen that stopped showing this is a licence condition dropped, not a
  // cosmetic regression.
  it.each(['starting', 'signedOut', 'signedIn', 'recovery'] as const)(
    'shows the WinFsp notice and its project address while %s',
    (phase) => {
      draw(model({ phase, vault: vaultStatus() }), actions());
      const footer = root.querySelector('[data-attribution="winfsp"]');
      expect(footer?.textContent).toContain(
        'WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos'
      );
      expect(footer?.textContent).toContain('https://github.com/winfsp/winfsp');
    }
  );

  it('offers the recovery phrase when a sign-in stops at the factor policy', () => {
    draw(model({ phase: 'recovery' }), actions());
    expect(root.querySelector('[data-testid="recovery-login"]')).not.toBeNull();
    expect(root.querySelector('[data-testid="recovery-phrase-input"]')).not.toBeNull();
    // The held login is not a front door: offering a method here would start a
    // second sign-in over the one waiting for the phrase.
    expect(root.querySelector('[data-method="google"]')).toBeNull();
    expect(root.querySelector('[data-method="email"]')).toBeNull();
  });

  it('hands the typed phrase to the shell', async () => {
    const acted = actions();
    draw(model({ phase: 'recovery' }), acted);
    const phrase = Array.from({ length: 24 }, (_, index) => `word${String(index)}`).join(' ');

    fireEvent.change(find('[data-testid="recovery-phrase-input"]'), { target: { value: phrase } });
    await act(async () => {
      fireEvent.click(find('[data-testid="recovery-submit"]'));
    });

    expect(acted.submitRecoveryPhrase).toHaveBeenCalledWith(phrase);
    // A phrase left in the field outlives the sign-in it answered.
    await waitFor(() =>
      expect(find<HTMLTextAreaElement>('[data-testid="recovery-phrase-input"]').value).toBe('')
    );
  });

  // The held Core Kit session is a live credential, so leaving the panel is not
  // enough to end it.
  it('signs out when the member abandons the phrase prompt', () => {
    const acted = actions();
    draw(model({ phase: 'recovery' }), acted);

    fireEvent.click(find('[data-testid="recovery-cancel"]'));

    expect(acted.logout).toHaveBeenCalled();
  });

  it('disables the phrase prompt while an attempt is in flight', () => {
    draw(model({ phase: 'recovery', busy: true, step: 'recovery' }), actions());
    const controls = root.querySelectorAll<HTMLButtonElement | HTMLTextAreaElement>(
      '[data-testid="recovery-login"] button, [data-testid="recovery-login"] textarea'
    );
    expect(controls).toHaveLength(3);
    for (const control of controls) expect(control.disabled).toBe(true);
  });

  /** The prompt carries the refusal, so it is not reported twice at once. */
  it('reports a refused phrase in the prompt and nowhere else', () => {
    draw(model({ phase: 'recovery', error: 'that phrase did not open it' }), actions());
    const banners = root.querySelectorAll('.login-error');
    expect(banners).toHaveLength(1);
    expect(find('[data-testid="recovery-login"] .login-error').textContent).toBe(
      'that phrase did not open it'
    );
  });

  it('reports a failure without offering it as markup', () => {
    draw(model({ error: '<img src=x onerror=alert(1)>' }), actions());
    expect(find('.login-error').textContent).toBe('<img src=x onerror=alert(1)>');
    expect(root.querySelector('img')).toBeNull();
  });
});

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
    codeSent: false,
    address: '',
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
    ...over,
  };
}

function actions(): ShellActions {
  return {
    google: vi.fn(),
    sendEmailCode: vi.fn(),
    submitEmailCode: vi.fn(),
    logout: vi.fn(),
  };
}

let root: HTMLElement;

beforeEach(() => {
  root = document.createElement('main');
  document.body.replaceChildren(root);
});

describe('the front door', () => {
  it('renders an affordance for each offered method', () => {
    renderShell(root, model(), actions());
    expect(root.querySelector('[data-method="google"]')).not.toBeNull();
    expect(root.querySelector('[data-method="email"]')).not.toBeNull();
  });

  it('says so when this build offers nothing to sign in with', () => {
    renderShell(root, model({ methods: [] }), actions());
    expect(root.textContent).toContain('no sign-in method configured');
  });

  it('says the shell is still starting', () => {
    renderShell(root, model({ phase: 'starting' }), actions());
    expect(root.textContent).toContain('Starting…');
  });

  it('starts the Google consent flow when its affordance is clicked', () => {
    const acted = actions();
    renderShell(root, model(), acted);
    root.querySelector<HTMLButtonElement>('[data-method="google"]')!.click();
    expect(acted.google).toHaveBeenCalled();
  });

  it('signs out when the signed-in affordance is clicked', () => {
    const acted = actions();
    renderShell(root, model({ phase: 'signedIn', email: 'member@example.com' }), acted);
    root.querySelector<HTMLButtonElement>('[data-action="logout"]')!.click();
    expect(acted.logout).toHaveBeenCalled();
  });

  it('renders no wallet affordance, even when a method list names one', () => {
    const methods = ['google', 'email', 'wallet'] as readonly IdentityMethod[];
    renderShell(root, model({ methods }), actions());
    expect(root.querySelector('[data-method="wallet"]')).toBeNull();
  });

  it('asks for a code only once one has been sent', () => {
    renderShell(root, model(), actions());
    expect(root.querySelector('input[name="code"]')).toBeNull();

    renderShell(root, model({ codeSent: true }), actions());
    expect(root.querySelector('input[name="code"]')).not.toBeNull();
  });

  it('keeps the address across a re-render', () => {
    renderShell(root, model({ codeSent: true, address: 'member@example.com' }), actions());
    const address = root.querySelector<HTMLInputElement>('input[name="email"]');
    expect(address?.value).toBe('member@example.com');
  });

  it('submits the collected email answer', () => {
    const acted = actions();
    renderShell(root, model({ codeSent: true, address: 'member@example.com' }), acted);
    root.querySelector<HTMLInputElement>('input[name="code"]')!.value = '123456';
    root.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    expect(acted.submitEmailCode).toHaveBeenCalledWith('member@example.com', '123456');
  });

  it('asks for a code before signing in, so the browser catches an empty one', () => {
    renderShell(root, model({ codeSent: true }), actions());
    expect(root.querySelector<HTMLInputElement>('input[name="code"]')!.required).toBe(true);
  });

  it('asks CipherBox for a code with the address in the form', () => {
    const acted = actions();
    renderShell(root, model(), acted);
    root.querySelector<HTMLInputElement>('input[name="email"]')!.value = 'member@example.com';
    root.querySelector('form')!.dispatchEvent(new Event('submit', { cancelable: true }));
    expect(acted.sendEmailCode).toHaveBeenCalledWith('member@example.com');
  });

  it('keeps focus on the control a member was typing in across a redraw', () => {
    renderShell(root, model(), actions());
    const address = root.querySelector<HTMLInputElement>('input[name="email"]')!;
    address.focus();

    renderShell(root, model({ error: 'that address was refused' }), actions());
    const redrawn = root.querySelector<HTMLInputElement>('input[name="email"]')!;
    expect(redrawn).not.toBe(address);
    expect(document.activeElement).toBe(redrawn);
  });

  it('disables every control while a transition is in flight', () => {
    renderShell(root, model({ busy: true, step: 'signIn', codeSent: true }), actions());
    for (const control of root.querySelectorAll<HTMLButtonElement>('button, input')) {
      expect(control.disabled).toBe(true);
    }
  });

  it('says a submitted code is being signed in', () => {
    renderShell(root, model({ busy: true, step: 'signIn', codeSent: true }), actions());
    const status = root.querySelector('[role="status"]');
    expect(status?.textContent).toBe('Signing in…');
  });

  it('names the step in flight, so one wait is not read as another', () => {
    renderShell(root, model({ busy: true, step: 'emailCode' }), actions());
    expect(root.querySelector('[role="status"]')?.textContent).toBe('Sending a code…');

    renderShell(root, model({ busy: true, step: 'google' }), actions());
    expect(root.querySelector('[role="status"]')?.textContent).toBe('Waiting for Google…');
  });

  it('shows no wait while the shell is idle', () => {
    renderShell(root, model({ codeSent: true }), actions());
    expect(root.querySelector('[role="status"]')).toBeNull();
  });

  it('waits for the first vault read rather than reporting an empty vault', () => {
    renderShell(root, model({ phase: 'signedIn', email: 'member@example.com' }), actions());
    expect(root.textContent).toContain('member@example.com');
    expect(root.textContent).toContain('Opening your vault…');
    expect(root.querySelector('[data-vault="items"]')).toBeNull();
    expect(root.querySelector('[data-action="logout"]')).not.toBeNull();
  });

  it('renders the vault the engine reports', () => {
    const vault = vaultStatus({ items: 3, staleness: 'reconciling' });
    renderShell(root, model({ phase: 'signedIn', vault }), actions());
    expect(root.querySelector('[data-vault="items"]')?.textContent).toBe('3 items in your vault');
    expect(root.querySelector('[data-vault="staleness"]')?.textContent).toBe('Reconciling');
  });

  it('says which rung the engine is on, so one state is not read as another', () => {
    for (const [staleness, label] of [
      ['fresh', 'Synced'],
      ['stale', 'Stale'],
      ['offline', 'Offline'],
    ] as const) {
      renderShell(root, model({ phase: 'signedIn', vault: vaultStatus({ staleness }) }), actions());
      expect(root.querySelector('[data-vault="staleness"]')?.textContent).toBe(label);
    }
  });

  /**
   * A parked write is not an old view: it gets its own line, and never
   * disappears into the staleness one.
   */
  it('surfaces dead-lettered work apart from staleness', () => {
    const vault = vaultStatus({ items: 1, deadLetters: 2, staleness: 'fresh' });
    renderShell(root, model({ phase: 'signedIn', vault }), actions());
    const parked = root.querySelector('[data-vault="dead-letters"]');
    expect(parked?.textContent).toContain('2 changes cannot publish');
    expect(root.querySelector('[data-vault="staleness"]')?.textContent).toBe('Synced');
  });

  it('says nothing about parked work when there is none', () => {
    renderShell(root, model({ phase: 'signedIn', vault: vaultStatus({ items: 1 }) }), actions());
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
    renderShell(root, model({ phase: 'signedIn', vault }), actions());

    const raised = root.querySelector('[data-warning="withheldUpdateEscalation"]');
    expect(raised?.getAttribute('role')).toBe('alert');
    expect(raised?.textContent).toContain('kept from its latest update');
    expect(root.querySelector('[data-vault="staleness"]')?.textContent).toBe('Synced');
  });

  it("says the engine's own words for a warning that carried any", () => {
    const vault = vaultStatus({
      warnings: [{ kind: 'renewalFailed', detail: 'the CAS race was lost' }],
    });
    renderShell(root, model({ phase: 'signedIn', vault }), actions());
    expect(root.querySelector('[data-warning="renewalFailed"]')?.textContent).toContain(
      'the CAS race was lost'
    );
  });

  /** A class this table has not learned yet must still raise a readable line. */
  it('names a warning it has no label for, rather than rendering nothing', () => {
    const vault = vaultStatus({
      warnings: [{ kind: 'somethingNewer' as VaultWarningKind, detail: null }],
    });
    renderShell(root, model({ phase: 'signedIn', vault }), actions());
    const raised = root.querySelector('[data-vault="warning"]');
    expect(raised?.textContent).toBe('CipherBox raised a condition it could not name');
  });

  it('says a vault that was never minted is not an empty one', () => {
    renderShell(
      root,
      model({ phase: 'signedIn', vault: vaultStatus({ provisioned: false }) }),
      actions()
    );
    const unminted = root.querySelector('[data-vault="unprovisioned"]');
    expect(unminted?.getAttribute('role')).toBe('alert');
    expect(unminted?.textContent).toContain('nothing will publish');
  });

  it('says nothing about provisioning once the vault is minted', () => {
    renderShell(root, model({ phase: 'signedIn', vault: vaultStatus() }), actions());
    expect(root.querySelector('[data-vault="unprovisioned"]')).toBeNull();
  });

  it('raises nothing when the engine raised nothing', () => {
    renderShell(root, model({ phase: 'signedIn', vault: vaultStatus() }), actions());
    expect(root.querySelector('[data-vault="warning"]')).toBeNull();
  });

  it('reports a vault that could not be read instead of an empty one', () => {
    renderShell(root, model({ phase: 'signedIn', vaultError: 'no session is live' }), actions());
    expect(root.querySelector('[data-vault="status"] .error')?.textContent).toBe(
      'no session is live'
    );
    expect(root.querySelector('[data-vault="items"]')).toBeNull();
  });

  it('reports a failure without offering it as markup', () => {
    renderShell(root, model({ error: '<img src=x onerror=alert(1)>' }), actions());
    const failure = root.querySelector('.error');
    expect(failure?.textContent).toBe('<img src=x onerror=alert(1)>');
    expect(root.querySelector('img')).toBeNull();
  });
});

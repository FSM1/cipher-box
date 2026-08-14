import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { IdentityMethod } from '@cipherbox/login';
import { renderShell, type ShellActions, type ShellModel } from './frontDoor';

function model(over: Partial<ShellModel> = {}): ShellModel {
  return {
    phase: 'signedOut',
    busy: false,
    methods: ['google', 'email'],
    email: null,
    error: null,
    codeSent: false,
    address: '',
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

  it('disables every control while a transition is in flight', () => {
    renderShell(root, model({ busy: true, codeSent: true }), actions());
    for (const control of root.querySelectorAll<HTMLButtonElement>('button, input')) {
      expect(control.disabled).toBe(true);
    }
  });

  it('says there is no vault behind a signed-in session', () => {
    renderShell(root, model({ phase: 'signedIn', email: 'member@example.com' }), actions());
    expect(root.textContent).toContain('member@example.com');
    expect(root.textContent).toContain('No vault on this device yet');
    expect(root.querySelector('[data-action="logout"]')).not.toBeNull();
  });

  it('reports a failure without offering it as markup', () => {
    renderShell(root, model({ error: '<img src=x onerror=alert(1)>' }), actions());
    const failure = root.querySelector('.error');
    expect(failure?.textContent).toBe('<img src=x onerror=alert(1)>');
    expect(root.querySelector('img')).toBeNull();
  });
});

/**
 * The shell's login chrome. Framework-free: this window is the front door and a
 * status line, and the vault UI lives on the web app.
 *
 * Which methods appear is read off the flow, never branched on here, so a
 * method this host cannot collect renders no affordance at all (ADR 0008 D2).
 */

import type { IdentityMethod } from '@cipherbox/login';

/** The transition this host asked for, which `LoginProgress` does not name. */
export type LoginStep = 'google' | 'emailCode' | 'signIn' | 'logout' | 'restore';

const STEP_LABELS: Record<LoginStep, string> = {
  google: 'Waiting for Google…',
  emailCode: 'Sending a code…',
  signIn: 'Signing in…',
  logout: 'Signing out…',
  restore: 'Restoring your session…',
};

export interface ShellModel {
  phase: 'starting' | 'signedOut' | 'signedIn';
  /** True while a restore, login, or logout is in flight. */
  busy: boolean;
  /** What that in-flight transition is, so the wait can say so. */
  step: LoginStep | null;
  /** The methods the login flow offers, in the order to show them. */
  methods: readonly IdentityMethod[];
  /** The signed-in address, when the method carried one. */
  email: string | null;
  error: string | null;
  /** True once CipherBox has sent a code to the address in the form. */
  codeSent: boolean;
  /** The address the form holds, kept across a re-render. */
  address: string;
}

export interface ShellActions {
  google(): void;
  sendEmailCode(email: string): void;
  submitEmailCode(email: string, code: string): void;
  logout(): void;
}

type Renderer = (model: ShellModel, actions: ShellActions) => HTMLElement;

/** One renderer per method the shell can collect. */
const RENDERERS: Partial<Record<IdentityMethod, Renderer>> = {
  google: googleButton,
  email: emailForm,
};

export function renderShell(root: HTMLElement, model: ShellModel, actions: ShellActions): void {
  const view = element('div', { class: 'shell' });
  view.append(text('h1', 'CipherBox'));

  if (model.phase === 'starting') view.append(note('Starting…'));
  else if (model.phase === 'signedIn') view.append(signedIn(model, actions));
  else view.append(frontDoor(model, actions));

  if (model.busy && model.step !== null) {
    view.append(text('p', STEP_LABELS[model.step], { class: 'muted', role: 'status' }));
  }

  if (model.error !== null) {
    view.append(text('p', model.error, { class: 'error', role: 'alert' }));
  }
  const focused = focusedName(root);
  root.replaceChildren(view);
  refocus(view, focused);
}

/** The `name` of the focused control inside `root`, so a redraw can restore it. */
function focusedName(root: HTMLElement): string | null {
  const active = document.activeElement;
  if (!(active instanceof HTMLElement) || !root.contains(active)) return null;
  return active.getAttribute('name');
}

/** A redraw replaces every node, which would otherwise drop a typist to the body. */
function refocus(view: HTMLElement, name: string | null): void {
  if (name === null) return;
  for (const node of view.querySelectorAll<HTMLElement>('[name]')) {
    if (node.getAttribute('name') === name) {
      node.focus();
      return;
    }
  }
}

function frontDoor(model: ShellModel, actions: ShellActions): HTMLElement {
  const section = element('section', { class: 'front-door' });
  section.append(note('Sign in to connect this device to your vault.'));

  const offered = model.methods.flatMap((method) => {
    const render = RENDERERS[method];
    return render ? [render(model, actions)] : [];
  });
  if (offered.length === 0) {
    section.append(note('This build has no sign-in method configured.'));
  }
  section.append(...offered);
  return section;
}

function googleButton(model: ShellModel, actions: ShellActions): HTMLElement {
  const button = text('button', 'Continue with Google', {
    'data-method': 'google',
    type: 'button',
  }) as HTMLButtonElement;
  button.disabled = model.busy;
  button.addEventListener('click', () => actions.google());
  return button;
}

function emailForm(model: ShellModel, actions: ShellActions): HTMLElement {
  const form = element('form', { 'data-method': 'email' }) as HTMLFormElement;

  const address = element('input', {
    name: 'email',
    type: 'email',
    placeholder: 'you@example.com',
    required: 'required',
    autocomplete: 'email',
  }) as HTMLInputElement;
  address.value = model.address;
  address.disabled = model.busy;
  form.append(address);

  const code = element('input', {
    name: 'code',
    type: 'text',
    placeholder: 'Verification code',
    required: 'required',
    inputmode: 'numeric',
    autocomplete: 'one-time-code',
  }) as HTMLInputElement;
  code.disabled = model.busy;

  const submit = text('button', model.codeSent ? 'Sign in' : 'Email me a code', {
    type: 'submit',
  }) as HTMLButtonElement;
  submit.disabled = model.busy;

  if (model.codeSent) form.append(code);
  form.append(submit);

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    if (model.codeSent) actions.submitEmailCode(address.value, code.value);
    else actions.sendEmailCode(address.value);
  });
  return form;
}

function signedIn(model: ShellModel, actions: ShellActions): HTMLElement {
  const section = element('section', { class: 'signed-in' });
  section.append(text('p', model.email ?? 'Signed in'));
  section.append(note('No vault on this device yet — the engine is not wired to this shell.'));

  const out = text('button', 'Sign out', {
    'data-action': 'logout',
    type: 'button',
  }) as HTMLButtonElement;
  out.disabled = model.busy;
  out.addEventListener('click', () => actions.logout());
  section.append(out);
  return section;
}

function note(message: string): HTMLElement {
  return text('p', message, { class: 'muted' });
}

function element(tag: string, attributes: Record<string, string> = {}): HTMLElement {
  const node = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes)) node.setAttribute(name, value);
  return node;
}

/** Text goes in as `textContent`, so nothing the API or a provider said is markup. */
function text(tag: string, content: string, attributes: Record<string, string> = {}): HTMLElement {
  const node = element(tag, attributes);
  node.textContent = content;
  return node;
}

/**
 * The shell's login chrome. Framework-free: this window is the front door and a
 * status line, and the vault UI lives on the mount and the web app.
 *
 * Which methods appear is read off the flow, never branched on here, so a
 * method this host cannot collect renders no affordance at all (ADR 0008 D2).
 */

import type { IdentityMethod } from '@cipherbox/login';
import type { MountStatus, Staleness, VaultStatus, VaultWarning, VaultWarningKind } from './vault';

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
  /** The engine's last reported vault state; `null` until the first read lands. */
  vault: VaultStatus | null;
  /** Why the last vault read did not land. Kept apart from `error`, which is
   * the login's: a vault that cannot be read is not a sign-in that failed. */
  vaultError: string | null;
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

/** The staleness rung as this window says it (blueprint/desktop.md, "Tray"). */
const STALENESS_LABELS: Record<Staleness, string> = {
  fresh: 'Synced',
  reconciling: 'Reconciling',
  stale: 'Stale',
  offline: 'Offline',
};

/**
 * A warning is a state of its own, never a rung on the staleness ladder: an
 * update being withheld and a view being old call for different reactions.
 */
const WARNING_LABELS: Record<VaultWarningKind, string> = {
  attributableAbuse: 'CipherBox refused an update that failed a trust check',
  withheldUpdateEscalation: 'A shared folder is being kept from its latest update',
  renewalFailed: 'CipherBox could not renew a record, so it may expire',
};

/** Shown until a sign-in mints the vault; nothing publishes before then. */
const UNPROVISIONED = 'CipherBox has not created your vault yet, so nothing will publish';

function signedIn(model: ShellModel, actions: ShellActions): HTMLElement {
  const section = element('section', { class: 'signed-in' });
  section.append(text('p', model.email ?? 'Signed in'));
  section.append(vault(model));

  const out = text('button', 'Sign out', {
    'data-action': 'logout',
    type: 'button',
  }) as HTMLButtonElement;
  out.disabled = model.busy;
  out.addEventListener('click', () => actions.logout());
  section.append(out);
  return section;
}

/** Counts and a rung; the files themselves are the mount's surface. */
function vault(model: ShellModel): HTMLElement {
  const panel = element('section', { class: 'vault', 'data-vault': 'status' });
  if (model.vaultError !== null) {
    panel.append(text('p', model.vaultError, { class: 'error', role: 'alert' }));
    return panel;
  }
  if (model.vault === null) {
    panel.append(note('Opening your vault…'));
    return panel;
  }

  const { items, staleness, deadLetters, provisioned, warnings, mount } = model.vault;
  panel.append(
    text('p', `${items} ${items === 1 ? 'item' : 'items'} in your vault`, {
      'data-vault': 'items',
    })
  );
  panel.append(
    text('p', STALENESS_LABELS[staleness], { class: 'muted', 'data-vault': 'staleness' })
  );
  panel.append(mountLine(mount));
  if (!provisioned) {
    panel.append(
      text('p', UNPROVISIONED, { class: 'error', role: 'alert', 'data-vault': 'unprovisioned' })
    );
  }
  panel.append(...warnings.map(warning));
  // Never silent, and never folded into the staleness line: a parked write is a
  // different thing from an old view.
  if (deadLetters > 0) {
    panel.append(
      text(
        'p',
        `${deadLetters} ${deadLetters === 1 ? 'change' : 'changes'} cannot publish — open CipherBox on the web to resolve`,
        { class: 'error', role: 'alert', 'data-vault': 'dead-letters' }
      )
    );
  }
  return panel;
}

/**
 * Where the vault is on this machine, or why it is nowhere.
 *
 * A refusal is an error rather than a muted note: a member who thinks the mount
 * is there works in a folder nothing is watching.
 */
function mountLine({ path, refusal }: MountStatus): HTMLElement {
  if (path !== null) {
    return text('p', `Mounted at ${path}`, { class: 'muted', 'data-vault': 'mount' });
  }
  return text('p', refusal ?? 'Your vault is not mounted on this device', {
    class: 'error',
    role: 'alert',
    'data-vault': 'mount-refused',
  });
}

/**
 * One engine warning, with the engine's own words for it where it had any.
 *
 * The fallback is unreachable by the types and kept anyway: a class the engine
 * gains before this table does must still raise something a member can act on,
 * which is the whole point of the line. The staleness table needs no such
 * guard — an unnamed rung is a cosmetic gap, not a silent warning.
 */
function warning({ kind, detail }: VaultWarning): HTMLElement {
  const label = WARNING_LABELS[kind] ?? 'CipherBox raised a condition it could not name';
  return text('p', detail === null ? label : `${label} — ${detail}`, {
    class: 'error',
    role: 'alert',
    'data-vault': 'warning',
    'data-warning': kind,
  });
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

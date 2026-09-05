/**
 * The shell's login chrome. The auth surfaces are `@cipherbox/auth-ui`'s, so
 * this window and the web app render one implementation of each; what stays
 * here is the shell's own — the vault panel, the wait line, and the licence
 * footer.
 *
 * Which methods appear is read off the flow, never branched on here, so a
 * method this host cannot collect renders no affordance at all (ADR 0008 D2).
 */

import { Fragment, type ReactElement } from 'react';
import { flushSync } from 'react-dom';
import { createRoot, type Root } from 'react-dom/client';
import { EmailLoginForm, LoginError, RecoveryPhraseForm } from '@cipherbox/auth-ui';
import type { IdentityMethod } from '@cipherbox/login';
import type { MountStatus, Staleness, VaultStatus, VaultWarning, VaultWarningKind } from './vault';

/** The transition this host asked for, which `LoginProgress` does not name. */
export type LoginStep = 'google' | 'emailCode' | 'signIn' | 'recovery' | 'logout' | 'restore';

const STEP_LABELS: Record<LoginStep, string> = {
  google: 'Waiting for Google…',
  emailCode: 'Sending a code…',
  signIn: 'Signing in…',
  recovery: 'Unlocking your account…',
  logout: 'Signing out…',
  restore: 'Restoring your session…',
};

export interface ShellModel {
  /** `recovery` is a sign-in held at the factor policy, not a failed one. */
  phase: 'starting' | 'signedOut' | 'signedIn' | 'recovery';
  /** True while a restore, login, or logout is in flight. */
  busy: boolean;
  /** What that in-flight transition is, so the wait can say so. */
  step: LoginStep | null;
  /** The methods the login flow offers, in the order to show them. */
  methods: readonly IdentityMethod[];
  /** The signed-in address, when the method carried one. */
  email: string | null;
  error: string | null;
  /** The engine's last reported vault state; `null` until the first read lands. */
  vault: VaultStatus | null;
  /** Why the last vault read did not land. Kept apart from `error`, which is
   * the login's: a vault that cannot be read is not a sign-in that failed. */
  vaultError: string | null;
}

export interface ShellActions {
  google(): void;
  /** Each rejects when the step failed, so a surface holds its own place. */
  sendEmailCode(email: string): Promise<void>;
  submitEmailCode(email: string, code: string): Promise<void>;
  /** Finishes a sign-in held at the factor policy from the phrase alone. */
  submitRecoveryPhrase(phrase: string): Promise<void>;
  logout(): void;
}

type Renderer = (model: ShellModel, actions: ShellActions) => ReactElement;

/** One renderer per method the shell can collect. */
const RENDERERS: Partial<Record<IdentityMethod, Renderer>> = {
  google: googleButton,
  email: emailForm,
};

/** One React root per window; a second would drop what the first had typed. */
const roots = new WeakMap<HTMLElement, Root>();

/**
 * Draws the window. The bootstrap redraws by calling this again and reads the
 * result in the same turn, so the tree is flushed rather than scheduled.
 */
export function renderShell(root: HTMLElement, model: ShellModel, actions: ShellActions): void {
  const mounted = roots.get(root) ?? createRoot(root);
  roots.set(root, mounted);
  flushSync(() => mounted.render(<Shell model={model} actions={actions} />));
}

function Shell({ model, actions }: { model: ShellModel; actions: ShellActions }) {
  return (
    <div className="shell">
      <h1>CipherBox</h1>
      {model.phase === 'starting' && <Note>Starting…</Note>}
      {model.phase === 'signedIn' && <SignedIn model={model} actions={actions} />}
      {model.phase === 'recovery' && (
        <RecoveryPhraseForm
          onSubmit={actions.submitRecoveryPhrase}
          onCancel={actions.logout}
          busy={model.busy}
          error={model.error}
        />
      )}
      {model.phase === 'signedOut' && <FrontDoor model={model} actions={actions} />}

      {model.busy && model.step !== null && (
        <p className="muted" role="status">
          {STEP_LABELS[model.step]}
        </p>
      )}
      {/* The phrase prompt carries its own banner, so a refused phrase is
          reported once rather than beside itself. */}
      {model.error !== null && model.phase !== 'recovery' && <LoginError message={model.error} />}
      <Attribution />
    </div>
  );
}

function FrontDoor({ model, actions }: { model: ShellModel; actions: ShellActions }) {
  const offered = model.methods.flatMap((method) => {
    const render = RENDERERS[method];
    return render ? [<Fragment key={method}>{render(model, actions)}</Fragment>] : [];
  });
  return (
    <section className="front-door">
      <Note>Sign in to connect this device to your vault.</Note>
      {offered.length === 0 && <Note>This build has no sign-in method configured.</Note>}
      {offered}
    </section>
  );
}

function googleButton(model: ShellModel, actions: ShellActions): ReactElement {
  return (
    <button type="button" data-method="google" disabled={model.busy} onClick={actions.google}>
      Continue with Google
    </button>
  );
}

function emailForm(model: ShellModel, actions: ShellActions): ReactElement {
  return (
    <div data-method="email">
      <EmailLoginForm
        onSendCode={actions.sendEmailCode}
        onVerify={actions.submitEmailCode}
        busy={model.busy}
      />
    </div>
  );
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
  scopeExitCutOwed: 'CipherBox could not rotate a shared folder a move left',
};

/** Shown until a sign-in mints the vault; nothing publishes before then. */
const UNPROVISIONED = 'CipherBox has not created your vault yet, so nothing will publish';

/**
 * Enrollment and device approval are the web app's (ADR 0009 D2 and consequence
 * 5), so this window offers neither affordance and says where they live — the
 * rule ADR 0008 applies to every method on this host: the affordance and the
 * truth agree.
 */
const SECURITY_LINES = [
  'Sign-in factors and device approval are managed in CipherBox on the web.',
  'Your recovery phrase is the guaranteed way back into your account, with no second device.',
];

function SignedIn({ model, actions }: { model: ShellModel; actions: ShellActions }) {
  return (
    <section className="signed-in">
      <p>{model.email ?? 'Signed in'}</p>
      <Vault model={model} />
      <section className="security" data-security="panel">
        {SECURITY_LINES.map((line) => (
          <Note key={line}>{line}</Note>
        ))}
      </section>
      <button type="button" data-action="logout" disabled={model.busy} onClick={actions.logout}>
        Sign out
      </button>
    </section>
  );
}

/** Counts and a rung; the files themselves are the mount's surface. */
function Vault({ model }: { model: ShellModel }) {
  if (model.vaultError !== null) {
    return (
      <section className="vault" data-vault="status">
        <p className="error" role="alert">
          {model.vaultError}
        </p>
      </section>
    );
  }
  if (model.vault === null) {
    return (
      <section className="vault" data-vault="status">
        <Note>Opening your vault…</Note>
      </section>
    );
  }

  const { items, staleness, deadLetters, provisioned, warnings, mount } = model.vault;
  return (
    <section className="vault" data-vault="status">
      <p data-vault="items">{`${String(items)} ${items === 1 ? 'item' : 'items'} in your vault`}</p>
      <p className="muted" data-vault="staleness">
        {STALENESS_LABELS[staleness]}
      </p>
      <MountLine mount={mount} />
      {!provisioned && (
        <p className="error" role="alert" data-vault="unprovisioned">
          {UNPROVISIONED}
        </p>
      )}
      {warnings.map((raised, index) => (
        <Warning key={`${raised.kind}-${String(index)}`} warning={raised} />
      ))}
      {/* Never silent, and never folded into the staleness line: a parked write
          is a different thing from an old view. */}
      {deadLetters > 0 && (
        <p className="error" role="alert" data-vault="dead-letters">
          {`${String(deadLetters)} ${deadLetters === 1 ? 'change' : 'changes'} cannot publish — open CipherBox on the web to resolve`}
        </p>
      )}
    </section>
  );
}

/**
 * Where the vault is on this machine, or why it is nowhere.
 *
 * A refusal is an error rather than a muted note: a member who thinks the mount
 * is there works in a folder nothing is watching.
 */
function MountLine({ mount }: { mount: MountStatus }) {
  switch (mount.state) {
    case 'opening':
      return (
        <p className="muted" data-vault="mount-opening">
          Mounting your vault…
        </p>
      );
    case 'mounted':
      return (
        <p className="muted" data-vault="mount">
          {`Mounted at ${mount.path}`}
        </p>
      );
    case 'refused':
      return (
        <p className="error" role="alert" data-vault="mount-refused">
          {mount.reason}
        </p>
      );
  }
}

/**
 * One engine warning, with the engine's own words for it where it had any.
 *
 * The fallback is unreachable by the types and kept anyway: a class the engine
 * gains before this table does must still raise something a member can act on,
 * which is the whole point of the line. The staleness table needs no such
 * guard — an unnamed rung is a cosmetic gap, not a silent warning.
 */
function Warning({ warning: { kind, detail } }: { warning: VaultWarning }) {
  const label = WARNING_LABELS[kind] ?? 'CipherBox raised a condition it could not name';
  return (
    <p className="error" role="alert" data-vault="warning" data-warning={kind}>
      {detail === null ? label : `${label} — ${detail}`}
    </p>
  );
}

/** Shown verbatim on every screen — the licence condition, see `docs/ATTRIBUTION.md`. */
const WINFSP_NOTICE = 'WinFsp - Windows File System Proxy, Copyright (C) Bill Zissimopoulos';
const WINFSP_HOME = 'https://github.com/winfsp/winfsp';

/**
 * The attribution footer. The address is text, not an anchor: this shell has no
 * opener plugin and its CSP admits nothing but itself, so a live link would
 * navigate the only window away from a signed-in session.
 */
function Attribution() {
  return (
    <footer className="attribution" data-attribution="winfsp">
      <Note>{WINFSP_NOTICE}</Note>
      <Note>{WINFSP_HOME}</Note>
    </footer>
  );
}

function Note({ children }: { children: string }) {
  return <p className="muted">{children}</p>;
}

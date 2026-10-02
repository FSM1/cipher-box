import { useEffect, useRef, useState, type FormEvent } from 'react';
import type { AuthMethodKind } from '@cipherbox/client';
import { useAuthMethods, type AuthMethodsRead } from '../../hooks/useAuthMethods';
import { formatDate } from '../../utils/format';
import { WalletSignature } from '../auth/WalletSignature';

const KIND_LABEL: Record<AuthMethodKind, string> = {
  identity: 'identity key',
  wallet: 'wallet',
  email: 'email',
  test: 'test',
  unknown: 'unrecognised',
};

/** Why the account's last remaining method cannot go, in the API's own terms. */
const ONLY_METHOD = 'an account must keep at least one login method';

const AUTHORISES_ITSELF = 'this login is the account itself, so unlinking it would revoke nothing';

/**
 * Why a row of this kind cannot go, or `null` where it can. Identity and test
 * logins authorise off the account rather than off the row, so the next one
 * through recreates it — the API refuses the same pair with a 409.
 */
const KIND_REFUSAL: Record<AuthMethodKind, string | null> = {
  identity: AUTHORISES_ITSELF,
  test: AUTHORISES_ITSELF,
  wallet: null,
  email: null,
  unknown: null,
};

/**
 * When the method last opened the account. `Intl` throws on a timestamp it
 * cannot format, so an unparseable one reads back verbatim rather than taking
 * the pane down.
 */
function lastUsedLabel(lastUsedAt: string | null): string {
  if (lastUsedAt === null) return 'never used';
  const millis = Date.parse(lastUsedAt);
  return Number.isNaN(millis) ? `last used ${lastUsedAt}` : `last used ${formatDate(millis)}`;
}

/**
 * Links an email code login: the address, then the code sent to it. The form
 * holds both only until the link lands or the member starts over.
 */
function EmailLinkForm({
  busy,
  sendCode,
  link,
  onClose,
}: {
  busy: AuthMethodsRead['busy'];
  sendCode: (email: string) => Promise<boolean>;
  link: (email: string, code: string) => Promise<boolean>;
  onClose: () => void;
}) {
  const [email, setEmail] = useState('');
  const [code, setCode] = useState('');
  const [sentTo, setSentTo] = useState<string | null>(null);
  const emailInput = useRef<HTMLInputElement>(null);
  const codeInput = useRef<HTMLInputElement>(null);

  const trimmed = email.trim().toLowerCase();
  const blocked = busy !== null;
  const sending = busy === 'emailLinkSendCode';
  const linking = busy === 'emailLink';

  // Each step swaps the field out from under the focused button.
  useEffect(() => {
    (sentTo === null ? emailInput : codeInput).current?.focus();
  }, [sentTo]);

  // The pane renders the refusal; this form only advances on success.
  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (blocked) return;
    if (sentTo === null) {
      if (trimmed && (await sendCode(trimmed))) setSentTo(trimmed);
      return;
    }
    if (code.length === 6 && (await link(sentTo, code))) onClose();
  };

  const restart = () => {
    setSentTo(null);
    setCode('');
  };

  return (
    <form
      onSubmit={(event) => void submit(event)}
      className="email-login-form"
      data-testid="settings-link-email-form"
    >
      {sentTo === null ? (
        <>
          <label htmlFor="link-email" className="sr-only">
            Email address
          </label>
          <input
            id="link-email"
            ref={emailInput}
            data-testid="settings-link-email-input"
            type="email"
            className="email-login-input"
            placeholder="enter email address"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            disabled={blocked}
            required
            autoComplete="email"
          />
          <button
            type="submit"
            data-testid="settings-link-email-send"
            className={filledButton(sending)}
            disabled={blocked || !trimmed}
            aria-busy={sending}
          >
            {sending ? 'sending code...' : '[SEND CODE]'}
          </button>
          <button
            type="button"
            data-testid="settings-link-email-cancel"
            className="email-login-restart"
            onClick={onClose}
            disabled={blocked}
          >
            // cancel
          </button>
        </>
      ) : (
        <>
          <p className="email-login-sent" aria-live="polite">
            // code sent to {sentTo}
          </p>
          <label htmlFor="link-code" className="sr-only">
            Verification code
          </label>
          <input
            id="link-code"
            ref={codeInput}
            data-testid="settings-link-email-code"
            type="text"
            className="email-login-input"
            placeholder="enter 6-digit code"
            value={code}
            onChange={(event) => setCode(event.target.value.replace(/\D/g, '').slice(0, 6))}
            disabled={blocked}
            required
            autoComplete="one-time-code"
            inputMode="numeric"
            maxLength={6}
          />
          <button
            type="submit"
            data-testid="settings-link-email-link"
            className={filledButton(linking)}
            disabled={blocked || code.length !== 6}
            aria-busy={linking}
          >
            {linking ? 'linking...' : '[LINK]'}
          </button>
          <button
            type="button"
            data-testid="settings-link-email-restart"
            className="email-login-restart"
            onClick={restart}
            disabled={blocked}
          >
            // use a different address
          </button>
        </>
      )}
    </form>
  );
}

function filledButton(loading: boolean): string {
  return loading
    ? 'terminal-btn terminal-btn--filled terminal-btn--loading'
    : 'terminal-btn terminal-btn--filled';
}

/**
 * The login methods on this account: what opens it, and the exchanges that add
 * or remove one.
 *
 * A listed row shows only the display identifier the API serves — never a
 * plaintext address and never the identifier hash. The one plaintext address
 * here is the one the member types into the email link form.
 */
export function AuthMethodsPane() {
  const { methods, busy, error, challenge, link, linkEmailSendCode, linkEmail, unlink } =
    useAuthMethods();
  const [walletError, setWalletError] = useState<string | null>(null);
  const [linkingEmail, setLinkingEmail] = useState(false);
  const linkEmailTrigger = useRef<HTMLButtonElement>(null);
  const wasLinkingEmail = useRef(false);

  // Closing the form mounts the trigger again, so keyboard focus moves back to it.
  useEffect(() => {
    if (!linkingEmail && wasLinkingEmail.current) linkEmailTrigger.current?.focus();
    wasLinkingEmail.current = linkingEmail;
  }, [linkingEmail]);

  const lastOne = methods.length <= 1;
  const message = walletError ?? error;

  return (
    <section className="settings-section" data-testid="settings-auth-methods">
      <h3>login methods</h3>
      <p className="sharing-note">
        {'// every method here opens this account. the account keeps at least one.'}
      </p>

      <ul className="settings-methods">
        {methods.map((method) => {
          const refusal = lastOne ? ONLY_METHOD : KIND_REFUSAL[method.kind];
          return (
            <li key={method.id} className="settings-method">
              <span className="settings-method-kind">{KIND_LABEL[method.kind]}</span>
              <span className="settings-method-id">{method.identifierDisplay ?? '—'}</span>
              <span className="settings-method-used">{lastUsedLabel(method.lastUsedAt)}</span>
              <button
                type="button"
                className="terminal-btn terminal-btn--danger"
                onClick={() => unlink(method.id)}
                disabled={refusal !== null || busy !== null}
                // A disabled control fires no hover, so the reason has to reach a
                // screen reader by name as well as by tooltip.
                title={refusal ?? undefined}
                aria-label={
                  refusal === null ? `unlink ${KIND_LABEL[method.kind]}` : `unlink — ${refusal}`
                }
                data-testid="settings-unlink"
              >
                unlink
              </button>
            </li>
          );
        })}
      </ul>

      <div className="settings-actions">
        <WalletSignature
          statement="Link wallet to CipherBox account"
          requestNonce={challenge}
          onSigned={link}
          trigger={{
            label: 'link a wallet',
            ariaLabel: 'Link a wallet',
            testId: 'settings-link-wallet',
          }}
          handoffLabel="linking..."
          onRejected={setWalletError}
          disabled={busy !== null}
        />
        {!linkingEmail && (
          <button
            ref={linkEmailTrigger}
            type="button"
            className="terminal-btn"
            onClick={() => {
              setWalletError(null);
              setLinkingEmail(true);
            }}
            disabled={busy !== null}
            aria-label="Link an email"
            data-testid="settings-link-email"
          >
            link an email
          </button>
        )}
      </div>

      {linkingEmail && (
        <EmailLinkForm
          busy={busy}
          sendCode={linkEmailSendCode}
          link={linkEmail}
          onClose={() => setLinkingEmail(false)}
        />
      )}

      {message !== null && (
        <p className="dialog-error" role="alert" data-testid="settings-auth-error">
          {message}
        </p>
      )}
    </section>
  );
}

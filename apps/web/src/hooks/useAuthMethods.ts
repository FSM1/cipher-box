/**
 * The account's login methods, and the exchanges that change the list. Each
 * change re-reads, so the pane shows what the account now carries.
 */

import { useCallback, useEffect, useState } from 'react';
import type { AuthMethodDescriptor } from '@cipherbox/client';
import { fromHex } from '@cipherbox/client';
import { useEngine } from '../providers/EngineProvider';
import { useCommandRunner } from './useCommandRunner';

export type AuthMethodsCommand =
  | 'authMethods'
  | 'siweLink'
  | 'emailLinkSendCode'
  | 'emailLink'
  | 'unlinkAuthMethod';

export interface AuthMethodsRead {
  methods: AuthMethodDescriptor[];
  /** The command in flight, so each control can label its own exchange. */
  busy: AuthMethodsCommand | null;
  error: string | null;
  /** Retires the refusal on screen once the member acts on it. */
  clearError(): void;
  /** Issues the single-use nonce a link message embeds. */
  challenge(): Promise<string>;
  link(message: string, signature: string): Promise<void>;
  /** Resolves `true` once the link code is on its way to `email`. */
  linkEmailSendCode(email: string): Promise<boolean>;
  /** Resolves `true` once `email` is linked; the list re-reads after it. */
  linkEmail(email: string, code: string): Promise<boolean>;
  unlink(methodId: string): void;
}

export function useAuthMethods(): AuthMethodsRead {
  const client = useEngine();
  const [methods, setMethods] = useState<AuthMethodDescriptor[]>([]);
  const { busy, error, run, clearError } = useCommandRunner<AuthMethodsCommand>();

  const reload = useCallback(
    () => run('authMethods', async (facade) => setMethods(await facade.authMethods())),
    [run]
  );

  useEffect(() => {
    void reload();
  }, [reload]);

  // The wallet flow reports its own refusals, so the challenge throws into it
  // rather than through the command runner.
  const challenge = useCallback(() => {
    if (client === null) return Promise.reject(new Error('the engine is not ready yet'));
    return client.facade.siweChallenge('link');
  }, [client]);

  const link = useCallback(
    async (message: string, signature: string) => {
      // The wallet hands back `0x`-prefixed hex; the engine takes the bytes and
      // owns every re-encoding of them below the facade.
      const bytes = fromHex(signature.replace(/^0x/, ''));
      if (await run('siweLink', (facade) => facade.siweLink(message, bytes))) await reload();
    },
    [run, reload]
  );

  const linkEmailSendCode = useCallback(
    (email: string) =>
      run('emailLinkSendCode', async (facade) => {
        await facade.emailLinkSendCode(email);
      }),
    [run]
  );

  const linkEmail = useCallback(
    async (email: string, code: string) => {
      const linked = await run('emailLink', (facade) => facade.emailLink(email, code));
      if (linked) await reload();
      return linked;
    },
    [run, reload]
  );

  const unlink = useCallback(
    (methodId: string) =>
      void run('unlinkAuthMethod', (facade) => facade.unlinkAuthMethod(methodId)).then(
        async (unlinked) => {
          if (unlinked) await reload();
        }
      ),
    [run, reload]
  );

  return {
    methods,
    busy,
    error,
    clearError,
    challenge,
    link,
    linkEmailSendCode,
    linkEmail,
    unlink,
  };
}

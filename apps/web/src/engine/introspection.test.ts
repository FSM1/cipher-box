import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { installIntrospection } from './introspection';
import { authStore } from '../stores/auth.store';
import { fakeEngine, flush, ROOT_ID, view } from './testFakes';

describe('installIntrospection', () => {
  beforeEach(() => {
    delete window.__CIPHERBOX_ENGINE__;
    authStore.signedOut();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it('publishes nothing without the e2e build flag', () => {
    const engine = fakeEngine();

    expect(installIntrospection(engine.client)).toBe(engine.client);
    expect(window.__CIPHERBOX_ENGINE__).toBeUndefined();
    expect(engine.subscriberCount()).toBe(0);
  });

  it('leaves the hook out for any value but the flag', () => {
    vi.stubEnv('VITE_E2E_HOOK', 'false');

    installIntrospection(fakeEngine().client);

    expect(window.__CIPHERBOX_ENGINE__).toBeUndefined();
  });

  describe('under the e2e build flag', () => {
    beforeEach(() => {
      vi.stubEnv('VITE_E2E_HOOK', 'true');
    });

    it('projects a snapshot into hex and decimal strings', async () => {
      const engine = fakeEngine();
      installIntrospection(engine.client);

      const pending = window.__CIPHERBOX_ENGINE__?.snapshot(null);
      await flush();
      const child = { ...view(ROOT_ID, 'fresh', 1).children[0]!, size: 42n };
      engine.pulls[0]?.resolve({ ...view(), children: [child] });

      const answer = await pending;
      expect(answer?.view.root).toBe('00000000000000000000000000000000');
      expect(answer?.view.children[0]?.id).toBe('01010101010101010101010101010101');
      expect(answer?.view.children[0]?.size).toBe('42');
      expect(answer?.settled).toBe(true);
    });

    it('addresses a folder by its hex node id', async () => {
      const engine = fakeEngine();
      installIntrospection(engine.client);

      void window.__CIPHERBOX_ENGINE__?.snapshot('0102030405060708090a0b0c0d0e0f10');
      await flush();

      expect(engine.pulls[0]?.folder).toEqual(
        new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
      );
    });

    it('is unsettled while the queue holds an op for a child', async () => {
      const engine = fakeEngine();
      installIntrospection(engine.client);

      const pending = window.__CIPHERBOX_ENGINE__?.snapshot(null);
      await flush();
      const listing = view(ROOT_ID, 'fresh', 1);
      listing.children[0]!.pending = 'content';
      engine.pulls[0]?.resolve(listing);

      expect((await pending)?.settled).toBe(false);
    });

    it('is unsettled while the vault is off the latest version', async () => {
      const engine = fakeEngine();
      installIntrospection(engine.client);

      const pending = window.__CIPHERBOX_ENGINE__?.snapshot(null);
      await flush();
      engine.pulls[0]?.resolve(view(ROOT_ID, 'reconciling'));

      expect((await pending)?.settled).toBe(false);
    });

    it('records the event stream in emission order', () => {
      const engine = fakeEngine();
      installIntrospection(engine.client);

      engine.emit({ kind: 'snapshotUpdated' });
      engine.emit({ kind: 'stalenessChanged', staleness: 'stale' });
      engine.emit({ kind: 'deadLetter', opId: 7n, reason: 'targetGone' });

      expect(window.__CIPHERBOX_ENGINE__?.events()).toEqual([
        { kind: 'snapshotUpdated' },
        { kind: 'stalenessChanged', staleness: 'stale' },
        { kind: 'deadLetter', opId: '7', reason: 'targetGone' },
      ]);
    });

    it('drops the replaced client subscription when a rebuild reinstalls', () => {
      const first = fakeEngine();
      installIntrospection(first.client);
      installIntrospection(fakeEngine().client);

      expect(first.subscriberCount()).toBe(0);
      expect(window.__CIPHERBOX_ENGINE__?.events()).toEqual([]);
    });

    it('signs the chrome in once the engine has taken the secret', async () => {
      const engine = fakeEngine();
      const start = vi.fn().mockResolvedValue(undefined);
      (engine.client.facade as unknown as { start: unknown }).start = start;
      installIntrospection(engine.client);

      await window.__CIPHERBOX_ENGINE__?.signIn('11'.repeat(32));

      expect(start).toHaveBeenCalledOnce();
      expect(authStore.getState()).toMatchObject({ isAuthenticated: true, method: 'test' });
    });

    it('refuses a secret that is not a 32-byte scalar, leaving the chrome signed out', async () => {
      const engine = fakeEngine();
      (engine.client.facade as unknown as { start: unknown }).start = vi.fn();
      installIntrospection(engine.client);

      await expect(window.__CIPHERBOX_ENGINE__?.signIn('11'.repeat(31))).rejects.toThrow(
        'not a 32-byte scalar'
      );
      expect(authStore.getState().isAuthenticated).toBe(false);
    });
  });
});

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

      const pending = window.__CIPHERBOX_ENGINE__?.snapshot();
      await flush();
      const child = { ...view(ROOT_ID, 'fresh', 1).children[0]!, size: 42n };
      engine.pulls[0]?.resolve({ ...view(), children: [child] });

      const answer = await pending;
      expect(answer?.view.root).toBe('00000000000000000000000000000000');
      expect(answer?.view.children[0]?.id).toBe('01010101010101010101010101010101');
      expect(answer?.view.children[0]?.size).toBe('42');
      expect(answer?.settled).toBe(true);
    });

    it('is unsettled while the queue holds an op for a child', async () => {
      const engine = fakeEngine();
      installIntrospection(engine.client);

      const pending = window.__CIPHERBOX_ENGINE__?.snapshot();
      await flush();
      const listing = view(ROOT_ID, 'fresh', 1);
      listing.children[0]!.pending = 'content';
      engine.pulls[0]?.resolve(listing);

      expect((await pending)?.settled).toBe(false);
    });

    it('is unsettled while the vault is off the latest version', async () => {
      const engine = fakeEngine();
      installIntrospection(engine.client);

      const pending = window.__CIPHERBOX_ENGINE__?.snapshot();
      await flush();
      engine.pulls[0]?.resolve(view(ROOT_ID, 'reconciling'));

      expect((await pending)?.settled).toBe(false);
    });

    it('reads a node named in hex and hands its plaintext back the same way', async () => {
      const engine = fakeEngine();
      const download = vi.fn().mockResolvedValue(Uint8Array.of(0xde, 0xad, 0xbe, 0xef).buffer);
      (engine.client.facade as unknown as { download: unknown }).download = download;
      installIntrospection(engine.client);

      const plaintext = await window.__CIPHERBOX_ENGINE__?.download('0102030405060708');

      expect(download).toHaveBeenCalledWith(Uint8Array.of(1, 2, 3, 4, 5, 6, 7, 8));
      expect(plaintext).toBe('deadbeef');
    });

    it.each(['010', 'zz'])('refuses %s as a node id, before the engine is asked', async (bad) => {
      const engine = fakeEngine();
      const download = vi.fn();
      (engine.client.facade as unknown as { download: unknown }).download = download;
      installIntrospection(engine.client);

      await expect(window.__CIPHERBOX_ENGINE__?.download(bad)).rejects.toThrow(TypeError);
      expect(download).not.toHaveBeenCalled();
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

    it('republishes over the replaced client when a rebuild reinstalls', () => {
      const first = fakeEngine();
      installIntrospection(first.client);
      first.emit({ kind: 'snapshotUpdated' });
      installIntrospection(fakeEngine().client);

      expect(window.__CIPHERBOX_ENGINE__?.events()).toEqual([]);
    });

    it('signs the chrome in once the engine has taken the secret', async () => {
      const engine = fakeEngine();
      const start = vi.fn().mockResolvedValue(undefined);
      (engine.client.facade as unknown as { start: unknown }).start = start;
      installIntrospection(engine.client);

      await window.__CIPHERBOX_ENGINE__?.signIn('11'.repeat(32), 'e2eaccount');

      expect(start).toHaveBeenCalledOnce();
      // The chrome names no login method: an injected cold start is none of them.
      expect(authStore.getState()).toMatchObject({ isAuthenticated: true, method: null });
    });

    it('refuses a secret that is not a 32-byte scalar, leaving the chrome signed out', async () => {
      const engine = fakeEngine();
      (engine.client.facade as unknown as { start: unknown }).start = vi.fn();
      installIntrospection(engine.client);

      await expect(
        window.__CIPHERBOX_ENGINE__?.signIn('11'.repeat(31), 'e2eaccount')
      ).rejects.toThrow('not a 32-byte scalar');
      expect(authStore.getState().isAuthenticated).toBe(false);
    });
  });
});

import { invoke } from '@tauri-apps/api/core';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { IDENTITY_TOKEN_HEADER, shellFacade } from './facade';

vi.mock('@tauri-apps/api/core', () => ({ invoke: vi.fn() }));

const ipc = vi.mocked(invoke);

describe('shellFacade.start', () => {
  beforeEach(() => {
    ipc.mockReset();
    ipc.mockResolvedValue(undefined);
  });

  it('sends the secret as the raw body and the identity token as a header', async () => {
    const secret = new ArrayBuffer(32);

    await shellFacade.start(secret, 'account', 'identity.jwt');

    expect(ipc).toHaveBeenCalledWith('session_start', secret, {
      headers: { [IDENTITY_TOKEN_HEADER]: 'identity.jwt' },
    });
  });

  it('sends no header for a start that follows no exchange', async () => {
    const secret = new ArrayBuffer(32);

    await shellFacade.start(secret, 'account');

    expect(ipc).toHaveBeenCalledWith('session_start', secret, undefined);
  });
});

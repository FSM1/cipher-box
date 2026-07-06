/**
 * CipherBoxClient.downloadSharedFile tests (68.2-08 Rule-2 facade addition).
 *
 * Moves the fetch+decrypt orchestration previously done directly in
 * `apps/web/src/hooks/useSharedNavigationActions.ts`'s `downloadSharedFile`/
 * `loadSharedFileContent` into the SDK, wrapping the UNCHANGED
 * `sdkCore.navigateReadChain` primitive (per 68.2-RESEARCH.md's guidance not
 * to modify it -- it has other existing callers within sdk-core's own test
 * suite). Only `navigateReadChain` and `fetchFromIpfs` are mocked at the
 * `@cipherbox/sdk-core` barrel -- the level `client.ts` actually imports
 * through (`import * as sdkCore from '@cipherbox/sdk-core'`); real
 * `decryptAesGcm`/`decryptAesCtr` run so the round-trip is genuinely
 * exercised.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { CipherBoxClient } from '../client';
import { createTestConfig } from './helpers';
import { encryptAesGcm, encryptAesCtr, bytesToHex } from '@cipherbox/crypto';
import type { NavigateResult } from '@cipherbox/sdk-core';

vi.mock('@cipherbox/sdk-core', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@cipherbox/sdk-core')>();
  return {
    ...actual,
    navigateReadChain: vi.fn(),
    fetchFromIpfs: vi.fn(),
  };
});

import * as sdkCore from '@cipherbox/sdk-core';

/** Mirrors the SDK's own private `sharedFileBytesToBase64` (test-local, kept independent). */
function bytesToBase64(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

describe('CipherBoxClient.downloadSharedFile', () => {
  let client: CipherBoxClient;

  beforeEach(() => {
    vi.clearAllMocks();
    client = new CipherBoxClient(createTestConfig());
  });

  it('bridges the hex readDescriptorRef to base64, fetches + decrypts the leaf content (GCM), and zeroes the recovered fileKey', async () => {
    const fileKey = new Uint8Array(32).fill(0x55);
    const plaintext = new TextEncoder().encode('hello shared file');
    const iv = new Uint8Array(12).fill(0x01);
    const ciphertext = await encryptAesGcm(plaintext, fileKey, iv);
    const contentFileKey = fileKey.slice();

    const navigateResult: NavigateResult = {
      status: 'ok',
      nodeId: 'file-node-id',
      content: {
        cid: 'bafyfile',
        fileIv: bytesToBase64(iv),
        size: plaintext.length,
        mimeType: 'text/plain',
        encryptionMode: 'GCM',
        fileKey: contentFileKey,
        versions: [],
      },
    };
    vi.mocked(sdkCore.navigateReadChain).mockResolvedValue(navigateResult);
    vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(ciphertext);

    const rawDescriptor = new Uint8Array([1, 2, 3, 4, 5]);
    const readDescriptorRefHex = bytesToHex(rawDescriptor);
    const recipientPrivateKey = new Uint8Array(32).fill(0x99);

    const result = await client.downloadSharedFile({
      readDescriptorRef: readDescriptorRefHex,
      recipientPrivateKey,
      rootIpnsName: 'k51root',
      rootExpectedGeneration: 0,
      path: ['k51leaf'],
    });

    expect(result.status).toBe('ok');
    if (result.status !== 'ok') throw new Error('unreachable');
    expect(result.plaintext).toEqual(plaintext);
    expect(result.mimeType).toBe('text/plain');
    expect(result.encryptionMode).toBe('GCM');

    // Bridged to base64 correctly before calling navigateReadChain.
    const callArgs = vi.mocked(sdkCore.navigateReadChain).mock.calls[0][0];
    expect(callArgs.readDescriptorRef).toBe(bytesToBase64(rawDescriptor));
    expect(callArgs.recipientPrivKey).toBe(recipientPrivateKey);
    expect(callArgs.rootIpnsName).toBe('k51root');
    expect(callArgs.rootExpectedGeneration).toBe(0);
    expect(callArgs.path).toEqual(['k51leaf']);

    expect(sdkCore.fetchFromIpfs).toHaveBeenCalledWith(expect.anything(), 'bafyfile');

    // Terminal-owner zeroing of the recovered fileKey (D-09).
    expect(contentFileKey.every((b) => b === 0)).toBe(true);
    // Caller-owned recipientPrivateKey is never touched.
    expect(recipientPrivateKey.every((b) => b === 0x99)).toBe(true);
  });

  it('decrypts CTR-mode content correctly', async () => {
    const fileKey = new Uint8Array(32).fill(0x66);
    const plaintext = new TextEncoder().encode('streaming media bytes');
    const iv = new Uint8Array(16).fill(0x02);
    const ciphertext = await encryptAesCtr(plaintext, fileKey, iv);

    vi.mocked(sdkCore.navigateReadChain).mockResolvedValue({
      status: 'ok',
      nodeId: 'file-node-id',
      content: {
        cid: 'bafyctr',
        fileIv: bytesToBase64(iv),
        size: plaintext.length,
        mimeType: 'video/mp4',
        encryptionMode: 'CTR',
        fileKey: fileKey.slice(),
        versions: [],
      },
    });
    vi.mocked(sdkCore.fetchFromIpfs).mockResolvedValue(ciphertext);

    const result = await client.downloadSharedFile({
      readDescriptorRef: bytesToHex(new Uint8Array([9, 9])),
      recipientPrivateKey: new Uint8Array(32).fill(0x11),
      rootIpnsName: 'k51root',
      rootExpectedGeneration: 0,
      path: [],
    });

    expect(result.status).toBe('ok');
    if (result.status !== 'ok') throw new Error('unreachable');
    expect(result.plaintext).toEqual(plaintext);
    expect(result.encryptionMode).toBe('CTR');
  });

  it('returns status revoked without calling fetchFromIpfs', async () => {
    vi.mocked(sdkCore.navigateReadChain).mockResolvedValue({ status: 'revoked' });

    const result = await client.downloadSharedFile({
      readDescriptorRef: bytesToHex(new Uint8Array([1])),
      recipientPrivateKey: new Uint8Array(32).fill(1),
      rootIpnsName: 'k51root',
      rootExpectedGeneration: 0,
      path: [],
    });

    expect(result.status).toBe('revoked');
    expect(sdkCore.fetchFromIpfs).not.toHaveBeenCalled();
  });

  it('returns status behind-retry when the root was rotated since the grant was issued', async () => {
    vi.mocked(sdkCore.navigateReadChain).mockResolvedValue({ status: 'behind-retry' });

    const result = await client.downloadSharedFile({
      readDescriptorRef: bytesToHex(new Uint8Array([1])),
      recipientPrivateKey: new Uint8Array(32).fill(1),
      rootIpnsName: 'k51root',
      rootExpectedGeneration: 0,
      path: [],
    });

    expect(result.status).toBe('behind-retry');
    expect(sdkCore.fetchFromIpfs).not.toHaveBeenCalled();
  });
});

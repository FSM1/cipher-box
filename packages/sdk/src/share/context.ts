/**
 * @cipherbox/sdk - Shared write context builder
 *
 * Extracted from apps/web/src/hooks/useSharedNavigation.ts buildSharedWriteCtx().
 * Takes explicit params instead of reading React state directly.
 */

import type { FolderChild } from '@cipherbox/core';
import type { SdkContext } from '@cipherbox/sdk-core';
import type { SharedWriteContext, ShareKeyType } from './shared-write';

/**
 * Parameters for building a SharedWriteContext.
 * All the state that was previously read from React hooks.
 */
export type SharedWriteContextParams = {
  ctx: SdkContext;
  folderKey: Uint8Array;
  ipnsPrivateKey: Uint8Array;
  ipnsName: string;
  sequenceNumber: bigint;
  children: FolderChild[];
  ownerPublicKey: Uint8Array;
  recipientPublicKey: Uint8Array;
  shareId: string;
  addShareKeysFn: (
    shareId: string,
    keys: Array<{ keyType: ShareKeyType; itemId: string; encryptedKey: string }>,
  ) => Promise<void>;
};

/**
 * Build a SharedWriteContext from explicit parameters.
 *
 * The web hook wrapper handles null-checking of each field before calling this.
 * This function assumes all required fields are present.
 *
 * @param params - All required state for shared write operations
 * @returns SharedWriteContext ready for SDK shared-write operations
 */
export function buildSharedWriteContext(params: SharedWriteContextParams): SharedWriteContext {
  return {
    ctx: params.ctx,
    folderKey: params.folderKey,
    ipnsPrivateKey: params.ipnsPrivateKey,
    ipnsName: params.ipnsName,
    sequenceNumber: params.sequenceNumber,
    children: params.children,
    ownerPublicKey: params.ownerPublicKey,
    recipientPublicKey: params.recipientPublicKey,
    shareId: params.shareId,
    addShareKeysFn: params.addShareKeysFn,
  };
}
